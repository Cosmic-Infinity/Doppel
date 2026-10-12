import uuid
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from doppel.config import DoppelConfig
from doppel.ai.deception_engine import DeceptionEngine
from doppel.sandbox.docker_manager import DockerSandboxManager
from doppel.router.hybrid_router import HybridRouter, RouteDecision
from doppel.analytics.db import TelemetryDB
from doppel.analytics.observer import ThreatObserver
from doppel.analytics.reporter import IncidentReporter
from doppel.core.fake_filesystem import FakeFilesystem
from doppel.analytics.profiler import AttackerProfiler, ProfilerState
from doppel.alerts.email import EmailAlerter

logger = logging.getLogger("doppel.core.session")


@dataclass
class SessionState:
    session_id: str
    remote_ip: str
    remote_port: int
    username: str
    password: str = ""
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cwd: str = "/home/ubuntu"
    container_id: Optional[str] = None
    history: List[Dict[str, str]] = field(default_factory=list)
    threat_score: int = 0
    is_active: bool = True
    credential_analysis: dict = field(default_factory=dict)
    fake_fs: object = field(default=None)  # FakeFilesystem, typed as object to avoid circular
    geoip: dict = field(default_factory=dict)
    profiler_state: object = field(default=None)  # ProfilerState, typed as object


class SessionManager:
    """Orchestrates active attacker sessions across sandbox, deception engine, and telemetry."""

    def __init__(
        self,
        config: DoppelConfig,
        deception_engine: DeceptionEngine,
        sandbox_manager: DockerSandboxManager,
        router: HybridRouter,
        db: TelemetryDB,
        observer: ThreatObserver,
        reporter: IncidentReporter,
        alerter: Optional[EmailAlerter] = None,
    ):
        self.config = config
        self.deception_engine = deception_engine
        self.sandbox_manager = sandbox_manager
        self.router = router
        self.db = db
        self.observer = observer
        self.reporter = reporter
        if alerter is not None:
            self.alerter = alerter
        else:
            email_cfg = getattr(getattr(config, "alerts", None), "email", None)
            if email_cfg and getattr(email_cfg, "enabled", False):
                self.alerter = EmailAlerter(
                    enabled=email_cfg.enabled,
                    smtp_server=email_cfg.smtp_server,
                    smtp_port=email_cfg.smtp_port,
                    smtp_user=email_cfg.smtp_user,
                    smtp_password=email_cfg.smtp_password,
                    use_tls=email_cfg.use_tls,
                    sender_email=email_cfg.sender_email,
                    receiver_email=email_cfg.receiver_email,
                    min_threat_score=email_cfg.min_threat_score,
                )
            else:
                self.alerter = None
        self.sessions: Dict[str, SessionState] = {}
        self._background_tasks: set[asyncio.Task] = set()
        self.event_callbacks: List[Any] = []
        self._profiler = AttackerProfiler()

    def register_event_listener(self, callback: Any):
        self.event_callbacks.append(callback)

    def _notify(self, event_type: str, data: Dict[str, Any]):
        for cb in self.event_callbacks:
            try:
                res = cb(event_type, data)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception as e:
                logger.debug(f"Event callback notification error: {e}")

    async def create_session(
        self,
        remote_ip: str,
        remote_port: int,
        username: str,
        password: str = "",
        session_id: Optional[str] = None,
        credential_analysis: Optional[dict] = None,
        geoip: Optional[dict] = None,
    ) -> SessionState:
        sess_id = session_id or str(uuid.uuid4())
        initial_cwd = "/root" if username == "root" else f"/home/{username}"

        container_id = None
        if self.config.sandbox.enabled:
            if not self.sandbox_manager.is_available:
                await asyncio.to_thread(self.sandbox_manager.check_availability)
            if self.sandbox_manager.is_available:
                container_id = await asyncio.to_thread(
                    self.sandbox_manager.create_sandbox_session, sess_id, username=username
                )

        session = SessionState(
            session_id=sess_id,
            remote_ip=remote_ip,
            remote_port=remote_port,
            username=username,
            password=password,
            cwd=initial_cwd,
            container_id=container_id,
            credential_analysis=credential_analysis or {},
            fake_fs=FakeFilesystem(),
            geoip=geoip or {},
            profiler_state=ProfilerState(),
        )
        self.sessions[sess_id] = session

        await self.db.log_session_start(
            session_id=sess_id,
            remote_ip=remote_ip,
            remote_port=remote_port,
            username=username,
            password=password,
            geoip=session.geoip,
            credential_risk=(session.credential_analysis.get("risk_level") if session.credential_analysis else None),
        )
        logger.info(f"Initialized session {sess_id[:8]} for {username}@{remote_ip}:{remote_port}")
        self._notify("session_created", {
            "session_id": sess_id,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "username": username,
            "start_time": session.start_time,
            "cwd": session.cwd,
            "credential_analysis": session.credential_analysis,
            "geoip": session.geoip,
        })
        return session

    def get_session(self, session_id: str) -> Optional[SessionState]:
        return self.sessions.get(session_id)

    async def process_command(self, session_id: str, raw_command: str) -> str:
        """Process incoming command string and return the shell output."""
        session = self.get_session(session_id)
        if not session:
            return "Session expired.\n"

        cmd_clean = raw_command.strip()
        if not cmd_clean:
            return ""

        # If sandbox enabled but session lacks a container, check if Docker became available
        if self.config.sandbox.enabled and not session.container_id:
            if not self.sandbox_manager.is_available:
                await asyncio.to_thread(self.sandbox_manager.check_availability)
            if self.sandbox_manager.is_available:
                session.container_id = await asyncio.to_thread(
                    self.sandbox_manager.create_sandbox_session,
                    session.session_id,
                    username=session.username,
                )

        # Update router sandbox availability status
        self.router.sandbox_available = bool(session.container_id and self.sandbox_manager.is_available)

        # Check whether this session's IP is in the safe allowlist
        is_safe_ip = session.remote_ip in self.config.access.safe_ips

        # 1. Routing classification
        decision, route_reason = self.router.classify_command(cmd_clean, is_safe_ip=is_safe_ip)
        output = ""

        # 2. Command execution based on route decision
        if decision == RouteDecision.BUILTIN:
            output = self._handle_builtin(session, cmd_clean)
        elif decision == RouteDecision.SANDBOX and session.container_id:
            try:
                res = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.sandbox_manager.execute_in_sandbox,
                        container_id=session.container_id,
                        command=cmd_clean,
                        workdir=session.cwd,
                        user=session.username,
                    ),
                    timeout=20.0,
                )
                output = (res.stdout or "") + (res.stderr or "")
            except asyncio.TimeoutError:
                logger.warning(f"Command '{cmd_clean}' timed out in sandbox")
                output = f"bash: {cmd_clean.split()[0] if cmd_clean.split() else 'command'}: command timed out\n"
        else:
            # LLM Deception — inject fake filesystem context so the model
            # knows about files the attacker created this session
            output = await self.deception_engine.generate_command_output(
                command=cmd_clean,
                cwd=session.cwd,
                user=session.username,
                session_history=session.history,
                fake_fs=session.fake_fs,
                session_id=session.session_id,
            )
            # After LLM responds, update the fake filesystem from this command
            if session.fake_fs:
                session.fake_fs.update_from_command(cmd_clean, output, cwd=session.cwd)

        # 3. Adaptive tar-pit delay — scales with attacker type
        base_delay_ms = self.config.deception.tar_pit_delay_ms
        if base_delay_ms > 0:
            attacker_type = (
                session.profiler_state.attacker_type
                if session.profiler_state else "unknown"
            )
            # Bots get max delay to waste their resources;
            # humans get a fraction so deception feels like real I/O.
            multipliers = {"bot": 3.0, "semi-automated": 1.5, "human": 0.3, "unknown": 1.0}
            multiplier = multipliers.get(attacker_type, 1.0)
            effective_ms = base_delay_ms * multiplier
            # Add ±20 % jitter so automated tools cannot fingerprint the constant delay
            import random as _random
            jitter = _random.uniform(0.8, 1.2)
            await asyncio.sleep(effective_ms * jitter / 1000.0)

        # 4. Record turn in session memory (with wall-clock timestamp for timing analysis)
        import time as _time
        session.history.append({
            "command": cmd_clean,
            "cwd": session.cwd,
            "output": output,
            "route_decision": decision.value,
            "ts": _time.monotonic(),
        })

        # 5. Immediate DB logging so command is recorded right away
        cmd_id = None
        try:
            cmd_id = await self.db.log_command(
                session_id=session.session_id,
                cwd=session.cwd,
                command=cmd_clean,
                output=output,
                route_decision=decision.value,
                threat_meta=None,
            )
        except Exception as db_err:
            logger.error(f"Failed to log command to DB: {db_err}")

        # 6. Background MITRE analysis & profiling
        task = asyncio.create_task(
            self._analyze_and_record(
                session=session,
                command=cmd_clean,
                output=output,
                decision=decision.value,
                cmd_id=cmd_id,
            )
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        _prof = session.profiler_state
        self._notify("command_executed", {
            "session_id": session_id,
            "command": cmd_clean,
            "cwd": session.cwd,
            "output": output,
            "decision": decision.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attacker_type": _prof.attacker_type if _prof else "unknown",
            "current_phase": _prof.current_phase if _prof else "Reconnaissance",
        })

        return output

    def _handle_builtin(self, session: SessionState, command: str) -> str:
        tokens = command.split()
        cmd = tokens[0].lower()

        if cmd == "cd":
            target = tokens[1] if len(tokens) > 1 else (f"/home/{session.username}" if session.username != "root" else "/root")
            if target == "~":
                session.cwd = f"/home/{session.username}" if session.username != "root" else "/root"
            elif target.startswith("/"):
                session.cwd = target
            elif target == "..":
                parts = [p for p in session.cwd.split("/") if p]
                session.cwd = "/" + "/".join(parts[:-1]) if parts[:-1] else "/"
            elif target == ".":
                pass
            else:
                session.cwd = (session.cwd.rstrip("/") + "/" + target).replace("//", "/")
            return ""

        if cmd == "clear":
            return "\033[H\033[2J"

        return ""

    async def _analyze_and_record(
        self,
        session: SessionState,
        command: str,
        output: str,
        decision: str,
        cmd_id: Optional[int] = None,
    ):
        try:
            threat_meta = None
            if self.config.analytics.enable_mitre_tagging:
                threat_meta = await self.observer.analyze_command(
                    session_id=session.session_id,
                    command=command,
                    cwd=session.cwd,
                    user=session.username,
                    session_history=[h["command"] for h in session.history],
                )
                if threat_meta:
                    session.threat_score = max(session.threat_score, threat_meta.get("threat_score", 0))
                    self._notify("threat_analyzed", {
                        "session_id": session.session_id,
                        "threat": threat_meta,
                        "threat_score": session.threat_score,
                    })
                    if self.alerter and self.alerter.should_alert(session.session_id, session.threat_score):
                        tech_desc = [f"{threat_meta.get('technique_id')}: {threat_meta.get('technique_name')}"] if threat_meta.get("technique_id") else []
                        geo_desc = f"{session.geoip.get('country_name', 'Unknown')}, {session.geoip.get('city', 'Unknown')} (ASN: {session.geoip.get('asn_org', 'Unknown')})"
                        asyncio.create_task(
                            self.alerter.maybe_send_alert(
                                session_id=session.session_id,
                                remote_ip=session.remote_ip,
                                threat_score=session.threat_score,
                                details={
                                    "username": session.username,
                                    "techniques": tech_desc,
                                    "last_command": command,
                                    "geo_summary": geo_desc,
                                },
                            )
                        )

            # ── Attacker profiler (timing + phase) ──────────────────────────────
            if session.profiler_state is not None:
                tactics_list = threat_meta.get("tactics", []) if threat_meta else []
                # Use the monotonic ts we stored in history for accurate gap measurement
                cmd_ts = session.history[-1].get("ts") if session.history else None
                updated_state, phase_event = self._profiler.record_command(
                    state=session.profiler_state,
                    command=command,
                    tactics=tactics_list,
                    now=cmd_ts,
                )
                session.profiler_state = updated_state

                from doppel.analytics.profiler import AttackerProfiler
                profile_summary = AttackerProfiler.summary(updated_state)
                self._notify("profile_updated", {
                    "session_id": session.session_id,
                    "profile": profile_summary,
                })

                if phase_event:
                    self._notify("phase_transition", {
                        "session_id": session.session_id,
                        **phase_event,
                    })
                    # Persist phase transition to DB (fire-and-forget; errors logged inside)
                    asyncio.create_task(self.db.log_phase_transition(
                        session_id=session.session_id,
                        from_phase=phase_event["from_phase"],
                        to_phase=phase_event["to_phase"],
                        phase_index=phase_event["phase_index"],
                        triggered_by=phase_event["triggered_by"],
                    ))

                # Persist live profile columns to DB (non-blocking)
                asyncio.create_task(self.db.update_session_profile(
                    session_id=session.session_id,
                    attacker_type=updated_state.attacker_type,
                    type_confidence=updated_state.type_confidence,
                    current_phase=updated_state.current_phase,
                ))

            if cmd_id is not None and threat_meta:
                await self.db.update_command_threat(cmd_id, threat_meta)
            elif cmd_id is None:
                await self.db.log_command(
                    session_id=session.session_id,
                    cwd=session.cwd,
                    command=command,
                    output=output,
                    route_decision=decision,
                    threat_meta=threat_meta,
                )
        except Exception as e:
            logger.error(f"Error in background threat analysis for session {session.session_id[:8]}: {e}", exc_info=True)

    async def close_session(self, session_id: str) -> Optional[str]:
        session = self.sessions.pop(session_id, None)
        if not session:
            return None

        session.is_active = False

        if session.container_id:
            await asyncio.to_thread(self.sandbox_manager.destroy_sandbox_session, session.container_id)

        # Wait for all background tasks to complete database writes before closing session
        if self._background_tasks:
            await asyncio.gather(*list(self._background_tasks), return_exceptions=True)

        await self.db.log_session_end(session_id)
        logger.info(f"Session {session_id[:8]} closed. Generating incident report...")

        report_path = await self.reporter.generate_session_report(session_id)
        self._notify("session_closed", {
            "session_id": session_id,
            "report_path": str(report_path) if report_path else None,
        })
        return str(report_path) if report_path else None
