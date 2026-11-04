import uuid
import asyncio
import logging
import posixpath
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
    fake_fs: Optional[Any] = None
    geoip: dict = field(default_factory=dict)
    profiler_state: object = field(default=None)  # ProfilerState, typed as object
    # Stateful Privilege Escalation
    effective_user: str = "ubuntu"
    is_elevated: bool = False
    pre_elevation_cwd: Optional[str] = None
    previous_cwd: Optional[str] = None  # bash's OLDPWD, for `cd -`


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
        # Reports are LLM calls; a burst of short sessions must not swamp the model
        max_reports = getattr(getattr(config, "analytics", None), "max_concurrent_reports", 2) or 1
        self._report_slots = asyncio.Semaphore(max(1, int(max_reports)))

    @staticmethod
    def can_drop_privileges(session: "SessionState") -> bool:
        """True inside a `sudo su`-style root shell opened by a non-root login."""
        return bool(session.is_elevated and session.effective_user != session.username)

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
            effective_user=username,
            is_elevated=(username == "root"),
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

    async def process_command(
        self,
        session_id: str,
        raw_command: str,
        keystroke_timestamps: Optional[List[float]] = None,
    ) -> str:
        """Process incoming command string and return the shell output."""
        session = self.get_session(session_id)
        if not session:
            return "Session expired.\n"

        cmd_clean = raw_command.strip()
        if not cmd_clean:
            return ""

        # Capture the prompt the command was typed at and when it arrived,
        # before execution can change cwd/user or add latency.
        import time as _time
        received_at = datetime.now(timezone.utc).isoformat()
        received_mono = _time.monotonic()
        prompt_cwd = session.cwd
        prompt_user = getattr(session, "effective_user", session.username)

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

        # Measure execution start time for latency harmonization
        cmd_start_time = _time.monotonic()
        sandbox_timeout = getattr(self.config.sandbox, "timeout_seconds", 10.0)

        # 1. Check for interactive privilege elevation (sudo su, su, etc.)
        elevation_cmds = (
            "sudo su", "sudo su -", "sudo -i", "sudo -s",
            "sudo bash", "sudo /bin/bash", "sudo sh", "sudo /bin/sh",
            "su", "su -", "su root",
        )
        if cmd_clean in elevation_cmds:
            if not self.can_drop_privileges(session):
                session.pre_elevation_cwd = session.cwd
            session.effective_user = "root"
            session.is_elevated = True
            session.cwd = "/root"
            decision = RouteDecision.BUILTIN
            output = ""
            reasoning = None
        elif cmd_clean in ("exit", "logout") and self.can_drop_privileges(session):
            # Leaving the root shell returns to the user's shell where it was
            session.effective_user = session.username
            session.is_elevated = False
            session.cwd = session.pre_elevation_cwd or f"/home/{session.username}"
            session.pre_elevation_cwd = None
            decision = RouteDecision.BUILTIN
            output = "exit"
            reasoning = None
        else:
            # Standard 3-tier routing classification
            decision, route_reason = self.router.classify_command(cmd_clean, is_safe_ip=is_safe_ip)
            output = ""
            reasoning = None

            # 2. Command execution based on 3-tier route decision
            if decision == RouteDecision.BUILTIN:
                output = self._handle_builtin(session, cmd_clean)
            elif decision == RouteDecision.SANDBOX and session.container_id:
                # Tier 1: Direct Sandbox Execution (Zero-latency, authentic Linux output)
                try:
                    res = await asyncio.wait_for(
                        asyncio.to_thread(
                            self.sandbox_manager.execute_in_sandbox,
                            container_id=session.container_id,
                            command=cmd_clean,
                            workdir=session.cwd,
                            user=getattr(session, "effective_user", session.username),
                        ),
                        timeout=sandbox_timeout,
                    )
                    output = (res.stdout or "") + (res.stderr or "")
                except asyncio.TimeoutError:
                    logger.warning(f"Command '{cmd_clean}' timed out in sandbox after {sandbox_timeout}s")
                    output = "Killed\n"
            elif decision == RouteDecision.GROUNDED_DECEPTION and session.container_id:
                # Tier 2: Grounded Deception (Run in Sandbox -> LLM Camouflage & Honeytoken Injection)
                try:
                    res = await asyncio.wait_for(
                        asyncio.to_thread(
                            self.sandbox_manager.execute_in_sandbox,
                            container_id=session.container_id,
                            command=cmd_clean,
                            workdir=session.cwd,
                            user=getattr(session, "effective_user", session.username),
                        ),
                        timeout=sandbox_timeout,
                    )
                    output, reasoning = await self.deception_engine.transform_grounded_output(
                        command=cmd_clean,
                        real_stdout=res.stdout or "",
                        real_stderr=res.stderr or "",
                        exit_code=res.exit_code,
                        user=getattr(session, "effective_user", session.username),
                        cwd=session.cwd,
                        session_id=session.session_id,
                        return_reasoning=True,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Grounded command '{cmd_clean}' timed out in sandbox; falling back to LLM synthesis")
                    output, reasoning = await self.deception_engine.generate_command_output(
                        command=cmd_clean,
                        cwd=session.cwd,
                        user=getattr(session, "effective_user", session.username),
                        session_history=session.history,
                        fake_fs=session.fake_fs,
                        session_id=session.session_id,
                        return_reasoning=True,
                    )
                if session.fake_fs:
                    mutated = session.fake_fs.update_from_command(cmd_clean, output, cwd=session.cwd)
                    if mutated and session.container_id and self.sandbox_manager.is_available:
                        for fpath in mutated:
                            file_obj = getattr(session.fake_fs, "_files", {}).get(fpath)
                            fcontent = file_obj.content if file_obj else ""
                            asyncio.create_task(
                                asyncio.to_thread(
                                    self.sandbox_manager.sync_file_to_sandbox,
                                    session.container_id,
                                    fpath,
                                    fcontent,
                                )
                            )
            else:
                # Tier 3: Pure Simulation / Containment
                if route_reason == "dos_containment":
                    output = "Killed\n"
                    reasoning = "DoS containment: simulated process termination"
                else:
                    output, reasoning = await self.deception_engine.generate_command_output(
                        command=cmd_clean,
                        cwd=session.cwd,
                        user=getattr(session, "effective_user", session.username),
                        session_history=session.history,
                        fake_fs=session.fake_fs,
                        session_id=session.session_id,
                        return_reasoning=True,
                    )
                # After LLM responds, update fake filesystem and sync mutations to container
                if session.fake_fs:
                    mutated = session.fake_fs.update_from_command(cmd_clean, output, cwd=session.cwd)
                    if mutated and session.container_id and self.sandbox_manager.is_available:
                        for fpath in mutated:
                            file_obj = getattr(session.fake_fs, "_files", {}).get(fpath)
                            fcontent = file_obj.content if file_obj else ""
                            asyncio.create_task(
                                asyncio.to_thread(
                                    self.sandbox_manager.sync_file_to_sandbox,
                                    session.container_id,
                                    fpath,
                                    fcontent,
                                )
                            )

        # 3. Latency Harmonization & Jitter Simulation (Timing Side-Channel Mitigation)
        import random as _random
        decep_cfg = getattr(self.config, "deception", None)
        simulate_latency = getattr(decep_cfg, "simulate_latency", True) if decep_cfg else True

        if simulate_latency:
            tokens = cmd_clean.split()
            first_cmd = tokens[0].lower() if tokens else ""
            heavy_cmds = {"find", "grep", "du", "tree", "tar", "zip", "unzip", "nmap", "sqlmap", "ps", "top"}
            medium_cmds = {"ls", "cat", "df", "netstat", "ss", "head", "tail", "wc", "sort", "uniq", "dmesg", "journalctl"}

            if first_cmd in heavy_cmds or len(cmd_clean) > 80 or "|" in cmd_clean:
                base_target_ms = _random.uniform(900, 1800)
            elif first_cmd in medium_cmds:
                base_target_ms = _random.uniform(300, 700)
            else:
                base_target_ms = _random.uniform(120, 280)

            # Natural OS/network jitter
            jitter_pct = getattr(decep_cfg, "jitter_percent", 25) / 100.0
            jitter_mult = _random.uniform(1.0 - jitter_pct, 1.0 + jitter_pct)
            target_ms = base_target_ms * jitter_mult

            # 10% probability of an occasional cloud/disk lag spike (600ms - 1400ms)
            spike_prob = getattr(decep_cfg, "spike_probability", 0.10)
            if _random.random() < spike_prob:
                target_ms += _random.uniform(
                    getattr(decep_cfg, "spike_min_ms", 600),
                    getattr(decep_cfg, "spike_max_ms", 1400),
                )

            # Tar-pit multiplier if attacker is a bot
            base_tar_pit = getattr(decep_cfg, "tar_pit_delay_ms", 0)
            if base_tar_pit > 0:
                attacker_type = session.profiler_state.attacker_type if session.profiler_state else "unknown"
                multipliers = {"bot": 3.0, "semi-automated": 1.5, "human": 0.3, "unknown": 1.0}
                target_ms += base_tar_pit * multipliers.get(attacker_type, 1.0)

            # Budget clamp: sleep only the remaining difference so LLM latency is masked
            elapsed_ms = (_time.monotonic() - cmd_start_time) * 1000.0
            remaining_ms = target_ms - elapsed_ms
            if remaining_ms > 0:
                await asyncio.sleep(remaining_ms / 1000.0)

        # 4. Record turn in session memory. "cwd" is the prompt directory the
        # command was typed at; "ts" is monotonic for profiler timing.
        completed_mono = _time.monotonic()
        duration_ms = int((completed_mono - received_mono) * 1000)
        cmd_reasoning = reasoning if "reasoning" in locals() else None
        session.history.append({
            "command": cmd_clean,
            "cwd": prompt_cwd,
            "user": prompt_user,
            "output": output,
            "route_decision": decision.value,
            "reasoning": cmd_reasoning,
            "ts": completed_mono,
            "timestamp": received_at,
            "duration_ms": duration_ms,
        })

        # 5. Immediate DB logging so command is recorded right away
        cmd_id = None
        try:
            cmd_id = await self.db.log_command(
                session_id=session.session_id,
                cwd=prompt_cwd,
                command=cmd_clean,
                output=output,
                route_decision=decision.value,
                threat_meta=None,
                reasoning=cmd_reasoning,
                timestamp=received_at,
                duration_ms=duration_ms,
                prompt_user=prompt_user,
            )
        except Exception as db_err:
            logger.error(f"Failed to log command to DB: {db_err}")

        # 6. Background MITRE analysis & profiling
        task = asyncio.create_task(
            self._analyze_and_record(
                session=session,
                command=cmd_clean,
                output=output,
                decision=decision.value if hasattr(decision, "value") else str(decision),
                cmd_id=cmd_id,
                keystroke_timestamps=keystroke_timestamps,
                cmd_ts=completed_mono,
                history_snapshot=[h["command"] for h in session.history],
                log_fields={
                    "cwd": prompt_cwd,
                    "timestamp": received_at,
                    "duration_ms": duration_ms,
                    "prompt_user": prompt_user,
                    "reasoning": cmd_reasoning,
                },
            )
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        _prof = session.profiler_state
        self._notify("command_executed", {
            "session_id": session_id,
            "command": cmd_clean,
            "cwd": session.cwd,
            "prompt_cwd": prompt_cwd,
            "prompt_user": prompt_user,
            "output": output,
            "decision": decision.value if hasattr(decision, "value") else str(decision),
            "reasoning": cmd_reasoning,
            "timestamp": received_at,
            "duration_ms": duration_ms,
            "attacker_type": _prof.attacker_type if _prof else "unknown",
            "current_phase": _prof.current_phase if _prof else "Reconnaissance",
            "effective_user": getattr(session, "effective_user", session.username),
            "is_elevated": getattr(session, "is_elevated", False),
        })

        return output

    def _handle_builtin(self, session: SessionState, command: str) -> str:
        tokens = command.split()
        cmd = tokens[0].lower()

        if cmd == "cd":
            return self._change_directory(session, tokens[1:])

        if cmd == "pwd":
            return session.cwd

        if cmd == "clear":
            return "\033[H\033[2J"

        return ""

    @staticmethod
    def _change_directory(session: SessionState, args: List[str]) -> str:
        """bash's `cd`: path resolution, `cd -`, `~`, and home-directory permissions."""
        user = getattr(session, "effective_user", session.username)
        is_root = user == "root"
        home_dir = "/root" if is_root else f"/home/{user}"

        if len(args) > 1:
            return "bash: cd: too many arguments"
        target = args[0] if args else home_dir
        announce = False
        if target == "-":
            if not session.previous_cwd:
                return "bash: cd: OLDPWD not set"
            target, announce = session.previous_cwd, True
        elif target == "~" or target.startswith("~/"):
            target = home_dir + target[1:]

        resolved = posixpath.normpath(posixpath.join(session.cwd, target))
        if resolved.startswith("//"):
            resolved = "/" + resolved.lstrip("/")

        # /root is 700 and Ubuntu 22.04 creates home directories as 750
        if not is_root:
            parts = resolved.strip("/").split("/")
            if parts[0] == "root" or (parts[0] == "home" and len(parts) > 1 and parts[1] != user):
                return f"bash: cd: {args[0]}: Permission denied"

        session.previous_cwd, session.cwd = session.cwd, resolved
        return resolved if announce else ""

    async def _analyze_and_record(
        self,
        session: SessionState,
        command: str,
        output: str,
        decision: str,
        cmd_id: Optional[int] = None,
        keystroke_timestamps: Optional[List[float]] = None,
        cmd_ts: Optional[float] = None,
        history_snapshot: Optional[List[str]] = None,
        log_fields: Optional[Dict[str, Any]] = None,
    ):
        # This runs in the background, so later commands may already have been
        # appended to session.history. Use the values captured for this command.
        fields = log_fields or {}
        try:
            threat_meta = None
            if self.config.analytics.enable_mitre_tagging:
                threat_meta = await self.observer.analyze_command(
                    session_id=session.session_id,
                    command=command,
                    cwd=fields.get("cwd", session.cwd),
                    user=fields.get("prompt_user") or getattr(session, "effective_user", session.username),
                    session_history=(
                        history_snapshot if history_snapshot is not None
                        else [h["command"] for h in session.history]
                    ),
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

            # ── Attacker profiler (timing + phase + keystroke flight dynamics) ──
            if session.profiler_state is not None:
                tactics_list = threat_meta.get("tactics", []) if threat_meta else []
                if cmd_ts is None and session.history:
                    cmd_ts = session.history[-1].get("ts")
                updated_state, phase_event = self._profiler.record_command(
                    state=session.profiler_state,
                    command=command,
                    tactics=tactics_list,
                    now=cmd_ts,
                    keystroke_timestamps=keystroke_timestamps,
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
                    cwd=fields.get("cwd", session.cwd),
                    command=command,
                    output=output,
                    route_decision=decision,
                    threat_meta=threat_meta,
                    reasoning=fields.get("reasoning"),
                    timestamp=fields.get("timestamp"),
                    duration_ms=fields.get("duration_ms"),
                    prompt_user=fields.get("prompt_user"),
                )
        except Exception as e:
            logger.error(f"Error in background threat analysis for session {session.session_id[:8]}: {e}", exc_info=True)

    async def close_session(self, session_id: str) -> Optional[str]:
        session = self.sessions.pop(session_id, None)
        if not session:
            return None

        session.is_active = False

        self._notify("session_closing", {
            "session_id": session_id,
            "stage": "initiating",
            "message": "Session terminated. Compiling incident report...",
        })

        if session.container_id:
            try:
                await asyncio.to_thread(self.sandbox_manager.destroy_sandbox_session, session.container_id)
            except Exception as e:
                logger.warning(f"Error destroying sandbox container for {session_id[:8]}: {e}")

        # Wait up to 10 seconds for any running background MITRE analysis tasks
        if self._background_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*list(self._background_tasks), return_exceptions=True),
                    timeout=10.0,
                )
            except asyncio.TimeoutError:
                logger.warning(f"Background MITRE tasks timed out for session {session_id[:8]}; proceeding with report.")
            except Exception as e:
                logger.debug(f"Background tasks finalization notice: {e}")

        try:
            await self.db.log_session_end(session_id)
        except Exception as e:
            logger.error(f"Error logging session end for {session_id[:8]}: {e}")

        logger.info(f"Session {session_id[:8]} closed. Generating incident report...")

        report_path = None
        try:
            async with self._report_slots:
                report_path = await self.reporter.generate_session_report(session_id)
        except Exception as e:
            logger.error(f"Error generating incident report for session {session_id[:8]}: {e}")

        self._notify("session_closed", {
            "session_id": session_id,
            "report_path": str(report_path) if report_path else None,
        })
        return str(report_path) if report_path else None

