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
    ):
        self.config = config
        self.deception_engine = deception_engine
        self.sandbox_manager = sandbox_manager
        self.router = router
        self.db = db
        self.observer = observer
        self.reporter = reporter
        self.sessions: Dict[str, SessionState] = {}
        self._background_tasks: set[asyncio.Task] = set()
        self.event_callbacks: List[Any] = []

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
    ) -> SessionState:
        sess_id = session_id or str(uuid.uuid4())
        initial_cwd = "/root" if username == "root" else f"/home/{username}"

        container_id = None
        if self.config.sandbox.enabled and self.sandbox_manager.is_available:
            container_id = self.sandbox_manager.create_sandbox_session(sess_id)

        session = SessionState(
            session_id=sess_id,
            remote_ip=remote_ip,
            remote_port=remote_port,
            username=username,
            password=password,
            cwd=initial_cwd,
            container_id=container_id,
        )
        self.sessions[sess_id] = session

        await self.db.log_session_start(
            session_id=sess_id,
            remote_ip=remote_ip,
            remote_port=remote_port,
            username=username,
            password=password,
        )
        logger.info(f"Initialized session {sess_id[:8]} for {username}@{remote_ip}:{remote_port}")
        self._notify("session_created", {
            "session_id": sess_id,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "username": username,
            "start_time": session.start_time,
            "cwd": session.cwd,
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

        # Update router sandbox availability status
        self.router.sandbox_available = bool(session.container_id and self.sandbox_manager.is_available)

        # 1. Routing classification
        decision, route_reason = self.router.classify_command(cmd_clean)
        output = ""

        # 2. Command execution based on route decision
        if decision == RouteDecision.BUILTIN:
            output = self._handle_builtin(session, cmd_clean)
        elif decision == RouteDecision.SANDBOX and session.container_id:
            res = self.sandbox_manager.execute_in_sandbox(
                container_id=session.container_id,
                command=cmd_clean,
                workdir=session.cwd,
                user=session.username,
            )
            output = res.stdout if res.stdout else res.stderr
        else:
            # LLM Deception
            output = await self.deception_engine.generate_command_output(
                command=cmd_clean,
                cwd=session.cwd,
                user=session.username,
                session_history=session.history,
            )

        # 3. Simulate configured tar-pit delay if specified
        if self.config.deception.tar_pit_delay_ms > 0:
            await asyncio.sleep(self.config.deception.tar_pit_delay_ms / 1000.0)

        # 4. Record turn in session memory
        session.history.append({
            "command": cmd_clean,
            "cwd": session.cwd,
            "output": output,
        })

        # 5. Background MITRE analysis & database logging
        task = asyncio.create_task(
            self._analyze_and_record(
                session=session,
                command=cmd_clean,
                output=output,
                decision=decision.value,
            )
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        self._notify("command_executed", {
            "session_id": session_id,
            "command": cmd_clean,
            "cwd": session.cwd,
            "output": output,
            "decision": decision.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
    ):
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

        await self.db.log_command(
            session_id=session.session_id,
            cwd=session.cwd,
            command=command,
            output=output,
            route_decision=decision,
            threat_meta=threat_meta,
        )

    async def close_session(self, session_id: str) -> Optional[str]:
        session = self.sessions.pop(session_id, None)
        if not session:
            return None

        session.is_active = False

        if session.container_id:
            self.sandbox_manager.destroy_sandbox_session(session.container_id)

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
