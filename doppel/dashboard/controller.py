import json
import time
import asyncio
import logging
from typing import Dict, Any, Optional, Set, Tuple, List, AsyncGenerator
from datetime import datetime, timezone
from fastapi import WebSocket
import httpx

from doppel.config import DoppelConfig, get_config, get_active_preset, get_presets_dict, resolve_persona_key, write_env_settings
from doppel.deception.honeytokens import derive_canary_base_url, get_honeytoken_manager
from doppel.ai.llm_client import LLMClient, clients_from_config
from doppel.ai.deception_engine import DeceptionEngine
from doppel.sandbox.docker_manager import DockerSandboxManager
from doppel.router.hybrid_router import HybridRouter
from doppel.analytics.db import TelemetryDB
from doppel.analytics.observer import ThreatObserver
from doppel.analytics.reporter import IncidentReporter
from doppel.core.session_manager import SessionManager
from doppel.core.ssh_server import start_ssh_server
from doppel.http_sensor.sensor import create_http_sensor

MODEL_LOAD_TIMEOUT_SECONDS = 300.0
MODEL_KEEP_ALIVE = "10m"
MODEL_KEEP_WARM_INTERVAL_SECONDS = 120.0
# After a switch the model stays loaded this long even if the honeypot isn't started
MODEL_KEEP_WARM_AFTER_SWITCH_SECONDS = 1800.0

logger = logging.getLogger("doppel.dashboard.controller")

# Settings exposed through GET/PATCH /api/settings, by config section. Secrets, file paths,
# the dashboard allow-list, bind addresses and sandbox network isolation are deliberately left out.
API_SETTINGS: Dict[str, Set[str]] = {
    "": {"active_preset", "http_sensor_port"},
    "honeypot": {"hostname", "default_user", "accept_any_password", "server_banner", "port", "motd"},
    "llm": {"base_url", "model", "timeout_seconds", "temperature", "mock_mode", "analysis_model",
            "analysis_timeout_seconds"},
    "deception": {"persona", "tar_pit_delay_ms", "intercept_sensitive_files", "intercept_missing_tools",
                  "dynamic_honeytokens", "canary_base_url", "simulate_latency", "min_latency_ms", "max_latency_ms",
                  "jitter_percent", "spike_probability", "spike_min_ms", "spike_max_ms"},
    "sandbox": {"enabled", "memory_limit", "timeout_seconds"},
    "analytics": {"enable_mitre_tagging", "auto_reports", "max_concurrent_reports", "background_idle_seconds"},
    "alerts.email": {"enabled", "min_threat_score", "receiver_email"},
}
# These are read when the honeypot starts; the rest apply immediately
SETTINGS_APPLIED_ON_START = {"honeypot.port", "honeypot.server_banner", "http_sensor_port", "sandbox.memory_limit",
                             "analytics.max_concurrent_reports", "deception.canary_base_url"}
# Saved to .env when changed in the dashboard, so they survive a restart
SETTINGS_SAVED_TO_ENV = {"alerts.email.enabled", "alerts.email.min_threat_score", "alerts.email.receiver_email"}


class HoneypotController:
    """Manages honeypot daemon lifecycle (start, stop, configure) and WebSocket telemetry broadcast."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config: DoppelConfig = get_config(config_path)
        self.status: str = "STOPPED"  # STOPPED, STARTING, RUNNING, STOPPING, ERROR
        self.start_time: Optional[str] = None
        self.error_message: Optional[str] = None

        self.session_manager: Optional[SessionManager] = None
        # Reasoning for attacker-facing replies. Off at every start: attackers wait
        # on these replies. Chat and reports reason by default; tagging never does.
        self.terminal_reasoning: bool = False
        self.ssh_server = None
        self.http_server = None          # uvicorn server for HTTP sensor
        self._http_server_task: Optional[asyncio.Task] = None
        self._http_sock = None
        self._server_task: Optional[asyncio.Task] = None
        self.active_websockets: Set[WebSocket] = set()
        self.active_sse_queues: Set[asyncio.Queue] = set()

        # Telemetry DB instance for dashboard queries even when honeypot is stopped
        self.db = TelemetryDB(db_path=self.config.analytics.db_path)
        self.active_report_tasks: Dict[str, asyncio.Task] = {}
        self.model_load: Dict[str, Any] = {"state": "idle", "model": None, "target": None, "seconds": None, "error": None}
        self._model_load_task: Optional[asyncio.Task] = None
        self._model_load_requested_at: float = 0.0
        self.active_assistant_tasks: Dict[str, asyncio.Task] = {}

    async def initialize(self):
        """Initialize database so historical telemetry is accessible immediately."""
        await self.db.initialize()

    def get_initial_snapshot(self) -> Dict[str, Any]:
        """Build initial status and fleet snapshot payload."""
        active_list = []
        if self.session_manager:
            for s_id, s in self.session_manager.sessions.items():
                active_list.append({
                    "session_id": s.session_id,
                    "remote_ip": s.remote_ip,
                    "remote_port": s.remote_port,
                    "username": s.username,
                    "start_time": s.start_time,
                    "is_active": True,
                    "threat_score": s.threat_score,
                    "command_count": len(s.history),
                    "last_command": s.history[-1]["command"] if s.history else "",
                    "cwd": s.cwd,
                })

        return {
            "type": "status_update",
            "status": self.status,
            "start_time": self.start_time,
            "config": self.get_config_dict(),
            "active_sessions": active_list,
        }

    async def connect_ws(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)
        await websocket.send_json(self.get_initial_snapshot())

    def disconnect_ws(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    async def broadcast(self, event: Dict[str, Any]):
        """Push an event to all connected dashboard WebSocket and SSE clients."""
        # WebSocket broadcast
        if self.active_websockets:
            dead_sockets = set()
            for ws in list(self.active_websockets):
                try:
                    await ws.send_json(event)
                except Exception:
                    dead_sockets.add(ws)

            for ws in dead_sockets:
                self.active_websockets.discard(ws)

        # SSE broadcast
        if self.active_sse_queues:
            dead_queues = set()
            for q in list(self.active_sse_queues):
                try:
                    q.put_nowait(event)
                except Exception:
                    dead_queues.add(q)

            for q in dead_queues:
                self.active_sse_queues.discard(q)

    def _on_session_event(self, event_type: str, data: Dict[str, Any]):
        """Callback invoked by SessionManager on honeypot events."""
        event_payload = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        asyncio.create_task(self.broadcast(event_payload))

    async def start(self) -> Dict[str, Any]:
        """Launch honeypot daemon with current configuration."""
        if self.status in ("RUNNING", "STARTING"):
            return {"status": self.status, "message": "Honeypot is already running"}

        self.status = "STARTING"
        self.error_message = None
        await self.broadcast({"type": "status_update", "status": self.status})

        try:
            # Re-read config to capture any edits
            llm_client, analysis_client = clients_from_config(self.config.llm)
            preset = get_active_preset(self.config) or {}
            deception_engine = DeceptionEngine(
                llm_client=llm_client,
                persona=preset.get("persona_context", self.config.deception.persona),
                host_profile=preset,
                dynamic_honeytokens=self.config.deception.dynamic_honeytokens,
                no_think=not self.terminal_reasoning,
            )
            sandbox_manager = DockerSandboxManager(
                image=self.config.sandbox.image,
                network_disabled=self.config.sandbox.network_disabled,
                memory_limit=self.config.sandbox.memory_limit,
                enabled=self.config.sandbox.enabled,
                hostname=preset.get("hostname", self.config.honeypot.hostname),
                cpu_quota=self.config.sandbox.cpu_quota,
            )
            # Leaked canary URLs point at the public HTTP decoy; tokens are
            # stored so they are still recognised after a restart
            get_honeytoken_manager().configure(
                base_url=derive_canary_base_url(self.config, preset),
                persist=self.db.save_honeytoken,
            )
            router = HybridRouter(
                intercept_sensitive_files=self.config.deception.intercept_sensitive_files,
                intercept_missing_tools=self.config.deception.intercept_missing_tools,
                sandbox_available=sandbox_manager.is_available,
                benign_commands=set(self.config.benign_commands),
            )
            observer = ThreatObserver(llm_client=analysis_client, db=self.db)
            reporter = IncidentReporter(
                llm_client=analysis_client,
                db=self.db,
                reports_dir=self.config.analytics.reports_dir,
            )

            self.session_manager = SessionManager(
                config=self.config,
                deception_engine=deception_engine,
                sandbox_manager=sandbox_manager,
                router=router,
                db=self.db,
                observer=observer,
                reporter=reporter,
            )
            self.session_manager.register_event_listener(self._on_session_event)

            self.ssh_server = await start_ssh_server(self.session_manager, self.config)

            # Start HTTP sensor on a background task
            self._http_server_task = asyncio.create_task(
                self._run_http_sensor(deception_engine)
            )

            self.status = "RUNNING"
            self.start_time = datetime.now(timezone.utc).isoformat()
            logger.info(f"Honeypot daemon started successfully on port {self.config.honeypot.port}")

            await self.broadcast({
                "type": "status_update",
                "status": self.status,
                "start_time": self.start_time,
                "config": self.get_config_dict(),
            })
            self._request_model_load()
            return {"status": self.status, "message": "Honeypot started"}
        except Exception as e:
            logger.error(f"Failed to start honeypot daemon: {e}", exc_info=True)
            self.status = "ERROR"
            self.error_message = str(e)
            await self.broadcast({
                "type": "status_update",
                "status": self.status,
                "error": str(e),
            })
            return {"status": self.status, "error": str(e)}

    async def stop(self) -> Dict[str, Any]:
        """Gracefully stop honeypot daemon and active attacker sessions."""
        if self.status not in ("RUNNING", "STARTING", "ERROR"):
            return {"status": self.status, "message": "Honeypot is not running"}

        self.status = "STOPPING"
        await self.broadcast({"type": "status_update", "status": self.status})

        try:
            if self.ssh_server:
                self.ssh_server.close()
                await self.ssh_server.wait_closed()
                self.ssh_server = None

            if self.http_server:
                self.http_server.should_exit = True

            if self._http_server_task and not self._http_server_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(self._http_server_task), timeout=1.5)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    self._http_server_task.cancel()
                    try:
                        await self._http_server_task
                    except (asyncio.CancelledError, Exception):
                        pass
                self._http_server_task = None

            if hasattr(self, "_http_sock") and self._http_sock:
                try:
                    self._http_sock.close()
                except Exception:
                    pass
                self._http_sock = None
            self.http_server = None

            if self.session_manager:
                # Reports for the sessions being closed run now rather than after idle time
                self.session_manager.background.run_now()
                active_ids = list(self.session_manager.sessions.keys())
                for sess_id in active_ids:
                    await self.session_manager.close_session(sess_id)
                await self.session_manager.background.shutdown()
                self.session_manager = None

            self.status = "STOPPED"
            self.start_time = None
            logger.info("Honeypot daemon stopped")
            await self.broadcast({
                "type": "status_update",
                "status": self.status,
                "start_time": None,
            })
            await self.release_model()
            return {"status": self.status, "message": "Honeypot stopped"}
        except Exception as e:
            logger.error(f"Error stopping honeypot: {e}")
            self.status = "ERROR"
            self.error_message = str(e)
            return {"status": self.status, "error": str(e)}

    async def _prepare_assistant_context(
        self, message: str, model_override: Optional[str] = None
    ) -> Tuple[LLMClient, str, List[Dict[str, str]], Dict[str, Any]]:
        """Assemble live telemetry, honeypot state context, and configured LLMClient for the assistant."""
        target_model = model_override or self.config.llm.model
        client = LLMClient(
            base_url=self.config.llm.base_url,
            model=target_model,
            api_key=self.config.llm.api_key,
            timeout=self.config.llm.timeout_seconds,
            mock_mode=self.config.llm.mock_mode,
        )

        # 1. Gather live software state
        docker_available = False
        if self.session_manager and hasattr(self.session_manager, "sandbox_manager"):
            docker_available = getattr(self.session_manager.sandbox_manager, "is_available", False)

        active_sessions_list = []
        if self.session_manager and self.session_manager.sessions:
            for s in self.session_manager.sessions.values():
                active_sessions_list.append({
                    "session_id": s.session_id[:8],
                    "remote_ip": s.remote_ip,
                    "username": s.username,
                    "cwd": s.cwd,
                    "threat_score": s.threat_score,
                    "command_count": len(s.history),
                })

        # 2. Gather recent attacker telemetry from DB
        recent_sessions = []
        try:
            all_sessions = await self.db.get_all_sessions()
            for s in all_sessions[:5]:
                sess_info = {
                    "session_id": s["session_id"][:8],
                    "remote_ip": s.get("remote_ip", "unknown"),
                    "city": s.get("city") or "unknown",
                    "country": s.get("country_name") or "unknown",
                    "username": s.get("username", "ubuntu"),
                    "start_time": s.get("start_time", ""),
                    "max_threat_score": s.get("max_threat_score", 0),
                    "command_count": s.get("command_count", 0),
                    "last_command": s.get("last_command", ""),
                    "credential_risk": s.get("credential_risk", "none"),
                }
                if len(recent_sessions) < 2:
                    try:
                        details = await self.db.get_session_details(s["session_id"])
                        cmds = [c.get("command", "") for c in details.get("commands", [])[-5:]]
                        sess_info["recent_commands"] = cmds
                    except Exception:
                        pass
                recent_sessions.append(sess_info)
        except Exception as e:
            logger.warning(f"Could not load recent telemetry for assistant: {e}")

        # 3. Build system prompt with live state
        system_prompt = (
            "You are the Doppel AI Security Intelligence Assistant and Live Benchmark Tool.\n"
            "You assist cybersecurity analysts by monitoring this honeypot system, testing model generation performance, "
            "analyzing live attacker telemetry, and evaluating defensive postures.\n\n"
            "CURRENT DOPPEL SYSTEM STATE:\n"
            f"- Honeypot Status: {self.status}\n"
            f"- SSH Port: {self.config.honeypot.port}\n"
            f"- Persona Profile: {self.config.deception.persona}\n"
            f"- Hostname: {self.config.honeypot.hostname}\n"
            f"- Docker Execution Sandbox: {'Ready' if docker_available else 'Offline (Pure AI Simulation)'}\n"
            f"- Active Inference Model: {target_model}\n"
            f"- Active Sessions ({len(active_sessions_list)}): {json.dumps(active_sessions_list)}\n\n"
            f"RECENT ATTACKER SESSIONS (Last {len(recent_sessions)}):\n"
            f"{json.dumps(recent_sessions, indent=2)}\n\n"
            "INSTRUCTIONS:\n"
            "- Answer directly, technically, and concisely in clean Markdown.\n"
            "- Be direct and concise; keep internal chain-of-thought brief so you can deliver the complete answer within token limits.\n"
            "- When asked about attacks or telemetry, reference the real session data above (IPs, usernames, commands, threat scores).\n"
            "- When asked for suggestions, provide prioritized, actionable defensive recommendations (SSH hardening, UFW firewall rules, sudoers audits, credential rotation).\n"
            "- When asked for speed tests or benchmarks, provide a complete, well-formed response so generation latency can be evaluated."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message},
        ]

        system_state = {
            "status": self.status,
            "port": self.config.honeypot.port,
            "persona": self.config.deception.persona,
            "active_sessions_count": len(active_sessions_list),
            "recent_sessions_count": len(recent_sessions),
        }

        return client, target_model, messages, system_state

    async def query_assistant(
        self, message: str, model_override: Optional[str] = None, reasoning: bool = True
    ) -> Dict[str, Any]:
        """Query the in-built security assistant with live telemetry, state context, and benchmark metrics."""
        client, target_model, messages, system_state = await self._prepare_assistant_context(message, model_override)
        client.reasoning_off = not reasoning
        try:
            metrics = await client.chat_completion_with_metrics(messages=messages, max_tokens=2048)
            return {
                "success": True,
                "reply": metrics["content"].strip(),
                "model": target_model,
                "latency_seconds": metrics["latency_seconds"],
                "tokens_generated": metrics["tokens"],
                "tokens_per_second": metrics["tokens_per_second"],
                "system_state": system_state,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "model": target_model,
                "latency_seconds": 0.0,
                "tokens_generated": 0,
                "tokens_per_second": 0.0,
                "system_state": system_state,
            }

    async def query_assistant_stream(
        self, message: str, model_override: Optional[str] = None, reasoning: bool = True
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream assistant response tokens, live latency, and throughput metrics."""
        client, target_model, messages, system_state = await self._prepare_assistant_context(message, model_override)
        client.reasoning_off = not reasoning
        try:
            async for chunk in client.chat_completion_stream(messages=messages, max_tokens=2048):
                chunk["system_state"] = system_state
                yield chunk
        except Exception as e:
            logger.warning(f"Assistant streaming query failed: {e}")
            yield {
                "delta": f"\n\n[Generation error: {e}]",
                "tokens": 0,
                "latency_seconds": 0.0,
                "tokens_per_second": 0.0,
                "model": target_model,
                "done": True,
                "error": str(e),
                "system_state": system_state,
            }

    def stop_report_generation(self, session_id: str) -> bool:
        """Cancel active report streaming generation task for a session."""
        task = self.active_report_tasks.pop(session_id, None)
        if task and not task.done():
            task.cancel()
            logger.info(f"Aborted active report generation for session {session_id[:8]}")
            return True
        return False

    def stop_assistant_stream(self, client_id: str = "default") -> bool:
        """Cancel active streaming assistant query task."""
        task = self.active_assistant_tasks.pop(client_id, None)
        if task and not task.done():
            task.cancel()
            logger.info(f"Aborted active assistant stream for client '{client_id}'")
            return True
        return False

    async def delete_session(self, session_id: str) -> bool:
        """Delete an attack session and all related records, files, and telemetry."""
        from pathlib import Path

        # 1. Close session if currently active in memory
        if self.session_manager and session_id in self.session_manager.sessions:
            try:
                await self.session_manager.close_session(session_id, generate_report=False)
            except Exception as e:
                logger.warning(f"Error closing active session during deletion: {e}")

        # 2. Cancel any active report generation task
        self.stop_report_generation(session_id)

        # 3. Purge database records
        db_success = await self.db.delete_session(session_id)

        # 4. Remove generated incident report markdown files from disk
        try:
            reports_dir = Path(self.config.analytics.reports_dir)
            if reports_dir.exists():
                for report_path in reports_dir.glob(f"incident_{session_id[:8]}_*.md"):
                    try:
                        report_path.unlink(missing_ok=True)
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Could not remove report files for session {session_id}: {e}")

        # 5. Broadcast session_deleted event to all connected dashboard clients
        await self.broadcast({
            "type": "session_deleted",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"session_id": session_id},
        })

        return db_success

    async def _run_http_sensor(self, deception_engine) -> None:
        """Run the HTTP honeypot sensor safely using uvicorn with a pre-bound socket."""
        import socket
        import uvicorn

        http_port = getattr(self.config, "http_sensor_port", 8080)
        if not http_port or http_port <= 0:
            logger.info("HTTP honeypot sensor disabled (port set to 0)")
            return

        host = self.config.honeypot.host or "0.0.0.0"

        # Pre-bind the socket to safely handle port conflicts without letting Uvicorn call sys.exit(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, http_port))
            sock.listen(128)
            sock.setblocking(False)
        except OSError as e:
            sock.close()
            logger.warning(
                f"HTTP honeypot sensor could not bind on {host}:{http_port} ([Errno {getattr(e, 'errno', 'unknown')}]: {e}). "
                "HTTP sensor disabled; SSH honeypot and dashboard remain operational."
            )
            return

        self._http_sock = sock

        async def _event_cb(event_type: str, data: dict) -> None:
            if event_type == "honeytoken_activated":
                await self._record_canary_use(data)
            self._on_session_event(event_type, data)

        preset = get_active_preset(self.config) or {}
        sensor_app = create_http_sensor(
            deception_engine=deception_engine,
            db=self.db,
            persona=self.config.deception.persona,
            event_callback=_event_cb,
            server_header=preset.get("http_server_header", "nginx/1.18.0 (Ubuntu)"),
        )
        cfg = uvicorn.Config(
            app=sensor_app,
            log_level="warning",
            access_log=False,
            lifespan="off",
            # The decoy sets its own nginx Server header; uvicorn's would sit next to it
            server_header=False,
        )
        server = uvicorn.Server(cfg)
        self.http_server = server
        logger.info(f"HTTP honeypot sensor listening on {host}:{http_port}")

        try:
            await server.serve(sockets=[sock])
        except asyncio.CancelledError:
            logger.info("HTTP honeypot sensor stopped")
        except (SystemExit, Exception) as e:
            logger.warning(f"HTTP honeypot sensor stopped: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self._http_sock = None
            self.http_server = None

    def get_config_dict(self) -> Dict[str, Any]:
        preset = get_active_preset(self.config) or {}
        return {
            # Shell prompt as the SSH server renders it (the active preset overrides hostname)
            "prompt": {
                "hostname": preset.get("hostname", self.config.honeypot.hostname).split(".")[0],
                "format": preset.get("prompt_format", "{user}@{hostname}:{cwd}$ "),
                "root_format": preset.get("root_prompt_format", "{user}@{hostname}:{cwd}# "),
            },
            "honeypot_host": self.config.honeypot.host,
            "honeypot_port": self.config.honeypot.port,
            "http_sensor_port": getattr(self.config, "http_sensor_port", 8080),
            "hostname": self.config.honeypot.hostname,
            "default_user": self.config.honeypot.default_user,
            "persona": self.config.deception.persona,
            "active_preset": getattr(self.config, "active_preset", "ubuntu_web_server"),
            "llm_base_url": self.config.llm.base_url,
            "llm_model": self.config.llm.model,
            "llm_timeout": self.config.llm.timeout_seconds,
            "llm_mock_mode": self.config.llm.mock_mode,
            "sandbox_enabled": self.config.sandbox.enabled,
            "sandbox_image": self.config.sandbox.image,
            "auto_reports": self.config.analytics.auto_reports,
            "llm_load": dict(self.model_load),
        }

    # -- Keeping the model loaded --------------------------------------------

    def _set_model_load(self, state: str, model: Optional[str] = None,
                        seconds: Optional[float] = None, error: Optional[str] = None,
                        target: Optional[str] = None) -> None:
        """States: idle, unloading, loading, ready, failed, unloaded. `target` is the model replacing `model`."""
        self.model_load = {"state": state, "model": model, "target": target, "seconds": seconds, "error": error}
        self._on_session_event("model_load", dict(self.model_load))

    def _request_model_load(self, force: bool = False) -> None:
        """Load the configured model now, so the first attacker command doesn't wait for it."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        model = self.config.llm.model
        running = self._model_load_task is not None and not self._model_load_task.done()
        if running and not force and not self.config.llm.mock_mode and self.model_load.get("model") == model:
            return
        if running:
            self._model_load_task.cancel()
        if self.config.llm.mock_mode:
            if self.model_load["state"] != "idle":
                self._set_model_load("idle")
            return
        self._model_load_requested_at = time.monotonic()
        self._model_load_task = asyncio.create_task(self._load_and_keep_warm(model))

    async def _load_and_keep_warm(self, model: str) -> None:
        await self._unload_other_models(model)
        started = time.monotonic()
        self._set_model_load("loading", model)
        try:
            renewable = await self._load_model(model)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"Could not load model {model}: {e}")
            self._set_model_load("failed", model, error=str(e)[:200] or type(e).__name__)
            return
        self._set_model_load("ready", model, seconds=round(time.monotonic() - started, 1))

        # Terminal requests reset the server's unload timer to its short default
        while renewable:
            await asyncio.sleep(MODEL_KEEP_WARM_INTERVAL_SECONDS)
            within_grace = time.monotonic() - self._model_load_requested_at < MODEL_KEEP_WARM_AFTER_SWITCH_SECONDS
            if self.status != "RUNNING" and not within_grace and not self.model_busy_work():
                self._set_model_load("unloading", model)
                await self._unload_model(model)
                self._set_model_load("unloaded", model)
                return
            try:
                await self._load_model(model)
                if self.model_load["state"] == "failed":
                    self._set_model_load("ready", model)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Could not keep {model} loaded: {e}")
                self._set_model_load("failed", model, error=str(e)[:200] or type(e).__name__)

    def model_busy_work(self, stopping: bool = False) -> List[str]:
        """What unloading the model would interrupt, in words for a confirmation.

        Stopping cancels queued analysis as well; a model switch leaves it for the new model.
        """
        def count(n: int, noun: str) -> str:
            return f"{n} {noun}{'' if n == 1 else 's'}"

        busy: List[str] = []
        manager = self.session_manager
        if manager:
            bg = manager.background.status()
            if stopping:
                if bg["reports"]:
                    busy.append(count(bg["reports"], "incident report"))
                if bg["tagging"]:
                    busy.append(f"ATT&CK tagging for {count(bg['tagging'], 'command')}")
            elif bg["running"] == "report":
                busy.append("an incident report being written")
            elif bg["running"]:
                busy.append("ATT&CK tagging in progress")
            if manager.sessions:
                busy.append(count(len(manager.sessions), "live session"))
        reports = sum(not t.done() for t in self.active_report_tasks.values())
        if reports:
            busy.append(count(reports, "report") + " being generated from the dashboard")
        chats = sum(not t.done() for t in self.active_assistant_tasks.values())
        if chats:
            busy.append(f"{chats} assistant {'reply' if chats == 1 else 'replies'}")
        return busy

    async def release_model(self) -> None:
        """Stop keeping the model warm and free its memory (shared machines need it back)."""
        if self._model_load_task and not self._model_load_task.done():
            self._model_load_task.cancel()
        model = self.model_load.get("model")
        if self.config.llm.mock_mode or not model or self.model_load["state"] in ("idle", "unloaded"):
            return
        self._set_model_load("unloading", model)
        for name in {model, self.config.llm.analysis_model} - {"", None}:
            await self._unload_model(name)
        self._set_model_load("unloaded", model)
        logger.info(f"Model {model} unloaded")

    def _model_server_root(self) -> str:
        base = self.config.llm.base_url.rstrip("/")
        return base[:-3] if base.endswith("/v1") else base

    async def _unload_model(self, model: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                await client.post(f"{self._model_server_root()}/api/generate", json={"model": model, "keep_alive": 0})
        except httpx.HTTPError as e:
            logger.debug(f"Could not unload {model}: {e}")

    async def _unload_other_models(self, model: str) -> None:
        """Free memory held by previously loaded models before loading `model` (Ollama only)."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self._model_server_root()}/api/ps")
            loaded = [m.get("name") for m in resp.json().get("models", [])] if resp.status_code == 200 else []
        except (httpx.HTTPError, ValueError):
            return
        keep = {model, self.config.llm.analysis_model}
        for old in loaded:
            if old and old not in keep:
                self._set_model_load("unloading", old, target=model)
                await self._unload_model(old)

    async def _load_model(self, model: str) -> bool:
        """Load `model`. True when the server supports renewing how long it stays loaded (Ollama)."""
        base = self.config.llm.base_url.rstrip("/")
        root = base[:-3] if base.endswith("/v1") else base
        async with httpx.AsyncClient(timeout=MODEL_LOAD_TIMEOUT_SECONDS) as client:
            resp = await client.post(f"{root}/api/generate", json={"model": model, "keep_alive": MODEL_KEEP_ALIVE})
            if resp.status_code == 200:
                return True
            # Other OpenAI-compatible servers load a model on its first request
            headers = {"Authorization": f"Bearer {self.config.llm.api_key}"} if getattr(self.config.llm, "api_key", "") else {}
            resp = await client.post(
                f"{base}/chat/completions",
                headers=headers,
                json={"model": model, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1},
            )
        if resp.status_code != 200:
            try:
                error = resp.json().get("error")
                error = error.get("message") if isinstance(error, dict) else error
            except ValueError:
                error = None
            raise RuntimeError(error or f"model server returned {resp.status_code}")
        return False

    async def _record_canary_use(self, activation: Dict[str, Any]) -> None:
        source = activation.get("session_id")
        if not activation.get("matched_honeytoken") or not source or not self.session_manager:
            return
        try:
            await self.session_manager.reporter.refresh_activations(source)
        except Exception as e:
            logger.error(f"Failed to add canary use to reports of {source[:8]}: {e}")

    def _sync_runtime_components(self):
        """Propagate updated config parameters to active session components without restart."""
        if not self.session_manager:
            return

        preset = get_active_preset(self.config)
        self.session_manager.apply_email_settings()

        if hasattr(self.session_manager, "deception_engine") and self.session_manager.deception_engine:
            target_persona = preset.get("persona_context", self.config.deception.persona) if preset else self.config.deception.persona
            self.session_manager.deception_engine.set_persona(target_persona)
            if preset:
                self.session_manager.deception_engine.set_host_profile(preset)
            self.session_manager.deception_engine.dynamic_honeytokens = self.config.deception.dynamic_honeytokens
            self.session_manager.deception_engine.no_think = not self.terminal_reasoning
            if hasattr(self.session_manager.deception_engine, "llm_client") and self.session_manager.deception_engine.llm_client:
                self.session_manager.deception_engine.llm_client.base_url = self.config.llm.base_url.rstrip("/")
                self.session_manager.deception_engine.llm_client.model = self.config.llm.model
                self.session_manager.deception_engine.llm_client.mock_mode = self.config.llm.mock_mode
        if hasattr(self.session_manager, "observer") and self.session_manager.observer and hasattr(self.session_manager.observer, "llm_client"):
            self.session_manager.observer.llm_client.base_url = self.config.llm.base_url.rstrip("/")
            self.session_manager.observer.llm_client.model = self.config.llm.analysis_model or self.config.llm.model
            self.session_manager.observer.llm_client.mock_mode = self.config.llm.mock_mode
        if hasattr(self.session_manager, "reporter") and self.session_manager.reporter and hasattr(self.session_manager.reporter, "llm_client"):
            self.session_manager.reporter.llm_client.base_url = self.config.llm.base_url.rstrip("/")
            self.session_manager.reporter.llm_client.model = self.config.llm.analysis_model or self.config.llm.model
            self.session_manager.reporter.llm_client.mock_mode = self.config.llm.mock_mode
        if hasattr(self.session_manager, "router") and self.session_manager.router:
            self.session_manager.router.intercept_sensitive_files = self.config.deception.intercept_sensitive_files
            self.session_manager.router.intercept_missing_tools = self.config.deception.intercept_missing_tools
        if hasattr(self.session_manager, "sandbox_manager") and self.session_manager.sandbox_manager:
            self.session_manager.sandbox_manager.enabled = self.config.sandbox.enabled
            if not self.config.sandbox.enabled:
                self.session_manager.sandbox_manager.is_available = False
            else:
                self.session_manager.sandbox_manager.check_availability()
        if hasattr(self.session_manager, "background"):
            self.session_manager.background.enabled = not self.config.llm.mock_mode
            self.session_manager.background.idle_seconds = max(0.0, float(self.config.analytics.background_idle_seconds))
        # Timeouts and temperature: the terminal client, then the analysis client(s)
        engine = getattr(self.session_manager, "deception_engine", None)
        terminal_client = getattr(engine, "llm_client", None)
        if terminal_client is not None:
            terminal_client.timeout = self.config.llm.timeout_seconds
            terminal_client.temperature = self.config.llm.temperature
        analysis_timeout = self.config.llm.analysis_timeout_seconds or self.config.llm.timeout_seconds
        for owner in ("observer", "reporter"):
            client = getattr(getattr(self.session_manager, owner, None), "llm_client", None)
            if client is not None and client is not terminal_client:
                client.timeout = analysis_timeout
                client.temperature = self.config.llm.temperature

    async def _attach_session_container(self, session) -> None:
        """Asynchronously attach a new isolated sandbox container to an active session."""
        try:
            if not self.session_manager or not self.session_manager.sandbox_manager:
                return
            # Same persona and honeytokens as a container created at login
            container_id = await asyncio.to_thread(
                self.session_manager._call_create_sandbox,
                session.session_id,
                session.username,
                get_active_preset(self.config),
                get_honeytoken_manager().session_honeytokens(session.session_id),
            )
            if container_id:
                session.container_id = container_id
                logger.info(f"Dynamically attached Docker sandbox {container_id[:12]} to active session {session.session_id[:8]}")
        except Exception as e:
            logger.warning(f"Could not dynamically attach container to session {session.session_id[:8]}: {e}")

    def update_config(self, updates: Dict[str, Any]):
        if "honeypot_port" in updates:
            self.config.honeypot.port = int(updates["honeypot_port"])
        if "persona" in updates:
            self.config.deception.persona = str(updates["persona"])
        if "active_preset" in updates:
            self.config.active_preset = str(updates["active_preset"])
        if "llm_base_url" in updates:
            self.config.llm.base_url = str(updates["llm_base_url"])
        if "llm_model" in updates:
            self.config.llm.model = str(updates["llm_model"])
            self._request_model_load()
        if "llm_mock_mode" in updates:
            self.config.llm.mock_mode = bool(updates["llm_mock_mode"])
        if "sandbox_enabled" in updates:
            self.config.sandbox.enabled = bool(updates["sandbox_enabled"])
        if "hostname" in updates:
            self.config.honeypot.hostname = str(updates["hostname"])
        if "http_sensor_port" in updates:
            self.config.http_sensor_port = int(updates["http_sensor_port"])
        self._sync_runtime_components()

    def _settings_section(self, section: str):
        obj = self.config
        for part in filter(None, section.split(".")):
            obj = getattr(obj, part)
        return obj

    def get_settings(self) -> Dict[str, Any]:
        """Every API-adjustable setting, nested by config section."""
        out: Dict[str, Any] = {}
        for section, fields in API_SETTINGS.items():
            obj = self._settings_section(section)
            target = out
            for part in filter(None, section.split(".")):
                target = target.setdefault(part, {})
            for name in sorted(fields):
                target[name] = getattr(obj, name)
        out["terminal_reasoning"] = self.terminal_reasoning
        return out

    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and apply a partial, nested settings update. All-or-nothing: on any
        error nothing changes. Returns the changed keys and which of them need a restart."""
        from pydantic import TypeAdapter, ValidationError

        flat: Dict[str, Any] = {}

        def walk(prefix: str, value: Any):
            section = prefix.rsplit(".", 1)[0] if "." in prefix else ""
            name = prefix.rsplit(".", 1)[-1]
            if prefix and name in API_SETTINGS.get(section, set()):
                flat[prefix] = value
            elif isinstance(value, dict):
                for k, v in value.items():
                    walk(f"{prefix}.{k}" if prefix else k, v)
            elif prefix == "terminal_reasoning":
                flat[prefix] = value
            else:
                raise ValueError(f"Unknown or read-only setting: {prefix}")

        walk("", patch)
        if not flat:
            raise ValueError("No settings given")

        staged: Dict[str, Tuple[Any, str, Any]] = {}
        for key, value in flat.items():
            if key == "terminal_reasoning":
                staged[key] = (self, "terminal_reasoning", TypeAdapter(bool).validate_python(value))
                continue
            section, name = key.rsplit(".", 1) if "." in key else ("", key)
            obj = self._settings_section(section)
            annotation = type(obj).model_fields[name].annotation
            try:
                parsed = TypeAdapter(annotation).validate_python(value)
            except ValidationError as e:
                raise ValueError(f"{key}: {e.errors()[0]['msg']}") from None
            if isinstance(parsed, (int, float)) and not isinstance(parsed, bool) and parsed < 0:
                raise ValueError(f"{key}: must not be negative")
            staged[key] = (obj, name, parsed)

        lat = self.config.deception
        lo = staged.get("deception.min_latency_ms", (None, None, lat.min_latency_ms))[2]
        hi = staged.get("deception.max_latency_ms", (None, None, lat.max_latency_ms))[2]
        if lo > hi:
            raise ValueError("deception.min_latency_ms must not exceed deception.max_latency_ms")
        if "active_preset" in staged:
            from doppel.config import get_presets_dict, get_preset_aliases
            name = staged["active_preset"][2]
            known = set(get_presets_dict()) | set(get_preset_aliases())
            if known and name not in known:
                raise ValueError(f"active_preset: unknown preset '{name}' (available: {', '.join(sorted(get_presets_dict()))})")
        for key in ("llm.timeout_seconds", "llm.analysis_timeout_seconds", "sandbox.timeout_seconds"):
            if key in staged and staged[key][2] == 0:
                raise ValueError(f"{key}: must be greater than zero")

        changed = []
        for key, (obj, name, parsed) in staged.items():
            if getattr(obj, name) != parsed:
                setattr(obj, name, parsed)
                changed.append(key)
        # Submitted values, not only changed ones: .env may have been edited since it was loaded
        to_save = {key: parsed for key, (_, _, parsed) in staged.items() if key in SETTINGS_SAVED_TO_ENV}
        if to_save:
            try:
                write_env_settings(to_save)
            except OSError as e:
                logger.warning(f"Could not save settings to .env; they last until the next restart: {e}")
        self._sync_runtime_components()
        if {"llm.model", "llm.base_url", "llm.mock_mode"} & set(changed):
            self._request_model_load(force=True)
        restart = [k for k in changed if k in SETTINGS_APPLIED_ON_START]
        if restart and self.status == "RUNNING":
            logger.info(f"Settings applied on next start: {', '.join(restart)}")
        return {"changed": changed, "applies_on_next_start": restart if self.status == "RUNNING" else [],
                "settings": self.get_settings()}

    async def diagnose_environment(self) -> Dict[str, Any]:
        """Perform proactive pre-flight checks on Docker, Ollama/LLM, and ports."""
        import socket
        import httpx

        # 1. Docker Sandbox check
        docker_diag = {
            "status": "unavailable",
            "available": False,
            "version": None,
            "enabled": self.config.sandbox.enabled,
            "detail": "Docker is not running. The model will answer every command.",
            "info": "Runs ordinary commands such as ls or id in a disposable container with no network. Without it, the model answers every command.",
        }
        if not self.config.sandbox.enabled:
            docker_diag["status"] = "disabled"
            docker_diag["detail"] = "The sandbox is off. The model answers every command."
            if self.session_manager and hasattr(self.session_manager, "sandbox_manager"):
                self.session_manager.sandbox_manager.is_available = False
        else:
            try:
                import docker
                client = docker.from_env()
                client.ping()
                ver = client.version().get("Version", "unknown")
                docker_diag["status"] = "ready"
                docker_diag["available"] = True
                docker_diag["version"] = ver
                docker_diag["detail"] = f"Docker {ver} is running."

                if self.session_manager and hasattr(self.session_manager, "sandbox_manager"):
                    sm = self.session_manager.sandbox_manager
                    sm.is_available = True
                    sm.client = client
                    for s in list(self.session_manager.sessions.values()):
                        if not s.container_id:
                            asyncio.create_task(self._attach_session_container(s))
            except Exception:
                docker_diag["status"] = "unavailable"
                docker_diag["available"] = False
                docker_diag["detail"] = "Docker is not running. The model will answer every command."
                if self.session_manager and hasattr(self.session_manager, "sandbox_manager"):
                    self.session_manager.sandbox_manager.is_available = False

        # 2. LLM / Ollama check
        llm_diag = {
            "status": "unreachable",
            "reachable": False,
            "latency_ms": 0,
            "models_available": [],
            "configured_model": self.config.llm.model,
            "endpoint": self.config.llm.base_url,
            "mock_mode": self.config.llm.mock_mode,
            "backend_available": False,
            "can_switch_live": False,
            # True / False from the server's model metadata; None when it cannot tell
            "supports_reasoning": None,
            "terminal_reasoning": self.terminal_reasoning,
            # Installed models that report reasoning support (Ollama only)
            "reasoning_models": [],
            "detail": "",
            "suggestion": None,
            "info": "Writes terminal replies and decoy credentials, and tags commands with ATT&CK techniques. Mock mode uses built-in replies and needs no model.",
        }

        # Probe LLM backend (even if currently in mock mode, to detect when Ollama comes online)
        start_t = time.time()
        base = self.config.llm.base_url.rstrip("/")
        models = []
        connected = False
        last_err = None

        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                ollama_url = base.replace("/v1", "") + "/api/tags"
                try:
                    resp = await client.get(ollama_url)
                    if resp.status_code == 200:
                        data = resp.json()
                        models = [m["name"] for m in data.get("models", [])]
                        connected = True
                except Exception as ex:
                    last_err = ex

                if not connected:
                    try:
                        resp = await client.get(f"{base}/models")
                        if resp.status_code == 200:
                            data = resp.json()
                            models = [m.get("id") or m.get("name") for m in data.get("data", []) if m]
                            connected = True
                        elif resp.status_code in (401, 403):
                            connected = True
                    except Exception as ex:
                        last_err = ex

                if not connected:
                    try:
                        resp = await client.get(base)
                        if resp.status_code < 500:
                            connected = True
                    except Exception as ex:
                        last_err = ex

                if not connected:
                    raise last_err or ConnectionError(f"Cannot reach endpoint at {self.config.llm.base_url}")

                elapsed_ms = int((time.time() - start_t) * 1000)
                llm_diag["backend_available"] = True
                llm_diag["latency_ms"] = elapsed_ms
                llm_diag["models_available"] = [m for m in models if m]

                curr_model = self.config.llm.model.lower()
                model_found = any(curr_model in m.lower() or m.lower() in curr_model for m in models) if models else True

                if self.config.llm.mock_mode:
                    llm_diag["status"] = "mock_mode"
                    llm_diag["reachable"] = True
                    llm_diag["can_switch_live"] = True
                    llm_diag["detail"] = f"Mock mode is on. The model server at {self.config.llm.base_url} is reachable."
                elif models and not model_found:
                    llm_diag["status"] = "model_missing"
                    llm_diag["reachable"] = True
                    llm_diag["detail"] = f"{self.config.llm.model} is not installed on the model server."
                    llm_diag["suggestion"] = f"Run 'ollama pull {self.config.llm.model}' or pick an installed model."
                else:
                    llm_diag["status"] = "ready"
                    llm_diag["reachable"] = True
                    llm_diag["detail"] = f"Using {self.config.llm.model} at {self.config.llm.base_url}."

                if models and model_found:
                    llm_diag["supports_reasoning"] = await self._model_supports_reasoning(client, base, self.config.llm.model)
                if models:
                    support = {m: await self._model_supports_reasoning(client, base, m) for m in models if m}
                    llm_diag["reasoning_models"] = [m for m, ok in support.items() if ok]
                    llm_diag["reasoning_unknown"] = all(ok is None for ok in support.values())
        except Exception:
            llm_diag["backend_available"] = False
            llm_diag["can_switch_live"] = False
            if self.config.llm.mock_mode:
                llm_diag["status"] = "mock_mode"
                llm_diag["reachable"] = False
                llm_diag["detail"] = "Mock mode is on. Replies come from built-in responses."
            else:
                llm_diag["status"] = "unreachable"
                llm_diag["reachable"] = False
                llm_diag["detail"] = f"Cannot reach {self.config.llm.base_url}."
                llm_diag["suggestion"] = "Start Ollama (ollama serve) or switch to mock mode."

        # 3. Port conflict check
        port_diag = {
            "port": self.config.honeypot.port,
            "available": True,
            "detail": f"Port {self.config.honeypot.port} is free.",
            "suggested_alternatives": [],
            "info": "The port attackers connect to over SSH. The default, 2222, avoids the host's own SSH server on port 22.",
        }
        # If honeypot is already running, port is occupied by ourselves
        if self.status != "RUNNING":
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_sock.bind((self.config.honeypot.host, self.config.honeypot.port))
                test_sock.close()
            except Exception:
                port_diag["available"] = False
                port_diag["detail"] = f"Port {self.config.honeypot.port} is in use by another program."
                # Find available alternatives
                for alt_port in [2223, 22222, 2022, 2200]:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        s.bind((self.config.honeypot.host, alt_port))
                        s.close()
                        port_diag["suggested_alternatives"].append(alt_port)
                    except Exception:
                        pass

        # 3b. HTTP sensor port check
        http_sensor_port = getattr(self.config, "http_sensor_port", 8080)
        http_port_diag = {
            "port": http_sensor_port,
            "available": True,
            "enabled": bool(http_sensor_port and http_sensor_port > 0),
            "detail": f"Port {http_sensor_port} is free." if http_sensor_port > 0 else "The HTTP decoy is off (port 0).",
            "info": "Answers web scanners probing for files such as /.env and /wp-admin.",
        }
        if self.status != "RUNNING" and http_sensor_port and http_sensor_port > 0:
            try:
                test_h_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_h_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_h_sock.bind((self.config.honeypot.host, http_sensor_port))
                test_h_sock.close()
            except Exception:
                http_port_diag["available"] = False
                http_port_diag["detail"] = f"Port {http_sensor_port} is in use by another program. Pick another port for the HTTP decoy."

        return {
            "docker": docker_diag,
            "llm": llm_diag,
            "port": port_diag,
            "http_port": http_port_diag,
            "persona": {
                "current": resolve_persona_key(self.config),
                "options": [
                    {"key": key, "name": p.get("name", key), "summary": p.get("summary", "")}
                    for key, p in get_presets_dict().items()
                ],
            },
        }

    async def _model_supports_reasoning(self, client, base: str, model: str) -> Optional[bool]:
        """Whether the model can reason, from Ollama's model metadata (cached per model).

        Ollama lists a "thinking" capability for reasoning models. Other servers
        have no such endpoint, so the answer there is None (unknown).
        """
        cache = self.__dict__.setdefault("_reasoning_capability", {})
        key = (base, model)
        if key not in cache:
            try:
                resp = await client.post(base.replace("/v1", "") + "/api/show", json={"model": model})
                caps = resp.json().get("capabilities") if resp.status_code == 200 else None
                cache[key] = ("thinking" in caps) if isinstance(caps, list) else None
            except Exception:
                return None  # not cached: try again on the next check
        return cache[key]

    async def apply_quick_fix(self, action: str, value: Any = None) -> Dict[str, Any]:
        """Apply 1-click proactive resolution for environment suggestions."""
        if action == "set_port":
            self.config.honeypot.port = int(value)
            return {"message": f"Port changed to {value}", "config": self.get_config_dict()}
        elif action == "set_model":
            self.config.llm.model = str(value)
            self._sync_runtime_components()
            self._request_model_load()
            return {"message": f"Model changed to {value}", "config": self.get_config_dict()}
        elif action == "toggle_mock":
            self.config.llm.mock_mode = bool(value)
            self._sync_runtime_components()
            self._request_model_load()
            return {"message": f"Mock mode set to {value}", "config": self.get_config_dict()}
        elif action == "set_terminal_reasoning":
            # Reasoning for attacker-facing replies; analysis settings are unaffected
            self.terminal_reasoning = bool(value)
            self._sync_runtime_components()
            return {"message": f"Terminal reasoning set to {bool(value)}", "config": self.get_config_dict()}
        elif action == "set_auto_reports":
            # Takes effect for sessions that close from now on; queued reports still run
            self.config.analytics.auto_reports = bool(value)
            return {"message": f"Automatic reports set to {bool(value)}", "config": self.get_config_dict()}
        elif action == "toggle_sandbox":
            self.config.sandbox.enabled = bool(value)
            self._sync_runtime_components()
            return {"message": f"Sandbox set to {value}", "config": self.get_config_dict()}
        elif action == "set_http_port":
            self.config.http_sensor_port = int(value)
            return {"message": f"HTTP sensor port set to {value}", "config": self.get_config_dict()}
        elif action == "recheck":
            if self.session_manager and hasattr(self.session_manager, "sandbox_manager"):
                self.session_manager.sandbox_manager.check_availability()
            return {"message": "Environment rechecked"}
        return {"error": f"Unknown quick-fix action: {action}"}

