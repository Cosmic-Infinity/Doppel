import json
import time
import asyncio
import logging
from typing import Dict, Any, Optional, Set, Tuple, List, AsyncGenerator
from datetime import datetime, timezone
from fastapi import WebSocket

from doppel.config import DoppelConfig, get_config, get_active_preset
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

logger = logging.getLogger("doppel.dashboard.controller")


class HoneypotController:
    """Manages honeypot daemon lifecycle (start, stop, configure) and WebSocket telemetry broadcast."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config: DoppelConfig = get_config(config_path)
        self.status: str = "STOPPED"  # STOPPED, STARTING, RUNNING, STOPPING, ERROR
        self.start_time: Optional[str] = None
        self.error_message: Optional[str] = None

        self.session_manager: Optional[SessionManager] = None
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
                no_think=self.config.llm.terminal_no_think,
            )
            sandbox_manager = DockerSandboxManager(
                image=self.config.sandbox.image,
                network_disabled=self.config.sandbox.network_disabled,
                memory_limit=self.config.sandbox.memory_limit,
                enabled=self.config.sandbox.enabled,
                hostname=preset.get("hostname", self.config.honeypot.hostname),
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
                active_ids = list(self.session_manager.sessions.keys())
                for sess_id in active_ids:
                    await self.session_manager.close_session(sess_id)
                self.session_manager = None

            self.status = "STOPPED"
            self.start_time = None
            logger.info("Honeypot daemon stopped")
            await self.broadcast({
                "type": "status_update",
                "status": self.status,
                "start_time": None,
            })
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

    async def query_assistant(self, message: str, model_override: Optional[str] = None) -> Dict[str, Any]:
        """Query the in-built security assistant with live telemetry, state context, and benchmark metrics."""
        client, target_model, messages, system_state = await self._prepare_assistant_context(message, model_override)
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
        self, message: str, model_override: Optional[str] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream assistant response tokens, live latency, and throughput metrics."""
        client, target_model, messages, system_state = await self._prepare_assistant_context(message, model_override)
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
                await self.session_manager.close_session(session_id)
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
        }

    def _sync_runtime_components(self):
        """Propagate updated config parameters to active session components without restart."""
        if not self.session_manager:
            return

        preset = get_active_preset(self.config)

        if hasattr(self.session_manager, "deception_engine") and self.session_manager.deception_engine:
            target_persona = preset.get("persona_context", self.config.deception.persona) if preset else self.config.deception.persona
            self.session_manager.deception_engine.set_persona(target_persona)
            if preset:
                self.session_manager.deception_engine.set_host_profile(preset)
            self.session_manager.deception_engine.dynamic_honeytokens = self.config.deception.dynamic_honeytokens
            self.session_manager.deception_engine.no_think = self.config.llm.terminal_no_think
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

    async def _attach_session_container(self, session) -> None:
        """Asynchronously attach a new isolated sandbox container to an active session."""
        try:
            if not self.session_manager or not self.session_manager.sandbox_manager:
                return
            container_id = await asyncio.to_thread(
                self.session_manager.sandbox_manager.create_sandbox_session,
                session.session_id,
                username=session.username,
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
        if "llm_mock_mode" in updates:
            self.config.llm.mock_mode = bool(updates["llm_mock_mode"])
        if "sandbox_enabled" in updates:
            self.config.sandbox.enabled = bool(updates["sandbox_enabled"])
        if "hostname" in updates:
            self.config.honeypot.hostname = str(updates["hostname"])
        if "http_sensor_port" in updates:
            self.config.http_sensor_port = int(updates["http_sensor_port"])
        self._sync_runtime_components()

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
            "detail": "Docker is not running. Honeypot will run in zero-risk LLM simulation mode.",
            "info": "Docker Sandbox executes safe bash commands (like 'ls' or 'id') in an isolated, disposable container without network egress. If unavailable, Doppel seamlessly uses AI to simulate the bash terminal.",
        }
        if not self.config.sandbox.enabled:
            docker_diag["status"] = "disabled"
            docker_diag["detail"] = "Docker sandbox is disabled in configuration. Using pure LLM simulation."
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
                docker_diag["detail"] = f"Docker Desktop is active (Engine v{ver}). Containers are isolated."

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
                docker_diag["detail"] = "Docker Desktop is not running. Safe simulation mode will be used automatically (whitelisted commands will not execute in container isolation)."
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
            "detail": "",
            "suggestion": None,
            "info": "The LLM powers dynamic terminal simulation, fake honeytoken credentials, and real-time MITRE ATT&CK analysis. Mock Mode runs locally using built-in simulated responses without requiring an AI model or GPU.",
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
                    llm_diag["detail"] = f"Mock Mode active. Ollama backend is online ({elapsed_ms}ms) with model '{self.config.llm.model}'."
                elif models and not model_found:
                    llm_diag["status"] = "model_missing"
                    llm_diag["reachable"] = True
                    llm_diag["detail"] = f"Connected to Ollama ({elapsed_ms}ms), but model '{self.config.llm.model}' is not pulled yet."
                    llm_diag["suggestion"] = f"Run 'ollama pull {self.config.llm.model}' or choose from installed models."
                else:
                    llm_diag["status"] = "ready"
                    llm_diag["reachable"] = True
                    llm_diag["detail"] = f"Connected to LLM backend ({elapsed_ms}ms). Model '{self.config.llm.model}' is ready."
        except Exception:
            llm_diag["backend_available"] = False
            llm_diag["can_switch_live"] = False
            if self.config.llm.mock_mode:
                llm_diag["status"] = "mock_mode"
                llm_diag["reachable"] = False
                llm_diag["detail"] = "Mock Mode is enabled. Built-in simulated responses will be used (no GPU/model required)."
            else:
                llm_diag["status"] = "unreachable"
                llm_diag["reachable"] = False
                llm_diag["detail"] = f"Cannot reach endpoint at {self.config.llm.base_url}."
                llm_diag["suggestion"] = "Start Ollama with 'ollama serve' in PowerShell, or switch to Mock Mode."

        # 3. Port conflict check
        port_diag = {
            "port": self.config.honeypot.port,
            "available": True,
            "detail": f"Port {self.config.honeypot.port} is available for SSH listener.",
            "suggested_alternatives": [],
            "info": "The network port where the honeypot listens for incoming attacker connections. Default is 2222 so it doesn't conflict with your standard SSH port (22).",
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
                port_diag["detail"] = f"Port {self.config.honeypot.port} is already in use by another service."
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
            "detail": f"HTTP sensor port {http_sensor_port} is available." if http_sensor_port > 0 else "HTTP sensor is disabled (port 0).",
            "info": "Listens for malicious web scanner probes (e.g. requests for /.env, /wp-admin, SQL injection).",
        }
        if self.status != "RUNNING" and http_sensor_port and http_sensor_port > 0:
            try:
                test_h_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_h_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_h_sock.bind((self.config.honeypot.host, http_sensor_port))
                test_h_sock.close()
            except Exception:
                http_port_diag["available"] = False
                http_port_diag["detail"] = f"Port {http_sensor_port} is currently in use by another service. HTTP sensor will be disabled automatically or can be configured to an alternate port."

        return {
            "docker": docker_diag,
            "llm": llm_diag,
            "port": port_diag,
            "http_port": http_port_diag,
            "persona": {
                "current": self.config.deception.persona,
                "info": "Deception Persona defines the system identity, installed fake services, and honeytokens that the attacker discovers during reconnaissance.",
            },
        }

    async def apply_quick_fix(self, action: str, value: Any = None) -> Dict[str, Any]:
        """Apply 1-click proactive resolution for environment suggestions."""
        if action == "set_port":
            self.config.honeypot.port = int(value)
            return {"message": f"Port changed to {value}", "config": self.get_config_dict()}
        elif action == "set_model":
            self.config.llm.model = str(value)
            self._sync_runtime_components()
            return {"message": f"Model changed to {value}", "config": self.get_config_dict()}
        elif action == "toggle_mock":
            self.config.llm.mock_mode = bool(value)
            self._sync_runtime_components()
            return {"message": f"Mock mode set to {value}", "config": self.get_config_dict()}
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

