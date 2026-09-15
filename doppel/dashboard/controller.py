import json
import time
import asyncio
import logging
from typing import Dict, Any, Optional, Set
from datetime import datetime, timezone
from fastapi import WebSocket

from doppel.config import DoppelConfig, get_config
from doppel.ai.llm_client import LLMClient
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
        self._server_task: Optional[asyncio.Task] = None
        self.active_websockets: Set[WebSocket] = set()
        self.active_sse_queues: Set[asyncio.Queue] = set()

        # Telemetry DB instance for dashboard queries even when honeypot is stopped
        self.db = TelemetryDB(db_path=self.config.analytics.db_path)

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
            llm_client = LLMClient(
                base_url=self.config.llm.base_url,
                model=self.config.llm.model,
                api_key=self.config.llm.api_key,
                timeout=self.config.llm.timeout_seconds,
                temperature=self.config.llm.temperature,
                mock_mode=self.config.llm.mock_mode,
            )
            deception_engine = DeceptionEngine(
                llm_client=llm_client, persona=self.config.deception.persona
            )
            sandbox_manager = DockerSandboxManager(
                image=self.config.sandbox.image,
                network_disabled=self.config.sandbox.network_disabled,
                memory_limit=self.config.sandbox.memory_limit,
                enabled=self.config.sandbox.enabled,
            )
            router = HybridRouter(
                intercept_sensitive_files=self.config.deception.intercept_sensitive_files,
                intercept_missing_tools=self.config.deception.intercept_missing_tools,
                sandbox_available=sandbox_manager.is_available,
            )
            observer = ThreatObserver(llm_client=llm_client, db=self.db)
            reporter = IncidentReporter(
                llm_client=llm_client,
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

            if self._http_server_task and not self._http_server_task.done():
                self._http_server_task.cancel()
                try:
                    await self._http_server_task
                except (asyncio.CancelledError, Exception):
                    pass
                self._http_server_task = None

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

    async def test_llm(self) -> Dict[str, Any]:
        """Test latency and status of configured LLM endpoint."""
        client = LLMClient(
            base_url=self.config.llm.base_url,
            model=self.config.llm.model,
            api_key=self.config.llm.api_key,
            timeout=self.config.llm.timeout_seconds,
            mock_mode=self.config.llm.mock_mode,
        )
        start_t = time.time()
        try:
            resp = await client.chat_completion([
                {"role": "user", "content": "ubuntu:/home/ubuntu# uname -a"}
            ])
            elapsed = time.time() - start_t
            return {
                "success": True,
                "latency_seconds": round(elapsed, 3),
                "model": self.config.llm.model,
                "endpoint": self.config.llm.base_url,
                "sample_output": resp.strip(),
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "model": self.config.llm.model,
                "endpoint": self.config.llm.base_url,
            }

    async def _run_http_sensor(self, deception_engine) -> None:
        """Run the HTTP honeypot sensor on port 8080 using uvicorn."""
        import uvicorn
        http_port = getattr(self.config, "http_sensor_port", 8080)

        async def _event_cb(event_type: str, data: dict) -> None:
            self._on_session_event(event_type, data)

        sensor_app = create_http_sensor(
            deception_engine=deception_engine,
            db=self.db,
            persona=self.config.deception.persona,
            event_callback=_event_cb,
        )
        cfg = uvicorn.Config(
            app=sensor_app,
            host=self.config.honeypot.host,
            port=http_port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(cfg)
        logger.info(f"HTTP honeypot sensor starting on port {http_port}")
        try:
            await server.serve()
        except asyncio.CancelledError:
            logger.info("HTTP honeypot sensor stopped")

    def get_config_dict(self) -> Dict[str, Any]:
        return {
            "honeypot_host": self.config.honeypot.host,
            "honeypot_port": self.config.honeypot.port,
            "hostname": self.config.honeypot.hostname,
            "default_user": self.config.honeypot.default_user,
            "persona": self.config.deception.persona,
            "llm_base_url": self.config.llm.base_url,
            "llm_model": self.config.llm.model,
            "llm_timeout": self.config.llm.timeout_seconds,
            "llm_mock_mode": self.config.llm.mock_mode,
            "sandbox_enabled": self.config.sandbox.enabled,
            "sandbox_image": self.config.sandbox.image,
        }

    def update_config(self, updates: Dict[str, Any]):
        if "honeypot_port" in updates:
            self.config.honeypot.port = int(updates["honeypot_port"])
        if "persona" in updates:
            self.config.deception.persona = str(updates["persona"])
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

    async def diagnose_environment(self) -> Dict[str, Any]:
        """Perform proactive pre-flight checks on Docker, Ollama/LLM, and ports."""
        import socket
        import httpx

        # 1. Docker Sandbox check
        docker_diag = {
            "status": "unavailable",
            "available": False,
            "version": None,
            "detail": "Docker is not running. Honeypot will run in zero-risk LLM simulation mode.",
            "info": "Docker Sandbox executes safe bash commands (like 'ls' or 'id') in an isolated, disposable container without network egress. If unavailable, Doppel seamlessly uses AI to simulate the bash terminal.",
        }
        if not self.config.sandbox.enabled:
            docker_diag["status"] = "disabled"
            docker_diag["detail"] = "Docker sandbox is disabled in configuration. Using pure LLM simulation."
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
            except Exception:
                docker_diag["status"] = "unavailable"
                docker_diag["available"] = False
                docker_diag["detail"] = "Docker Desktop is not running. Safe simulation mode will be used automatically."

        # 2. LLM / Ollama check
        llm_diag = {
            "status": "unreachable",
            "reachable": False,
            "latency_ms": 0,
            "models_available": [],
            "configured_model": self.config.llm.model,
            "detail": "",
            "suggestion": None,
            "info": "The LLM powers dynamic terminal simulation, fake honeytoken credentials, and real-time MITRE ATT&CK analysis. Mock Mode runs locally using built-in simulated responses without requiring an AI model or GPU.",
        }
        if self.config.llm.mock_mode:
            llm_diag["status"] = "mock_mode"
            llm_diag["detail"] = "Mock Mode is enabled. Built-in simulated responses will be used (no GPU/model required)."
        else:
            try:
                start_t = time.time()
                base = self.config.llm.base_url.rstrip("/")
                models = []
                async with httpx.AsyncClient(timeout=3.0) as client:
                    # Attempt Ollama native tags API first
                    ollama_url = base.replace("/v1", "") + "/api/tags"
                    try:
                        resp = await client.get(ollama_url)
                        if resp.status_code == 200:
                            data = resp.json()
                            models = [m["name"] for m in data.get("models", [])]
                    except Exception:
                        pass

                    # Fallback to OpenAI /v1/models
                    if not models:
                        try:
                            resp = await client.get(f"{base}/models")
                            if resp.status_code == 200:
                                data = resp.json()
                                models = [m.get("id") or m.get("name") for m in data.get("data", []) if m]
                        except Exception:
                            pass

                    elapsed_ms = int((time.time() - start_t) * 1000)
                    llm_diag["reachable"] = True
                    llm_diag["latency_ms"] = elapsed_ms
                    llm_diag["models_available"] = [m for m in models if m]

                    curr_model = self.config.llm.model.lower()
                    model_found = any(curr_model in m.lower() or m.lower() in curr_model for m in models) if models else True

                    if models and not model_found:
                        llm_diag["status"] = "model_missing"
                        llm_diag["detail"] = f"Connected to Ollama ({elapsed_ms}ms), but model '{self.config.llm.model}' is not pulled yet."
                        llm_diag["suggestion"] = f"Run 'ollama pull {self.config.llm.model}' or choose from installed models."
                    else:
                        llm_diag["status"] = "ready"
                        llm_diag["detail"] = f"Connected to LLM backend ({elapsed_ms}ms). Model '{self.config.llm.model}' is ready."
            except Exception as e:
                llm_diag["status"] = "unreachable"
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

        return {
            "docker": docker_diag,
            "llm": llm_diag,
            "port": port_diag,
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
            return {"message": f"Model changed to {value}", "config": self.get_config_dict()}
        elif action == "toggle_mock":
            self.config.llm.mock_mode = bool(value)
            return {"message": f"Mock mode set to {value}", "config": self.get_config_dict()}
        elif action == "toggle_sandbox":
            self.config.sandbox.enabled = bool(value)
            return {"message": f"Sandbox set to {value}", "config": self.get_config_dict()}
        return {"error": f"Unknown quick-fix action: {action}"}

