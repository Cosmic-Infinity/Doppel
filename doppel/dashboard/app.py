import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from doppel.dashboard.controller import HoneypotController

logger = logging.getLogger("doppel.dashboard.api")

app = FastAPI(title="Doppel Control Center", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

controller = HoneypotController()


class ConfigUpdateRequest(BaseModel):
    honeypot_port: Optional[int] = None
    hostname: Optional[str] = None
    persona: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_model: Optional[str] = None
    llm_mock_mode: Optional[bool] = None
    sandbox_enabled: Optional[bool] = None


class QuickFixRequest(BaseModel):
    action: str
    value: Any = None


@app.on_event("startup")
async def startup_event():
    await controller.initialize()


@app.get("/api/diagnostics")
async def get_diagnostics():
    return await controller.diagnose_environment()


@app.post("/api/quick-fix")
async def apply_quick_fix(req: QuickFixRequest):
    res = await controller.apply_quick_fix(req.action, req.value)
    diag = await controller.diagnose_environment()
    return {"result": res, "diagnostics": diag}


@app.get("/api/status")
async def get_status():
    active_count = len(controller.session_manager.sessions) if controller.session_manager else 0
    return {
        "status": controller.status,
        "start_time": controller.start_time,
        "active_sessions": active_count,
        "config": controller.get_config_dict(),
        "error": controller.error_message,
    }


@app.post("/api/start")
async def start_honeypot():
    res = await controller.start()
    return res


@app.post("/api/stop")
async def stop_honeypot():
    res = await controller.stop()
    return res


@app.get("/api/config")
async def get_config_endpoint():
    return controller.get_config_dict()


@app.post("/api/config")
async def update_config_endpoint(req: ConfigUpdateRequest):
    updates = req.model_dump(exclude_unset=True)
    controller.update_config(updates)
    return {"message": "Configuration updated", "config": controller.get_config_dict()}


@app.post("/api/test-llm")
async def test_llm_endpoint():
    res = await controller.test_llm()
    return res


@app.get("/api/sessions")
async def get_sessions():
    """Retrieve combined active and historical attacker sessions."""
    db_sessions = await controller.db.get_all_sessions()
    sessions_map = {s["session_id"]: s for s in db_sessions}

    # Overlay active session live states if running
    if controller.session_manager:
        for sess_id, live_sess in controller.session_manager.sessions.items():
            if sess_id in sessions_map:
                sessions_map[sess_id]["is_active"] = True
                sessions_map[sess_id]["cwd"] = live_sess.cwd
                sessions_map[sess_id]["threat_score"] = live_sess.threat_score
            else:
                sessions_map[sess_id] = {
                    "session_id": sess_id,
                    "remote_ip": live_sess.remote_ip,
                    "remote_port": live_sess.remote_port,
                    "username": live_sess.username,
                    "start_time": live_sess.start_time,
                    "end_time": None,
                    "max_threat_score": live_sess.threat_score,
                    "is_active": True,
                    "command_count": len(live_sess.history),
                    "last_command": live_sess.history[-1]["command"] if live_sess.history else "",
                }

    # Sort descending by start_time
    sorted_sessions = sorted(
        sessions_map.values(),
        key=lambda x: x.get("start_time") or "",
        reverse=True,
    )
    return {"sessions": sorted_sessions}


@app.get("/api/sessions/{session_id}")
async def get_session_details(session_id: str):
    details = await controller.db.get_session_details(session_id)
    if not details:
        # Check in memory if it's brand new
        if controller.session_manager and session_id in controller.session_manager.sessions:
            live = controller.session_manager.sessions[session_id]
            return {
                "session_id": live.session_id,
                "remote_ip": live.remote_ip,
                "remote_port": live.remote_port,
                "username": live.username,
                "start_time": live.start_time,
                "end_time": None,
                "max_threat_score": live.threat_score,
                "cwd": live.cwd,
                "is_active": True,
                "commands": [
                    {"command": h["command"], "output": h["output"], "cwd": h["cwd"], "timestamp": ""}
                    for h in live.history
                ],
            }
        raise HTTPException(status_code=404, detail="Session not found")

    is_active = bool(
        controller.session_manager and session_id in controller.session_manager.sessions
    )
    details["is_active"] = is_active
    return details


@app.get("/api/sessions/{session_id}/report")
async def get_session_report(session_id: str):
    reports_dir = Path(controller.config.analytics.reports_dir)
    matches = list(reports_dir.glob(f"incident_{session_id[:8]}_*.md"))
    if not matches:
        raise HTTPException(status_code=404, detail="Report not found for session")

    report_path = matches[-1]
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()
    return PlainTextResponse(content)


@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await controller.connect_ws(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        controller.disconnect_ws(websocket)
    except Exception:
        controller.disconnect_ws(websocket)


# Mount static directory for frontend
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def serve_index():
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return PlainTextResponse("Doppel Dashboard Frontend Loading...")
