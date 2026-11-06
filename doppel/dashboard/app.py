import os
import json
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from doppel.dashboard.controller import HoneypotController
from doppel.dashboard.ip_filter import IPAllowlistMiddleware

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

# Firewall: added last so it is the outermost layer and runs before CORS/routes.
app.add_middleware(
    IPAllowlistMiddleware,
    get_allowed=lambda: controller.config.access.dashboard_allowed_ips,
)


class ConfigUpdateRequest(BaseModel):
    honeypot_port: Optional[int] = None
    hostname: Optional[str] = None
    persona: Optional[str] = None
    active_preset: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_model: Optional[str] = None
    llm_mock_mode: Optional[bool] = None
    sandbox_enabled: Optional[bool] = None
    http_sensor_port: Optional[int] = None


class QuickFixRequest(BaseModel):
    action: str
    value: Any = None


class AssistantChatRequest(BaseModel):
    message: str
    model: Optional[str] = None
    # Chat reasons by default; the assistant panel has its own switch
    reasoning: bool = True


class ReportStreamRequest(BaseModel):
    custom_instructions: Optional[str] = None
    model: Optional[str] = None


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


@app.post("/api/chat-assistant")
async def chat_assistant(req: AssistantChatRequest):
    return await controller.query_assistant(message=req.message, model_override=req.model, reasoning=req.reasoning)


@app.post("/api/chat-assistant/stream")
async def chat_assistant_stream(req: AssistantChatRequest):
    """Stream assistant response tokens and live throughput metrics via Server-Sent Events."""
    async def sse_generator():
        try:
            async for chunk in controller.query_assistant_stream(
                message=req.message, model_override=req.model, reasoning=req.reasoning
            ):
                yield f"data: {json.dumps(chunk)}\n\n"
        except asyncio.CancelledError:
            yield f"data: {json.dumps({'delta': '', 'done': True, 'stopped': True})}\n\n"
        except Exception as e:
            err_data = {"error": str(e), "done": True}
            yield f"data: {json.dumps(err_data)}\n\n"

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/chat-assistant/stop")
async def stop_chat_assistant():
    """Stop active streaming chat assistant query."""
    stopped = controller.stop_assistant_stream()
    return {"stopped": stopped}



@app.get("/api/status")
async def get_status():
    active_count = len(controller.session_manager.sessions) if controller.session_manager else 0
    return {
        "status": controller.status,
        "start_time": controller.start_time,
        "active_sessions": active_count,
        "background": controller.session_manager.background.status() if controller.session_manager else None,
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


@app.post("/api/background/run-now")
async def run_background_now():
    """Process queued ATT&CK tagging and reports without waiting for idle time."""
    if not controller.session_manager:
        return {"background": None}
    controller.session_manager.background.run_now()
    return {"background": controller.session_manager.background.status()}


@app.get("/api/config")
async def get_config_endpoint():
    return controller.get_config_dict()


@app.post("/api/config")
async def update_config_endpoint(req: ConfigUpdateRequest):
    updates = req.model_dump(exclude_unset=True)
    controller.update_config(updates)
    return {"message": "Configuration updated", "config": controller.get_config_dict()}



@app.get("/api/sessions")
async def get_sessions():
    """Retrieve combined active and historical attacker sessions."""
    db_sessions = await controller.db.get_all_sessions()
    sessions_map = {s["session_id"]: s for s in db_sessions}

    # Explicitly determine active status strictly based on real in-memory connections
    active_ids = set(controller.session_manager.sessions.keys()) if controller.session_manager else set()
    for s in sessions_map.values():
        s["is_active"] = (s["session_id"] in active_ids)

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
            prof_state = getattr(live, "profiler_state", None)
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
                "attacker_type": getattr(prof_state, "attacker_type", "unknown") if prof_state else "unknown",
                "type_confidence": getattr(prof_state, "type_confidence", 0.0) if prof_state else 0.0,
                "current_phase": getattr(prof_state, "current_phase", "Reconnaissance") if prof_state else "Reconnaissance",
                "commands": [
                    {
                        "command": h["command"],
                        "output": h["output"],
                        "cwd": h["cwd"],
                        "prompt_user": h.get("user"),
                        "route_decision": h.get("route_decision"),
                        "timestamp": h.get("timestamp", ""),
                        "duration_ms": h.get("duration_ms"),
                    }
                    for h in live.history
                ],
            }
        raise HTTPException(status_code=404, detail="Session not found")

    is_active = bool(
        controller.session_manager and session_id in controller.session_manager.sessions
    )
    details["is_active"] = is_active
    if is_active:
        live = controller.session_manager.sessions[session_id]
        details["cwd"] = live.cwd
        details["max_threat_score"] = max(details.get("max_threat_score") or 0, live.threat_score)
        if hasattr(live, "profiler_state") and live.profiler_state:
            details["attacker_type"] = getattr(live.profiler_state, "attacker_type", details.get("attacker_type"))
            details["type_confidence"] = getattr(live.profiler_state, "type_confidence", details.get("type_confidence"))
            details["current_phase"] = getattr(live.profiler_state, "current_phase", details.get("current_phase"))
        db_cmds = details.get("commands", [])
        if len(live.history) > len(db_cmds):
            live_cmds = [
                {
                    "command": h["command"],
                    "output": h["output"],
                    "cwd": h.get("cwd", live.cwd),
                    "route_decision": h.get("route_decision", "standard"),
                    "prompt_user": h.get("user"),
                    "timestamp": h.get("timestamp", ""),
                    "duration_ms": h.get("duration_ms"),
                }
                for h in live.history
            ]
            for idx, c in enumerate(db_cmds):
                if idx < len(live_cmds):
                    live_cmds[idx].update({k: v for k, v in c.items() if v is not None})
            details["commands"] = live_cmds
    return details


@app.get("/api/sessions/{session_id}/replay")
async def get_session_replay(session_id: str):
    """Return session commands with inter-command delay_ms for timeline replay."""
    data = await controller.db.get_session_replay(session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    return data


def _active_session_ids() -> set:
    return set(controller.session_manager.sessions.keys()) if controller.session_manager else set()


@app.get("/api/campaigns")
async def get_campaigns():
    """Return multi-session attacker campaigns linked by IP, credentials, or command sequence."""
    # Re-run correlation on every call so it reflects the latest sessions
    await controller.db.correlate_campaigns()
    campaigns = await controller.db.get_campaigns()
    return {"campaign_count": len(campaigns), "campaigns": campaigns}


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign_sessions(campaign_id: str):
    """Return all sessions belonging to a campaign."""
    members = await controller.db.get_campaign_sessions(campaign_id)
    if not members:
        raise HTTPException(status_code=404, detail="Campaign not found")
    active_ids = _active_session_ids()
    for s in members:
        s["is_active"] = s["session_id"] in active_ids
    return {"campaign_id": campaign_id, "sessions": members}


@app.get("/api/sessions/{session_id}/report")
async def get_session_report(session_id: str):
    reports_dir = Path(controller.config.analytics.reports_dir)
    matches = list(reports_dir.glob(f"incident_{session_id[:8]}_*.md"))
    if not matches:
        if session_id in controller.active_report_tasks and not controller.active_report_tasks[session_id].done():
            return JSONResponse(
                status_code=202,
                content={"status": "compiling", "message": "Incident report is compiling in the background..."},
            )
        raise HTTPException(status_code=404, detail="Report not found for session")

    matches.sort(key=lambda p: p.stat().st_mtime)
    report_path = matches[-1]
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()
    return PlainTextResponse(content)


@app.post("/api/sessions/{session_id}/report/stream")
async def stream_session_report(session_id: str, req: Optional[ReportStreamRequest] = None):
    """Stream live incident report generation with real-time reasoning and progress."""
    instructions = req.custom_instructions if req else None
    model_override = req.model if req else None

    # Resolve reporter instance
    if controller.session_manager and controller.session_manager.reporter:
        reporter = controller.session_manager.reporter
    else:
        from doppel.analytics.reporter import IncidentReporter
        from doppel.ai.llm_client import LLMClient
        llm_client = LLMClient(
            base_url=controller.config.llm.base_url,
            model=model_override or controller.config.llm.model,
            api_key=controller.config.llm.api_key,
            timeout=controller.config.llm.timeout_seconds,
            temperature=controller.config.llm.temperature,
            mock_mode=controller.config.llm.mock_mode,
        )
        reporter = IncidentReporter(
            llm_client=llm_client,
            db=controller.db,
            reports_dir=controller.config.analytics.reports_dir,
        )

    queue = asyncio.Queue()

    async def run_generation():
        try:
            async for chunk in reporter.generate_session_report_stream(
                session_id=session_id,
                custom_instructions=instructions,
                model_override=model_override,
            ):
                await queue.put(chunk)
        except asyncio.CancelledError:
            await queue.put({"stage": "stopped", "message": "Generation stopped by user", "done": True})
        except Exception as e:
            await queue.put({"stage": "error", "error": str(e), "done": True})
        finally:
            controller.active_report_tasks.pop(session_id, None)

    task = asyncio.create_task(run_generation())
    controller.active_report_tasks[session_id] = task

    async def sse_generator():
        try:
            while True:
                chunk = await queue.get()
                yield f"data: {json.dumps(chunk)}\n\n"
                if chunk.get("done"):
                    break
        except asyncio.CancelledError:
            controller.stop_report_generation(session_id)
            yield f"data: {json.dumps({'stage': 'stopped', 'message': 'Stream cancelled', 'done': True})}\n\n"

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/sessions/{session_id}/report/stop")
async def stop_session_report(session_id: str):
    """Cancel active report streaming generation for a session."""
    stopped = controller.stop_report_generation(session_id)
    return {"stopped": stopped, "session_id": session_id}


@app.delete("/api/sessions/{session_id}")
async def delete_session_endpoint(session_id: str):
    """Purge an attack session, all related commands/phases, and disk artifacts."""
    success = await controller.delete_session(session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or already deleted")
    return {"success": True, "session_id": session_id}




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


@app.get("/api/stream")
async def sse_stream(request: Request):
    """Resilient Server-Sent Events (SSE) telemetry stream when WebSockets are unavailable."""
    async def event_generator():
        q: asyncio.Queue = asyncio.Queue()
        controller.active_sse_queues.add(q)
        try:
            # Yield initial snapshot immediately upon connection
            init_payload = controller.get_initial_snapshot()
            yield f"data: {json.dumps(init_payload)}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat comment for SSE
                    yield ": ping\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            controller.active_sse_queues.discard(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


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