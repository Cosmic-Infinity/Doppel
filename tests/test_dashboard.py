import json
import pytest
from fastapi.testclient import TestClient
from doppel.dashboard.app import app, controller


@pytest.fixture
def client():
    # Force mock mode for test
    controller.config.llm.mock_mode = True
    controller.config.access.dashboard_allowed_ips = ["testclient", "127.0.0.1"]
    return TestClient(app, client=("127.0.0.1", 50000))


def test_dashboard_status_endpoint(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "config" in data
    assert "active_sessions" in data


def test_dashboard_config_endpoints(client):
    # 1. Get config
    get_res = client.get("/api/config")
    assert get_res.status_code == 200
    cfg = get_res.json()
    assert "honeypot_port" in cfg
    assert "http_sensor_port" in cfg
    assert "persona" in cfg

    # 2. Update config
    post_res = client.post("/api/config", json={"honeypot_port": 2223, "persona": "cloud_worker", "http_sensor_port": 8088})
    assert post_res.status_code == 200
    updated = post_res.json()["config"]
    assert updated["honeypot_port"] == 2223
    assert updated["persona"] == "cloud_worker"
    assert updated["http_sensor_port"] == 8088

    # Revert back to 2222
    client.post("/api/config", json={"honeypot_port": 2222, "persona": "ubuntu_web_server", "http_sensor_port": 8080})


def test_dashboard_sessions_endpoint(client):
    response = client.get("/api/sessions")
    assert response.status_code == 200
    data = response.json()
    assert "sessions" in data
    assert isinstance(data["sessions"], list)


def test_dashboard_diagnostics_endpoint(client):
    response = client.get("/api/diagnostics")
    assert response.status_code == 200
    data = response.json()
    assert "docker" in data
    assert "llm" in data
    assert "port" in data
    assert "persona" in data
    assert "info" in data["docker"]
    assert "info" in data["llm"]
    assert "info" in data["port"]


def test_dashboard_quick_fix_endpoint(client):
    # Test setting port via quick-fix
    response = client.post("/api/quick-fix", json={"action": "set_port", "value": 2225})
    assert response.status_code == 200
    data = response.json()
    assert "result" in data
    assert controller.config.honeypot.port == 2225

    # Revert back to 2222
    client.post("/api/quick-fix", json={"action": "set_port", "value": 2222})

    # Test recheck action
    recheck_res = client.post("/api/quick-fix", json={"action": "recheck"})
    assert recheck_res.status_code == 200
    recheck_data = recheck_res.json()
    assert recheck_data["result"]["message"] == "Environment rechecked"
    assert "diagnostics" in recheck_data
    assert "docker" in recheck_data["diagnostics"]
    assert "llm" in recheck_data["diagnostics"]
    assert "enabled" in recheck_data["diagnostics"]["docker"]
    assert "endpoint" in recheck_data["diagnostics"]["llm"]

    # Test toggle_mock action
    mock_res = client.post("/api/quick-fix", json={"action": "toggle_mock", "value": True})
    assert mock_res.status_code == 200
    assert controller.config.llm.mock_mode is True


def test_diagnostics_unreachable_llm(client):
    orig_mock = controller.config.llm.mock_mode
    orig_url = controller.config.llm.base_url
    try:
        controller.config.llm.mock_mode = False
        controller.config.llm.base_url = "http://127.0.0.1:59999/v1"
        res = client.get("/api/diagnostics")
        assert res.status_code == 200
        data = res.json()
        assert data["llm"]["status"] == "unreachable"
        assert data["llm"]["reachable"] is False
        assert "59999" in data["llm"]["detail"]
    finally:
        controller.config.llm.mock_mode = orig_mock
        controller.config.llm.base_url = orig_url


def test_diagnostics_docker_status(client):
    orig_enabled = controller.config.sandbox.enabled
    try:
        controller.config.sandbox.enabled = False
        res = client.get("/api/diagnostics")
        assert res.status_code == 200
        assert res.json()["docker"]["status"] == "disabled"

        controller.config.sandbox.enabled = True
        res2 = client.get("/api/diagnostics")
        assert res2.status_code == 200
        docker_data = res2.json()["docker"]
        assert docker_data["enabled"] is True
        assert docker_data["status"] in ("ready", "unavailable")
    finally:
        controller.config.sandbox.enabled = orig_enabled


def test_index_html_has_warning_elements(client):
    res = client.get("/")
    assert res.status_code == 200
    html = res.text
    assert "system-warning-banner" in html
    assert "warning-banner-messages" in html
    assert "nav-badge-llm" in html
    assert "nav-badge-docker" in html
    assert "btn-banner-recheck" in html



def test_dashboard_firewall_blocks_unlisted_ip():
    controller.config.access.dashboard_allowed_ips = ["10.0.0.0/24"]
    try:
        allowed = TestClient(app, client=("10.0.0.7", 5000))
        denied = TestClient(app, client=("203.0.113.9", 5000))
        assert allowed.get("/api/status").status_code == 200
        assert denied.get("/api/status").status_code == 403
        assert denied.get("/").status_code == 403
    finally:
        controller.config.access.dashboard_allowed_ips = []


def test_dashboard_chat_assistant_benchmark(client):
    res = client.post("/api/chat-assistant", json={"message": "Run a model speed benchmark test"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "reply" in data and len(data["reply"]) > 0
    assert "latency_seconds" in data and data["latency_seconds"] >= 0
    assert "tokens_generated" in data and data["tokens_generated"] > 0
    assert "tokens_per_second" in data and data["tokens_per_second"] > 0
    assert "model" in data
    assert "system_state" in data
    assert data["system_state"]["status"] == controller.status


def test_dashboard_chat_assistant_model_override_and_state(client):
    res = client.post("/api/chat-assistant", json={
        "message": "What was the last attack like and what are your suggestions?",
        "model": "qwen3.6:35b-a3b"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["model"] == "qwen3.6:35b-a3b"
    assert "reply" in data and len(data["reply"]) > 0
    assert "system_state" in data
    assert data["system_state"]["port"] == controller.config.honeypot.port


def test_dashboard_chat_assistant_streaming(client):
    res = client.post("/api/chat-assistant/stream", json={"message": "Run a speed benchmark test"})
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]

    body = res.text
    assert "data: " in body

    chunks = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            data = json.loads(line[5:].strip())
            chunks.append(data)

    assert len(chunks) > 1
    assert any(c.get("delta") for c in chunks)
    last = chunks[-1]
    assert last.get("done") is True
    assert "system_state" in last
    assert last["system_state"]["status"] == controller.status


def test_index_html_has_assistant_elements(client):
    res = client.get("/")
    assert res.status_code == 200
    html = res.text
    assert "btn-open-assistant" in html
    assert "assistant-modal" in html
    assert "assistant-model-select" in html
    assert "btn-reset-assistant" in html
    assert "assistant-empty" in html
    assert html.count('class="assistant-chip"') >= 4


@pytest.mark.asyncio
async def test_http_sensor_port_conflict_resilience():
    import socket
    # Pre-occupy a port to simulate another service running on it (like port 8080)
    conflict_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conflict_sock.bind(("127.0.0.1", 0))
    conflict_port = conflict_sock.getsockname()[1]
    conflict_sock.listen(1)

    orig_port = controller.config.http_sensor_port
    orig_mock = controller.config.llm.mock_mode
    orig_host = controller.config.honeypot.host
    orig_hp_port = controller.config.honeypot.port
    controller.config.honeypot.host = "127.0.0.1"
    controller.config.honeypot.port = 2229
    controller.config.http_sensor_port = conflict_port
    controller.config.llm.mock_mode = True

    try:
        # Start honeypot while HTTP sensor port is occupied
        res = await controller.start()
        # Honeypot must successfully start without crashing or sys.exit
        assert res["status"] == "RUNNING"
        assert controller.status == "RUNNING"
        # Stop honeypot cleanly
        stop_res = await controller.stop()
        assert stop_res["status"] == "STOPPED"
    finally:
        conflict_sock.close()
        controller.config.http_sensor_port = orig_port
        controller.config.llm.mock_mode = orig_mock
        controller.config.honeypot.host = orig_host
        controller.config.honeypot.port = orig_hp_port


def test_dashboard_stop_assistant_endpoint(client):
    res = client.post("/api/chat-assistant/stop")
    assert res.status_code == 200
    assert "stopped" in res.json()


def test_index_html_has_report_and_delete_elements(client):
    res = client.get("/")
    assert res.status_code == 200
    html = res.text
    assert "btn-delete-session" in html
    assert "btn-stop-report" in html
    assert "btn-toggle-regen-report" in html
    assert "report-thought-wrapper" in html
    assert "btn-stop-assistant" in html


@pytest.mark.asyncio
async def test_session_report_stream_and_delete_flow(client):
    import uuid
    test_id = str(uuid.uuid4())

    # 1. Seed a test session in the database
    await controller.db.log_session_start(
        session_id=test_id,
        remote_ip="198.51.100.22",
        remote_port=54321,
        username="testuser",
        password="secretpassword",
    )
    await controller.db.log_command(
        session_id=test_id,
        cwd="/home/testuser",
        command="cat /etc/passwd",
        output="root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000:Test User,,,:/home/testuser:/bin/bash",
        route_decision="deception",
        threat_meta={"tactics": ["Discovery"], "technique_id": "T1087", "technique_name": "Account Discovery", "threat_score": 45},
    )
    await controller.db.log_session_end(test_id)

    # 2. Test streaming report endpoint
    res = client.post(
        f"/api/sessions/{test_id}/report/stream",
        json={"custom_instructions": "Focus on credential theft."}
    )
    assert res.status_code == 200
    body = res.text
    assert "data:" in body

    # Parse stream chunks
    chunks = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            chunks.append(json.loads(line[5:].strip()))
    assert len(chunks) > 0
    stages = [c.get("stage") for c in chunks]
    assert "ready" in stages or any(c.get("done") for c in chunks)

    # 3. Test stop report endpoint
    stop_res = client.post(f"/api/sessions/{test_id}/report/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["session_id"] == test_id

    # 4. Test delete session endpoint
    del_res = client.delete(f"/api/sessions/{test_id}")
    assert del_res.status_code == 200
    assert del_res.json()["success"] is True

    # 5. Verify records are purged from database
    details = await controller.db.get_session_details(test_id)
    assert details == {}

    # Deleting again returns 404
    del_res_404 = client.delete(f"/api/sessions/{test_id}")
    assert del_res_404.status_code == 404




def test_terminal_reasoning_switch(client):
    # Not read from the config file: off at start, switched live from the dashboard
    assert not hasattr(controller.config.llm, "terminal_no_think")
    orig = controller.terminal_reasoning
    try:
        res = client.post("/api/quick-fix", json={"action": "set_terminal_reasoning", "value": True})
        assert res.status_code == 200
        assert controller.terminal_reasoning is True
        client.post("/api/quick-fix", json={"action": "set_terminal_reasoning", "value": False})
        assert controller.terminal_reasoning is False
        diag = client.get("/api/diagnostics").json()
        assert diag["llm"]["terminal_reasoning"] is False
        assert "supports_reasoning" in diag["llm"] and "reasoning_models" in diag["llm"]
        html = client.get("/").text
        assert 'id="toggle-terminal-reasoning"' in html and 'id="toggle-chat-reasoning"' in html
    finally:
        controller.terminal_reasoning = orig


def test_settings_api_reads_validates_and_applies(client):
    import copy
    saved = copy.deepcopy(controller.config)
    try:
        settings = client.get("/api/settings").json()
        assert "timeout_seconds" in settings["llm"] and "auto_reports" in settings["analytics"]
        assert "api_key" not in settings["llm"] and "access" not in settings
        assert "email" in settings["alerts"] and "smtp_password" not in settings["alerts"]["email"]

        res = client.patch("/api/settings", json={"llm": {"timeout_seconds": 75},
                                                  "analytics": {"auto_reports": False, "background_idle_seconds": 5}})
        assert res.status_code == 200
        assert set(res.json()["changed"]) == {"llm.timeout_seconds", "analytics.auto_reports",
                                              "analytics.background_idle_seconds"}
        assert controller.config.llm.timeout_seconds == 75
        assert controller.config.analytics.auto_reports is False

        # Rejected as a whole: one bad value means nothing changes
        bad = [
            {"llm": {"api_key": "x"}},                                   # secret, not exposed
            {"access": {"dashboard_allowed_ips": ["0.0.0.0/0"]}},        # access control, not exposed
            {"sandbox": {"network_disabled": False}},                    # isolation, not exposed
            {"llm": {"timeout_seconds": "soon"}},                        # wrong type
            {"llm": {"timeout_seconds": 0}},
            {"deception": {"min_latency_ms": 5000, "max_latency_ms": 100}},
            {"active_preset": "no_such_preset"},
            {"llm": {"temperature": 0.5}, "honeypot": {"port": -1}},
        ]
        for patch in bad:
            r = client.patch("/api/settings", json=patch)
            assert r.status_code == 422, patch
        assert controller.config.llm.temperature == saved.llm.temperature
        assert controller.config.sandbox.network_disabled is True
    finally:
        controller.config = saved


def test_auto_reports_switch(client):
    orig = controller.config.analytics.auto_reports
    try:
        res = client.post("/api/quick-fix", json={"action": "set_auto_reports", "value": False})
        assert res.status_code == 200
        assert controller.config.analytics.auto_reports is False
        assert client.get("/api/status").json()["config"]["auto_reports"] is False
        client.post("/api/quick-fix", json={"action": "set_auto_reports", "value": True})
        assert client.get("/api/status").json()["config"]["auto_reports"] is True
    finally:
        controller.config.analytics.auto_reports = orig


def test_terminal_reasoning_is_off_at_start():
    from doppel.dashboard.controller import HoneypotController
    assert HoneypotController().terminal_reasoning is False


def test_chat_reasoning_flag_reaches_the_model_request(client):
    seen = {}
    orig = controller.query_assistant

    async def fake(message, model_override=None, reasoning=True):
        seen["reasoning"] = reasoning
        return {"success": True, "reply": "ok"}

    controller.query_assistant = fake
    try:
        client.post("/api/chat-assistant", json={"message": "hi"})
        assert seen["reasoning"] is True  # chat reasons by default
        client.post("/api/chat-assistant", json={"message": "hi", "reasoning": False})
        assert seen["reasoning"] is False
    finally:
        controller.query_assistant = orig


def test_reasoning_capability_from_ollama_metadata():
    import asyncio

    class Resp:
        def __init__(self, caps):
            self.status_code = 200
            self._caps = caps

        def json(self):
            return {"capabilities": self._caps} if self._caps is not None else {}

    class Client:
        def __init__(self):
            self.calls = 0

        async def post(self, url, json=None):
            self.calls += 1
            assert url.endswith("/api/show")
            return Resp({"thinker": ["completion", "thinking"], "plain": ["completion", "tools"]}.get(json["model"]))

    c = Client()
    controller.__dict__.pop("_reasoning_capability", None)
    run = lambda m: asyncio.run(controller._model_supports_reasoning(c, "http://x:11434/v1", m))
    assert run("thinker") is True
    assert run("plain") is False
    assert run("other-server-model") is None  # no capabilities field: unknown
    run("thinker")
    assert c.calls == 3  # cached per model
