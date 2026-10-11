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
    assert "persona" in cfg

    # 2. Update config
    post_res = client.post("/api/config", json={"honeypot_port": 2223, "persona": "cloud_worker"})
    assert post_res.status_code == 200
    updated = post_res.json()["config"]
    assert updated["honeypot_port"] == 2223
    assert updated["persona"] == "cloud_worker"

    # Revert back to 2222
    client.post("/api/config", json={"honeypot_port": 2222, "persona": "ubuntu_web_server"})


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
