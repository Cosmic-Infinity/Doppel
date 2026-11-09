"""
Regression tests for issues found by simulating hostile clients against a
local instance: input flooding, terminal handling, fingerprintable responses,
telemetry loss under concurrency, and the canary tripwire.
"""
import asyncio
import os
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from doppel.ai.deception_engine import DeceptionEngine
from doppel.ai.llm_client import LLMClient
from doppel.analytics.db import TelemetryDB
from doppel.config import DoppelConfig
from doppel.core.ssh_server import MAX_LINE_CHARS, DoppelSSHServerSession, _software_version
from doppel.deception.honeytokens import HoneytokenManager, derive_canary_base_url
from doppel.http_sensor import sensor as sensor_module
from doppel.http_sensor.sensor import create_http_sensor


# ── SSH terminal input ────────────────────────────────────────────────────────

class FakeChannel:
    def __init__(self):
        self.out = []
        self.closed = False

    def write(self, text):
        if self.closed:
            raise BrokenPipeError("Channel not open for sending")
        self.out.append(text)

    def close(self):
        self.closed = True

    def exit(self, status):
        pass

    @property
    def text(self):
        return "".join(self.out)


class FakeSessionManager:
    """Records commands; optionally blocks until released to model a slow LLM."""

    def __init__(self):
        self.commands = []
        self.release = asyncio.Event()
        self.release.set()

    @staticmethod
    def can_drop_privileges(session):
        return bool(session.is_elevated and session.effective_user != session.username)

    async def process_command(self, session_id, command, keystroke_timestamps=None):
        self.commands.append(command)
        await self.release.wait()
        return f"out:{command}"


def make_shell():
    mgr = FakeSessionManager()
    sess = DoppelSSHServerSession(mgr, DoppelConfig(), "203.0.113.7", 40000, "ubuntu", "pw")
    sess.chan = FakeChannel()
    sess.session = SimpleNamespace(
        session_id="s1", cwd="/home/ubuntu", effective_user="ubuntu", username="ubuntu", is_elevated=False,
    )
    sess._shell_ready.set()
    return sess, mgr


async def settle():
    for _ in range(5):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_input_flood_is_capped_and_linear():
    sess, mgr = make_shell()
    t0 = time.perf_counter()
    for _ in range(64):  # 4 MB in 64 KB chunks, no newline
        sess.data_received("A" * 65536, None)
    elapsed = time.perf_counter() - t0
    assert len(sess._input_buffer) == MAX_LINE_CHARS
    assert elapsed < 2.0, f"4 MB of input took {elapsed:.1f}s"

    sess.data_received("\r", None)
    await settle()
    assert mgr.commands == ["A" * MAX_LINE_CHARS]


@pytest.mark.asyncio
async def test_arrow_keys_recall_history_instead_of_typing_escape_codes():
    sess, mgr = make_shell()
    sess.data_received("uname -a\r", None)
    await settle()
    sess.data_received("\x1b[A", None)
    assert sess._input_buffer == "uname -a"
    sess.data_received("\x1b[B", None)
    assert sess._input_buffer == ""
    # Left/right and other sequences never reach the command line
    sess.data_received("ls\x1b[D\x1b[C\x1b[3~", None)
    assert sess._input_buffer == "ls"


@pytest.mark.asyncio
async def test_escape_sequence_split_across_chunks():
    sess, mgr = make_shell()
    sess.data_received("id\r", None)
    await settle()
    sess.data_received("\x1b", None)
    sess.data_received("[", None)
    sess.data_received("A", None)
    assert sess._input_buffer == "id"


@pytest.mark.asyncio
async def test_ctrl_c_drops_output_of_running_command():
    sess, mgr = make_shell()
    mgr.release.clear()
    sess.data_received("nmap -p- 10.0.4.50\r", None)
    await settle()
    sess.data_received("\x03", None)
    mgr.release.set()
    await settle()
    assert "out:nmap" not in sess.chan.text
    assert sess.chan.text.rstrip().endswith("$")


@pytest.mark.asyncio
async def test_ctrl_c_discards_typed_ahead_lines():
    sess, mgr = make_shell()
    mgr.release.clear()
    sess.data_received("sleep 5\rwhoami\r", None)
    await settle()
    sess.data_received("\x03", None)
    mgr.release.set()
    await settle()
    assert mgr.commands == ["sleep 5"]


@pytest.mark.asyncio
async def test_exec_channel_ignores_stdin():
    sess, mgr = make_shell()
    sess._is_exec = True
    sess.data_received("C0644 5 x\nhello\n", None)
    await settle()
    assert sess.chan.text == ""
    assert mgr.commands == []


@pytest.mark.asyncio
async def test_writes_after_disconnect_do_not_raise():
    sess, mgr = make_shell()
    mgr.release.clear()
    sess.data_received("ps aux\r", None)
    await settle()
    sess.chan.closed = True
    mgr.release.set()
    await settle()  # would raise BrokenPipeError inside the task before


def test_banner_prefix_not_doubled():
    assert _software_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6") == "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    assert _software_version("OpenSSH_7.4p1") == "OpenSSH_7.4p1"


# ── Deterministic fast path ───────────────────────────────────────────────────

def test_fast_path_leaves_shell_syntax_to_the_model():
    engine = DeceptionEngine(LLMClient(mock_mode=True))
    for cmd in ["id && uname -a", "uname -a; cat /proc/cpuinfo", "whoami | base64",
                "id > /tmp/x", "echo $(id)", "hostname -I", "id www-data"]:
        assert engine.deterministic_posix_response(cmd, user="ubuntu") is None, cmd


def test_fast_path_identity_values():
    engine = DeceptionEngine(LLMClient(mock_mode=True))
    assert engine.deterministic_posix_response("id", user="root") == "uid=0(root) gid=0(root) groups=0(root)"
    assert engine.deterministic_posix_response("id -u", user="root") == "0"
    assert engine.deterministic_posix_response("id -un", user="ubuntu") == "ubuntu"
    assert engine.deterministic_posix_response("uname -sr", user="ubuntu") == "Linux 5.15.0-105-generic"
    assert "invalid option" in engine.deterministic_posix_response("uname -q", user="ubuntu")


def test_fast_path_follows_preset_host_profile():
    engine = DeceptionEngine(LLMClient(mock_mode=True), host_profile={
        "hostname": "db-cluster-node-03",
        "kernel_release": "3.10.0-1160.99.1.el7.x86_64",
        "kernel_version": "#1 SMP Wed Sep 13 14:19:20 UTC 2023",
        "user_groups": "4(adm),10(wheel)",
    })
    assert engine.deterministic_posix_response("hostname", user="centos") == "db-cluster-node-03"
    assert "3.10.0-1160.99.1.el7.x86_64" in engine.deterministic_posix_response("uname -a", user="centos")
    assert engine.deterministic_posix_response("id", user="centos").endswith("groups=1000(centos),4(adm),10(wheel)")


def test_failure_output_does_not_deny_core_utilities():
    assert DeceptionEngine.failure_output("cat /etc/passwd") == ""
    assert DeceptionEngine.failure_output("echo hi") == ""
    assert DeceptionEngine.failure_output("nmap -sV 10.0.0.1") == "bash: nmap: command not found"


def test_clean_output_keeps_first_line_indentation():
    engine = DeceptionEngine(LLMClient(mock_mode=True))
    assert engine._clean_output("\n    1  cd /var/www\n    2  ls\n", command="history") == "    1  cd /var/www\n    2  ls"


# ── HTTP decoy ────────────────────────────────────────────────────────────────

@pytest.fixture
def sensor_client(tmp_path, monkeypatch):
    manager = HoneytokenManager(base_url="http://203.0.113.10:8080")
    monkeypatch.setattr(sensor_module, "get_honeytoken_manager", lambda: manager)
    db = TelemetryDB(str(tmp_path / "t.db"))
    events = []

    async def on_event(kind, data):
        events.append((kind, data))

    app = create_http_sensor(DeceptionEngine(LLMClient(mock_mode=True)), db, event_callback=on_event)
    with TestClient(app, client=("198.51.100.4", 51000)) as client:
        yield SimpleNamespace(client=client, db=db, manager=manager, events=events, path=str(tmp_path / "t.db"))


def _rows(path, sql):
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_decoy_does_not_expose_framework_endpoints(sensor_client):
    for path in ("/openapi.json", "/docs", "/redoc"):
        r = sensor_client.client.get(path)
        assert r.status_code == 404
        assert "Doppel" not in r.text and "openapi" not in r.text.lower()


def test_unknown_paths_get_nginx_404(sensor_client):
    r = sensor_client.client.get("/robots.txt")
    assert r.status_code == 404
    assert r.headers["content-type"] == "text/html"
    assert "<center><h1>404 Not Found</h1></center>" in r.text
    assert r.headers["server"] == "nginx/1.18.0 (Ubuntu)"
    assert "x-powered-by" not in r.headers


def test_probes_from_one_ip_share_one_session(sensor_client):
    for path in ("/.env", "/wp-admin/", "/a", "/b", "/c"):
        sensor_client.client.get(path)
    sessions = _rows(sensor_client.path, "SELECT session_id FROM sessions WHERE username='http_probe'")
    assert len(sessions) == 1
    assert _rows(sensor_client.path, "SELECT COUNT(*) FROM commands")[0][0] == 5
    assert _rows(sensor_client.path, "SELECT COUNT(*) FROM web_probes")[0][0] == 5


def test_canary_tripwire_on_decoy_port(sensor_client):
    tokens = sensor_client.manager.generate_session_honeytokens("ssh-session-1")
    assert tokens["aws"].canary_url.startswith("http://203.0.113.10:8080/auth/v1/verify?token=")

    r = sensor_client.client.get(f"/auth/v1/verify?token={tokens['aws'].identifier}")
    assert r.status_code == 401
    kinds = [k for k, _ in sensor_client.events]
    assert "honeytoken_activated" in kinds
    activation = dict(sensor_client.events)["honeytoken_activated"]
    assert activation["matched_honeytoken"] is True
    assert activation["session_id"] == "ssh-session-1"
    labels = _rows(sensor_client.path, "SELECT probe_label FROM web_probes")
    assert ("honeytoken_activated:aws",) in labels

    # The use is stored with both sessions, and an unknown token records nothing
    sensor_client.client.get("/auth/v1/verify?token=AKIAFAKEFAKEFAKEFAKE")
    rows = _rows(sensor_client.path, "SELECT source_session_id, web_session_id, token_type FROM honeytoken_activations")
    assert len(rows) == 1
    source, web, token_type = rows[0]
    assert (source, token_type) == ("ssh-session-1", "aws") and web.startswith("http_")
    assert activation["web_session_id"] == web

    # Reports and campaigns reference the other session
    from doppel.analytics.reporter import ACTIVATIONS_HEADING, IncidentReporter, with_activations
    from doppel.ai.llm_client import LLMClient
    db = sensor_client.db

    async def linked():
        await db.log_session_start("ssh-session-1", "198.51.100.7", 22, "ubuntu", "ubuntu")
        await db.correlate_campaigns()
        return await db.get_session_details("ssh-session-1"), await db.get_session_details(web)

    ssh, web_row = sensor_client.client.portal.call(linked)
    assert ssh["campaign_id"] == web_row["campaign_id"] and "honeytoken_use" in ssh["campaign_reasons"]
    assert web_row["honeytoken_activations"][0]["source_session_id"] == "ssh-session-1"

    hits = ssh["honeytoken_activations"]
    once = with_activations("# Report\n\nBody", "ssh-session-1", hits)
    assert f"web session `{web}`" in once and once.count(ACTIVATIONS_HEADING) == 1
    assert with_activations(once, "ssh-session-1", hits) == once
    assert "SSH session `ssh-session-1`" in with_activations("# Report", web, hits)

    reports = Path(sensor_client.path).parent / "reports"
    reporter = IncidentReporter(LLMClient(mock_mode=True), db, str(reports))
    written = reports / "incident_ssh-sess_20261109_120000.md"
    written.write_text("# Report", encoding="utf-8")
    sensor_client.client.portal.call(reporter.refresh_activations, "ssh-session-1")
    assert ACTIVATIONS_HEADING in written.read_text(encoding="utf-8")


def test_canary_recognised_after_restart(sensor_client):
    """Tokens issued by an earlier process are matched from the database."""
    async def seed():
        await sensor_client.db.save_honeytoken(SimpleNamespace(
            identifier="AKIAOLDPROCESS000001", token_type="aws", session_id="old-session",
            canary_url="x", created_at="2026-11-01T00:00:00+00:00",
        ))
    sensor_client.client.portal.call(seed)

    sensor_client.client.post("/auth/v1/verify", json={"api_key": "AKIAOLDPROCESS000001"})
    activation = dict(sensor_client.events)["honeytoken_activated"]
    assert activation["matched_honeytoken"] is True
    assert activation["session_id"] == "old-session"


def test_canary_base_url_derivation():
    cfg = DoppelConfig()
    cfg.honeypot.host = "0.0.0.0"
    assert derive_canary_base_url(cfg, {"hostname": "prod-api-node-01"}) == "http://prod-api-node-01:8080"
    cfg.deception.canary_base_url = "http://203.0.113.10:8080/"
    assert derive_canary_base_url(cfg, {}) == "http://203.0.113.10:8080"


# ── Telemetry DB under concurrency ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_concurrent_writes_are_not_lost(tmp_path):
    db = TelemetryDB(str(tmp_path / "t.db"))
    await db.initialize()
    assert _rows(db.db_path, "PRAGMA journal_mode")[0][0] == "wal"

    async def session(i):
        sid = f"s{i}"
        await db.log_session_start(sid, f"10.0.0.{i}", 1, "u", "p")
        for j in range(10):
            await db.log_command(sid, "/", f"cmd{j}", "out", "sandbox")

    await asyncio.gather(*[session(i) for i in range(30)])
    assert _rows(db.db_path, "SELECT COUNT(*) FROM sessions")[0][0] == 30
    assert _rows(db.db_path, "SELECT COUNT(*) FROM commands")[0][0] == 300


# ── Privilege drop is recorded ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_exit_from_root_shell_is_logged_and_restores_cwd(tmp_path):
    from doppel.analytics.observer import ThreatObserver
    from doppel.analytics.reporter import IncidentReporter
    from doppel.core.session_manager import SessionManager
    from doppel.router.hybrid_router import HybridRouter
    from doppel.sandbox.docker_manager import DockerSandboxManager

    config = DoppelConfig()
    config.llm.mock_mode = True
    config.sandbox.enabled = False
    config.deception.simulate_latency = False
    config.analytics.enable_mitre_tagging = False
    db = TelemetryDB(str(tmp_path / "t.db"))
    await db.initialize()
    llm = LLMClient(mock_mode=True)
    mgr = SessionManager(
        config=config, deception_engine=DeceptionEngine(llm),
        sandbox_manager=DockerSandboxManager(enabled=False), router=HybridRouter(sandbox_available=False),
        db=db, observer=ThreatObserver(llm, db), reporter=IncidentReporter(llm, db, reports_dir=str(tmp_path / "r")),
    )
    s = await mgr.create_session(remote_ip="10.0.0.9", remote_port=1, username="ubuntu", password="x")
    await mgr.process_command(s.session_id, "cd /var/www/html")
    await mgr.process_command(s.session_id, "sudo su")
    assert (s.effective_user, s.cwd) == ("root", "/root")
    assert await mgr.process_command(s.session_id, "exit") == "exit"
    assert (s.effective_user, s.cwd, s.is_elevated) == ("ubuntu", "/var/www/html", False)

    cmds = (await db.get_session_details(s.session_id))["commands"]
    assert [(c["command"], c["prompt_user"]) for c in cmds][-1] == ("exit", "root")
    await mgr.close_session(s.session_id)


def test_session_keeps_one_honeytoken_set():
    """Repeated requests for a session's decoy credentials return the same tokens,
    so a sandbox retry or a later model reply never leaks a second set."""
    manager = HoneytokenManager(base_url="http://203.0.113.10:8080")
    first = manager.session_honeytokens("sess-a")
    again = manager.session_honeytokens("sess-a")
    assert {k: t.identifier for k, t in first.items()} == {k: t.identifier for k, t in again.items()}
    assert len(manager.tokens) == 3
    block = manager.build_injection_prompt_block("sess-a")
    assert first["aws"].identifier in block and first["api_key"].identifier in block
    assert len(manager.tokens) == 3
    other = manager.session_honeytokens("sess-b")
    assert other["aws"].identifier != first["aws"].identifier
