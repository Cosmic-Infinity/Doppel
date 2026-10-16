"""
Tests for Feature: Session Replay & Cross-Session Attacker Correlation
=======================================================================
Run with:  pytest tests/test_replay_campaigns.py -v
"""
import os
import asyncio
import tempfile
from datetime import datetime, timezone, timedelta

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
                         commands: list[tuple[str, str, float]]):
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
        import aiosqlite, json
        ts = _ts(offset)
        async with aiosqlite.connect(db.db_path) as conn:
            await conn.execute(
                """INSERT INTO commands
                   (session_id, timestamp, cwd, command, output,
                    route_decision, technique_id, technique_name, tactics, threat_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, ts, "/home/ubuntu", cmd, output,
                 "llm", None, None, json.dumps([]), 10),
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
    async def test_replay_single_command_has_zero_delay(self, db):
        await _seed_session(db, "s1", "10.0.0.1", "root", "toor",
                            [("whoami", "root", 0)])
        replay = await db.get_session_replay("s1")

        assert replay is not None
        assert len(replay["events"]) == 1
        assert replay["events"][0]["delay_ms"] == 0, "First command always has zero delay"

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
        assert events[0]["delay_ms"] == 0

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
        # total = sum of delays for events[1:] → ~5000 ms
        assert replay["total_duration_ms"] >= 4500

    @pytest.mark.asyncio
    async def test_replay_event_fields_present(self, db):
        await _seed_session(db, "s4", "10.0.0.4", "pi", "raspberry",
                            [("ls", "bin\nboot", 0)])
        replay = await db.get_session_replay("s4")
        event = replay["events"][0]
        for field in ("command", "output", "delay_ms", "timestamp", "cwd"):
            assert field in event, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_replay_event_order_is_chronological(self, db):
        cmds = [("cmd1", "out1", 0), ("cmd2", "out2", 1), ("cmd3", "out3", 1)]
        await _seed_session(db, "s5", "10.0.0.5", "user", "pw", cmds)
        replay = await db.get_session_replay("s5")
        names = [e["command"] for e in replay["events"]]
        assert names == ["cmd1", "cmd2", "cmd3"]


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
        """Same username:password from different IPs → single campaign."""
        await _seed_session(db, "cred-a", "5.5.5.5", "admin", "Password1",
                            [("id", "uid=0", 0)])
        await _seed_session(db, "cred-b", "6.6.6.6", "admin", "Password1",
                            [("id", "uid=0", 0)])
        count = await db.correlate_campaigns()
        assert count == 1

    @pytest.mark.asyncio
    async def test_same_command_fingerprint_groups_into_one_campaign(self, db):
        """Identical top-3 command sets from different IPs/creds → single campaign."""
        shared_cmds = [("curl", "...", 0), ("wget", "...", 1), ("chmod +x", "...", 1)]
        await _seed_session(db, "fp-a", "7.7.7.1", "ubuntu", "aaa", shared_cmds)
        await _seed_session(db, "fp-b", "7.7.7.2", "ubuntu", "bbb", shared_cmds)
        count = await db.correlate_campaigns()
        assert count == 1

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
                      "peak_threat", "first_seen", "last_seen"):
            assert field in c, f"Missing campaign field: {field}"

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


# ══════════════════════════════════════════════════════════════════════════════
# API endpoint smoke tests (no running server needed — FastAPI TestClient)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def api_client(tmp_path):
    """Spin up a TestClient backed by a fresh temp DB."""
    from fastapi.testclient import TestClient
    from doppel.dashboard.app import app, controller

    controller.config.llm.mock_mode = True
    controller.config.analytics.db_path = str(tmp_path / "test.db")
    controller.db = TelemetryDB(db_path=controller.config.analytics.db_path)

    # Initialize DB synchronously via event loop
    asyncio.get_event_loop().run_until_complete(controller.db.initialize())
    return TestClient(app)


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