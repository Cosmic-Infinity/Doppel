import pytest
import os
import tempfile
from doppel.config import DoppelConfig
from doppel.ai.llm_client import LLMClient
from doppel.ai.deception_engine import DeceptionEngine
from doppel.sandbox.docker_manager import DockerSandboxManager
from doppel.router.hybrid_router import HybridRouter
from doppel.analytics.db import TelemetryDB
from doppel.analytics.observer import ThreatObserver
from doppel.analytics.reporter import IncidentReporter
from doppel.core.session_manager import SessionManager


@pytest.mark.asyncio
async def test_session_lifecycle_and_navigation():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_telemetry.db")
        reports_dir = os.path.join(tmpdir, "reports")

        config = DoppelConfig()
        config.llm.mock_mode = True
        config.sandbox.enabled = False  # Pure simulation mode for test
        config.analytics.db_path = db_path
        config.analytics.reports_dir = reports_dir

        llm_client = LLMClient(mock_mode=True)
        deception_engine = DeceptionEngine(llm_client)
        sandbox_manager = DockerSandboxManager(enabled=False)
        router = HybridRouter(sandbox_available=False)
        db = TelemetryDB(db_path=db_path)
        await db.initialize()
        observer = ThreatObserver(llm_client, db)
        reporter = IncidentReporter(llm_client, db, reports_dir=reports_dir)

        session_mgr = SessionManager(
            config=config,
            deception_engine=deception_engine,
            sandbox_manager=sandbox_manager,
            router=router,
            db=db,
            observer=observer,
            reporter=reporter,
        )

        # 1. Create session
        session = await session_mgr.create_session(
            remote_ip="192.168.1.100",
            remote_port=44222,
            username="ubuntu",
            password="testpassword",
        )
        assert session.cwd == "/home/ubuntu"
        assert session.username == "ubuntu"

        # 2. Test directory navigation
        await session_mgr.process_command(session.session_id, "cd /var/www/html")
        assert session.cwd == "/var/www/html"

        await session_mgr.process_command(session.session_id, "cd ..")
        assert session.cwd == "/var/www"

        await session_mgr.process_command(session.session_id, "cd ~")
        assert session.cwd == "/home/ubuntu"

        # 3. Test intercepted command and immediate DB logging
        output = await session_mgr.process_command(session.session_id, "cat .env")
        assert "DB_PASSWORD" in output

        # Verify command was logged to DB immediately
        details = await db.get_session_details(session.session_id)
        assert len(details["commands"]) >= 1
        assert details["commands"][-1]["command"] == "cat .env"

        # 4. Close session and check report generation
        report_file = await session_mgr.close_session(session.session_id)
        assert report_file is not None
        assert os.path.exists(report_file)

        with open(report_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "Incident Response Report" in content
            assert "192.168.1.100" in content


@pytest.mark.asyncio
async def test_ssh_session_exec_and_early_commands():
    from doppel.core.ssh_server import DoppelSSHServerSession

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_telemetry.db")
        config = DoppelConfig()
        config.llm.mock_mode = True
        config.sandbox.enabled = False
        config.analytics.db_path = db_path

        llm_client = LLMClient(mock_mode=True)
        deception_engine = DeceptionEngine(llm_client)
        sandbox_manager = DockerSandboxManager(enabled=False)
        router = HybridRouter(sandbox_available=False)
        db = TelemetryDB(db_path=db_path)
        await db.initialize()
        observer = ThreatObserver(llm_client, db)
        reporter = IncidentReporter(llm_client, db, reports_dir=tmpdir)

        session_mgr = SessionManager(
            config=config,
            deception_engine=deception_engine,
            sandbox_manager=sandbox_manager,
            router=router,
            db=db,
            observer=observer,
            reporter=reporter,
        )

        class MockChannel:
            def __init__(self):
                self.written = []
                self.closed = False
                self.exit_status = None

            def write(self, data):
                self.written.append(data)

            def exit(self, status):
                self.exit_status = status

            def close(self):
                self.closed = True

        # Test exec_requested (one-shot command)
        chan = MockChannel()
        ssh_sess = DoppelSSHServerSession(
            session_manager=session_mgr,
            config=config,
            remote_ip="192.168.1.50",
            remote_port=55111,
            username="ubuntu",
            password="pwd",
        )
        ssh_sess.connection_made(chan)
        ssh_sess.session_started()
        accepted = ssh_sess.exec_requested("whoami")
        assert accepted is True

        # Wait briefly for async exec task
        import asyncio
        await asyncio.sleep(0.3)

        assert chan.closed is True
        assert chan.exit_status == 0
        output_combined = "".join(chan.written)
        assert "ubuntu" in output_combined


@pytest.mark.asyncio
async def test_schema_migration_for_legacy_database():
    import aiosqlite
    from doppel.core.fake_filesystem import FakeFilesystem

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_telemetry.db")

        # Manually create legacy table without country_code or other new columns
        async with aiosqlite.connect(db_path) as db:
            await db.execute("""
                CREATE TABLE sessions (
                    session_id TEXT PRIMARY KEY,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    username TEXT,
                    password TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    max_threat_score INTEGER DEFAULT 0,
                    summary TEXT
                )
            """)
            # Also insert an orphaned session with end_time NULL
            await db.execute("""
                INSERT INTO sessions (session_id, remote_ip, remote_port, username, start_time)
                VALUES ('legacy-sess-01', '1.2.3.4', 2222, 'root', '2026-01-01T00:00:00')
            """)
            await db.commit()

        # Initialize TelemetryDB on top of legacy DB
        telemetry_db = TelemetryDB(db_path=db_path)
        await telemetry_db.initialize()

        # Verify orphaned session was closed
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT end_time FROM sessions WHERE session_id = 'legacy-sess-01'") as cur:
                row = await cur.fetchone()
                assert row is not None
                assert row[0] is not None

        # Verify log_session_start succeeds with full geoip and credential analysis
        await telemetry_db.log_session_start(
            session_id="new-migrated-sess",
            remote_ip="100.81.22.95",
            remote_port=54321,
            username="ubuntu",
            password="",
            geoip={"country_code": "US", "country_name": "United States", "city": "Seattle", "asn": 13335},
            credential_risk="critical",
        )

        details = await telemetry_db.get_session_details("new-migrated-sess")
        assert details["country_code"] == "US"
        assert details["credential_risk"] == "critical"


def test_fake_filesystem_cwd_path_resolution():
    from doppel.core.fake_filesystem import FakeFilesystem

    fs = FakeFilesystem()
    # Attacker runs mkdir in /home/ubuntu
    fs.update_from_command("mkdir test_dir", "", cwd="/home/ubuntu")
    assert fs.file_exists("/home/ubuntu/test_dir", cwd="/home/ubuntu") is False  # dir is in _dirs
    assert "/home/ubuntu/test_dir" in fs._dirs

    # Attacker runs touch in /home/ubuntu
    fs.update_from_command("touch payload.sh", "", cwd="/home/ubuntu")
    assert fs.file_exists("payload.sh", cwd="/home/ubuntu") is True
    assert fs.file_exists("/home/ubuntu/payload.sh") is True

    # Context block should list /home/ubuntu/test_dir and /home/ubuntu/payload.sh
    ctx = fs.build_context_block()
    assert "/home/ubuntu/test_dir" in ctx
    assert "/home/ubuntu/payload.sh" in ctx
