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

        # 3. Test intercepted command
        output = await session_mgr.process_command(session.session_id, "cat .env")
        assert "DB_PASSWORD" in output

        # 4. Close session and check report generation
        report_file = await session_mgr.close_session(session.session_id)
        assert report_file is not None
        assert os.path.exists(report_file)

        with open(report_file, "r", encoding="utf-8") as f:
            content = f.read()
            assert "Incident Response Report" in content
            assert "192.168.1.100" in content
