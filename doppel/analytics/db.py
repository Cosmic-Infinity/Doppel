import json
import logging
import aiosqlite
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("doppel.analytics.db")


class TelemetryDB:
    """Async SQLite database storing honeypot sessions, commands, and MITRE threat telemetry."""

    def __init__(self, db_path: str = "doppel_telemetry.db"):
        self.db_path = db_path

    async def initialize(self):
        """Create tables and indexes if they do not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
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
            await db.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    timestamp TEXT,
                    cwd TEXT,
                    command TEXT,
                    output TEXT,
                    route_decision TEXT,
                    technique_id TEXT,
                    technique_name TEXT,
                    tactics TEXT,
                    threat_score INTEGER,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)
            await db.commit()
            logger.info(f"Telemetry database initialized at {self.db_path}")

    async def log_session_start(
        self,
        session_id: str,
        remote_ip: str,
        remote_port: int,
        username: str,
        password: Optional[str] = None,
    ):
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO sessions
                (session_id, remote_ip, remote_port, username, password, start_time)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, remote_ip, remote_port, username, password or "", now),
            )
            await db.commit()

    async def log_command(
        self,
        session_id: str,
        cwd: str,
        command: str,
        output: str,
        route_decision: str,
        threat_meta: Optional[Dict[str, Any]] = None,
    ):
        now = datetime.now(timezone.utc).isoformat()
        meta = threat_meta or {}
        tactics_str = json.dumps(meta.get("tactics", []))
        score = meta.get("threat_score", 0)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO commands
                (session_id, timestamp, cwd, command, output, route_decision,
                 technique_id, technique_name, tactics, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now,
                    cwd,
                    command,
                    output,
                    route_decision,
                    meta.get("technique_id"),
                    meta.get("technique_name"),
                    tactics_str,
                    score,
                ),
            )
            # Update max threat score in session if higher
            await db.execute(
                """
                UPDATE sessions
                SET max_threat_score = MAX(max_threat_score, ?)
                WHERE session_id = ?
                """,
                (score, session_id),
            )
            await db.commit()

    async def log_session_end(self, session_id: str, summary: Optional[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE sessions
                SET end_time = ?, summary = COALESCE(?, summary)
                WHERE session_id = ?
                """,
                (now, summary, session_id),
            )
            await db.commit()

    async def get_session_details(self, session_id: str) -> Dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)) as cur:
                sess_row = await cur.fetchone()
                if not sess_row:
                    return {}
                session_dict = dict(sess_row)

            async with db.execute(
                "SELECT * FROM commands WHERE session_id = ? ORDER BY id ASC", (session_id,)
            ) as cur:
                cmd_rows = await cur.fetchall()
                session_dict["commands"] = [dict(r) for r in cmd_rows]

            return session_dict
