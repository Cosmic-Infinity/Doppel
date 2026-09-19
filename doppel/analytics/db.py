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
                    summary TEXT,
                    country_code TEXT,
                    country_name TEXT,
                    city TEXT,
                    asn INTEGER,
                    asn_org TEXT,
                    is_datacenter INTEGER DEFAULT 0,
                    attacker_type TEXT DEFAULT 'unknown',
                    type_confidence REAL DEFAULT 0.0,
                    current_phase TEXT DEFAULT 'Reconnaissance',
                    credential_risk TEXT
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
            # Attack phase transitions
            await db.execute("""
                CREATE TABLE IF NOT EXISTS phase_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    timestamp TEXT,
                    from_phase TEXT,
                    to_phase TEXT,
                    phase_index INTEGER,
                    triggered_by TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)
            # Web probe events from the HTTP sensor
            await db.execute("""
                CREATE TABLE IF NOT EXISTS web_probes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    method TEXT,
                    path TEXT,
                    query TEXT,
                    user_agent TEXT,
                    probe_label TEXT,
                    status_code INTEGER,
                    response_snippet TEXT
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
        geoip: Optional[Dict[str, Any]] = None,
        credential_risk: Optional[str] = None,
    ):
        now = datetime.now(timezone.utc).isoformat()
        geo = geoip or {}
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO sessions
                (session_id, remote_ip, remote_port, username, password, start_time,
                 country_code, country_name, city, asn, asn_org, is_datacenter,
                 credential_risk)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id, remote_ip, remote_port, username, password or "", now,
                    geo.get("country_code"), geo.get("country_name"), geo.get("city"),
                    geo.get("asn"), geo.get("asn_org"),
                    1 if geo.get("is_datacenter") else 0,
                    credential_risk,
                ),
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

    async def log_phase_transition(
        self,
        session_id: str,
        from_phase: str,
        to_phase: str,
        phase_index: int,
        triggered_by: str,
    ):
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO phase_transitions
                (session_id, timestamp, from_phase, to_phase, phase_index, triggered_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, now, from_phase, to_phase, phase_index, triggered_by[:200]),
            )
            await db.commit()

    async def update_session_profile(
        self,
        session_id: str,
        attacker_type: str,
        type_confidence: float,
        current_phase: str,
    ):
        """Update the live profiling columns on the session row."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE sessions
                SET attacker_type = ?, type_confidence = ?, current_phase = ?
                WHERE session_id = ?
                """,
                (attacker_type, type_confidence, current_phase, session_id),
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

    async def get_all_sessions(self) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM sessions ORDER BY start_time DESC") as cur:
                rows = await cur.fetchall()
                sessions = [dict(r) for r in rows]

            for s in sessions:
                async with db.execute(
                    "SELECT COUNT(*) FROM commands WHERE session_id = ?", (s["session_id"],)
                ) as cur:
                    c_row = await cur.fetchone()
                    s["command_count"] = c_row[0] if c_row else 0

                async with db.execute(
                    "SELECT command FROM commands WHERE session_id = ? ORDER BY id DESC LIMIT 1",
                    (s["session_id"],),
                ) as cur:
                    last_cmd_row = await cur.fetchone()
                    s["last_command"] = last_cmd_row[0] if last_cmd_row else ""

            return sessions
