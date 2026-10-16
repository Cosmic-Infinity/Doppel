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
        self._initialized = False

    async def _ensure_initialized(self):
        if not self._initialized:
            await self.initialize()

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
                    credential_risk TEXT,
                    campaign_id TEXT
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
                    reasoning TEXT,
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

            # Schema migration: dynamically add any newly introduced columns to existing database tables
            try:
                async with db.execute("PRAGMA table_info(sessions)") as cur:
                    cols = {row[1] for row in await cur.fetchall()}

                needed_session_cols = {
                    "country_code": "TEXT",
                    "country_name": "TEXT",
                    "city": "TEXT",
                    "asn": "INTEGER",
                    "asn_org": "TEXT",
                    "is_datacenter": "INTEGER DEFAULT 0",
                    "attacker_type": "TEXT DEFAULT 'unknown'",
                    "type_confidence": "REAL DEFAULT 0.0",
                    "current_phase": "TEXT DEFAULT 'Reconnaissance'",
                    "credential_risk": "TEXT",
                    "summary": "TEXT",
                    "max_threat_score": "INTEGER DEFAULT 0",
                }
                for col_name, col_type in needed_session_cols.items():
                    if col_name not in cols:
                        await db.execute(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_type}")

                async with db.execute("PRAGMA table_info(commands)") as cur:
                    cmd_cols = {row[1] for row in await cur.fetchall()}

                needed_cmd_cols = {
                    "route_decision": "TEXT",
                    "technique_id": "TEXT",
                    "technique_name": "TEXT",
                    "tactics": "TEXT",
                    "threat_score": "INTEGER DEFAULT 0",
                    "reasoning": "TEXT",
                }
                for col_name, col_type in needed_cmd_cols.items():
                    if col_name not in cmd_cols:
                        await db.execute(f"ALTER TABLE commands ADD COLUMN {col_name} {col_type}")

                # Clean up any orphaned sessions from previous runs
                await db.execute("UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE end_time IS NULL")
            except Exception as mig_err:
                logger.warning(f"Database schema migration notice: {mig_err}")

            await db.commit()

            # Idempotent migration: add campaign_id if upgrading from older schema
            try:
                await db.execute("ALTER TABLE sessions ADD COLUMN campaign_id TEXT")
                await db.commit()
                logger.info("Migrated sessions table: added campaign_id column")
            except Exception:
                pass  # Column already exists

            self._initialized = True
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
        await self._ensure_initialized()
        now = datetime.now(timezone.utc).isoformat()
        geo = geoip or {}
        try:
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
        except Exception as e:
            logger.error(f"Failed to log session start for {session_id}: {e}", exc_info=True)

    async def log_command(
        self,
        session_id: str,
        cwd: str,
        command: str,
        output: str,
        route_decision: str,
        threat_meta: Optional[Dict[str, Any]] = None,
        reasoning: Optional[str] = None,
    ) -> int:
        await self._ensure_initialized()
        now = datetime.now(timezone.utc).isoformat()
        meta = threat_meta or {}
        tactics_str = json.dumps(meta.get("tactics", []))
        score = meta.get("threat_score", 0)

        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                """
                INSERT INTO commands
                (session_id, timestamp, cwd, command, output, route_decision,
                 technique_id, technique_name, tactics, threat_score, reasoning)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    reasoning,
                ),
            )
            cmd_id = cur.lastrowid
            # Update max threat score in session if higher
            if score > 0:
                await db.execute(
                    """
                    UPDATE sessions
                    SET max_threat_score = MAX(max_threat_score, ?)
                    WHERE session_id = ?
                    """,
                    (score, session_id),
                )
            await db.commit()
            return cmd_id

    async def update_command_threat(
        self,
        command_id: int,
        threat_meta: Dict[str, Any],
    ):
        """Update an already-logged command with MITRE ATT&CK intelligence."""
        await self._ensure_initialized()
        meta = threat_meta or {}
        tactics_str = json.dumps(meta.get("tactics", []))
        score = meta.get("threat_score", 0)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE commands
                SET technique_id = ?, technique_name = ?, tactics = ?, threat_score = ?
                WHERE id = ?
                """,
                (
                    meta.get("technique_id"),
                    meta.get("technique_name"),
                    tactics_str,
                    score,
                    command_id,
                ),
            )
            if score > 0:
                async with db.execute("SELECT session_id FROM commands WHERE id = ?", (command_id,)) as cur:
                    row = await cur.fetchone()
                    if row and row[0]:
                        await db.execute(
                            """
                            UPDATE sessions
                            SET max_threat_score = MAX(max_threat_score, ?)
                            WHERE session_id = ?
                            """,
                            (score, row[0]),
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
        await self._ensure_initialized()
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

    # ── Session Replay ────────────────────────────────────────────────────────

    async def get_session_replay(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return session metadata plus commands with inter-command delay_ms fields."""
        await self._ensure_initialized()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ) as cur:
                sess_row = await cur.fetchone()
            if not sess_row:
                return None
            session = dict(sess_row)

            async with db.execute(
                "SELECT * FROM commands WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]

        # Compute inter-command timing from stored timestamps
        events = []
        prev_ts: Optional[datetime] = None
        for cmd in rows:
            ts_str = cmd.get("timestamp") or ""
            try:
                ts = datetime.fromisoformat(ts_str)
            except (ValueError, TypeError):
                ts = None
            delay_ms = 0
            if ts and prev_ts:
                delta = (ts - prev_ts).total_seconds()
                delay_ms = max(0, int(delta * 1000))
            events.append({**cmd, "delay_ms": delay_ms})
            if ts:
                prev_ts = ts

        session["events"] = events
        session["total_duration_ms"] = (
            sum(e["delay_ms"] for e in events[1:]) if len(events) > 1 else 0
        )
        return session

    # ── Campaign Correlation ──────────────────────────────────────────────────

    async def correlate_campaigns(self) -> int:
        """
        Group sessions into campaign_id buckets by shared attacker signals:
          1. Same remote_ip
          2. Same username+password credential pair
          3. Same command playbook fingerprint (top-3 commands sorted)

        Returns the number of distinct campaigns written.
        """
        await self._ensure_initialized()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT session_id, remote_ip, username, password FROM sessions") as cur:
                sessions = [dict(r) for r in await cur.fetchall()]

            # Build command fingerprint per session (sorted top-3 commands)
            fingerprints: Dict[str, str] = {}
            for s in sessions:
                async with db.execute(
                    "SELECT command FROM commands WHERE session_id = ? ORDER BY id ASC LIMIT 10",
                    (s["session_id"],),
                ) as cur:
                    cmds = [r[0].strip().split()[0] for r in await cur.fetchall() if r[0] and r[0].strip()]
                top3 = "|".join(sorted(set(cmds))[:3])
                fingerprints[s["session_id"]] = top3

            # Union-Find for grouping
            parent: Dict[str, str] = {s["session_id"]: s["session_id"] for s in sessions}

            def find(x: str) -> str:
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            def union(a: str, b: str):
                ra, rb = find(a), find(b)
                if ra != rb:
                    parent[rb] = ra

            # Group by shared IP
            ip_map: Dict[str, str] = {}
            for s in sessions:
                ip = s.get("remote_ip") or ""
                if ip:
                    if ip in ip_map:
                        union(s["session_id"], ip_map[ip])
                    else:
                        ip_map[ip] = s["session_id"]

            # Group by shared credential pair (non-empty)
            cred_map: Dict[str, str] = {}
            for s in sessions:
                u, p = (s.get("username") or ""), (s.get("password") or "")
                if u and p:
                    key = f"{u}:{p}"
                    if key in cred_map:
                        union(s["session_id"], cred_map[key])
                    else:
                        cred_map[key] = s["session_id"]

            # Group by command fingerprint (non-empty, min 2 commands)
            fp_map: Dict[str, str] = {}
            for s in sessions:
                fp = fingerprints.get(s["session_id"], "")
                if fp and "|" in fp:  # at least 2 distinct commands
                    if fp in fp_map:
                        union(s["session_id"], fp_map[fp])
                    else:
                        fp_map[fp] = s["session_id"]

            # Assign stable campaign IDs (root → deterministic hex prefix)
            import hashlib
            root_to_campaign: Dict[str, str] = {}
            for s in sessions:
                root = find(s["session_id"])
                if root not in root_to_campaign:
                    cid = "cmp-" + hashlib.md5(root.encode()).hexdigest()[:8]
                    root_to_campaign[root] = cid
                campaign_id = root_to_campaign[root]
                await db.execute(
                    "UPDATE sessions SET campaign_id = ? WHERE session_id = ?",
                    (campaign_id, s["session_id"]),
                )

            await db.commit()
            return len(root_to_campaign)

    async def get_campaigns(self) -> List[Dict[str, Any]]:
        """Return grouped campaign summary list."""
        await self._ensure_initialized()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT campaign_id,
                       COUNT(*) AS session_count,
                       COUNT(DISTINCT remote_ip) AS unique_ips,
                       MAX(max_threat_score) AS peak_threat,
                       MIN(start_time) AS first_seen,
                       MAX(COALESCE(end_time, start_time)) AS last_seen,
                       GROUP_CONCAT(DISTINCT username) AS usernames,
                       GROUP_CONCAT(DISTINCT remote_ip) AS ips
                FROM sessions
                WHERE campaign_id IS NOT NULL
                GROUP BY campaign_id
                ORDER BY last_seen DESC
                """
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]
        return rows

    async def get_all_sessions(self) -> List[Dict[str, Any]]:
        await self._ensure_initialized()
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

    async def delete_session(self, session_id: str) -> bool:
        """Purge a session and all its associated commands and phase transitions from the database."""
        await self._ensure_initialized()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM commands WHERE session_id = ?", (session_id,))
            await db.execute("DELETE FROM phase_transitions WHERE session_id = ?", (session_id,))
            cur = await db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            await db.commit()
            return cur.rowcount > 0

