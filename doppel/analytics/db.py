import json
import hashlib
import logging
import aiosqlite
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from doppel.core.credential_analyzer import CredentialAnalyzer

logger = logging.getLogger("doppel.analytics.db")

_credential_analyzer: Optional[CredentialAnalyzer] = None


def _get_credential_analyzer() -> CredentialAnalyzer:
    global _credential_analyzer
    if _credential_analyzer is None:
        _credential_analyzer = CredentialAnalyzer()
    return _credential_analyzer


class TelemetryDB:
    """Async SQLite database storing honeypot sessions, commands, and MITRE threat telemetry."""

    def __init__(self, db_path: str = "doppel_telemetry.db"):
        self.db_path = db_path
        self._initialized = False

    # Seconds a write waits for another connection's lock before failing.
    BUSY_TIMEOUT_S = 30.0

    def _connect(self):
        """Open a connection that waits for locks instead of failing after 5 s."""
        return aiosqlite.connect(self.db_path, timeout=self.BUSY_TIMEOUT_S)

    async def _ensure_initialized(self):
        if not self._initialized:
            await self.initialize()

    async def initialize(self):
        """Create tables and indexes if they do not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        async with self._connect() as db:
            # WAL lets readers and the writer work concurrently; the setting is
            # stored in the database file, so it only needs to be applied once.
            await db.execute("PRAGMA journal_mode=WAL")
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
                    campaign_id TEXT,
                    campaign_reasons TEXT
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
                    duration_ms INTEGER,
                    prompt_user TEXT,
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
            # Decoy credentials issued to sessions, so leaked tokens are still
            # recognised after a restart
            await db.execute("""
                CREATE TABLE IF NOT EXISTS honeytokens (
                    identifier TEXT PRIMARY KEY,
                    token_type TEXT,
                    session_id TEXT,
                    canary_url TEXT,
                    created_at TEXT
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
                    "campaign_id": "TEXT",
                    "campaign_reasons": "TEXT",
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
                    "duration_ms": "INTEGER",
                    "prompt_user": "TEXT",
                }
                for col_name, col_type in needed_cmd_cols.items():
                    if col_name not in cmd_cols:
                        await db.execute(f"ALTER TABLE commands ADD COLUMN {col_name} {col_type}")

                # Schema migration: geolocation columns for web_probes
                async with db.execute("PRAGMA table_info(web_probes)") as cur:
                    probe_cols = {row[1] for row in await cur.fetchall()}

                needed_probe_cols = {
                    "country_code": "TEXT",
                    "city": "TEXT",
                    "asn": "INTEGER",
                    "asn_org": "TEXT",
                }
                for col_name, col_type in needed_probe_cols.items():
                    if col_name not in probe_cols:
                        await db.execute(
                            f"ALTER TABLE web_probes ADD COLUMN {col_name} {col_type}"
                        )

                # Clean up any orphaned sessions from previous runs
                await db.execute(
                    "UPDATE sessions SET end_time = strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now') "
                    "WHERE end_time IS NULL"
                )
            except Exception as mig_err:
                logger.warning(f"Database schema migration notice: {mig_err}")

            await db.commit()

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
            async with self._connect() as db:
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
        timestamp: Optional[str] = None,
        duration_ms: Optional[int] = None,
        prompt_user: Optional[str] = None,
    ) -> int:
        """
        Record one command. `timestamp` is when the command was received and
        `cwd`/`prompt_user` describe the prompt it was typed at; `duration_ms`
        is how long the response took to come back.
        """
        await self._ensure_initialized()
        now = timestamp or datetime.now(timezone.utc).isoformat()
        meta = threat_meta or {}
        tactics_str = json.dumps(meta.get("tactics", []))
        score = meta.get("threat_score", 0)

        async with self._connect() as db:
            cur = await db.execute(
                """
                INSERT INTO commands
                (session_id, timestamp, cwd, command, output, route_decision,
                 technique_id, technique_name, tactics, threat_score, reasoning,
                 duration_ms, prompt_user)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    duration_ms,
                    prompt_user,
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

        async with self._connect() as db:
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
        async with self._connect() as db:
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
        async with self._connect() as db:
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
        async with self._connect() as db:
            await db.execute(
                """
                UPDATE sessions
                SET end_time = ?, summary = COALESCE(?, summary)
                WHERE session_id = ?
                """,
                (now, summary, session_id),
            )
            await db.commit()

    # ── HTTP decoy & honeytokens ───────────────────────────────────────────────

    async def ensure_http_session(
        self,
        session_id: str,
        remote_ip: str,
        remote_port: int,
        timestamp: str,
        geoip: Optional[Dict[str, Any]] = None,
    ):
        """
        Create the session row that groups an IP's web probes (one per IP per
        UTC day) if it does not exist yet, and move its last-seen time forward.

        ``geoip`` is persisted on INSERT; it is intentionally not updated on
        subsequent calls so the first-seen geolocation is preserved.
        """
        await self._ensure_initialized()
        geo = geoip or {}
        async with self._connect() as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO sessions
                (session_id, remote_ip, remote_port, username, password, start_time, end_time,
                 country_code, country_name, city, asn, asn_org, is_datacenter)
                VALUES (?, ?, ?, 'http_probe', '', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id, remote_ip, remote_port, timestamp, timestamp,
                    geo.get("country_code"), geo.get("country_name"), geo.get("city"),
                    geo.get("asn"), geo.get("asn_org"),
                    1 if geo.get("is_datacenter") else 0,
                ),
            )
            await db.execute(
                "UPDATE sessions SET end_time = ? WHERE session_id = ?",
                (timestamp, session_id),
            )
            await db.commit()

    async def log_web_probe(
        self,
        timestamp: str,
        remote_ip: str,
        remote_port: int,
        method: str,
        path: str,
        query: str,
        user_agent: str,
        probe_label: str,
        status_code: int,
        response_snippet: str,
        geoip: Optional[Dict[str, Any]] = None,
    ):
        await self._ensure_initialized()
        geo = geoip or {}
        async with self._connect() as db:
            await db.execute(
                """
                INSERT INTO web_probes
                (timestamp, remote_ip, remote_port, method, path, query, user_agent,
                 probe_label, status_code, response_snippet,
                 country_code, city, asn, asn_org)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp, remote_ip, remote_port, method,
                    path[:2048], query[:2048], user_agent[:512],
                    probe_label, status_code, response_snippet[:512],
                    geo.get("country_code"), geo.get("city"),
                    geo.get("asn"), geo.get("asn_org"),
                ),
            )
            await db.commit()

    async def save_honeytoken(self, token: Any):
        """Persist a CanaryToken (or any object with the same attributes)."""
        await self._ensure_initialized()
        try:
            async with self._connect() as db:
                await db.execute(
                    """
                    INSERT OR IGNORE INTO honeytokens
                    (identifier, token_type, session_id, canary_url, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (token.identifier, token.token_type, token.session_id, token.canary_url, token.created_at),
                )
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to persist honeytoken {token.identifier[:12]}: {e}")

    async def get_honeytoken(self, identifier: str) -> Optional[Dict[str, Any]]:
        await self._ensure_initialized()
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM honeytokens WHERE identifier = ?", (identifier,)) as cur:
                row = await cur.fetchone()
        return dict(row) if row else None

    async def get_session_details(self, session_id: str) -> Dict[str, Any]:
        await self._ensure_initialized()
        async with self._connect() as db:
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

    @staticmethod
    def _parse_ts(value: Optional[str]) -> Optional[datetime]:
        """Parse a stored timestamp into an aware UTC datetime (None if unparseable)."""
        if not value:
            return None
        try:
            ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts

    async def get_session_replay(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Return session metadata plus its commands as timed replay events.

        Each event carries:
          delay_ms     idle time before the command was typed, measured from the
                       moment the previous output appeared (or from login for
                       the first command)
          duration_ms  time the response took to appear after the command
        """
        await self._ensure_initialized()
        async with self._connect() as db:
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

        events = []
        output_shown_at = self._parse_ts(session.get("start_time"))
        for cmd in rows:
            ts = self._parse_ts(cmd.get("timestamp"))
            duration_ms = max(0, int(cmd.get("duration_ms") or 0))
            delay_ms = 0
            if ts and output_shown_at:
                delay_ms = max(0, int((ts - output_shown_at).total_seconds() * 1000))
            events.append({**cmd, "delay_ms": delay_ms, "duration_ms": duration_ms})
            if ts:
                output_shown_at = ts + timedelta(milliseconds=duration_ms)

        session["events"] = events
        session["total_duration_ms"] = sum(e["delay_ms"] + e["duration_ms"] for e in events)
        return session

    # ── Campaign Correlation ──────────────────────────────────────────────────

    LINK_SHARED_IP = "shared_ip"
    LINK_SHARED_CREDENTIALS = "shared_credentials"
    LINK_COMMAND_SEQUENCE = "command_sequence"
    _LINK_ORDER = (LINK_SHARED_IP, LINK_SHARED_CREDENTIALS, LINK_COMMAND_SEQUENCE)

    # A session's opening playbook is its first PLAYBOOK_LENGTH commands, in order.
    # It only counts as a fingerprint when it is distinctive enough: at least
    # PLAYBOOK_MIN_COMMANDS commands, or one long chained one-liner (typical of
    # dropper bots that send everything in a single line).
    PLAYBOOK_LENGTH = 5
    PLAYBOOK_MIN_COMMANDS = 3
    PLAYBOOK_MIN_CHARS = 40

    async def correlate_campaigns(self) -> int:
        """
        Group sessions into campaigns when they share any of:
          1. the same source IP
          2. the same username/password pair, unless the pair is generic
             (defaults, common-wordlist passwords, username reuse, blanks)
          3. the same opening command sequence

        Every session receives a campaign_id (singletons included). A campaign is
        named after its earliest session, so its ID does not change as later
        sessions join. The signals that linked each campaign are stored in
        campaign_reasons.

        Returns the number of distinct groups written.
        """
        await self._ensure_initialized()
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT session_id, remote_ip, username, password, start_time, "
                "(username = 'http_probe') AS is_http "
                "FROM sessions ORDER BY start_time ASC, session_id ASC"
            ) as cur:
                sessions = [dict(r) for r in await cur.fetchall()]
            if not sessions:
                return 0

            playbooks: Dict[str, List[str]] = {}
            async with db.execute("SELECT session_id, command FROM commands ORDER BY id ASC") as cur:
                async for row in cur:
                    seq = playbooks.setdefault(row[0], [])
                    command = row[1]
                    if len(seq) < self.PLAYBOOK_LENGTH and command and command.strip():
                        seq.append(" ".join(command.split()))

            order = {s["session_id"]: i for i, s in enumerate(sessions)}
            parent: Dict[str, str] = {sid: sid for sid in order}

            def find(x: str) -> str:
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            def union(a: str, b: str):
                ra, rb = find(a), find(b)
                if ra == rb:
                    return
                # The earliest session always stays the root
                if order[rb] < order[ra]:
                    ra, rb = rb, ra
                parent[rb] = ra

            links: List[Tuple[str, str]] = []

            def link_by(key_fn: Callable[[Dict[str, Any]], Optional[str]], reason: str):
                first_with_key: Dict[str, str] = {}
                for s in sessions:
                    key = key_fn(s)
                    if not key:
                        continue
                    if key in first_with_key:
                        union(s["session_id"], first_with_key[key])
                        links.append((s["session_id"], reason))
                    else:
                        first_with_key[key] = s["session_id"]

            analyzer = _get_credential_analyzer()

            # Web probe groups only link by IP: scanners share wordlists and
            # user agents, so their "credentials" and request sequences say
            # nothing about who is behind them.
            def credential_key(s: Dict[str, Any]) -> Optional[str]:
                if s.get("is_http"):
                    return None
                username, password = s.get("username") or "", s.get("password") or ""
                if not username or analyzer.is_generic(username, password):
                    return None
                return f"{username}\x00{password}"

            def playbook_key(s: Dict[str, Any]) -> Optional[str]:
                if s.get("is_http"):
                    return None
                seq = playbooks.get(s["session_id"], [])
                if len(seq) >= self.PLAYBOOK_MIN_COMMANDS or (
                    seq and sum(len(c) for c in seq) >= self.PLAYBOOK_MIN_CHARS
                ):
                    return "\x00".join(seq)
                return None

            link_by(lambda s: s.get("remote_ip") or None, self.LINK_SHARED_IP)
            link_by(credential_key, self.LINK_SHARED_CREDENTIALS)
            link_by(playbook_key, self.LINK_COMMAND_SEQUENCE)

            reasons_by_root: Dict[str, set] = {}
            for sid, reason in links:
                reasons_by_root.setdefault(find(sid), set()).add(reason)

            updates = []
            roots = set()
            for s in sessions:
                root = find(s["session_id"])
                roots.add(root)
                campaign_id = "cmp-" + hashlib.md5(root.encode()).hexdigest()[:8]
                found = reasons_by_root.get(root, set())
                reasons = ",".join(r for r in self._LINK_ORDER if r in found) or None
                updates.append((campaign_id, reasons, s["session_id"]))

            await db.executemany(
                "UPDATE sessions SET campaign_id = ?, campaign_reasons = ? WHERE session_id = ?",
                updates,
            )
            await db.commit()
            return len(roots)

    async def get_campaigns(self, min_sessions: int = 2) -> List[Dict[str, Any]]:
        """Return campaign summaries with at least `min_sessions` member sessions."""
        await self._ensure_initialized()
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT campaign_id,
                       COUNT(*) AS session_count,
                       COUNT(DISTINCT remote_ip) AS unique_ips,
                       MAX(max_threat_score) AS peak_threat,
                       MIN(start_time) AS first_seen,
                       MAX(COALESCE(end_time, start_time)) AS last_seen,
                       MAX(campaign_reasons) AS campaign_reasons,
                       GROUP_CONCAT(DISTINCT username) AS usernames,
                       GROUP_CONCAT(DISTINCT remote_ip) AS ips,
                       GROUP_CONCAT(session_id) AS session_ids
                FROM sessions
                WHERE campaign_id IS NOT NULL
                GROUP BY campaign_id
                HAVING COUNT(*) >= ?
                ORDER BY last_seen DESC
                """,
                (min_sessions,),
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]

        for row in rows:
            reasons = row.pop("campaign_reasons", None) or ""
            row["link_reasons"] = [r for r in reasons.split(",") if r]
            row["usernames"] = sorted(u for u in (row.get("usernames") or "").split(",") if u)
            row["ips"] = sorted(ip for ip in (row.get("ips") or "").split(",") if ip)
            row["session_ids"] = [sid for sid in (row.get("session_ids") or "").split(",") if sid]
        return rows

    async def get_campaign_sessions(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Return the sessions in a campaign, newest first."""
        await self._ensure_initialized()
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sessions WHERE campaign_id = ? ORDER BY start_time DESC",
                (campaign_id,),
            ) as cur:
                sessions = [dict(r) for r in await cur.fetchall()]
            await self._attach_command_stats(db, sessions)
            return sessions

    @staticmethod
    async def _attach_command_stats(db: aiosqlite.Connection, sessions: List[Dict[str, Any]]):
        """Add command_count and last_command to each session dict."""
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

    async def get_all_sessions(self) -> List[Dict[str, Any]]:
        await self._ensure_initialized()
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM sessions ORDER BY start_time DESC") as cur:
                rows = await cur.fetchall()
                sessions = [dict(r) for r in rows]
            await self._attach_command_stats(db, sessions)
            return sessions

    async def delete_session(self, session_id: str) -> bool:
        """Purge a session and all its associated commands and phase transitions from the database."""
        await self._ensure_initialized()
        async with self._connect() as db:
            await db.execute("DELETE FROM commands WHERE session_id = ?", (session_id,))
            await db.execute("DELETE FROM phase_transitions WHERE session_id = ?", (session_id,))
            await db.execute("DELETE FROM honeytokens WHERE session_id = ?", (session_id,))
            cur = await db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            await db.commit()
            return cur.rowcount > 0
