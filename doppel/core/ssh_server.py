import asyncio
import logging
import asyncssh
from typing import Optional
from pathlib import Path

from doppel.config import DoppelConfig
from doppel.core.session_manager import SessionManager, SessionState
from doppel.core.credential_analyzer import CredentialAnalyzer
from doppel.core.geoip import enrich as geoip_enrich, format_summary as geoip_summary

logger = logging.getLogger("doppel.ssh")

# One shared analyzer instance — stateless, safe to reuse across connections
_credential_analyzer = CredentialAnalyzer()


class DoppelSSHServerSession(asyncssh.SSHServerSession):
    """Handles an interactive PTY shell session for an SSH client."""

    def __init__(self, session_manager: SessionManager, config: DoppelConfig, remote_ip: str, remote_port: int, username: str, password: str, credential_analysis: dict | None = None, geoip: dict | None = None):
        self.session_manager = session_manager
        self.config = config
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.username = username
        self.password = password
        self.credential_analysis = credential_analysis or {}
        self.geoip = geoip or {}
        self.session: Optional[SessionState] = None
        self.chan = None
        self._input_buffer = ""
        self._last_char_was_cr = False
        self._execution_lock = asyncio.Lock()
        self._shell_ready = asyncio.Event()
        self._shell_started = False
        self._is_exec = False
        self._closed = False

    def pty_requested(self, term_type, term_size, term_modes):
        return True

    def shell_requested(self):
        return True

    def exec_requested(self, command: str) -> bool:
        self._is_exec = True
        asyncio.create_task(self._start_shell_and_exec(command))
        return True

    async def _start_shell_and_exec(self, command: str):
        await self._start_shell()
        await self._handle_exec(command)

    async def _handle_exec(self, command: str):
        await self._shell_ready.wait()
        if not self.session:
            if self.chan:
                self.chan.close()
            return
        output = await self.session_manager.process_command(self.session.session_id, command)
        if output:
            formatted = output.replace("\r\n", "\n").replace("\n", "\r\n")
            self.chan.write(formatted.rstrip("\r\n") + "\r\n")
        self.chan.exit(0)
        self.chan.close()

    def connection_made(self, chan):
        self.chan = chan
        if hasattr(chan, "set_echo"):
            chan.set_echo(False)
        if hasattr(chan, "set_line_mode"):
            chan.set_line_mode(False)

    async def _start_shell(self):
        if self._shell_started:
            await self._shell_ready.wait()
            return
        self._shell_started = True
        try:
            self.session = await self.session_manager.create_session(
                remote_ip=self.remote_ip,
                remote_port=self.remote_port,
                username=self.username,
                password=self.password,
                credential_analysis=self.credential_analysis,
                geoip=self.geoip,
            )
            if self._closed:
                if self.session:
                    logger.info(f"SSH channel closed before shell ready, terminating session {self.session.session_id[:8]}")
                    asyncio.create_task(self.session_manager.close_session(self.session.session_id))
                return
            if not self._is_exec:
                # Send Ubuntu MOTD
                if self.config.honeypot.motd:
                    self.chan.write(self.config.honeypot.motd.replace("\n", "\r\n") + "\r\n")
                self._write_prompt()
        except Exception as e:
            logger.error(f"Error starting shell session: {e}", exc_info=True)
        finally:
            self._shell_ready.set()

    def _get_prompt(self) -> str:
        cwd = self.session.cwd if self.session else "/home/ubuntu"
        user = self.username
        hostname = self.config.honeypot.hostname
        symbol = "#" if user == "root" else "$"

        home_prefix = "/root" if user == "root" else f"/home/{user}"
        display_cwd = "~" if cwd == home_prefix else (cwd.replace(home_prefix, "~") if cwd.startswith(home_prefix) else cwd)
        return f"{user}@{hostname}:{display_cwd}{symbol} "

    def _write_prompt(self):
        self.chan.write(self._get_prompt())

    def session_started(self):
        if not self._is_exec:
            asyncio.create_task(self._start_shell())

    def data_received(self, data, datatype):
        """Process incoming raw terminal characters and keystrokes."""
        for char in data:
            # Ctrl+C
            if char == "\x03":
                self._input_buffer = ""
                self._last_char_was_cr = False
                self.chan.write("^C\r\n")
                self._write_prompt()
            # Ctrl+D
            elif char == "\x04":
                self._last_char_was_cr = False
                if not self._input_buffer:
                    self.chan.write("exit\r\n")
                    self.chan.close()
            # Backspace / Delete
            elif char in ("\x08", "\x7f"):
                self._last_char_was_cr = False
                if self._input_buffer:
                    self._input_buffer = self._input_buffer[:-1]
                    self.chan.write("\b \b")
            # Enter / Return (handle CR, LF, and CRLF cleanly)
            elif char in ("\r", "\n"):
                if char == "\n" and self._last_char_was_cr:
                    self._last_char_was_cr = False
                    continue
                self._last_char_was_cr = (char == "\r")

                cmd = self._input_buffer
                self._input_buffer = ""
                self.chan.write("\r\n")
                asyncio.create_task(self._execute_line(cmd))
            else:
                self._last_char_was_cr = False
                # Printable ASCII characters
                if ord(char) >= 32:
                    self._input_buffer += char
                    self.chan.write(char)

    async def _execute_line(self, command: str):
        await self._shell_ready.wait()
        async with self._execution_lock:
            cmd_clean = command.strip()
            if not cmd_clean:
                self._write_prompt()
                return

            if cmd_clean in ("exit", "logout"):
                self.chan.write("logout\r\n")
                self.chan.close()
                return

            if self.session:
                output = await self.session_manager.process_command(self.session.session_id, command)
                if output:
                    # Format newlines for terminal carriage returns and strip trailing excess newlines
                    formatted = output.replace("\r\n", "\n").replace("\n", "\r\n")
                    self.chan.write(formatted.rstrip("\r\n") + "\r\n")

            self._write_prompt()

    def close_session(self):
        if self._closed:
            return
        self._closed = True
        if self.session:
            logger.info(f"SSH connection closed for session {self.session.session_id[:8]}")
            asyncio.create_task(self.session_manager.close_session(self.session.session_id))

    def connection_lost(self, exc):
        self.close_session()

    def eof_received(self):
        if self.chan:
            self.chan.close()
        self.close_session()
        return False


class DoppelSSHServer(asyncssh.SSHServer):
    """Server callbacks for authentication and session initiation."""

    def __init__(self, session_manager: SessionManager, config: DoppelConfig):
        self.session_manager = session_manager
        self.config = config
        self._client_creds = {}
        self._geoip_cache: dict = {}  # ip → enrichment result, reused per connection
        self._sessions: set = set()

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        self.remote_ip = peer[0] if peer else "unknown"
        self.remote_port = peer[1] if peer else 0

        # GeoIP enrichment — synchronous, sub-millisecond against local mmdb
        geo_cfg = getattr(self.config, "geoip", None)
        city_db = getattr(geo_cfg, "city_db_path", "") if geo_cfg else ""
        asn_db  = getattr(geo_cfg, "asn_db_path",  "") if geo_cfg else ""
        geo = geoip_enrich(self.remote_ip, city_db_path=city_db, asn_db_path=asn_db)
        self._client_creds["geoip"] = geo

        geo_str = geoip_summary(geo)
        dc_flag = " [DATACENTER/CLOUD]" if geo.get("is_datacenter") else ""

        safe_ips = self.config.access.safe_ips
        if self.remote_ip in safe_ips:
            logger.info(
                f"[SAFE IP] Trusted connection from {self.remote_ip}:{self.remote_port} | {geo_str}"
            )
        else:
            logger.warning(
                f"[ALERT] SSH probe from {self.remote_ip}:{self.remote_port}{dc_flag} | {geo_str} — "
                "honeypot deception active."
            )

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # Run credential pattern analysis before accepting
        analysis = _credential_analyzer.analyze(username, password)
        self._client_creds["user"] = username
        self._client_creds["pass"] = password
        self._client_creds["credential_analysis"] = analysis

        logger.info(
            f"Auth attempt: user='{username}' from {self.remote_ip} | "
            f"risk={analysis['risk_level']} | label={analysis['primary_label']} | "
            f"note={analysis['notes']}"
        )

        # Emit a structured alert for high/critical risk credential patterns
        if analysis["risk_level"] in ("high", "critical"):
            logger.warning(
                f"[CRED ALERT] {analysis['risk_level'].upper()} risk credential from "
                f"{self.remote_ip} — {analysis['primary_label']}: {analysis['notes']}"
            )

        # Always accept to bait the attacker inside
        return self.config.honeypot.accept_any_password

    def session_requested(self):
        user = self._client_creds.get("user", self.config.honeypot.default_user)
        pw = self._client_creds.get("pass", "")
        cred_analysis = self._client_creds.get("credential_analysis", {})
        geoip_data    = self._client_creds.get("geoip", {})
        sess = DoppelSSHServerSession(
            session_manager=self.session_manager,
            config=self.config,
            remote_ip=self.remote_ip,
            remote_port=self.remote_port,
            username=user,
            password=pw,
            credential_analysis=cred_analysis,
            geoip=geoip_data,
        )
        self._sessions.add(sess)
        return sess

    def connection_lost(self, exc):
        for s in list(self._sessions):
            s.close_session()
        self._sessions.clear()


async def start_ssh_server(session_manager: SessionManager, config: DoppelConfig) -> asyncssh.SSHServer:
    """Initialize and start the honeypot SSH listener."""
    host_key_path = Path("host_key")
    if not host_key_path.exists():
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(str(host_key_path))
        logger.info("Generated new SSH host key at ./host_key")

    server = await asyncssh.create_server(
        lambda: DoppelSSHServer(session_manager, config),
        host=config.honeypot.host,
        port=config.honeypot.port,
        server_host_keys=[str(host_key_path)],
        server_version=config.honeypot.server_banner,
        line_editor=False,
    )
    logger.info(f"Doppel SSH honeypot listening on {config.honeypot.host}:{config.honeypot.port}")
    return server
