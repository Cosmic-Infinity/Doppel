import asyncio
import logging
import asyncssh
from typing import Optional
from pathlib import Path

from doppel.config import DoppelConfig
from doppel.core.session_manager import SessionManager, SessionState

logger = logging.getLogger("doppel.ssh")


class DoppelSSHServerSession(asyncssh.SSHServerSession):
    """Handles an interactive PTY shell session for an SSH client."""

    def __init__(self, session_manager: SessionManager, config: DoppelConfig, remote_ip: str, remote_port: int, username: str, password: str):
        self.session_manager = session_manager
        self.config = config
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.username = username
        self.password = password
        self.session: Optional[SessionState] = None
        self.chan = None
        self._input_buffer = ""
        self._last_char_was_cr = False
        self._execution_lock = asyncio.Lock()

    def pty_requested(self, term_type, term_size, term_modes):
        return True

    def shell_requested(self):
        return True

    def connection_made(self, chan):
        self.chan = chan

    async def _start_shell(self):
        self.session = await self.session_manager.create_session(
            remote_ip=self.remote_ip,
            remote_port=self.remote_port,
            username=self.username,
            password=self.password,
        )
        # Send Ubuntu MOTD
        if self.config.honeypot.motd:
            self.chan.write(self.config.honeypot.motd.replace("\n", "\r\n") + "\r\n")
        self._write_prompt()

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

    def connection_lost(self, exc):
        if self.session:
            logger.info(f"SSH connection closed for session {self.session.session_id[:8]}")
            asyncio.create_task(self.session_manager.close_session(self.session.session_id))


class DoppelSSHServer(asyncssh.SSHServer):
    """Server callbacks for authentication and session initiation."""

    def __init__(self, session_manager: SessionManager, config: DoppelConfig):
        self.session_manager = session_manager
        self.config = config
        self._client_creds = {}

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        self.remote_ip = peer[0] if peer else "unknown"
        self.remote_port = peer[1] if peer else 0
        logger.info(f"Incoming SSH connection from {self.remote_ip}:{self.remote_port}")

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        logger.info(f"Auth attempt: user='{username}', pass='{password}' from {self.remote_ip}")
        self._client_creds["user"] = username
        self._client_creds["pass"] = password
        # Always accept password to bait the attacker inside
        return self.config.honeypot.accept_any_password

    def session_requested(self):
        user = self._client_creds.get("user", self.config.honeypot.default_user)
        pw = self._client_creds.get("pass", "")
        return DoppelSSHServerSession(
            session_manager=self.session_manager,
            config=self.config,
            remote_ip=self.remote_ip,
            remote_port=self.remote_port,
            username=user,
            password=pw,
        )


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
    )
    logger.info(f"Doppel SSH honeypot listening on {config.honeypot.host}:{config.honeypot.port}")
    return server
