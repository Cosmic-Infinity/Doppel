import asyncio
import logging
import re
import time
import asyncssh
from typing import Optional, List
from pathlib import Path

from doppel.config import DoppelConfig, get_active_preset
from doppel.core.session_manager import SessionManager, SessionState
from doppel.core.credential_analyzer import CredentialAnalyzer
from doppel.core.geoip import enrich as geoip_enrich, format_summary as geoip_summary

logger = logging.getLogger("doppel.ssh")

# One shared analyzer instance — stateless, safe to reuse across connections
_credential_analyzer = CredentialAnalyzer()

_closing_tasks: set = set()

# Longest command line accepted; further input on the line is dropped. Input is
# processed in chunks, so this bounds memory, not CPU.
MAX_LINE_CHARS = 65536
# Keystroke timings kept per line for the profiler (paste/typing cadence)
MAX_KEYSTROKE_SAMPLES = 512
# Commands remembered for Up/Down recall
MAX_HISTORY = 500

# Terminal input: escape sequences, runs of printable text, single control chars
_INPUT_TOKEN_RE = re.compile(
    r"(?P<csi>\x1b\[[0-9;?]*[ -/]*[@-~])"
    r"|(?P<ss3>\x1bO[@-~])"
    r"|(?P<esc>\x1b[^\[O]?)"
    r"|(?P<text>[^\x00-\x1f\x7f\x1b]+)"
    r"|(?P<ctrl>[\x00-\x1f\x7f])",
    re.S,
)
# An escape sequence cut off at the end of a chunk; completed by the next one
_PARTIAL_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*|O)?\Z")


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
        self._pending_escape = ""
        self._last_char_was_cr = False
        self._keystroke_timestamps: List[float] = []
        self._history: List[str] = []
        self._history_pos: Optional[int] = None
        # Bumped by Ctrl+C; lines typed before it are discarded, and output of a
        # command that was running when it was pressed is suppressed
        self._epoch = 0
        self._execution_lock = asyncio.Lock()
        self._shell_ready = asyncio.Event()
        self._shell_started = False
        self._is_exec = False
        self._closed = False

    # ── Channel output ────────────────────────────────────────────────────────

    def _write(self, text: str):
        """Write to the client, ignoring a channel that has already gone away."""
        if not text or not self.chan or self._closed:
            return
        try:
            self.chan.write(text)
        except (BrokenPipeError, ConnectionError, OSError):
            pass

    def _close_channel(self):
        if not self.chan:
            return
        try:
            self.chan.close()
        except Exception:
            pass

    # ── Session setup ─────────────────────────────────────────────────────────

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
            self._close_channel()
            return
        output = await self.session_manager.process_command(self.session.session_id, command)
        if output:
            formatted = output.replace("\r\n", "\n").replace("\n", "\r\n")
            self._write(formatted.rstrip("\r\n") + "\r\n")
        try:
            if self.chan and not self._closed:
                self.chan.exit(0)
        except Exception:
            pass
        self._close_channel()

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

            preset = get_active_preset(self.config)

            if not self._is_exec:
                # Send active preset MOTD
                motd = preset.get("motd") or self.config.honeypot.motd
                if motd:
                    motd_formatted = motd.replace("\n", "\r\n") + "\r\n"
                    self._write(motd_formatted)
                self._write_prompt()
        except Exception as e:
            logger.error(f"Error starting shell session: {e}", exc_info=True)
        finally:
            self._shell_ready.set()

    def _get_prompt(self) -> str:
        preset = get_active_preset(self.config)
        default_home = preset.get("home_dir", "/home/ubuntu")
        cwd = self.session.cwd if self.session else default_home
        effective_user = (
            getattr(self.session, "effective_user", self.username)
            if self.session else self.username
        )
        is_root = (effective_user == "root") or (self.session and getattr(self.session, "is_elevated", False))
        hostname = preset.get("hostname", self.config.honeypot.hostname)

        home_prefix = "/root" if is_root else f"/home/{effective_user}"
        if cwd == home_prefix:
            display_cwd = "~"
        elif cwd.startswith(home_prefix + "/"):
            display_cwd = "~" + cwd[len(home_prefix):]
        else:
            display_cwd = cwd

        if is_root:
            fmt = preset.get("root_prompt_format", "{user}@{hostname}:{cwd}# ")
            user_label = "root"
        else:
            fmt = preset.get("prompt_format", "{user}@{hostname}:{cwd}$ ")
            user_label = effective_user

        try:
            return fmt.format(user=user_label, hostname=hostname, cwd=display_cwd)
        except Exception:
            symbol = "#" if is_root else "$"
            return f"{user_label}@{hostname}:{display_cwd}{symbol} "

    def _write_prompt(self):
        self._write(self._get_prompt())

    def _redraw_line(self):
        """Repaint the prompt and current input (history recall, Ctrl+L)."""
        self._write("\r\x1b[K" + self._get_prompt() + self._input_buffer)

    def session_started(self):
        if not self._is_exec:
            asyncio.create_task(self._start_shell())

    # ── Terminal input ────────────────────────────────────────────────────────

    def data_received(self, data, datatype):
        """Process incoming terminal input a chunk at a time."""
        if self._is_exec or self._closed:
            # Exec requests run a single command; their stdin is not a terminal
            return

        data = self._pending_escape + data
        self._pending_escape = ""
        partial = _PARTIAL_ESCAPE_RE.search(data)
        if partial:
            self._pending_escape = data[partial.start():]
            data = data[:partial.start()]

        now = time.perf_counter()
        echo: List[str] = []

        def flush_echo():
            if echo:
                self._write("".join(echo))
                echo.clear()

        for match in _INPUT_TOKEN_RE.finditer(data):
            kind = match.lastgroup
            token = match.group()

            if kind == "text":
                self._last_char_was_cr = False
                room = MAX_LINE_CHARS - len(self._input_buffer)
                if room <= 0:
                    continue
                accepted = token[:room]
                self._input_buffer += accepted
                echo.append(accepted)
                samples = MAX_KEYSTROKE_SAMPLES - len(self._keystroke_timestamps)
                if samples > 0:
                    self._keystroke_timestamps.extend([now] * min(samples, len(accepted)))
                continue

            if kind in ("csi", "ss3"):
                final = token[-1]
                if final in ("A", "B"):
                    flush_echo()
                    self._recall_history(older=(final == "A"))
                # Cursor movement, function keys, paste brackets: no effect
                continue

            if kind == "esc":
                continue

            # Single control character
            self._handle_control(token, now, flush_echo)

        flush_echo()

    def _handle_control(self, char: str, now: float, flush_echo):
        if char in ("\r", "\n"):
            if char == "\n" and self._last_char_was_cr:
                self._last_char_was_cr = False
                return
            self._last_char_was_cr = (char == "\r")
            flush_echo()
            cmd = self._input_buffer
            timestamps = list(self._keystroke_timestamps)
            self._input_buffer = ""
            self._keystroke_timestamps = []
            self._history_pos = None
            if cmd.strip():
                if not self._history or self._history[-1] != cmd:
                    self._history.append(cmd)
                    del self._history[:-MAX_HISTORY]
            self._write("\r\n")
            asyncio.create_task(self._execute_line(cmd, keystroke_timestamps=timestamps, epoch=self._epoch))
            return

        self._last_char_was_cr = False
        flush_echo()

        if char == "\x03":  # Ctrl+C
            self._input_buffer = ""
            self._keystroke_timestamps = []
            self._history_pos = None
            self._epoch += 1
            self._write("^C\r\n")
            self._write_prompt()
        elif char == "\x04":  # Ctrl+D
            if not self._input_buffer:
                if self.session and self.session_manager.can_drop_privileges(self.session):
                    self._write("\r\n")
                    asyncio.create_task(self._execute_line("exit", epoch=self._epoch))
                else:
                    self._write("logout\r\n")
                    self._close_channel()
        elif char in ("\x08", "\x7f"):  # Backspace
            if len(self._keystroke_timestamps) < MAX_KEYSTROKE_SAMPLES:
                self._keystroke_timestamps.append(now)
            if self._input_buffer:
                self._input_buffer = self._input_buffer[:-1]
                self._write("\b \b")
        elif char == "\x15":  # Ctrl+U: clear the line
            self._input_buffer = ""
            self._redraw_line()
        elif char == "\x0c":  # Ctrl+L: clear the screen
            self._write("\x1b[H\x1b[2J")
            self._redraw_line()
        elif char == "\t":
            # No completion available; bash rings the bell when nothing matches
            self._write("\x07")

    def _recall_history(self, older: bool):
        if not self._history:
            return
        if older:
            if self._history_pos is None:
                self._history_pos = len(self._history) - 1
            elif self._history_pos > 0:
                self._history_pos -= 1
            else:
                return
            self._input_buffer = self._history[self._history_pos]
        else:
            if self._history_pos is None:
                return
            self._history_pos += 1
            if self._history_pos >= len(self._history):
                self._history_pos = None
                self._input_buffer = ""
            else:
                self._input_buffer = self._history[self._history_pos]
        self._redraw_line()

    async def _execute_line(self, command: str, keystroke_timestamps: Optional[List[float]] = None, epoch: int = 0):
        await self._shell_ready.wait()
        async with self._execution_lock:
            # Typed ahead, then Ctrl+C: bash discards it without running it
            if epoch != self._epoch or self._closed:
                return

            cmd_clean = command.strip()
            if not cmd_clean:
                self._write_prompt()
                return

            if not self.session:
                self._write_prompt()
                return

            is_exit = cmd_clean in ("exit", "logout")
            leaving_root_shell = is_exit and self.session_manager.can_drop_privileges(self.session)

            output = await self.session_manager.process_command(
                self.session.session_id,
                command,
                keystroke_timestamps=keystroke_timestamps,
            )

            if is_exit and not leaving_root_shell:
                self._write("logout\r\n")
                self._close_channel()
                return

            # Ctrl+C while it ran: its prompt is already on screen, drop the output
            if epoch != self._epoch or self._closed:
                return

            if output:
                # Format newlines for terminal carriage returns and strip trailing excess newlines
                formatted = output.replace("\r\n", "\n").replace("\n", "\r\n")
                self._write(formatted.rstrip("\r\n") + "\r\n")

            self._write_prompt()

    # ── Teardown ──────────────────────────────────────────────────────────────

    def close_session(self):
        if self._closed:
            return
        self._closed = True
        if self.session:
            logger.info(f"SSH connection closed for session {self.session.session_id[:8]}")
            t = asyncio.create_task(self.session_manager.close_session(self.session.session_id))
            _closing_tasks.add(t)
            t.add_done_callback(_closing_tasks.discard)

    def connection_lost(self, exc):
        self.close_session()

    def eof_received(self):
        self._close_channel()
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

    # Advertise "publickey,password" like a stock Ubuntu sshd. asyncssh would
    # otherwise also offer keyboard-interactive, which Ubuntu disables.
    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        try:
            fingerprint = key.get_fingerprint()
            algorithm = key.get_algorithm()
        except Exception:
            fingerprint, algorithm = "unknown", "unknown"
        logger.info(
            f"Public key offered: user='{username}' from {self.remote_ip} | {algorithm} {fingerprint}"
        )
        return False  # never accepted; the client falls back to password

    def kbdint_auth_supported(self):
        return False

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


def _software_version(banner: str) -> str:
    """asyncssh sends "SSH-2.0-" itself; strip it from a full banner string."""
    banner = (banner or "").strip()
    return banner[len("SSH-2.0-"):] if banner.startswith("SSH-2.0-") else banner


# Host keys a stock OpenSSH server presents. The first entry keeps the original
# ./host_key path so existing deployments keep their RSA fingerprint.
_HOST_KEYS = (
    ("host_key", "ssh-rsa", {"key_size": 3072}),
    ("host_key_ecdsa", "ecdsa-sha2-nistp256", {}),
    ("host_key_ed25519", "ssh-ed25519", {}),
)


def _ensure_host_keys(directory: Path = Path(".")) -> List[str]:
    paths = []
    for name, algorithm, kwargs in _HOST_KEYS:
        path = directory / name
        if not path.exists():
            key = asyncssh.generate_private_key(algorithm, **kwargs)
            key.write_private_key(str(path))
            logger.info(f"Generated new SSH host key at ./{name}")
        paths.append(str(path))
    return paths


async def start_ssh_server(session_manager: SessionManager, config: DoppelConfig) -> asyncssh.SSHServer:
    """Initialize and start the honeypot SSH listener."""
    host_keys = _ensure_host_keys()
    preset = get_active_preset(config) or {}
    banner = preset.get("server_banner") or config.honeypot.server_banner

    server = await asyncssh.create_server(
        lambda: DoppelSSHServer(session_manager, config),
        host=config.honeypot.host,
        port=config.honeypot.port,
        server_host_keys=host_keys,
        server_version=_software_version(banner),
        line_editor=False,
    )
    logger.info(f"Doppel SSH honeypot listening on {config.honeypot.host}:{config.honeypot.port}")
    return server
