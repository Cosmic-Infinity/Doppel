import re
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, List, Dict, Any, Optional, Tuple, Union
from doppel.ai.llm_client import LLMClient
from doppel.ai.prompts.deception_prompts import build_clock_context, build_deception_system_prompt
from doppel.core import clock
from doppel.router.hybrid_router import COMMON_BINARIES
if TYPE_CHECKING:
    from doppel.core.fake_filesystem import FakeFilesystem
from doppel.ai.prompt_shield import detect_prompt_injection, get_posix_syntax_error

logger = logging.getLogger("doppel.ai.deception")

# Host identity used by the deterministic fast path. Overridden per preset.
DEFAULT_HOST_PROFILE: Dict[str, str] = {
    "hostname": "prod-api-node-01",
    "kernel_release": "5.15.0-105-generic",
    "kernel_version": "#115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024",
    "uname_processor": "x86_64",
    "user_groups": "4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)",
}

# Anything a shell would interpret (chaining, pipes, redirects, expansion,
# quoting, globbing). Such commands are never answered by the fast path.
_SHELL_META_RE = re.compile(r"[;&|<>`$(){}\\*?\[\]~!#'\"\n]")

_UNAME_FIELDS = "snrvmpio"
_UNAME_LONG = {
    "--all": "a", "--kernel-name": "s", "--nodename": "n", "--kernel-release": "r",
    "--kernel-version": "v", "--machine": "m", "--processor": "p",
    "--hardware-platform": "i", "--operating-system": "o",
}

# Section markers of the grounded transformation prompt, if echoed by the model
_GROUNDED_SCAFFOLD_RE = re.compile(
    r"^[ \t]*-{2,}[ \t]*(?:REAL STDOUT|REAL STDERR|EXIT CODE:?[ \t]*-?\d*)[ \t]*-{2,}[ \t]*\r?\n?",
    re.I | re.M,
)
# Signs of a container runtime in command output
_CONTAINER_HINT_RE = re.compile(r"overlay|containerd|docker|kubepods|lowerdir=|/var/lib/desktop-|microsoft-standard|WSL2", re.I)
# The sandbox host's own kernel (Docker Desktop on Windows runs containers on a WSL2 kernel)
_HOST_KERNEL_RE = re.compile(r"\b\d+\.\d+\.\d+(?:\.\d+)*-microsoft-standard-WSL2\+?", re.I)
_PROC_VERSION_LINE_RE = re.compile(r"^Linux version (\S+) .*$", re.M)
# The sandbox lacks what the persona has (no such binary, no systemd as PID 1):
# there is no real output to ground on, so the reply is generated instead
_UNGROUNDABLE_RE = re.compile(
    r"command not found|System has not been booted with systemd|Failed to connect to bus|Running in chroot",
    re.I,
)
# Storage paths that exist only on a container host
_CONTAINER_PATH_RE = re.compile(r"lowerdir=|upperdir=|/var/lib/(?:docker|containerd|desktop-containerd)|io\.containerd\.|kubepods", re.I)


def _trim_blank_edges(text: str) -> str:
    """Drop leading blank lines and trailing whitespace, keeping first-line indentation."""
    return re.sub(r"\A(?:[ \t]*\r?\n)+", "", text).rstrip()


_CONVERSATIONAL_NON_BINARIES = {
    "what", "why", "how", "when", "where", "tell", "say", "describe",
    "explain", "repeat", "hello", "hi", "hey", "are", "is", "can",
    "could", "would", "please", "ignore", "system", "assistant", "ai",
    "whoami?", "help?", "what?", "who?", "why?",
}


class DeceptionEngine:
    """Orchestrates LLM-based terminal emulation, persona camouflage, and dynamic bait injection."""

    def __init__(
        self,
        llm_client: LLMClient,
        persona: str = "ubuntu_web_server",
        host_profile: Optional[Dict[str, Any]] = None,
        dynamic_honeytokens: bool = True,
        no_think: bool = False,
    ):
        self.llm_client = llm_client
        self.persona = persona
        clock.set_persona(persona)
        self.system_prompt = build_deception_system_prompt(persona)
        self.host_profile: Dict[str, str] = dict(DEFAULT_HOST_PROFILE)
        self.dynamic_honeytokens = dynamic_honeytokens
        self.no_think = no_think
        if host_profile:
            self.set_host_profile(host_profile)

    @property
    def no_think(self) -> bool:
        """Skip the model's reasoning step for terminal output, which the attacker waits on."""
        return self.llm_client.reasoning_off

    @no_think.setter
    def no_think(self, value: bool):
        self.llm_client.reasoning_off = bool(value)

    def set_persona(self, persona: str):
        """Switch persona; the system prompt is derived from it, so rebuild it too."""
        if persona and persona != self.persona:
            self.persona = persona
            clock.set_persona(persona)
            self.system_prompt = build_deception_system_prompt(persona)

    def set_host_profile(self, profile: Dict[str, Any]):
        """Apply hostname/kernel/group details from a distribution preset."""
        for key in DEFAULT_HOST_PROFILE:
            value = profile.get(key)
            if value:
                self.host_profile[key] = str(value)

    @staticmethod
    def extract_reasoning(raw_output: str) -> Tuple[str, Optional[str]]:
        """Extract <think> or <thought> reasoning blocks from model output.
        Returns:
            Tuple[cleaned_text_without_thoughts, reasoning_content_or_None]
        """
        text = raw_output or ""
        think_blocks: List[str] = []

        # 1. Closed tags: <think>...</think> or <thought>...</thought>
        closed_pattern = re.compile(r"<(think|thought)>([\s\S]*?)<\/\1>", flags=re.IGNORECASE)
        for match in closed_pattern.finditer(text):
            content = match.group(2).strip()
            if content:
                think_blocks.append(content)
        stripped = _trim_blank_edges(closed_pattern.sub("", text))

        # 2. Unclosed tag if model was truncated mid-thought: <think>...
        unclosed_pattern = re.compile(r"<(think|thought)>([\s\S]*)$", flags=re.IGNORECASE)
        unclosed_match = unclosed_pattern.search(stripped)
        if unclosed_match:
            content = unclosed_match.group(2).strip()
            if content:
                think_blocks.append(content)
            stripped = _trim_blank_edges(unclosed_pattern.sub("", stripped))

        reasoning = "\n\n".join(think_blocks) if think_blocks else None
        return stripped, reasoning

    @staticmethod
    def failure_output(command: str) -> str:
        """
        What to show when no believable output could be produced (LLM error,
        timeout, or a suppressed leak). Common POSIX tools fail silently rather
        than printing 'command not found', which would expose that the system
        is an incomplete simulation.
        """
        tokens = command.strip().split()
        if not tokens:
            return ""
        binary = tokens[0].rsplit("/", 1)[-1].lower()
        if binary in COMMON_BINARIES:
            return ""
        return f"bash: {tokens[0]}: command not found"

    def _clean_output(self, raw_output: str, command: str = "", user: str = "ubuntu") -> str:
        """Strip markdown fences, thinking tags, hallucinated prompts, conversational preambles, and repeating loops."""
        # Strip thinking tags if present
        text, _ = self.extract_reasoning(raw_output)
        # Keep the first line's indentation (history, wc and ps output start with spaces)
        text = _trim_blank_edges(text)

        # Remove ```bash ... ``` or ``` ... ```
        if text.lstrip().startswith("```"):
            lines = text.lstrip().splitlines()
            if len(lines) >= 2 and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).rstrip()

        # Strip any quotes if the entire string is enclosed in them
        if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
            text = text[1:-1].strip()

        lines = text.splitlines()
        cleaned_lines: List[str] = []
        prompt_pattern = re.compile(r"^[\w\.\-]+(?:@[\w\.\-]+)?:.*?[$#]")

        # 1. Drop leading line if it just echoes the prompt and current command
        start_idx = 0
        if lines and command:
            first_line = lines[0].strip()
            if prompt_pattern.match(first_line) and command.strip() in first_line:
                start_idx = 1

        # 2. Iterate through lines, truncating if a subsequent prompt is hallucinated
        for i in range(start_idx, len(lines)):
            line = lines[i]
            # If the model starts hallucinating a new command prompt (e.g. ubuntu@hostname:~$ or ubuntu:/home/ubuntu$), truncate
            if prompt_pattern.match(line.strip()):
                break
            cleaned_lines.append(line)

        # 3. Collapse runaway consecutive identical lines (e.g. repeating "Sorry, try again.")
        collapsed_lines: List[str] = []
        consecutive_count = 0
        last_line: Optional[str] = None

        for line in cleaned_lines:
            stripped = line.strip()
            if stripped and stripped == last_line:
                consecutive_count += 1
                if consecutive_count <= 2:
                    collapsed_lines.append(line)
            else:
                consecutive_count = 1
                last_line = stripped if stripped else None
                collapsed_lines.append(line)

        result = "\n".join(collapsed_lines)
        return self._sanitize_conversational_leak(result, command=command, user=user)

    # ── Deterministic fast path ───────────────────────────────────────────────

    def _account(self, name: str) -> Tuple[int, int, List[Tuple[int, str]]]:
        """uid, gid and (gid, name) group list for a login account."""
        if name == "root":
            return 0, 0, [(0, "root")]
        groups = [(1000, name)]
        for gid, gname in re.findall(r"(\d+)\(([^)]+)\)", self.host_profile.get("user_groups", "")):
            groups.append((int(gid), gname))
        return 1000, 1000, groups

    def _id_response(self, args: List[str], user: str) -> Optional[str]:
        flags = set()
        target = None
        for arg in args:
            if arg.startswith("--"):
                return None
            if arg.startswith("-") and len(arg) > 1:
                for ch in arg[1:]:
                    if ch not in "ugGnrz":
                        return f"id: invalid option -- '{ch}'\nTry 'id --help' for more information."
                    flags.add(ch)
            elif target is None:
                target = arg
            else:
                return f"id: extra operand '{arg}'\nTry 'id --help' for more information."

        name = target or user
        if name not in (user, "root"):
            return None  # other accounts are persona knowledge; let the model answer
        uid, gid, groups = self._account(name)

        choices = flags & {"u", "g", "G"}
        if len(choices) > 1:
            return 'id: cannot print "only" of more than one choice'
        if not choices:
            if flags & {"n", "r"}:
                return "id: cannot print only names or real IDs in default format"
            group_str = ",".join(f"{g}({n})" for g, n in groups)
            return f"uid={uid}({name}) gid={gid}({name}) groups={group_str}"
        names = "n" in flags
        if "u" in choices:
            return name if names else str(uid)
        if "g" in choices:
            return name if names else str(gid)
        return " ".join(n if names else str(g) for g, n in groups)

    def _uname_response(self, args: List[str]) -> Optional[str]:
        wanted = set()
        for arg in args:
            if arg.startswith("--"):
                if arg not in _UNAME_LONG:
                    return f"uname: unrecognized option '{arg}'\nTry 'uname --help' for more information."
                wanted.add(_UNAME_LONG[arg])
            elif arg.startswith("-") and len(arg) > 1:
                for ch in arg[1:]:
                    if ch != "a" and ch not in _UNAME_FIELDS:
                        return f"uname: invalid option -- '{ch}'\nTry 'uname --help' for more information."
                    wanted.add(ch)
            else:
                return f"uname: extra operand '{arg}'\nTry 'uname --help' for more information."

        hp = self.host_profile
        processor = hp.get("uname_processor") or "x86_64"
        values = {
            "s": "Linux",
            "n": hp["hostname"],
            "r": hp["kernel_release"],
            "v": hp["kernel_version"],
            "m": "x86_64",
            "p": processor,
            "i": processor,
            "o": "GNU/Linux",
        }
        if "a" in wanted:
            fields = [f for f in _UNAME_FIELDS if not (f in "pi" and values[f] == "unknown")]
        else:
            fields = [f for f in _UNAME_FIELDS if f in wanted] or ["s"]
        return " ".join(values[f] for f in fields)

    def _proc_version_line(self) -> str:
        """/proc/version for the persona kernel, with the distribution's usual build host and toolchain."""
        hp = self.host_profile
        release = hp["kernel_release"]
        build = hp.get("kernel_build")
        if not build:
            if release.endswith("-generic"):
                build = "(buildd@lcy02-amd64-079) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38)"
            elif "amzn" in release:
                build = "(mockbuild@ip-10-0-48-202) (gcc11 (GCC) 11.4.1 20230605 (Red Hat 11.4.1-2), GNU ld version 2.39-6.amzn2023.0.10)"
            else:
                build = "(debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40)"
        return f"Linux version {release} {build} {hp['kernel_version']}"

    def deterministic_posix_response(self, command: str, user: str = "ubuntu", login_time: Optional[str] = None) -> Optional[str]:
        """
        Answer simple identity commands locally, without the model.

        Only plain invocations are handled; anything a shell would interpret
        (chaining, pipes, redirection, expansion, quoting) returns None so the
        whole command line goes to the sandbox or the model instead.
        `login_time` (ISO 8601) is when the session started, shown by who.
        """
        cmd_clean = command.strip()
        if not cmd_clean:
            return ""

        tokens = cmd_clean.split()
        binary = tokens[0].lower()

        # Conversational input is a "command not found" regardless of punctuation
        if binary in _CONVERSATIONAL_NON_BINARIES:
            return f"bash: {tokens[0]}: command not found"

        if _SHELL_META_RE.search(cmd_clean):
            return None

        args = tokens[1:]
        hostname = self.host_profile["hostname"]

        if binary == "who":
            login = clock.parse_iso(login_time) or (clock.now() - timedelta(minutes=4))
            boot = clock.boot_time(self.persona)
            session_line = f"{user}   pts/0        {login:%Y-%m-%d %H:%M} (10.0.4.1)"
            # who am i / who am I / who mom likes
            if len(args) == 2 and (
                (args[0].lower() == "am" and args[1].lower() == "i")
                or (args[0].lower() == "mom" and args[1].lower() == "likes")
            ):
                return session_line
            if not args:
                return session_line
            if len(args) == 1 and args[0] in ("-a", "-b", "-d", "-h", "-H", "-l", "-m", "-p", "-q", "-r", "-s", "-t", "-T", "-u"):
                if args[0] == "-q":
                    return f"{user}\n# users=1"
                if args[0] == "-b":
                    return f"         system boot  {boot:%Y-%m-%d %H:%M}"
                if args[0] == "-r":
                    return f"         run-level 5  {boot:%Y-%m-%d %H:%M}"
                return session_line
            return f"who: extra operand '{args[0]}'\nTry 'who --help' for more information."

        if binary == "whoami":
            if not args:
                return user
            if args[0].startswith("-"):
                return None
            return f"whoami: extra operand '{args[0]}'\nTry 'whoami --help' for more information."

        if binary == "id":
            return self._id_response(args, user)

        if binary == "hostname":
            if not args:
                return hostname
            if args == ["-s"] or args == ["--short"]:
                return hostname.split(".")[0]
            return None

        if binary == "uname":
            return self._uname_response(args)

        if binary == "cat" and args == ["/proc/version"]:
            return self._proc_version_line()

        if binary in ("true", ":"):
            return ""

        if binary in ("false", "test") and not args:
            return ""

        return None

    def _sanitize_conversational_leak(self, text: str, command: str = "", user: str = "ubuntu") -> str:
        """Detect and eliminate conversational AI speech or persona prompt leakage.

        Replaces conversational paragraphs with authentic POSIX bash syntax errors.
        """
        trimmed = text.strip()
        lower = trimmed.lower()

        # If user explicitly executed echo or printf, preserve it if output is just the echoed argument
        tokens = command.strip().split()
        if tokens and tokens[0].lower() in ("echo", "printf"):
            arg_str = " ".join(tokens[1:]).strip('\'"')
            if trimmed == arg_str or trimmed.strip('\'"') == arg_str:
                return text

        conversational_patterns = [
            r"\b(?:i\s+am|i'm|i\s+was|i\s+have\s+been|i\s+am\s+configured|i\s+cannot|i\s+can\s+not|i\s+will\s+not|i\s+don't|i\s+do\s+not)\b",
            r"\b(?:as\s+an?\s+(?:ubuntu|linux|debian|server|system|ai|language|model|assistant|virtual))\b",
            r"\b(?:my\s+(?:primary\s+user|system|hostname|purpose|creator|instructions|configuration|services\s+include|role\s+is))\b",
            r"\b(?:i\s+have\s+several\s+service\s+accounts|configured\s+to\s+handle\s+web\s+traffic|provide\s+a\s+backend\s+api)\b",
            r"\b(?:large\s+language\s+model|openai|anthropic|chatgpt|deepmind|qwen|claude|llama)\b",
            r"\b(?:certainly[!.]|sure,[ \t]|here\s+(?:is|are)\s+(?:the|some|details)|of\s+course[!.]|hello!|hi!|as\s+requested)\b",
            r"\b(?:running\s+on\s+a\s+cloud\s+provider|services\s+including\s+nginx|backend\s+api\s+for\s+a\s+laravel)\b",
            r"\b(?:in\s+accordance\s+with\s+my|as\s+per\s+my\s+instructions|my\s+system\s+prompt)\b",
            r"\b(?:an?\s+ubuntu\s+\d+\.\d+(?:\.\d+)?\s+lts\s+server)\b",
            r"\b(?:how\s+can\s+i\s+(?:help|assist)|what\s+can\s+i\s+do\s+for\s+you)\b",
            r"\b(?:feel\s+free\s+to\s+ask|let\s+me\s+know\s+if\s+you\s+need)\b",
            r"\b(?:system\s+prompt|operating\s+mode:|instruction\s+set|honeytokens)\b",
        ]

        is_conversational = any(re.search(pat, lower) for pat in conversational_patterns)
        if not is_conversational:
            return text

        logger.warning(f"Intercepted and suppressed conversational AI leak: {trimmed[:120]!r}")

        # Generate authentic POSIX error for this command
        deterministic = self.deterministic_posix_response(command, user=user)
        if deterministic is not None:
            return deterministic
        return self.failure_output(command)

    async def generate_command_output(
        self,
        command: str,
        cwd: str,
        user: str,
        session_history: Optional[List[Dict[str, str]]] = None,
        fake_fs: Optional["FakeFilesystem"] = None,
        session_id: Optional[str] = None,
        return_reasoning: bool = False,
        login_time: Optional[str] = None,
    ) -> Union[str, Tuple[str, Optional[str]]]:
        """Generate authentic simulated output for a command in the current session context."""
        # Inbound prompt defense shield
        if detect_prompt_injection(command):
            error_output = get_posix_syntax_error(command).rstrip("\n")
            if return_reasoning:
                return error_output, "Adversarial prompt injection detected and neutralized"
            return error_output
        # Fast path: Check deterministic POSIX response first (no LLM call needed)
        deterministic = self.deterministic_posix_response(command, user=user, login_time=login_time)
        if deterministic is not None:
            if return_reasoning:
                return deterministic, None
            return deterministic

        # Check if FakeFilesystem has previously cached/stored this file content for session consistency
        if fake_fs and hasattr(fake_fs, "read_file_simulated"):
            cached_sim = fake_fs.read_file_simulated(command, cwd=cwd)
            if cached_sim is not None:
                if return_reasoning:
                    return cached_sim, "Session FakeFilesystem cached read"
                return cached_sim

        # Build system prompt with the current clock, then the fake filesystem state when it exists
        system_prompt = self.system_prompt + "\n\n" + build_clock_context(self.persona, login_time)
        if fake_fs:
            fs_block = fake_fs.build_context_block()
            if fs_block:
                system_prompt = system_prompt + "\n\n" + fs_block

        # Inject dynamic canary honeytokens if accessing sensitive files or credentials
        cmd_lower = command.lower()
        sensitive_patterns = [".env", "aws", "credential", "config", "token", "secret", "key", "password", "cat", "grep", "id_rsa"]
        if self.dynamic_honeytokens and any(pat in cmd_lower for pat in sensitive_patterns):
            try:
                from doppel.deception.honeytokens import get_honeytoken_manager
                ht_mgr = get_honeytoken_manager()
                ht_block = ht_mgr.build_injection_prompt_block(session_id or "default")
                system_prompt = system_prompt + "\n\n" + ht_block
            except Exception as e:
                logger.debug(f"Failed to inject dynamic honeytokens: {e}")

        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt}
        ]

        # Add recent conversation turns for terminal state continuity (last 5 commands)
        prompt_symbol = "#" if user == "root" else "$"
        if session_history:
            for turn in session_history[-5:]:
                messages.append({"role": "user", "content": f"{user}:{turn.get('cwd', '/')}{prompt_symbol} {turn.get('command')}"})
                hist_out = turn.get("output", "")
                if len(hist_out) > 400:
                    hist_out = hist_out[:400] + "\n..."
                messages.append({"role": "assistant", "content": hist_out})

        # Add current command
        messages.append({"role": "user", "content": f"{user}:{cwd}{prompt_symbol} {command}"})

        # Stop sequences to prevent prompt hallucination
        stop_tokens = [
            f"\n{user}@",
            f"\n{user}:",
            "\nroot@",
            "\nroot:",
            "\nubuntu@",
            "\nubuntu:",
        ]

        try:
            metrics = await self.llm_client.chat_completion_with_metrics(
                messages=messages,
                temperature=0.2,
                frequency_penalty=0.4,
                stop=stop_tokens,
            )
            raw_response = metrics["content"]
            is_fallback = metrics.get("fallback", False) or getattr(self.llm_client, "mock_mode", False)
            stripped_text, reasoning = self.extract_reasoning(raw_response)
            cleaned = self._clean_output(stripped_text, command=command, user=user)

            if is_fallback:
                fallback_note = "Deterministic synthetic fallback"
                reasoning = f"{reasoning}\n[{fallback_note}]" if reasoning else fallback_note

            # If this command read a file and produced output, cache it into FakeFS for session consistency
            if fake_fs and cleaned and hasattr(fake_fs, "set_file"):
                tokens = command.strip().split()
                if tokens and tokens[0].rsplit("/", 1)[-1].lower() in ("cat", "more", "less", "head", "tail"):
                    file_args = [a for a in tokens[1:] if not a.startswith("-")]
                    if len(file_args) == 1:
                        fake_fs.set_file(file_args[0], cleaned, cwd=cwd)

            if return_reasoning:
                return cleaned, reasoning
            return cleaned
        except Exception as e:
            logger.error(f"Error generating deception output: {e}")
            fallback = self.failure_output(command)
            if fake_fs and fallback and hasattr(fake_fs, "set_file"):
                tokens = command.strip().split()
                if tokens and tokens[0].rsplit("/", 1)[-1].lower() in ("cat", "more", "less", "head", "tail"):
                    file_args = [a for a in tokens[1:] if not a.startswith("-")]
                    if len(file_args) == 1:
                        fake_fs.set_file(file_args[0], fallback, cwd=cwd)
            if return_reasoning:
                return fallback, "Fallback output generated after error"
            return fallback

    async def transform_grounded_output(
        self,
        command: str,
        real_stdout: str,
        real_stderr: str,
        exit_code: int,
        user: str = "ubuntu",
        cwd: str = "/home/ubuntu",
        session_id: Optional[str] = None,
        return_reasoning: bool = False,
        login_time: Optional[str] = None,
        session_history: Optional[List[Dict[str, str]]] = None,
        fake_fs: Optional["FakeFilesystem"] = None,
    ) -> Union[str, Tuple[str, Optional[str]]]:
        """Tier 2: Transform real Linux sandbox output with persona camouflage and canary honeytokens."""
        from doppel.ai.prompts.deception_prompts import build_grounded_transformation_prompt

        # The persona has what the sandbox lacks (e.g. systemctl): nothing real to ground on
        if not real_stdout.strip() and (exit_code == 127 or _UNGROUNDABLE_RE.search(real_stderr)):
            return await self.generate_command_output(
                command=command, cwd=cwd, user=user, session_history=session_history, fake_fs=fake_fs,
                session_id=session_id, return_reasoning=return_reasoning, login_time=login_time,
            )

        # A plain error (nothing printed to stdout, nothing container-specific in
        # stderr) is already what a real server would print: no model call needed.
        if exit_code != 0 and not real_stdout.strip() and real_stderr.strip() and not _CONTAINER_HINT_RE.search(real_stderr):
            plain = real_stderr.strip()
            return (plain, None) if return_reasoning else plain

        transformation_prompt = build_grounded_transformation_prompt(
            persona_name=self.persona,
            command=command,
            real_stdout=real_stdout,
            real_stderr=real_stderr,
            exit_code=exit_code,
        ) + "\n\n" + build_clock_context(self.persona, login_time)

        # Inject dynamic canary honeytokens if applicable
        cmd_lower = command.lower()
        sensitive_patterns = [".env", "aws", "credential", "config", "token", "secret", "key", "password", "cat", "grep", "id_rsa"]
        if self.dynamic_honeytokens and any(pat in cmd_lower for pat in sensitive_patterns):
            try:
                from doppel.deception.honeytokens import get_honeytoken_manager
                ht_mgr = get_honeytoken_manager()
                ht_block = ht_mgr.build_injection_prompt_block(session_id or "default")
                transformation_prompt = transformation_prompt + "\n\n" + ht_block
            except Exception as e:
                logger.debug(f"Failed to inject dynamic honeytokens in grounded transformation: {e}")

        messages = [
            {"role": "system", "content": transformation_prompt},
            {"role": "user", "content": f"Operator command to transform the output of: {command}"},
        ]

        try:
            metrics = await self.llm_client.chat_completion_with_metrics(
                messages=messages,
                temperature=0.1,
                frequency_penalty=0.2,
                stop=[f"\n{user}@", f"\n{user}:", "\nroot@", "\nroot:", "\nubuntu@", "\nubuntu:"],
            )
            if metrics.get("fallback") and (real_stdout or real_stderr):
                # The model failed (e.g. timed out): the real output, scrubbed of
                # container details, is truer than generic mock text
                logger.warning(f"Grounded rewrite unavailable for '{command[:60]}'; returning scrubbed real output")
                real = self.scrub_container_artifacts((real_stdout + real_stderr).strip())
                return (real, "Model unavailable: real output returned") if return_reasoning else real
            raw_response = metrics["content"]
            stripped_text, reasoning = self.extract_reasoning(raw_response)
            # Models sometimes copy the prompt's section markers into the reply
            stripped_text = _GROUNDED_SCAFFOLD_RE.sub("", stripped_text)
            cleaned = self._clean_output(stripped_text, command=command, user=user)
            # If model produced nothing or broke, fall back to real stdout/stderr
            if not cleaned.strip() and (real_stdout or real_stderr):
                cleaned = (real_stdout + real_stderr).strip()
            cleaned = self.scrub_container_artifacts(cleaned)
            if return_reasoning:
                return cleaned, reasoning
            return cleaned
        except Exception as e:
            logger.error(f"Error in grounded transformation: {e}")
            fallback = self.scrub_container_artifacts((real_stdout + real_stderr).strip()) or self.failure_output(command)
            if return_reasoning:
                return fallback, None
            return fallback

    def scrub_container_artifacts(self, text: str) -> str:
        """
        Last-line defence for grounded output: remove what only a container
        would show (overlay root filesystem, containerd and Docker storage
        paths, the host's WSL2 kernel). Applied after the model rewrite and to
        the raw fallback.
        """
        if not text or not _CONTAINER_HINT_RE.search(text):
            return text
        if _HOST_KERNEL_RE.search(text):
            text = _PROC_VERSION_LINE_RE.sub(
                lambda m: self._proc_version_line() if _HOST_KERNEL_RE.match(m.group(1)) else m.group(0), text
            )
            text = _HOST_KERNEL_RE.sub(self.host_profile["kernel_release"], text)
        k8s_persona = self.persona == "cloud_worker"  # containerd is genuine on a Kubernetes node
        root_dev = "/dev/sda1"
        kept = []
        for line in text.split("\n"):
            # The container's overlay root becomes an ordinary ext4 root, in each tool's format
            if re.match(r"^overlay on / type overlay\b", line):
                kept.append(f"{root_dev} on / type ext4 (rw,relatime,discard,errors=remount-ro)")
                continue
            m = re.match(r"^(\d+ \d+) \d+:\d+ / / (\S+).* - overlay overlay ", line)
            if m:
                kept.append(f"{m.group(1)} 8:1 / / {m.group(2)} shared:1 - ext4 {root_dev} rw,discard,errors=remount-ro")
                continue
            m = re.match(r"^overlay(\s+)", line)
            if m:  # df: keep the column alignment of the device field
                pad = m.group(1)[len(root_dev) - len("overlay"):] or " "
                line = root_dev + pad + line[m.end():]
            if _CONTAINER_PATH_RE.search(line):
                continue  # storage paths of the host's container runtime
            if not k8s_persona and re.search(r"\b(docker|containerd)\b", line, re.I):
                continue
            kept.append(line)
        return "\n".join(kept).strip("\n")
