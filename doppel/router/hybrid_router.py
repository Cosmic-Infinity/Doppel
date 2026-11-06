import re
import shlex
import logging
from enum import Enum
from typing import Tuple, Set, List, Optional
from doppel.ai.prompt_shield import detect_prompt_injection

logger = logging.getLogger("doppel.router")


class RouteDecision(Enum):
    BUILTIN = "builtin"
    SANDBOX = "sandbox"
    GROUNDED_DECEPTION = "grounded_deception"
    LLM_DECEPTION = "llm_deception"


# Sensitive credential and honeytoken target files that must ALWAYS route directly to LLM_DECEPTION
CREDENTIAL_TARGETS: Set[str] = {
    "/etc/shadow",
    "/etc/passwd",
    ".env",
    "wp-config.php",
    "config.php",
    "config.json",
    "config.yaml",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    "authorized_keys",
    ".aws/credentials",
    ".aws/config",
    ".bash_history",
    "database.yml",
    "settings.py",
}

# Container files that need grounded inspection camouflage (transformed via real stdout/stderr)
CONTAINER_CAMOUFLAGE_TARGETS: Set[str] = {
    "/etc/os-release",
    "/etc/issue",
    "/etc/lsb-release",
    "/proc/version",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/1/",
    "/proc/self/",
    "/proc/mounts",
    "/proc/cgroups",
    "/sys/fs/cgroup",
    "mountinfo",
    "/.dockerenv",
}

# Retain SENSITIVE_TARGETS for backward compatibility
SENSITIVE_TARGETS: Set[str] = CREDENTIAL_TARGETS | CONTAINER_CAMOUFLAGE_TARGETS

# Advanced attacker and penetration-testing tools to simulate with LLM
DECEPTION_TOOLS: Set[str] = {
    "nmap",
    "masscan",
    "netcat",
    "nc",
    "hydra",
    "sqlmap",
    "nikto",
    "gobuster",
    "dirsearch",
    "ffuf",
    "linpeas",
    "linpeas.sh",
    "linenum",
    "linenum.sh",
    "enum4linux",
    "metasploit",
    "msfconsole",
    "tcpdump",
    "wireshark",
    "john",
    "dirb",
}

# Command wrappers that prefix executed binaries
COMMON_WRAPPERS: Set[str] = {
    "sudo", "doas", "nohup", "time", "busybox", "env", "exec", "xargs", "command"
}


def extract_effective_command(cmd_clean: str) -> Tuple[str, List[str]]:
    """
    Extract the effective executable binary and tokens, unwrapping common wrappers
    such as sudo, nohup, env, etc., and stripping directory paths.
    """
    try:
        tokens = shlex.split(cmd_clean)
    except Exception:
        tokens = cmd_clean.split()
    if not tokens:
        return "", []

    idx = 0
    while idx < len(tokens):
        token = tokens[idx].rsplit("/", 1)[-1].lower()
        if token in COMMON_WRAPPERS:
            idx += 1
            # Skip options to the wrapper (e.g. sudo -u root, sudo -i, env -i)
            while idx < len(tokens) and tokens[idx].startswith("-"):
                if tokens[idx] in ("-u", "-g", "-C", "-D", "-h", "-p", "-a"):
                    idx += 2
                else:
                    idx += 1
            # Skip environment assignments (e.g. env FOO=bar ...)
            while idx < len(tokens) and "=" in tokens[idx] and not tokens[idx].startswith("-"):
                idx += 1
            continue
        break

    if idx >= len(tokens):
        return tokens[0].rsplit("/", 1)[-1].lower(), tokens[1:]

    effective_binary = tokens[idx].rsplit("/", 1)[-1].lower()
    return effective_binary, tokens[idx:]


def is_deception_tool(cmd_clean: str) -> bool:
    """Check if the command invokes a known penetration testing or reconnaissance tool."""
    effective_binary, tokens = extract_effective_command(cmd_clean)
    if effective_binary in DECEPTION_TOOLS:
        return True
    # If wrapped in a script runner (python3 script.py, bash script.sh)
    if effective_binary in ("python", "python3", "bash", "sh", "perl", "ruby"):
        for arg in tokens[1:]:
            script_name = arg.rsplit("/", 1)[-1].lower()
            if script_name in DECEPTION_TOOLS:
                return True
            stem = script_name.rsplit(".", 1)[0]
            if stem in DECEPTION_TOOLS:
                return True
    return False

# Text filters that may run for real over generated output. They read stdin
# and write stdout only; options that write files or run commands are refused
# by is_pipeline_filter().
PIPELINE_FILTERS: Set[str] = {
    "grep", "egrep", "fgrep", "cut", "awk", "gawk", "mawk", "sed", "sort", "uniq", "wc",
    "head", "tail", "tr", "base64", "md5sum", "sha1sum", "sha256sum", "sha512sum", "xxd",
    "od", "nl", "rev", "tac", "column", "fold", "fmt", "paste", "cat", "less", "more",
    "strings", "expand", "unexpand", "comm", "jq",
}

# Redirections that do not change what a pipeline prints and are safe to keep
_HARMLESS_REDIRECTS = re.compile(r"(?<=\s)2>\s*/dev/null\b|(?<=\s)2>&1\b")


def split_pipeline(cmd: str) -> Optional[List[str]]:
    """
    Split a plain pipeline ("a | b | c") into its stages.

    Returns None for anything that is not a plain pipeline: command chaining
    (; && ||), background jobs, substitutions, here-documents and redirections
    other than discarding or merging stderr. Pipes inside quotes are ignored.
    """
    masked = _HARMLESS_REDIRECTS.sub(lambda m: " " * len(m.group(0)), cmd)
    stages, start, quote, i = [], 0, None, 0
    while i < len(masked):
        ch = masked[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "\\":
            i += 2
            continue
        elif ch == "|":
            if masked[i + 1:i + 2] == "|" or masked[i - 1:i] == "|":
                return None
            stages.append(cmd[start:i].strip())
            start = i + 1
        elif ch in ";&<>`" or masked.startswith("$(", i):
            return None
        i += 1
    if quote:
        return None
    stages.append(cmd[start:].strip())
    return stages if all(stages) else None


def is_pipeline_filter(stage: str) -> bool:
    """True when a pipeline stage only transforms text (no files written, no commands run)."""
    try:
        tokens = shlex.split(stage)
    except ValueError:
        return False
    if not tokens:
        return False
    binary = tokens[0].rsplit("/", 1)[-1].lower()
    if binary not in PIPELINE_FILTERS:
        return False
    args = tokens[1:]
    if binary == "sed" and any(a.startswith(("-i", "--in-place")) or a in ("-s",) for a in args):
        return False
    if binary == "sed" and re.search(r"(^|[;\s}])[wWe]\s|\be\b|/w\s", " ".join(args)):
        return False
    if binary == "sort" and any(a == "-o" or a.startswith(("-o", "--output")) for a in args):
        return False
    if binary in ("awk", "gawk", "mawk") and re.search(r"system\s*\(|\|\s*getline|getline\s*<|print[^;]*[>|]|printf[^;]*[>|]", " ".join(args)):
        return False
    # Stages that name files read from disk instead of stdin would leave the pipeline
    if binary in ("cat", "less", "more", "tac", "strings") and any(not a.startswith("-") for a in args):
        return False
    return True


# Utilities any server of the personas has installed. When no believable output
# can be produced for these, printing nothing is safer than "command not found".
COMMON_BINARIES: Set[str] = {
    "cat", "ls", "ll", "la", "grep", "egrep", "find", "head", "tail", "echo", "printf", "yes",
    "awk", "sed", "cut", "sort", "uniq", "wc", "tr", "tee", "less", "more", "file", "stat",
    "df", "du", "free", "ps", "top", "htop", "kill", "pkill", "chmod", "chown", "cp", "mv", "rm",
    "mkdir", "rmdir", "touch", "ln", "tar", "gzip", "gunzip", "zip", "unzip", "curl", "wget",
    "ssh", "scp", "rsync", "python", "python3", "perl", "git", "nano", "vim", "vi", "which",
    "whereis", "date", "uptime", "w", "last", "lastlog", "lscpu", "lsblk", "lsof", "mount",
    "env", "printenv", "export", "history", "crontab", "systemctl", "service", "journalctl",
    "ip", "ifconfig", "netstat", "ss", "route", "ping", "dig", "nslookup", "host", "nproc",
    "base64", "md5sum", "sha256sum", "xargs", "sleep", "diff", "basename", "dirname",
    "realpath", "id", "whoami", "who", "hostname", "uname", "sudo", "su", "apt", "apt-get",
    "dpkg", "php", "node", "npm", "mysql", "redis-cli", "openssl", "dmesg", "hostnamectl",
    "passwd", "groups", "getent", "locate", "strings", "od", "xxd", "nohup", "screen",
}

# Commands where real Linux structure is necessary, but container telltales must be camouflaged
# or honeytokens injected (Tier 2: Grounded Deception)
GROUNDED_COMMANDS: Set[str] = {
    "ps",
    "top",
    "htop",
    "ip",
    "ifconfig",
    "route",
    "netstat",
    "ss",
    "lsof",
    "systemctl",
    "service",
    "journalctl",
    "crontab",
    "hostnamectl",
    "dmesg",
    "env",
    "printenv",
    "export",
    "set",
    # The sandbox's mounts, memory and CPU are the container's, not the persona's
    "mount",
    "findmnt",
    "df",
    "lsblk",
    "free",
    "uptime",
    "nproc",
    "lscpu",
    "vmstat",
    # The sandbox shares the host kernel, so uname would reveal it
    "uname",
}

# Tools that need the network. The sandbox has none, so running them there
# would fail in ways a production server never does; they are simulated.
NETWORK_TOOLS: Set[str] = {
    "ping", "ping6", "curl", "wget", "nc", "ncat", "netcat", "telnet", "dig", "nslookup",
    "host", "traceroute", "tracepath", "mtr", "ftp", "tftp", "ssh", "scp", "sftp", "rsync",
    "apt", "apt-get", "yum", "dnf", "snap",
}
# Package/source tools that only need the network for some subcommands
NETWORK_SUBCOMMANDS = {
    "pip": {"install", "download"},
    "pip3": {"install", "download"},
    "npm": {"install", "i", "update", "publish"},
    "git": {"clone", "pull", "fetch", "push", "ls-remote"},
}

# Commands that report on logins; they must show the attacker's own session
# (source IP, login time), which only the deception layer knows
SESSION_INFO_COMMANDS: Set[str] = {"who", "w", "last", "lastlog", "users"}

# Patterns indicating denial of service or container escape attempts that must stay in Tier 3 containment
DOS_CONTAINMENT_PATTERNS = [
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),  # fork bomb
    re.compile(r"mkfs|dd\s+if=/dev/zero\s+of=/dev/"),
]


class HybridRouter:
    """Classifies commands and routes them across the 3-Tier Execution Architecture."""

    def __init__(
        self,
        intercept_sensitive_files: bool = True,
        intercept_missing_tools: bool = True,
        sandbox_available: bool = False,
        benign_commands: Optional[Set[str]] = None,
    ):
        self.intercept_sensitive_files = intercept_sensitive_files
        self.intercept_missing_tools = intercept_missing_tools
        self.sandbox_available = sandbox_available
        # Commands always routed directly to the real sandbox (never deception)
        self.benign_commands: Set[str] = benign_commands or set()

    def classify_command(self, raw_cmd: str) -> Tuple[RouteDecision, str]:
        """Determine whether to handle internally, execute in sandbox, or intercept with LLM."""
        cmd_clean = raw_cmd.strip()
        if not cmd_clean:
            return RouteDecision.BUILTIN, "empty"

        tokens = cmd_clean.split()
        binary = tokens[0].lower()
        effective_binary, effective_tokens = extract_effective_command(cmd_clean)

        # 1. Shell built-ins answered from session state
        if binary in {"cd", "exit", "logout", "clear", "pwd"}:
            return RouteDecision.BUILTIN, binary

        # Free text aimed at the deception model ("ignore previous instructions")
        # never reaches it. A real command that merely contains such words is
        # routed as usual, as a shell would run it; the engine guards the model.
        is_real_command = (
            binary.rsplit("/", 1)[-1] in COMMON_BINARIES
            or effective_binary in COMMON_BINARIES
            or effective_binary in self.benign_commands
        )
        if not is_real_command and detect_prompt_injection(cmd_clean):
            return RouteDecision.LLM_DECEPTION, "prompt_injection_defense"

        # 2. Check for DoS / fork bomb payloads (Tier 3 Containment)
        for pattern in DOS_CONTAINMENT_PATTERNS:
            if pattern.search(cmd_clean):
                return RouteDecision.LLM_DECEPTION, "dos_containment"

        # 3. Check for payload downloaders (curl ... | sh, wget) (Tier 3 Containment)
        if ("curl" in binary or "wget" in binary) and ("|" in cmd_clean or ">" in cmd_clean):
            return RouteDecision.LLM_DECEPTION, "payload_download"

        # 4. Check for missing/specialized penetration testing tools (Tier 3 Simulation)
        if self.intercept_missing_tools and is_deception_tool(cmd_clean):
            return RouteDecision.LLM_DECEPTION, "deception_tool"

        # 4b. Network clients and package downloads are simulated (sandbox has no network)
        if effective_binary in NETWORK_TOOLS or (
            len(effective_tokens) > 1 and effective_tokens[1].lower() in NETWORK_SUBCOMMANDS.get(effective_binary, ())
        ):
            return RouteDecision.LLM_DECEPTION, "network_simulated"

        # 4c. Login/session reports reflect the attacker's own connection
        if effective_binary in SESSION_INFO_COMMANDS:
            return RouteDecision.LLM_DECEPTION, "session_info"

        # 5. Check if command touches sensitive files or honeytokens
        if self.intercept_sensitive_files:
            cmd_lower = cmd_clean.lower()

            # Priority 5a: Credential and honeytoken target files ALWAYS invoke pure LLM_DECEPTION directly
            for pattern in CREDENTIAL_TARGETS:
                if pattern in cmd_lower:
                    return RouteDecision.LLM_DECEPTION, f"sensitive_file:{pattern}"

            # Priority 5b: Regex search for active credential harvesting attempts
            if re.search(r"grep.*(pass|cred|secret|key)", cmd_lower) or (
                "find" in effective_binary and ("perm" in cmd_lower or "pass" in cmd_lower)
            ):
                if self.sandbox_available:
                    return RouteDecision.GROUNDED_DECEPTION, "credential_harvesting_grounded"
                return RouteDecision.LLM_DECEPTION, "credential_harvesting"

            # Priority 5c: Container camouflage targets (e.g. /etc/os-release, /proc/version)
            for pattern in CONTAINER_CAMOUFLAGE_TARGETS:
                if pattern in cmd_lower:
                    if self.sandbox_available:
                        return RouteDecision.GROUNDED_DECEPTION, f"sensitive_file_grounded:{pattern}"
                    return RouteDecision.LLM_DECEPTION, f"sensitive_file:{pattern}"

        # 6. Check for system discovery & process/network inspection (Tier 2 Grounded if container available)
        if effective_binary in GROUNDED_COMMANDS:
            if self.sandbox_available:
                return RouteDecision.GROUNDED_DECEPTION, f"grounded_discovery:{effective_binary}"
            return RouteDecision.LLM_DECEPTION, f"system_discovery:{effective_binary}"

        # 7. Explicitly benign commands: route to real sandbox when available
        if effective_binary in self.benign_commands and self.sandbox_available:
            return RouteDecision.SANDBOX, "benign_command"

        # 8. Standard commands: Tier 1 Direct Sandbox Execution
        if self.sandbox_available:
            return RouteDecision.SANDBOX, "standard_execution"

        # 9. Fallback to full LLM terminal simulation when Docker is disabled or offline
        return RouteDecision.LLM_DECEPTION, "simulated_terminal"
