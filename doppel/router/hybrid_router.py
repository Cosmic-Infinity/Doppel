import re
import logging
from enum import Enum
from typing import Tuple, Set, Optional

logger = logging.getLogger("doppel.router")


class RouteDecision(Enum):
    BUILTIN = "builtin"
    SANDBOX = "sandbox"
    LLM_DECEPTION = "llm_deception"


# Sensitive file patterns that should trigger deception/honeytokens rather than real file reads
SENSITIVE_TARGETS: Set[str] = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/os-release",
    "/etc/issue",
    "/etc/lsb-release",
    "/proc/version",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/1/cgroup",
    "/.dockerenv",
    ".env",
    "wp-config.php",
    "config.json",
    "config.yaml",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    ".aws/credentials",
    ".aws/config",
    ".bash_history",
    "credentials",
    "password",
    "secret",
    "token",
    "database.yml",
    "settings.py",
}

# Advanced attacker tools to simulate with LLM if missing from standard minimal container
DECEPTION_TOOLS: Set[str] = {
    "nmap",
    "linpeas",
    "linpeas.sh",
    "sqlmap",
    "hydra",
    "john",
    "nikto",
    "gobuster",
    "dirb",
    "metasploit",
    "msfconsole",
}

# System fingerprinting, kernel inspection, network config, and admin commands
# that could betray container isolation or host kernel details
SYSTEM_DISCOVERY_COMMANDS: Set[str] = {
    "uname",
    "ps",
    "top",
    "htop",
    "ip",
    "ifconfig",
    "route",
    "netstat",
    "ss",
    "uptime",
    "w",
    "who",
    "last",
    "lsof",
    "dpkg",
    "apt",
    "apt-get",
    "systemctl",
    "service",
    "journalctl",
    "shutdown",
    "reboot",
    "poweroff",
    "init",
    "sudo",
    "su",
    "crontab",
    "lsb_release",
    "hostnamectl",
    "dmesg",
}


class HybridRouter:
    """Classifies commands and routes them either to the real isolated sandbox or the LLM deception engine."""

    def __init__(
        self,
        intercept_sensitive_files: bool = True,
        intercept_missing_tools: bool = True,
        sandbox_available: bool = False,
        benign_commands: Optional[Set[str]] = None,
        safe_ip_mode: bool = False,
    ):
        self.intercept_sensitive_files = intercept_sensitive_files
        self.intercept_missing_tools = intercept_missing_tools
        self.sandbox_available = sandbox_available
        # Commands always routed to the real sandbox (never deception)
        self.benign_commands: Set[str] = benign_commands or set()
        # When True, ALL commands go to sandbox — no deception at all
        self.safe_ip_mode = safe_ip_mode

    def classify_command(self, raw_cmd: str, is_safe_ip: Optional[bool] = None) -> Tuple[RouteDecision, str]:
        """Determine whether to handle internally, execute in sandbox, or intercept with LLM."""
        cmd_clean = raw_cmd.strip()
        if not cmd_clean:
            return RouteDecision.BUILTIN, "empty"

        tokens = cmd_clean.split()
        binary = tokens[0].lower()

        # 1. Shell built-ins that modify state directly
        if binary in {"cd", "exit", "logout", "clear"}:
            return RouteDecision.BUILTIN, binary

        # 2. Safe-IP mode: bypass all deception for trusted admin connections
        safe_ip_active = self.safe_ip_mode if is_safe_ip is None else is_safe_ip
        if safe_ip_active and self.sandbox_available:
            return RouteDecision.SANDBOX, "safe_ip_passthrough"

        # 3. Check for missing/specialized penetration testing tools
        if self.intercept_missing_tools and any(tool in binary for tool in DECEPTION_TOOLS):
            return RouteDecision.LLM_DECEPTION, "deception_tool"

        # 4. Check for system discovery & fingerprinting queries (routed to deception to prevent container telltales)
        if binary in SYSTEM_DISCOVERY_COMMANDS:
            return RouteDecision.LLM_DECEPTION, f"system_discovery:{binary}"

        # 5. Check if command touches sensitive files or honeytokens
        if self.intercept_sensitive_files:
            cmd_lower = cmd_clean.lower()

            # Regex search for active credential harvesting attempts (e.g. grep -i password)
            if re.search(r"grep.*(pass|cred|secret|key)", cmd_lower) or ("find" in binary and ("perm" in cmd_lower or "pass" in cmd_lower)):
                return RouteDecision.LLM_DECEPTION, "credential_harvesting"

            for pattern in SENSITIVE_TARGETS:
                if pattern in cmd_lower:
                    return RouteDecision.LLM_DECEPTION, f"sensitive_file:{pattern}"

        # 6. Check for payload downloaders (curl ... | sh, wget)
        if ("curl" in binary or "wget" in binary) and ("|" in cmd_clean or ">" in cmd_clean):
            return RouteDecision.LLM_DECEPTION, "payload_download"

        # 7. Explicitly benign commands: route to real sandbox when available
        if binary in self.benign_commands and self.sandbox_available:
            return RouteDecision.SANDBOX, "benign_command"

        # 8. If sandbox is active and available, execute real command safely
        if self.sandbox_available:
            return RouteDecision.SANDBOX, "standard_execution"

        # 9. Fallback to full LLM terminal simulation
        return RouteDecision.LLM_DECEPTION, "simulated_terminal"
