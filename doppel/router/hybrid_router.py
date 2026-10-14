import re
import logging
from enum import Enum
from typing import Tuple, Set, Optional

logger = logging.getLogger("doppel.router")


class RouteDecision(Enum):
    BUILTIN = "builtin"
    SANDBOX = "sandbox"
    GROUNDED_DECEPTION = "grounded_deception"
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
}

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
        safe_ip_mode: bool = False,
    ):
        self.intercept_sensitive_files = intercept_sensitive_files
        self.intercept_missing_tools = intercept_missing_tools
        self.sandbox_available = sandbox_available
        # Commands always routed directly to the real sandbox (never deception)
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

        # 3. Check for DoS / fork bomb payloads (Tier 3 Containment)
        for pattern in DOS_CONTAINMENT_PATTERNS:
            if pattern.search(cmd_clean):
                return RouteDecision.LLM_DECEPTION, "dos_containment"

        # 4. Check for payload downloaders (curl ... | sh, wget) (Tier 3 Containment)
        if ("curl" in binary or "wget" in binary) and ("|" in cmd_clean or ">" in cmd_clean):
            return RouteDecision.LLM_DECEPTION, "payload_download"

        # 5. Check for missing/specialized penetration testing tools (Tier 3 Simulation)
        if self.intercept_missing_tools and any(tool in binary for tool in DECEPTION_TOOLS):
            return RouteDecision.LLM_DECEPTION, "deception_tool"

        # 6. Check if command touches sensitive files or honeytokens (Tier 2 Grounded if container available)
        if self.intercept_sensitive_files:
            cmd_lower = cmd_clean.lower()

            # Regex search for active credential harvesting attempts (e.g. grep -i password)
            if re.search(r"grep.*(pass|cred|secret|key)", cmd_lower) or ("find" in binary and ("perm" in cmd_lower or "pass" in cmd_lower)):
                if self.sandbox_available:
                    return RouteDecision.GROUNDED_DECEPTION, "credential_harvesting_grounded"
                return RouteDecision.LLM_DECEPTION, "credential_harvesting"

            for pattern in SENSITIVE_TARGETS:
                if pattern in cmd_lower:
                    if self.sandbox_available:
                        return RouteDecision.GROUNDED_DECEPTION, f"sensitive_file_grounded:{pattern}"
                    return RouteDecision.LLM_DECEPTION, f"sensitive_file:{pattern}"

        # 7. Check for system discovery & process/network inspection (Tier 2 Grounded if container available)
        if binary in GROUNDED_COMMANDS:
            if self.sandbox_available:
                return RouteDecision.GROUNDED_DECEPTION, f"grounded_discovery:{binary}"
            return RouteDecision.LLM_DECEPTION, f"system_discovery:{binary}"

        # 8. Explicitly benign commands: route to real sandbox when available
        if binary in self.benign_commands and self.sandbox_available:
            return RouteDecision.SANDBOX, "benign_command"

        # 9. Standard commands: Tier 1 Direct Sandbox Execution
        if self.sandbox_available:
            return RouteDecision.SANDBOX, "standard_execution"

        # 10. Fallback to full LLM terminal simulation when Docker is disabled or offline
        return RouteDecision.LLM_DECEPTION, "simulated_terminal"
