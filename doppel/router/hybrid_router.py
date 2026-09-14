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


class HybridRouter:
    """Classifies commands and routes them either to the real isolated sandbox or the LLM deception engine."""

    def __init__(
        self,
        intercept_sensitive_files: bool = True,
        intercept_missing_tools: bool = True,
        sandbox_available: bool = False,
    ):
        self.intercept_sensitive_files = intercept_sensitive_files
        self.intercept_missing_tools = intercept_missing_tools
        self.sandbox_available = sandbox_available

    def classify_command(self, raw_cmd: str) -> Tuple[RouteDecision, str]:
        """Determine whether to handle internally, execute in sandbox, or intercept with LLM."""
        cmd_clean = raw_cmd.strip()
        if not cmd_clean:
            return RouteDecision.BUILTIN, "empty"

        tokens = cmd_clean.split()
        binary = tokens[0].lower()

        # 1. Shell built-ins that modify state directly
        if binary in {"cd", "exit", "logout", "clear"}:
            return RouteDecision.BUILTIN, binary

        # 2. Check for missing/specialized penetration testing tools
        if self.intercept_missing_tools and any(tool in binary for tool in DECEPTION_TOOLS):
            return RouteDecision.LLM_DECEPTION, "deception_tool"

        # 3. Check if command touches sensitive files or honeytokens
        if self.intercept_sensitive_files:
            cmd_lower = cmd_clean.lower()

            # Regex search for active credential harvesting attempts (e.g. grep -i password)
            if re.search(r"grep.*(pass|cred|secret|key)", cmd_lower) or ("find" in binary and ("perm" in cmd_lower or "pass" in cmd_lower)):
                return RouteDecision.LLM_DECEPTION, "credential_harvesting"

            for pattern in SENSITIVE_TARGETS:
                if pattern in cmd_lower:
                    return RouteDecision.LLM_DECEPTION, f"sensitive_file:{pattern}"

        # 4. Check for payload downloaders (curl ... | sh, wget)
        if ("curl" in binary or "wget" in binary) and ("|" in cmd_clean or ">" in cmd_clean):
            return RouteDecision.LLM_DECEPTION, "payload_download"

        # 5. If sandbox is active and available, execute real command safely
        if self.sandbox_available:
            return RouteDecision.SANDBOX, "standard_execution"

        # 6. Fallback to full LLM terminal simulation
        return RouteDecision.LLM_DECEPTION, "simulated_terminal"
