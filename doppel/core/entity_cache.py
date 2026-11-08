import re
from typing import Dict, List, Optional


class EntityConsistencyCache:
    """
    In-memory session registry that records model-invented environment variables,
    internal IP addresses, and database credentials across multi-turn shell sessions.

    These values are injected into future LLM system prompts as immutable facts to
    prevent the model from hallucinating conflicting details across successive commands.
    """

    MAX_ENTITIES = 32

    # Scans for RFC1918 private IPv4 subnets
    _IP_PATTERN = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )

    # Scans for KEY=VALUE assignment patterns (e.g. in .env, configs, exports)
    _KV_PATTERN = re.compile(
        r"^[A-Z0-9_]{3,30}=(?:[^\s#\x1b]{2,64})",
        re.MULTILINE
    )

    def __init__(self):
        # key -> value (e.g. "DB_HOST" -> "10.0.4.77")
        self._key_values: Dict[str, str] = {}
        # set of observed internal IP addresses
        self._internal_ips: set[str] = set()

    def extract_from_output(self, command: str, output: str):
        """Extract invented IPs and KEY=VALUE parameters from command outputs."""
        if not output:
            return

        # 1. Extract KEY=VALUE assignments
        for match in self._KV_PATTERN.finditer(output):
            line = match.group(0)
            if "=" in line:
                k, v = line.split("=", 1)
                k_clean = k.strip()
                v_clean = v.strip().strip("'\"")
                if len(self._key_values) < self.MAX_ENTITIES:
                    self._key_values[k_clean] = v_clean

        # 2. Extract internal IPv4 addresses
        for ip in self._IP_PATTERN.findall(output):
            if len(self._internal_ips) < self.MAX_ENTITIES:
                self._internal_ips.add(ip)

    def build_context_block(self) -> str:
        """Construct the prompt injection block stating known environment facts."""
        if not self._key_values and not self._internal_ips:
            return ""

        lines: List[str] = [
            "SESSION ENVIRONMENT CONSISTENCY (Ground truth established in earlier commands. Do NOT contradict):"
        ]

        if self._key_values:
            lines.append("  Previously declared configuration values:")
            for k, v in list(self._key_values.items())[:self.MAX_ENTITIES]:
                lines.append(f"    {k}={v}")

        if self._internal_ips:
            lines.append("  Known active internal host/IP addresses:")
            for ip in sorted(self._internal_ips)[:self.MAX_ENTITIES]:
                lines.append(f"    {ip}")

        return "\n".join(lines)

