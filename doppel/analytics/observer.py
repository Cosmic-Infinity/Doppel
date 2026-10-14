import json
import re
import logging
from typing import Dict, Any, Optional
from doppel.ai.llm_client import LLMClient
from doppel.ai.prompts.threat_prompts import (
    MITRE_ANALYSIS_SYSTEM_PROMPT,
    build_command_analysis_prompt,
)
from doppel.analytics.db import TelemetryDB

logger = logging.getLogger("doppel.analytics.observer")

# Deterministic fast-path lookup table for standard Unix reconnaissance commands (< 1 ms latency)
FAST_PATH_RULES: Dict[str, Dict[str, Any]] = {
    "whoami": {
        "tactics": ["Discovery"],
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
        "threat_score": 15,
        "attacker_intent": "Determine current user identity and privilege level",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "id": {
        "tactics": ["Discovery"],
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
        "threat_score": 15,
        "attacker_intent": "Inspect current UID, GID, and supplementary group memberships",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "pwd": {
        "tactics": ["Discovery"],
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "threat_score": 10,
        "attacker_intent": "Identify current working directory",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "clear": {
        "tactics": ["Defense Evasion"],
        "technique_id": "T1070",
        "technique_name": "Indicator Removal: Clear Terminal",
        "threat_score": 5,
        "attacker_intent": "Clear terminal display buffer",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "uname": {
        "tactics": ["Discovery"],
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "threat_score": 20,
        "attacker_intent": "Query OS kernel name",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "uname -a": {
        "tactics": ["Discovery"],
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "threat_score": 25,
        "attacker_intent": "Query complete OS kernel architecture, version, and hostname",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "hostname": {
        "tactics": ["Discovery"],
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "threat_score": 15,
        "attacker_intent": "Discover network system hostname",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "uptime": {
        "tactics": ["Discovery"],
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "threat_score": 10,
        "attacker_intent": "Check system uptime and load average",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "date": {
        "tactics": ["Discovery"],
        "technique_id": "T1124",
        "technique_name": "System Time Discovery",
        "threat_score": 5,
        "attacker_intent": "Determine current system date and timezone",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "w": {
        "tactics": ["Discovery"],
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
        "threat_score": 15,
        "attacker_intent": "Discover logged in users and current tasks",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "who": {
        "tactics": ["Discovery"],
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
        "threat_score": 15,
        "attacker_intent": "List currently logged in system users",
        "is_automated": False,
        "confidence": 0.99,
        "iocs": [],
    },
    "ls": {
        "tactics": ["Discovery"],
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "threat_score": 10,
        "attacker_intent": "List directory contents",
        "is_automated": False,
        "confidence": 0.95,
        "iocs": [],
    },
    "ls -la": {
        "tactics": ["Discovery"],
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "threat_score": 15,
        "attacker_intent": "List detailed directory contents including hidden dotfiles and permissions",
        "is_automated": False,
        "confidence": 0.95,
        "iocs": [],
    },
    "ls -l": {
        "tactics": ["Discovery"],
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "threat_score": 15,
        "attacker_intent": "List detailed directory contents and permissions",
        "is_automated": False,
        "confidence": 0.95,
        "iocs": [],
    },
}


class ThreatObserver:
    """Monitors live honeypot sessions, mapping actions to MITRE ATT&CK techniques in real time."""

    def __init__(self, llm_client: LLMClient, db: TelemetryDB):
        self.llm_client = llm_client
        self.db = db

    def _extract_json(self, response_text: str) -> Dict[str, Any]:
        """Extract JSON object from LLM response reliably."""
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", response_text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

        # Fallback default analysis
        return {
            "tactics": ["Discovery"],
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "threat_score": 30,
            "attacker_intent": "General reconnaissance",
            "is_automated": False,
            "confidence": 0.5,
            "iocs": []
        }

    async def analyze_command(
        self,
        session_id: str,
        command: str,
        cwd: str,
        user: str,
        session_history: Optional[list] = None,
    ) -> Dict[str, Any]:
        """Analyze attacker command and return structured MITRE threat intelligence."""
        cmd_clean = command.strip()
        cmd_lower = cmd_clean.lower()

        # Fast-Path Rulebook Check: Bypass LLM for standard simple recon commands (< 1 ms)
        is_compound = any(sep in cmd_clean for sep in ("|", ">", "<", ";", "&&", "||", "`", "$("))
        if not is_compound and cmd_lower in FAST_PATH_RULES:
            match = dict(FAST_PATH_RULES[cmd_lower])
            logger.debug(
                f"Fast-path rulebook hit for '{cmd_clean}' -> {match['technique_id']} ({match['technique_name']})"
            )
            return match

        # Complex, piped, encoded, or unknown commands proceed to full LLM analysis
        messages = [
            {"role": "system", "content": MITRE_ANALYSIS_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_command_analysis_prompt(
                    command, {"cwd": cwd, "user": user, "history": session_history or []}
                ),
            },
        ]

        try:
            resp_str = await self.llm_client.chat_completion(
                messages=messages,
                temperature=0.1,
                response_format={"type": "json_object"} if not self.llm_client.mock_mode else None,
            )
            analysis = self._extract_json(resp_str)
            logger.info(
                f"Session {session_id[:8]} | Cmd: '{command}' | MITRE: {analysis.get('technique_id')} "
                f"({analysis.get('technique_name')}) | Score: {analysis.get('threat_score')}"
            )
            return analysis
        except Exception as e:
            logger.error(f"Failed to analyze command '{command}': {e}")
            return {
                "tactics": ["Discovery"],
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "threat_score": 25,
                "attacker_intent": "Standard execution",
                "is_automated": False,
                "confidence": 0.3,
                "iocs": []
            }
