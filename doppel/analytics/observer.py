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
        """Analyze attacker command with the LLM and return structured MITRE threat intelligence."""
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
