import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from doppel.ai.llm_client import LLMClient
from doppel.ai.prompts.threat_prompts import (
    REPORT_GENERATION_SYSTEM_PROMPT,
    build_incident_report_prompt,
)
from doppel.analytics.db import TelemetryDB

logger = logging.getLogger("doppel.analytics.reporter")


class IncidentReporter:
    """Compiles and exports comprehensive cybersecurity incident reports from honeypot sessions."""

    def __init__(self, llm_client: LLMClient, db: TelemetryDB, reports_dir: str = "reports"):
        self.llm_client = llm_client
        self.db = db
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    async def generate_session_report(self, session_id: str) -> Optional[Path]:
        """Generate a complete Markdown incident report for an attacker session."""
        session_data = await self.db.get_session_details(session_id)
        if not session_data:
            logger.warning(f"No session data found for ID: {session_id}")
            return None

        commands = session_data.get("commands", [])
        cmd_summary_lines = []
        tactics_count: Dict[str, int] = {}

        for cmd in commands:
            cmd_summary_lines.append(
                f"[{cmd.get('timestamp')}] {cmd.get('cwd')}$ {cmd.get('command')} "
                f"-> Technique: {cmd.get('technique_id')} ({cmd.get('technique_name')}) [Score: {cmd.get('threat_score')}]"
            )
            try:
                tactics = json.loads(cmd.get("tactics", "[]"))
                for t in tactics:
                    tactics_count[t] = tactics_count.get(t, 0) + 1
            except Exception:
                pass

        session_data["commands_summary"] = "\n".join(cmd_summary_lines)

        messages = [
            {"role": "system", "content": REPORT_GENERATION_SYSTEM_PROMPT},
            {"role": "user", "content": build_incident_report_prompt(session_data)},
        ]

        if self.llm_client.mock_mode:
            report_content = self._generate_mock_report(session_data, tactics_count)
        else:
            try:
                report_content = await self.llm_client.chat_completion(messages=messages, temperature=0.3)
            except Exception as e:
                logger.error(f"Failed to generate LLM report: {e}. Generating structured template.")
                report_content = self._generate_mock_report(session_data, tactics_count)

        report_file = self.reports_dir / f"incident_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_content)

        logger.info(f"Incident report generated at {report_file}")
        return report_file

    def _generate_mock_report(self, session_data: Dict[str, Any], tactics_count: Dict[str, int]) -> str:
        tactics_md = "\n".join([f"- **{t}**: {count} event(s)" for t, count in tactics_count.items()])
        return f"""# Incident Response Report: Session {session_data.get('session_id', 'N/A')}

**Date of Report:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Attacker IP:** `{session_data.get('remote_ip', 'Unknown')}`  
**Attacker Port:** `{session_data.get('remote_port', 'Unknown')}`  
**Attempted Username:** `{session_data.get('username', 'root')}`  
**Session Start:** `{session_data.get('start_time', 'N/A')}`  
**Session End:** `{session_data.get('end_time', 'N/A')}`  
**Maximum Threat Score:** `{session_data.get('max_threat_score', 0)} / 100`  

---

## 1. Executive Summary
An unauthorized remote actor initiated an interactive SSH session targeting the honeypot sensor.
The activity included environmental reconnaissance, account enumeration, and attempts to retrieve configuration tokens.
No host systems were compromised; all interactions were either safely handled within an isolated sandbox or intercepted by generative deception layers.

---

## 2. Observed MITRE ATT&CK Tactics
{tactics_md or "None recorded"}

---

## 3. Timeline of Commands
```
{session_data.get('commands_summary') or "No commands recorded"}
```

---

## 4. Remediation & Recommendations
1. Enforce strict firewall rules preventing public exposure of administrative ports (e.g., SSH port 22/2222).
2. Deploy multi-factor authentication (MFA) for all administrative accounts.
3. Invalidate any leaked canary credentials accessed during this session.
"""
