import os
import re
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, AsyncGenerator
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

    async def generate_session_report(
        self, session_id: str, custom_instructions: Optional[str] = None
    ) -> Optional[Path]:
        """Generate a complete Markdown incident report for an attacker session (blocking helper)."""
        report_path = None
        try:
            async for event in self.generate_session_report_stream(
                session_id=session_id, custom_instructions=custom_instructions
            ):
                if event.get("done") and event.get("report_path"):
                    report_path = Path(event["report_path"])
        except Exception as e:
            logger.error(f"Error compiling session report for {session_id}: {e}")
        return report_path

    async def generate_session_report_stream(
        self,
        session_id: str,
        custom_instructions: Optional[str] = None,
        model_override: Optional[str] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Stream the incident report generation in real time.
        Yields live reasoning thought chunks while the model plans, followed by
        report markdown compiling chunks. Persists ONLY the clean report (without reasoning)
        to disk upon completion.
        """
        session_data = await self.db.get_session_details(session_id)
        if not session_data:
            logger.warning(f"No session data found for ID: {session_id}")
            yield {
                "stage": "error",
                "error": f"No session data found for ID: {session_id}",
                "done": True,
            }
            return

        commands = session_data.get("commands", [])
        cmd_summary_lines = []
        tactics_count: Dict[str, int] = {}

        for cmd in commands:
            cmd_summary_lines.append(
                f"[{cmd.get('timestamp')}] {cmd.get('cwd')}$ {cmd.get('command')} "
                f"-> Technique: {cmd.get('technique_id')} ({cmd.get('technique_name')}) [Score: {cmd.get('threat_score')}]"
            )
            raw_tactics = cmd.get("tactics")
            if raw_tactics:
                try:
                    tactics = json.loads(raw_tactics) if isinstance(raw_tactics, str) else raw_tactics
                    if isinstance(tactics, list):
                        for t in tactics:
                            tactics_count[t] = tactics_count.get(t, 0) + 1
                except Exception:
                    pass

        session_data["commands_summary"] = "\n".join(cmd_summary_lines)

        messages = [
            {"role": "system", "content": REPORT_GENERATION_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": build_incident_report_prompt(
                    session_data, custom_instructions=custom_instructions
                ),
            },
        ]

        yield {
            "stage": "initiating",
            "message": "Analyzing session telemetry and compiling timeline...",
            "done": False,
        }

        # Mock Mode Stream
        if self.llm_client.mock_mode:
            yield {
                "stage": "reasoning",
                "delta": "Reviewing attacker session metadata, command execution patterns, and MITRE ATT&CK taxonomy...\nSynthesizing executive summary and defensive hardening guidelines.\n",
                "done": False,
            }
            await asyncio.sleep(0.1)

            report_content = self._generate_mock_report(session_data, tactics_count)
            chunks = re.split(r'(\n\n)', report_content)
            for ch in chunks:
                if not ch:
                    continue
                await asyncio.sleep(0.02)
                yield {
                    "stage": "compiling",
                    "delta": ch,
                    "content": ch,
                    "done": False,
                }

            report_file = self.reports_dir / f"incident_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report_content)

            yield {
                "stage": "completed",
                "report_path": str(report_file),
                "content": report_content,
                "report": report_content,
                "done": True,
            }
            return

        # Live LLM Inference Stream
        accumulated_thought = []
        accumulated_content = []
        target_model = model_override or self.llm_client.model
        saved_model = self.llm_client.model

        try:
            if model_override:
                self.llm_client.model = model_override

            async for chunk in self.llm_client.chat_completion_stream(
                messages=messages,
                temperature=0.3,
                max_tokens=4096,
            ):
                stage = chunk.get("stage", "compiling")
                delta_thought = chunk.get("thought", "")
                delta_content = chunk.get("content", "")
                raw_delta = chunk.get("delta", "")

                if stage == "reasoning":
                    piece = delta_thought or raw_delta
                    if piece:
                        accumulated_thought.append(piece)
                        yield {
                            "stage": "reasoning",
                            "delta": piece,
                            "thought": piece,
                            "tokens": chunk.get("tokens", 0),
                            "tokens_per_second": chunk.get("tokens_per_second", 0),
                            "model": chunk.get("model", target_model),
                            "done": False,
                        }
                elif stage == "compiling":
                    piece = delta_content or raw_delta
                    if piece:
                        accumulated_content.append(piece)
                        yield {
                            "stage": "compiling",
                            "delta": piece,
                            "content": piece,
                            "tokens": chunk.get("tokens", 0),
                            "tokens_per_second": chunk.get("tokens_per_second", 0),
                            "model": chunk.get("model", target_model),
                            "done": False,
                        }

            # Finalize report body: strip any think blocks so clean markdown is preserved
            full_content = "".join(accumulated_content).strip()
            # If content was captured inside think tags (fallback parser)
            if not full_content:
                full_raw = "".join(accumulated_thought).strip()
                # If the model output think tags without separating, extract what follows </think>
                if "</think>" in full_raw:
                    parts = full_raw.split("</think>", 1)
                    full_content = parts[1].strip()
                else:
                    # Model only reasoned and never produced report; generate fallback
                    logger.warning("Model finished reasoning without generating report content. Generating structured fallback.")
                    full_content = self._generate_mock_report(session_data, tactics_count)

            clean_report = re.sub(r'<think>[\s\S]*?</think>', '', full_content, flags=re.IGNORECASE).strip()
            if not clean_report:
                clean_report = self._generate_mock_report(session_data, tactics_count)

            report_file = self.reports_dir / f"incident_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(clean_report)

            logger.info(f"Clean incident report persisted to {report_file}")
            yield {
                "stage": "completed",
                "report_path": str(report_file),
                "content": clean_report,
                "report": clean_report,
                "done": True,
            }

        except asyncio.CancelledError:
            logger.info(f"Report generation stream cancelled by user for session {session_id[:8]}")
            # If cancelled, write partial content or fallback so file is available
            partial_text = "".join(accumulated_content).strip()
            if not partial_text:
                partial_text = self._generate_mock_report(session_data, tactics_count)
            clean_partial = re.sub(r'<think>[\s\S]*?</think>', '', partial_text, flags=re.IGNORECASE).strip()
            report_file = self.reports_dir / f"incident_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(clean_partial + "\n\n*(Generation stopped by analyst)*")
            yield {
                "stage": "stopped",
                "report_path": str(report_file),
                "content": clean_partial,
                "done": True,
            }
        except Exception as e:
            logger.error(f"Failed to generate streaming LLM report: {e}. Generating structured template.")
            fallback_report = self._generate_mock_report(session_data, tactics_count)
            report_file = self.reports_dir / f"incident_{session_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(fallback_report)
            yield {
                "stage": "completed",
                "report_path": str(report_file),
                "content": fallback_report,
                "warning": str(e),
                "done": True,
            }
        finally:
            if model_override:
                self.llm_client.model = saved_model

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

