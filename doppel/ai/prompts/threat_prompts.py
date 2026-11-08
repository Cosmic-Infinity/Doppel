from typing import List, Dict, Any, Optional

MITRE_ANALYSIS_SYSTEM_PROMPT = """You are a senior SOC analyst and threat intelligence engine.
Analyze the provided attacker shell command in the context of an ongoing honeypot session.
Map the command to MITRE ATT&CK enterprise tactics and techniques.

You MUST respond strictly with valid JSON conforming to this schema:
{
  "tactics": ["TacticName"],
  "technique_id": "TXXXX.YYY",
  "technique_name": "Technique Name",
  "threat_score": 0-100,
  "attacker_intent": "Brief description of attacker's goal",
  "is_automated": true/false,
  "confidence": 0.0-1.0,
  "iocs": ["extracted_ips", "extracted_urls", "filenames"]
}

Tactics can be one of:
- Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation,
  Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

Scoring guidance:
- Benign basic navigation (e.g., pwd, date, clear): 0 - 15
- Standard discovery (whoami, id, uname, ls): 20 - 45
- Credential searching (cat /etc/shadow, find password, grep .env): 60 - 85
- Download/execution of external scripts (curl ... | bash, wget): 85 - 100
- Persistence / privilege escalation attempts (sudo su, editing crontab, adding ssh keys): 85 - 100
"""

REPORT_GENERATION_SYSTEM_PROMPT = """You are an automated Cyber Incident Response Analyst.
Generate an Executive Incident Report in Markdown summarizing an attacker's honeypot session.
The report should be professional, comprehensive, and include:
1. Executive Summary
2. Attacker Profile & Session Metadata (IP, Login credentials tried, Duration)
3. MITRE ATT&CK Matrix Summary (Tactics, Techniques observed)
4. Timeline of Significant Actions
5. Identified Indicators of Compromise (IOCs)
6. Recommended Defensive Remediations for Production Environments
"""


def build_command_analysis_prompt(command: str, session_context: Dict[str, Any]) -> str:
    history_snippet = "\n".join([f"- {cmd}" for cmd in session_context.get("history", [])[-5:]])
    return f"""Command: {command}
User: {session_context.get('user', 'ubuntu')}
CWD: {session_context.get('cwd', '/home/ubuntu')}
Recent Session History:
{history_snippet or 'None (initial command)'}

Analyze this command and output JSON only."""


def _duration(start: Optional[str], end: Optional[str]) -> str:
    """'1 min 12 s' between two ISO timestamps, or 'unknown'."""
    from datetime import datetime
    try:
        seconds = int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except (TypeError, ValueError):
        return "unknown"
    minutes, seconds = divmod(max(seconds, 0), 60)
    return f"{minutes} min {seconds} s" if minutes else f"{seconds} s"


def build_incident_report_prompt(
    session_data: Dict[str, Any], custom_instructions: Optional[str] = None
) -> str:
    analyst_section = ""
    if custom_instructions and custom_instructions.strip():
        analyst_section = f"\nAdditional Analyst Directives & Focus Areas:\n{custom_instructions.strip()}\n"

    password = session_data.get("password")
    location = ", ".join(str(v) for v in (session_data.get("city"), session_data.get("country_name"),
                                          session_data.get("asn_org")) if v) or "unknown"
    confidence = session_data.get("type_confidence")
    attacker_type = session_data.get("attacker_type") or "unknown"
    if isinstance(confidence, (int, float)) and confidence:
        attacker_type += f" ({confidence:.0%} confidence)"
    return f"""Generate an incident report for the following honeypot session:
Session ID: {session_data.get('session_id')}
Attacker IP: {session_data.get('remote_ip')} (port {session_data.get('remote_port')})
Location: {location}
Login: user '{session_data.get('username')}', password {repr(password) if password else '(empty)'}, credential risk {session_data.get('credential_risk') or 'unknown'}
Start Time: {session_data.get('start_time')}
End Time: {session_data.get('end_time') or 'still connected'}
Duration: {_duration(session_data.get('start_time'), session_data.get('end_time'))}
Attacker Type: {attacker_type}
Furthest Kill-Chain Phase: {session_data.get('current_phase') or 'Reconnaissance'}
Max Threat Score: {session_data.get('max_threat_score')}
Total Commands: {len(session_data.get('commands', []))}
{analyst_section}
Commands & Telemetry:
{session_data.get('commands_summary') or 'No commands recorded'}

Instructions:
Conclude any internal reasoning before outputting the report. Begin the final report directly with the top-level Markdown heading '# Incident Response Report'.
"""

