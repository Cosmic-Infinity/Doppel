"""
Mock-mode analysis: ATT&CK tags from a fixed rulebook and assistant answers built
from the telemetry in the assistant's prompt. Used by LLMClient when no model is
available, so tagging, kill-chain phases, alerts and the assistant still behave
sensibly in development and demos.
"""
import json
import re
from typing import Any, Dict, List, Optional

# (pattern, tactic, technique id, technique name, score, intent). First match wins,
# so specific patterns come before general ones. Scores follow the guidance in
# MITRE_ANALYSIS_SYSTEM_PROMPT.
_TAG_RULES = [
    (r":\(\)\s*\{.*\};\s*:", "Impact", "T1499", "Endpoint Denial of Service", 90, "Exhaust the process table with a fork bomb"),
    (r"\brm\s+-[a-z]*r[a-z]*f?\s+/(\s|$)|\bmkfs\b|\bdd\s+if=/dev/(zero|urandom)", "Impact", "T1485", "Data Destruction", 95, "Destroy data on the host"),
    (r"xmrig|minerd|cpuminer|stratum\+tcp", "Impact", "T1496", "Resource Hijacking", 90, "Run a cryptocurrency miner"),
    (r"history\s+-c|unset\s+histfile|histfile=/dev/null|rm\b.*\.bash_history|>\s*~?/?\S*\.bash_history",
     "Defense Evasion", "T1070.003", "Indicator Removal: Clear Command History", 80, "Remove traces of the session"),
    (r"(curl|wget)\b.*\|\s*(ba)?sh\b", "Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell", 95, "Download and run a script"),
    (r"\b(wget|curl|tftp|ftp)\b.*(https?|ftp|tftp)://|\bscp\b.*:\S", "Command and Control", "T1105", "Ingress Tool Transfer", 85, "Download tools to the host"),
    (r"authorized_keys", "Persistence", "T1098.004", "Account Manipulation: SSH Authorized Keys", 90, "Keep access with an SSH key"),
    (r"\bcrontab\b|/etc/cron|systemctl\s+enable|/etc/systemd/system/\S+\.service", "Persistence", "T1053.003", "Scheduled Task/Job: Cron", 85, "Run code on a schedule to keep access"),
    (r"\b(useradd|adduser|usermod)\b", "Persistence", "T1136.001", "Create Account: Local Account", 85, "Add an account to keep access"),
    (r"/etc/shadow|\bunshadow\b", "Credential Access", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", 85, "Read password hashes"),
    (r"\.env\b|\.aws/credentials|id_rsa|id_ed25519|wp-config|\.git-credentials|\.pgpass|\.my\.cnf|\.mysql_history|grep\b.*-i?\s*(pass|secret|token|key)",
     "Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files", 75, "Look for credentials in files"),
    (r"\bsudo\s+(-i|su\b|-s\b|bash|sh)\b|^\s*su(\s|$)|\bsudo\s+-l\b", "Privilege Escalation", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", 85, "Gain root"),
    (r"\b(nc|ncat|netcat|socat)\b|/dev/tcp/", "Command and Control", "T1095", "Non-Application Layer Protocol", 85, "Open a raw network channel"),
    (r"\bssh\s+\S*@?\S+|\bsshpass\b", "Lateral Movement", "T1021.004", "Remote Services: SSH", 70, "Move to another host"),
    (r"\b(nmap|masscan|zmap|hydra)\b|ping\s+-c\s*\d+\s+\d+\.\d+\.\d+\.", "Discovery", "T1046", "Network Service Discovery", 60, "Scan for services"),
    (r"\b(tar|zip|7z|gzip)\b\s+-?[a-z]*c", "Collection", "T1560.001", "Archive Collected Data: Archive via Utility", 65, "Package data for theft"),
    (r"\b(chmod\s+\+x|python[\d.]*\s+-c|perl\s+-e|bash\s+-c|sh\s+-c)\b|^\s*\./\S+", "Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell", 65, "Run code on the host"),
    (r"/etc/passwd|\bgetent\s+passwd\b|\blastlog\b|^\s*last\b", "Discovery", "T1087.001", "Account Discovery: Local Account", 35, "List accounts on the host"),
    (r"^\s*(whoami|id|w|who|groups)\b", "Discovery", "T1033", "System Owner/User Discovery", 25, "Check the current user"),
    (r"\b(ifconfig|ip\s+(a|addr|route|r)\b|netstat|ss\s+-|route\b|arp\b|/etc/hosts|/etc/resolv\.conf)", "Discovery", "T1016", "System Network Configuration Discovery", 30, "Map the network"),
    (r"^\s*(ps|top|htop|pstree)\b", "Discovery", "T1057", "Process Discovery", 25, "List running processes"),
    (r"^\s*(uname|hostname|hostnamectl|lscpu|lsb_release|uptime|df|free|nproc|dmesg)\b|/etc/(os-release|issue)|/proc/(cpuinfo|meminfo|version)",
     "Discovery", "T1082", "System Information Discovery", 25, "Identify the host"),
    (r"^\s*(dpkg\s+-l|apt\s+list|rpm\s+-qa|which|whereis)\b", "Discovery", "T1518", "Software Discovery", 25, "Check installed software"),
    (r"^\s*(ls|ll|la|find|tree|du|stat|file|cat|head|tail|less|more)\b", "Discovery", "T1083", "File and Directory Discovery", 20, "Browse the file system"),
    (r"^\s*(date|timedatectl)\b", "Discovery", "T1124", "System Time Discovery", 10, "Check the time"),
    (r"^\s*(pwd|cd|clear|echo|env|printenv|export|alias|history)\b", "Discovery", "T1083", "File and Directory Discovery", 5, "Find their way around the shell"),
]
_TAG_RULES = [(re.compile(p, re.I), *rest) for p, *rest in _TAG_RULES]

_IOC_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"|;]+|\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_tagging_request(messages: List[Dict[str, str]]) -> bool:
    system = messages[0]["content"] if messages and messages[0].get("role") == "system" else ""
    user = messages[-1]["content"] if messages else ""
    return ("MITRE ATT&CK" in system and "respond strictly with valid JSON" in system)         or user.lower().startswith("analyze command")


def mock_tag(messages: List[Dict[str, str]]) -> str:
    """JSON tag for the command in a tagging prompt ("Command: ..." on its first line)."""
    user = messages[-1]["content"] if messages else ""
    m = re.match(r"(?:analyze\s+)?command:\s*(.*)", user, re.I)
    command = m.group(1).strip() if m else user.strip()
    for pattern, tactic, tid, name, score, intent in _TAG_RULES:
        if pattern.search(command):
            break
    else:
        tactic, tid, name, score, intent = "Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell", 15, "Run a shell command"
    return json.dumps({
        "tactics": [tactic],
        "technique_id": tid,
        "technique_name": name,
        "threat_score": score,
        "attacker_intent": intent,
        "is_automated": False,
        "confidence": 0.6,
        "iocs": _IOC_RE.findall(command),
    })


def _between(text: str, start: str, end: str) -> str:
    i = text.find(start)
    if i < 0:
        return ""
    i += len(start)
    j = text.find(end, i)
    return text[i:j if j >= 0 else None]


def _recent_sessions(system: str) -> List[Dict[str, Any]]:
    # "RECENT ATTACKER SESSIONS (Last N):\n[...json...]\n\nINSTRUCTIONS"
    block = _between(system, "RECENT ATTACKER SESSIONS", "\n\nINSTRUCTIONS")
    block = block[block.find("\n") + 1:] if block else ""
    try:
        data = json.loads(block)
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def mock_assistant(messages: List[Dict[str, str]]) -> Optional[str]:
    """Assistant answer built from the system state and recent sessions in its prompt,
    or None when the prompt is not the assistant's."""
    system = messages[0]["content"] if messages and messages[0].get("role") == "system" else ""
    if "Security Intelligence Assistant" not in system:
        return None
    question = (messages[-1]["content"] if messages else "").lower()
    sessions = _recent_sessions(system)
    state = [line[2:] for line in _between(system, "CURRENT DOPPEL SYSTEM STATE:\n", "\n\n").splitlines() if line.startswith("- ")]
    note = "\n\n*Mock mode: this answer is assembled from recorded data without a model.*"

    if "last attack" in question or ("attack" in question and "like" in question):
        if not sessions:
            return "No sessions have been recorded yet." + note
        s = sessions[0]
        where = ", ".join(p for p in (s.get("city"), s.get("country")) if p and p != "unknown")
        lines = [
            f"The most recent session came from **{s.get('remote_ip', 'unknown')}**"
            f"{f' ({where})' if where else ''} as `{s.get('username', 'unknown')}`, starting {s.get('start_time', 'at an unknown time')}.",
            "",
            f"- Commands: {s.get('command_count', 0)}",
            f"- Highest threat score: {s.get('max_threat_score', 0)} / 100",
            f"- Credential risk: {s.get('credential_risk', 'none')}",
        ]
        if s.get("recent_commands"):
            lines.append("- Last commands: " + ", ".join(f"`{c}`" for c in s["recent_commands"]))
        return "\n".join(lines) + note

    if any(k in question for k in ("suggestion", "recommend", "harden", "mitigat", "defen")):
        seen = " ".join(" ".join(s.get("recent_commands") or []) + " " + str(s.get("last_command", "")) for s in sessions).lower()
        tips = ["Disable SSH password logins (`PasswordAuthentication no`) and use keys.",
                "Rate-limit or ban repeated failed logins, for example with fail2ban."]
        if any(k in seen for k in ("wget", "curl", "http")):
            tips.append("Block outbound connections that servers do not need, so downloaded tools cannot reach their hosts.")
        if any(k in seen for k in (".env", "credentials", "id_rsa", "shadow", "passwd")):
            tips.append("Keep secrets out of web roots and home directories; rotate any credential stored in plain files.")
        if any(k in seen for k in ("crontab", "authorized_keys", "useradd")):
            tips.append("Audit cron jobs, `authorized_keys` files and local accounts for unexpected changes.")
        if "sudo" in seen:
            tips.append("Review `/etc/sudoers.d/` and remove passwordless sudo rules.")
        return (f"Based on the last {len(sessions)} session(s):\n\n" if sessions else "") + \
            "\n".join(f"{i}. {t}" for i, t in enumerate(tips, 1)) + note

    if any(k in question for k in ("status", "subsystem", "software", "configuration", "config")):
        return ("Current state:\n\n" + "\n".join(f"- {line}" for line in state) if state else "No system state available.") + note

    if any(k in question for k in ("speed", "benchmark", "tokens")):
        return "Mock mode returns built-in text, so there is no model speed to measure. Turn mock mode off to test the model." + note

    if sessions:
        top = max(sessions, key=lambda s: s.get("max_threat_score") or 0)
        return (f"{len(sessions)} recent session(s) are recorded. The highest scoring came from {top.get('remote_ip')} "
                f"({top.get('max_threat_score', 0)} / 100). Ask about the last attack, defensive suggestions or system status.") + note
    return "No sessions have been recorded yet. Ask about system status, or start the honeypot and connect over SSH." + note
