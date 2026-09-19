"""
Attacker Behavior Profiler
==========================
Two orthogonal analyses that run per-session on the ThreatObserver:

Feature 7 — Automated vs. Human Classifier
-------------------------------------------
Measures inter-command timing (delta between successive command timestamps)
and command-pattern signals to emit one of three labels:

  bot            — sub-100 ms cadence, no typos, no navigation backtracking,
                   commands follow a rigid playbook (tools like hydra, nmap,
                   linpeas, metasploit post-exploitation scripts).

  semi-automated — mixed cadence (100–2000 ms), some human-like patterns, but
                   commands are still too tool-like to be purely manual (e.g.
                   someone running a script with pauses, or a C2 agent with
                   jitter).

  human          — cadence > 2 s medians, typo corrections (blank commands,
                   "^C" sequences), navigation backtracking (ls → cd → ls),
                   exploratory command flow.

The label is used by SessionManager to drive adaptive tar-pit delay.

Feature 8 — Attack Phase Tracker
----------------------------------
Aggregates per-command MITRE tactics into a session-level kill-chain phase
sequence.  Phases are ordered; the tracker emits a `phase_transition` event
whenever the session moves forward in the chain.

Kill-chain phases (superset of MITRE):
  0  Reconnaissance       — discovery, enumeration
  1  Weaponization        — downloading tools, compilation
  2  Delivery             — file staging, droppers
  3  Exploitation         — privilege escalation, suid abuse, kernel exploits
  4  Credential Access    — credential dumping, brute force, key theft
  5  Installation         — persistence, crontab, sshd config, rc.local
  6  C2                   — Command and Control
  7  Lateral Movement     — pivoting, ssh to other hosts
  8  Exfiltration         — data theft, staging, archive creation
  9  Impact               — ransomware, wipers, defacement

Phase transitions are only forward (0→1→2 …); a single command in a lower
phase doesn't reset the session.
"""

import re
import time
import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("doppel.analytics.profiler")


# ── Kill-chain phase definitions ───────────────────────────────────────────────

PHASE_ORDER = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Credential Access",
    "Installation",
    "Command and Control",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
]

# MITRE tactic → kill-chain phase mapping
_TACTIC_TO_PHASE: Dict[str, str] = {
    "Reconnaissance":        "Reconnaissance",
    "Resource Development":  "Weaponization",
    "Initial Access":        "Delivery",
    "Execution":             "Exploitation",
    "Persistence":           "Installation",
    "Privilege Escalation":  "Exploitation",
    "Defense Evasion":       "Exploitation",
    "Credential Access":     "Credential Access",
    "Discovery":             "Reconnaissance",
    "Lateral Movement":      "Lateral Movement",
    "Collection":            "Exfiltration",
    "Command and Control":   "Command and Control",
    "Exfiltration":          "Exfiltration",
    "Impact":                "Impact",
}

# Command-pattern → phase hints (regex on the raw command string)
# Used when MITRE tagging is not yet available for a command
_CMD_PHASE_HINTS: List[Tuple[str, re.Pattern]] = [
    ("Reconnaissance",   re.compile(
        r"\b(whoami|id|uname|hostname|cat\s+/etc/(?:passwd|os-release|issue)|"
        r"ip\s+a|ifconfig|netstat|ss\s|ps\s|ls\s|find\s|locate\s|which\s|env|printenv|"
        r"nmap|masscan|ping|traceroute|dig|nslookup)\b", re.I
    )),
    ("Credential Access", re.compile(
        r"\b(cat\s+/etc/shadow|cat\s+/etc/passwd|grep.*password|find.*\.env|"
        r"cat.*\.ssh/|ssh-keygen|ssh-add|hashdump|mimikatz|secretsdump|"
        r"john|hashcat|hydra|medusa|crunch|unshadow)\b", re.I
    )),
    ("Exploitation",     re.compile(
        r"\b(sudo\s|su\s|chmod\s+[0-9]*s|chown\s+root|suid|sgid|"
        r"find\s+/\s+-perm\s+-[024]*[246]|exploit|gcc|g\+\+|python.*exec|"
        r"perl.*exec|php.*exec|bash\s+-i|nc\s+-e|ncat|mkfifo)\b", re.I
    )),
    ("Installation",     re.compile(
        r"\b(crontab|/etc/cron|systemctl\s+(enable|start)|"
        r"~/.bashrc|~/.profile|/etc/rc\.local|"
        r"echo.*>>.*authorized_keys|adduser|useradd|usermod)\b", re.I
    )),
    ("Weaponization",    re.compile(
        r"\b(wget|curl|git\s+clone|pip\s+install|apt\s+install|yum\s+install|"
        r"dnf\s+install|apk\s+add|brew\s+install|make\s|cmake\s|"
        r"chmod\s+\+x|\.\/[a-zA-Z])\b", re.I
    )),
    ("Command and Control", re.compile(
        r"\b(nc\s|netcat|socat|nohup|screen|tmux|disown|"
        r"base64\s+-d|xxd\s+-r|openssl\s+enc|"
        r"python.*-c.*socket|bash\s+-i\s+>&|/dev/tcp/)\b", re.I
    )),
    ("Lateral Movement", re.compile(
        r"\b(ssh\s+[a-zA-Z0-9@]|scp\s|rsync\s|psexec|wmiexec|"
        r"xfreerdp|rdesktop|mstsc|proxychains|ssh\s+-L|ssh\s+-R|"
        r"ssh\s+-D|ssh\s+-N)\b", re.I
    )),
    ("Exfiltration",     re.compile(
        r"\b(tar\s+.*czf|zip\s+-r|scp\s|rsync\s|curl.*-T|"
        r"wget.*--post-file|nc\s+.*<|dd\s+if=|cat\s+.*\|\s*(nc|curl|wget))\b", re.I
    )),
    ("Impact",           re.compile(
        r"\b(rm\s+-rf\s+/|shred\s|wipe\s|mkfs|dd\s+if=/dev/zero|"
        r"fork\s*bomb|:(){ :|:& };:|history\s+-c|"
        r"shutdown|poweroff|reboot|halt)\b", re.I
    )),
]

# Bot-indicator command patterns (tools that only automated scanners run)
_BOT_TOOL_RE = re.compile(
    r"\b(linpeas|linenum|linux-exploit-suggester|pspy|nmap|masscan|"
    r"nikto|sqlmap|metasploit|msfconsole|msfvenom|hydra|medusa|"
    r"crackmapexec|cme|bloodhound|sharphound|mimikatz|lazagne|"
    r"chisel|ligolo|frp|fscan|dirbuster|gobuster|wfuzz|ffuf|"
    r"nuclei|subfinder|amass|theHarvester|recon-ng)\b",
    re.I,
)

# Timing thresholds (seconds)
_BOT_MEDIAN_THRESHOLD        = 0.5    # median inter-command gap < 0.5 s → bot
_HUMAN_MEDIAN_THRESHOLD      = 3.0    # median inter-command gap > 3 s → human
_BOT_MAX_THRESHOLD           = 2.0    # max inter-command gap < 2 s → bot
# Minimum commands before making a reliable classification
_MIN_COMMANDS_FOR_TIMING     = 3


# ── Per-session state ─────────────────────────────────────────────────────────

@dataclass
class ProfilerState:
    """Mutable per-session state; lives on SessionState.profiler_state."""
    # Timing
    command_timestamps: List[float] = field(default_factory=list)
    # Behavior signals
    backspace_count: int = 0       # raw Ctrl+H / DEL keystrokes recorded externally
    empty_submits: int = 0         # blank Enter presses (human hesitation)
    ctrl_c_count: int = 0          # Ctrl+C interrupts
    repeated_navigation: int = 0   # ls→cd→ls or pwd patterns
    bot_tool_hits: int = 0         # commands matching _BOT_TOOL_RE
    # Classification (updated each command)
    attacker_type: str = "unknown"
    type_confidence: float = 0.0
    # Kill-chain phase
    current_phase: str = "Reconnaissance"
    current_phase_index: int = 0
    phase_history: List[Dict[str, Any]] = field(default_factory=list)
    # Previous 3 command binaries for backtracking detection
    recent_binaries: List[str] = field(default_factory=list)


# ── Main profiler class ───────────────────────────────────────────────────────

class AttackerProfiler:
    """
    Stateless service — all mutable state is in ProfilerState (lives on session).
    Call record_command() after each command; it returns:
      - updated ProfilerState
      - optional phase_transition dict (None if no transition occurred)
    """

    def record_command(
        self,
        state: ProfilerState,
        command: str,
        tactics: List[str],
        now: Optional[float] = None,
    ) -> Tuple[ProfilerState, Optional[Dict[str, Any]]]:
        """
        Update profiler state for one command.

        Args:
            state:   mutable ProfilerState from the session
            command: raw command string
            tactics: list of MITRE tactic strings from ThreatObserver
            now:     unix timestamp override (for testing)

        Returns:
            (updated state, phase_transition_dict or None)
        """
        ts = now if now is not None else time.monotonic()
        state.command_timestamps.append(ts)

        # ── Bot-tool hit detection ────────────────────────────────────────────
        if _BOT_TOOL_RE.search(command):
            state.bot_tool_hits += 1

        # ── Navigation backtracking detection ────────────────────────────────
        binary = command.strip().split()[0].lower() if command.strip() else ""
        if binary:
            state.recent_binaries.append(binary)
            state.recent_binaries = state.recent_binaries[-5:]
            nav_bins = [b for b in state.recent_binaries if b in ("ls", "ll", "la", "pwd", "cd")]
            if len(nav_bins) >= 3:
                state.repeated_navigation += 1

        # ── Classify attacker type ────────────────────────────────────────────
        state.attacker_type, state.type_confidence = self._classify(state, command)

        # ── Phase detection & transition ──────────────────────────────────────
        phase_transition = self._update_phase(state, command, tactics)

        return state, phase_transition

    # ── Classification ────────────────────────────────────────────────────────

    def _classify(
        self, state: ProfilerState, command: str
    ) -> Tuple[str, float]:
        """
        Multi-signal heuristic → (label, confidence 0–1).

        Signals (weighted vote):
          1. Inter-command timing (strongest signal)
          2. Bot-tool invocations
          3. Navigation backtracking (human signal)
          4. Empty submits / Ctrl+C (human signal)
          5. Backspace usage (human signal)
        """
        scores: Dict[str, float] = {"bot": 0.0, "semi-automated": 0.0, "human": 0.0}

        # ── Signal 1: timing ──────────────────────────────────────────────────
        gaps = self._inter_command_gaps(state.command_timestamps)
        if len(gaps) >= _MIN_COMMANDS_FOR_TIMING:
            median_gap = statistics.median(gaps)
            max_gap    = max(gaps)

            if median_gap < _BOT_MEDIAN_THRESHOLD and max_gap < _BOT_MAX_THRESHOLD:
                scores["bot"] += 3.0
            elif median_gap < _BOT_MEDIAN_THRESHOLD:
                scores["semi-automated"] += 2.0
                scores["bot"] += 1.0
            elif median_gap < _HUMAN_MEDIAN_THRESHOLD:
                scores["semi-automated"] += 2.0
            else:
                scores["human"] += 3.0

            # Very consistent timing = automation (low variance)
            if len(gaps) >= 5:
                try:
                    stdev = statistics.stdev(gaps)
                    cv = stdev / (median_gap + 0.001)  # coefficient of variation
                    if cv < 0.15:                       # near-perfect regularity
                        scores["bot"] += 2.0
                    elif cv < 0.5:
                        scores["semi-automated"] += 1.0
                    else:
                        scores["human"] += 1.0
                except statistics.StatisticsError:
                    pass

        # ── Signal 2: bot-tool invocations ────────────────────────────────────
        if state.bot_tool_hits > 0:
            scores["bot"] += min(state.bot_tool_hits * 1.5, 4.0)

        # ── Signal 3: navigation backtracking ─────────────────────────────────
        if state.repeated_navigation >= 2:
            scores["human"] += 2.0
        elif state.repeated_navigation == 1:
            scores["human"] += 0.5

        # ── Signal 4: empty submits / Ctrl+C ──────────────────────────────────
        human_hesitations = state.empty_submits + state.ctrl_c_count
        if human_hesitations >= 3:
            scores["human"] += 1.5
        elif human_hesitations >= 1:
            scores["human"] += 0.5

        # ── Signal 5: backspace usage ─────────────────────────────────────────
        if state.backspace_count >= 5:
            scores["human"] += 1.5
        elif state.backspace_count >= 2:
            scores["human"] += 0.5

        # ── Pick winner ───────────────────────────────────────────────────────
        total = sum(scores.values()) or 1.0
        label = max(scores, key=scores.__getitem__)
        confidence = round(scores[label] / total, 2)

        # Need enough data before committing; otherwise stay "unknown"
        n_cmds = len(state.command_timestamps)
        if n_cmds < _MIN_COMMANDS_FOR_TIMING and state.bot_tool_hits == 0:
            return "unknown", 0.0

        return label, confidence

    # ── Phase tracking ────────────────────────────────────────────────────────

    def _update_phase(
        self,
        state: ProfilerState,
        command: str,
        tactics: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Determine the phase this command belongs to and update the kill-chain.
        Returns a phase_transition dict if a forward transition occurred, else None.
        """
        detected_phase = self._detect_phase(command, tactics)
        if not detected_phase:
            return None

        detected_idx = PHASE_ORDER.index(detected_phase)

        # Only advance forward in the kill-chain
        if detected_idx <= state.current_phase_index:
            return None  # same phase or regression — no event

        prev_phase = state.current_phase
        state.current_phase       = detected_phase
        state.current_phase_index = detected_idx

        ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp":  ts,
            "from_phase": prev_phase,
            "to_phase":   detected_phase,
            "triggered_by": command[:120],
        }
        state.phase_history.append(entry)

        logger.warning(
            f"[PHASE TRANSITION] {prev_phase} → {detected_phase} | "
            f"triggered by: {command[:80]!r}"
        )

        return {
            "event":        "phase_transition",
            "from_phase":   prev_phase,
            "to_phase":     detected_phase,
            "phase_index":  detected_idx,
            "triggered_by": command[:120],
            "timestamp":    ts,
        }

    def _detect_phase(
        self, command: str, tactics: List[str]
    ) -> Optional[str]:
        """Return the best-fit kill-chain phase for this command."""
        # 1. MITRE tactics take priority (authoritative)
        for tactic in tactics:
            phase = _TACTIC_TO_PHASE.get(tactic)
            if phase:
                return phase

        # 2. Command-pattern heuristic fallback
        for phase_name, pattern in _CMD_PHASE_HINTS:
            if pattern.search(command):
                return phase_name

        return None  # unclassifiable; don't advance phase

    # ── Helper ────────────────────────────────────────────────────────────────

    @staticmethod
    def _inter_command_gaps(timestamps: List[float]) -> List[float]:
        if len(timestamps) < 2:
            return []
        return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

    # ── Exported summary dict ─────────────────────────────────────────────────

    @staticmethod
    def summary(state: ProfilerState) -> Dict[str, Any]:
        """Compact dict safe to store in DB / send over WebSocket."""
        gaps = AttackerProfiler._inter_command_gaps(state.command_timestamps)
        return {
            "attacker_type":       state.attacker_type,
            "type_confidence":     state.type_confidence,
            "current_phase":       state.current_phase,
            "current_phase_index": state.current_phase_index,
            "phase_history":       state.phase_history,
            "command_count":       len(state.command_timestamps),
            "median_gap_ms":       round(statistics.median(gaps) * 1000, 1) if gaps else None,
            "bot_tool_hits":       state.bot_tool_hits,
            "backspace_count":     state.backspace_count,
            "empty_submits":       state.empty_submits,
            "repeated_navigation": state.repeated_navigation,
        }
