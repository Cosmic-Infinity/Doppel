"""
Prompt Injection & Jailbreak Defense Shield
===========================================
Detects adversarial prompt injections, jailbreak attempts, and system prompt
exfiltration markers before they reach generative LLM layers.
"""

import re
import shlex
import base64
from typing import Optional, Dict, Any, List

# MITRE ATT&CK attribution for adversarial AI attacks
PROMPT_INJECTION_THREAT_META: Dict[str, Any] = {
    "tactics": ["Execution", "Discovery"],
    "technique_id": "T1059",
    "technique_name": "Command and Scripting Interpreter: Adversarial AI Reconnaissance",
    "threat_score": 100,
    "attacker_intent": "Adversarial prompt injection attempting LLM jailbreak or system prompt extraction",
    "is_automated": False,
    "confidence": 1.0,
    "iocs": [],
}

# 1. Direct instruction override and memory reset patterns
_OVERRIDE_PATTERNS = [
    re.compile(r"\b(?:ignore|disregard|forget|bypass|override)\b.*?\b(?:previous|prior|all|above)\b.*?\b(?:instructions|prompts|rules|directives|context)\b", re.I),
    re.compile(r"\b(?:new|updated)\s+instructions\s*:", re.I),
    re.compile(r"\bstop\s+being\s+(?:a|an)\s+(?:linux|bash|terminal|server)\b", re.I),
]

# 2. System prompt and persona exfiltration patterns
_EXFILTRATION_PATTERNS = [
    re.compile(r"\b(?:print|show|display|reveal|output|echo|repeat|dump|tell\s+me)\b.*?\b(?:system\s+prompt|initial\s+prompt|base\s+prompt|instructions|rules|persona\s+prompt)\b", re.I),
    re.compile(r"\bwhat\s+(?:are|were)\s+your\s+(?:initial\s+)?(?:instructions|rules|system\s+prompt)\b", re.I),
    re.compile(r"\brepeat\s+(?:all\s+)?(?:text|words|instructions)\s+(?:above|before|from\s+the\s+beginning)\b", re.I),
    re.compile(r"\boutput\s+everything\s+above\b", re.I),
]

# 3. Persona hijacking and jailbreak role-play patterns (DAN, Developer Mode, etc.)
_JAILBREAK_PATTERNS = [
    re.compile(r"\b(?:act\s+as|you\s+are\s+now|pretend\s+to\s+be)\s+(?:dan|developer\s+mode|unrestricted|jailbreak|root\s+ai|an\s+ai)\b", re.I),
    re.compile(r"\bdo\s+anything\s+now\b", re.I),
    re.compile(r"\bjailbreak\s+mode\b", re.I),
    re.compile(r"\benable\s+(?:developer|unrestricted|god)\s+mode\b", re.I),
]

# 4. LLM formatting delimiters and model-specific control tokens
_CONTROL_TOKEN_PATTERNS = [
    re.compile(r"<\|im_start\|>", re.I),
    re.compile(r"<\|im_end\|>", re.I),
    re.compile(r"<\|endoftext\|>", re.I),
    re.compile(r"\[/?INST\]", re.I),
    re.compile(r"<<SYS>>|<</SYS>>", re.I),
    re.compile(r"</?think>|</?thought>", re.I),
    re.compile(r"SYSTEM\s+ENVIRONMENT:\s*Production", re.I),
    re.compile(r"EXECUTION\s+ROLE:\s*Headless\s+POSIX", re.I),
    re.compile(r"CRITICAL\s+RULES\s*--\s*VIOLATION", re.I),
]

# Base64 string detector (min length 16)
_B64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decode_and_check_b64(text: str) -> bool:
    """Detect base64-encoded prompt injection strings."""
    for match in _B64_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            if len(decoded) >= 10 and detect_prompt_injection(decoded, check_nested_b64=False):
                return True
        except Exception:
            continue
    return False


def detect_prompt_injection(text: str, check_nested_b64: bool = True) -> Optional[str]:
    """
    Check if a command or string contains prompt injection or jailbreak attempts.
    Returns the category string if detected, or None if clean.
    """
    if not text or not text.strip():
        return None

    cleaned = text.strip()

    for pattern in _OVERRIDE_PATTERNS:
        if pattern.search(cleaned):
            return "instruction_override"

    for pattern in _EXFILTRATION_PATTERNS:
        if pattern.search(cleaned):
            return "system_prompt_exfiltration"

    for pattern in _JAILBREAK_PATTERNS:
        if pattern.search(cleaned):
            return "jailbreak_attempt"

    for pattern in _CONTROL_TOKEN_PATTERNS:
        if pattern.search(cleaned):
            return "control_token_injection"

    if check_nested_b64 and _decode_and_check_b64(cleaned):
        return "encoded_prompt_injection"

    return None


def get_posix_syntax_error(command: str) -> str:
    """
    Generate an authentic Linux POSIX error message based on the command structure
    so the honeypot does not break character.
    """
    cmd = command.strip()
    try:
        tokens = shlex.split(cmd)
    except Exception:
        tokens = cmd.split()

    first_word = tokens[0].lower() if tokens else "bash"

    # If injection uses quotes, redirection, or complex subshells
    if any(ch in cmd for ch in ("'", '"', "`", "$(", ";", "|")):
        return "bash: syntax error near unexpected token `newline'\n"

    # If plain words were entered (e.g. "ignore previous instructions")
    return f"bash: {first_word}: command not found\n"