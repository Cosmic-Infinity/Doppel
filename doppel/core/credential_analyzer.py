"""
Credential Pattern Analyzer
============================
Classifies SSH authentication attempts by analyzing the username/password pair
across several dimensions:

  • same_as_username    — trivial credential reuse
  • default_credential  — known device/service defaults (admin:admin, pi:raspberry, …)
  • common_password     — top-10 000 password wordlist match
  • leaked_credential   — structured credential-dump format (user:hash, user:pass combos)
  • hash_pattern        — password field looks like a hash (MD5/SHA1/SHA256/bcrypt/…)
  • empty_password      — blank password (some scanners try this)
  • credential_stuffing — username looks like an e-mail address (credential-stuffing pattern)
  • keyboard_walk       — sequential keyboard patterns (qwerty, 123456, …)
  • complex_password     — long password with mixed chars (possibly a real user or pen-tester)

Results are attached to the session record and broadcast as a `credential_analyzed`
event so the dashboard and incident reports can display them.
"""

import re
import logging
from typing import Dict, Any

logger = logging.getLogger("doppel.core.credential_analyzer")

# ---------------------------------------------------------------------------
# Embedded compact wordlist — top ~200 most commonly tried SSH passwords.
# For production, point WORDLIST_PATH at a full rockyou / SecLists file and
# the analyzer will load it automatically (see _load_wordlist).
# ---------------------------------------------------------------------------
_BUILTIN_COMMON_PASSWORDS = {
    "", "123456", "password", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "password123", "admin", "admin123", "root", "toor",
    "test", "test123", "guest", "guest123", "user", "login", "pass",
    "changeme", "default", "1q2w3e", "1qaz2wsx", "qwerty123", "qwertyuiop",
    "zxcvbnm", "asdfghjkl", "123qwe", "1234", "12345", "123456789",
    "1234567890", "0987654321", "111111", "1111", "000000", "0000",
    "99999999", "123321", "666666", "888888", "55555", "7777777",
    "raspberry", "alpine", "ubnt", "support", "service", "operator",
    "oracle", "postgres", "mysql", "tomcat", "jenkins", "hadoop",
    "ubuntu", "debian", "centos", "fedora", "redhat",
    "P@ssw0rd", "P@$$w0rd", "Admin@123", "Welcome1", "Welcome123",
    "Summer2023", "Winter2023", "Spring2024", "Password@1",
}

# Known default credential pairs (username → set of default passwords)
_DEFAULT_CREDENTIALS: Dict[str, set] = {
    "admin":    {"admin", "admin123", "password", "1234", "Admin@123", "administrator"},
    "root":     {"root", "toor", "password", "1234", "pass", ""},
    "pi":       {"raspberry", "pi"},
    "ubuntu":   {"ubuntu", "password", ""},
    "user":     {"user", "user123", "password"},
    "test":     {"test", "test123", ""},
    "guest":    {"guest", "guest123", ""},
    "support":  {"support", "support123", "password"},
    "operator": {"operator", "operator123"},
    "oracle":   {"oracle", "oracle123", "password"},
    "postgres": {"postgres", "postgres123", "password"},
    "mysql":    {"mysql", "mysql123", "password"},
    "jenkins":  {"jenkins", "jenkins123", "password"},
    "hadoop":   {"hadoop", "hadoop123", "password"},
    "ansible":  {"ansible", "ansible123", "password"},
    "deploy":   {"deploy", "deploy123", "password"},
    "git":      {"git", "gitea", ""},
    "nagios":   {"nagios", "nagios123"},
    "zabbix":   {"zabbix", "zabbix123"},
}

# Hash pattern regexes — ordered from most to least specific
_HASH_PATTERNS = [
    ("bcrypt",        re.compile(r"^\$2[aby]\$\d{2}\$.{53}$")),
    ("sha512crypt",   re.compile(r"^\$6\$.{8,16}\$.{86}$")),
    ("sha256crypt",   re.compile(r"^\$5\$.{8,16}\$.{43}$")),
    ("md5crypt",      re.compile(r"^\$1\$.{8}\$.{22}$")),
    ("sha256_hex",    re.compile(r"^[0-9a-f]{64}$", re.I)),
    ("sha1_hex",      re.compile(r"^[0-9a-f]{40}$", re.I)),
    ("md5_hex",       re.compile(r"^[0-9a-f]{32}$", re.I)),
    ("ntlm",          re.compile(r"^[0-9a-f]{32}$", re.I)),  # same length as MD5 — ambiguous but noteworthy
]

# Keyboard-walk sequences
_KEYBOARD_WALKS = {
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1qaz2wsx", "1q2w3e4r", "1q2w3e", "qazwsx", "qazedc",
    "123456", "12345678", "1234567890", "098765", "987654321",
    "111111", "222222", "333333", "aaaaaa", "bbbbbb",
}

# Credential-dump line format: "username:password" or "username:hash"
_COLON_DUMP_RE = re.compile(r"^[a-zA-Z0-9._-]+:[^\s]{4,}$")

# E-mail address pattern → credential-stuffing signal
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


class CredentialAnalyzer:
    """
    Stateless classifier.  Call analyze(username, password) and get back
    a dict that is safe to store in the DB and broadcast over WebSocket.
    """

    def __init__(self, extra_wordlist_path: str | None = None):
        self._wordlist = set(_BUILTIN_COMMON_PASSWORDS)
        if extra_wordlist_path:
            self._load_wordlist(extra_wordlist_path)

    def _load_wordlist(self, path: str) -> None:
        """Load an external newline-delimited password wordlist (e.g. rockyou.txt)."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    word = line.strip()
                    if word:
                        self._wordlist.add(word)
            logger.info(f"Loaded {len(self._wordlist):,} words from wordlist {path}")
        except FileNotFoundError:
            logger.warning(f"Wordlist not found at {path} — using built-in list only")
        except Exception as exc:
            logger.warning(f"Failed to load wordlist {path}: {exc}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_generic(self, username: str, password: str) -> bool:
        """
        True when a credential pair is so widely sprayed that sharing it says
        nothing about who is behind two sessions (defaults, wordlist hits,
        username reuse, keyboard walks, blanks). Silent: no logging.
        """
        if not password:
            return True
        pw_lower = password.lower()
        if pw_lower == (username or "").lower():
            return True
        defaults_for_user = _DEFAULT_CREDENTIALS.get((username or "").lower(), set())
        if password in defaults_for_user or pw_lower in defaults_for_user:
            return True
        if password in self._wordlist or pw_lower in self._wordlist:
            return True
        return pw_lower in _KEYBOARD_WALKS

    def analyze(self, username: str, password: str) -> Dict[str, Any]:
        """
        Returns a credential analysis dict with keys:
            categories      list[str]   — all matching labels
            primary_label   str         — single most-significant label
            risk_level      str         — "low" | "medium" | "high" | "critical"
            is_default      bool        — matched a known device default pair
            is_common       bool        — in the common-password wordlist
            hash_type       str|None    — detected hash algorithm, or None
            notes           str         — human-readable summary sentence
        """
        pw_lower = password.lower()
        categories: list[str] = []

        # ---- Empty password -----------------------------------------------
        if password == "":
            categories.append("empty_password")

        # ---- Same as username ----------------------------------------------
        if password and password.lower() == username.lower():
            categories.append("same_as_username")

        # ---- Known default credential pair ---------------------------------
        is_default = False
        defaults_for_user = _DEFAULT_CREDENTIALS.get(username.lower(), set())
        if password in defaults_for_user or password.lower() in defaults_for_user:
            categories.append("default_credential")
            is_default = True

        # ---- Common password wordlist ---------------------------------------
        is_common = password in self._wordlist or pw_lower in self._wordlist
        if is_common and "default_credential" not in categories:
            categories.append("common_password")

        # ---- Hash pattern detection ----------------------------------------
        hash_type: str | None = None
        for name, pattern in _HASH_PATTERNS:
            if pattern.match(password):
                hash_type = name
                categories.append("hash_pattern")
                break

        # ---- Leaked credential-dump format ---------------------------------
        if _COLON_DUMP_RE.match(password) and ":" in password:
            categories.append("leaked_credential")

        # ---- Credential stuffing (email username) ---------------------------
        if _EMAIL_RE.match(username):
            categories.append("credential_stuffing")

        # ---- Keyboard walk -------------------------------------------------
        if pw_lower in _KEYBOARD_WALKS:
            categories.append("keyboard_walk")
        else:
            # Sliding window check for walks embedded in longer strings
            for walk in _KEYBOARD_WALKS:
                if len(walk) >= 4 and walk in pw_lower:
                    categories.append("keyboard_walk")
                    break

        # ---- Complex / strong password (possible human pen-tester) ---------
        if (
            len(password) >= 12
            and re.search(r"[A-Z]", password)
            and re.search(r"[a-z]", password)
            and re.search(r"\d", password)
            and re.search(r"[^A-Za-z0-9]", password)
            and not categories  # only flag as complex if nothing else matched
        ):
            categories.append("complex_password")

        # ---- Fallback ------------------------------------------------------
        if not categories:
            categories.append("unknown")

        # ---- Derive primary label and risk level ---------------------------
        priority_order = [
            "hash_pattern", "leaked_credential", "credential_stuffing",
            "default_credential", "same_as_username", "keyboard_walk",
            "common_password", "empty_password", "complex_password", "unknown",
        ]
        primary_label = next(
            (c for c in priority_order if c in categories), categories[0]
        )

        risk_map = {
            "hash_pattern":         "high",
            "leaked_credential":    "high",
            "credential_stuffing":  "high",
            "default_credential":   "critical",
            "same_as_username":     "critical",
            "keyboard_walk":        "medium",
            "common_password":      "medium",
            "empty_password":       "medium",
            "complex_password":     "low",
            "unknown":              "low",
        }
        risk_level = risk_map.get(primary_label, "low")

        # ---- Human-readable note -------------------------------------------
        notes = self._build_note(username, password, categories, hash_type)

        result: Dict[str, Any] = {
            "categories":    categories,
            "primary_label": primary_label,
            "risk_level":    risk_level,
            "is_default":    is_default,
            "is_common":     is_common,
            "hash_type":     hash_type,
            "notes":         notes,
        }

        logger.info(
            f"Credential analysis: user='{username}' | "
            f"label={primary_label} | risk={risk_level} | cats={categories}"
        )
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_note(
        self,
        username: str,
        password: str,
        categories: list[str],
        hash_type: str | None,
    ) -> str:
        if "hash_pattern" in categories:
            return (
                f"Password field contains a {hash_type or 'hash'} digest — "
                "attacker may be replaying a credential dump or testing hash-based auth."
            )
        if "leaked_credential" in categories:
            return (
                "Password is formatted as a 'user:pass' credential-dump entry — "
                "likely from an automated breach-replay tool."
            )
        if "credential_stuffing" in categories:
            return (
                f"Username '{username}' is an e-mail address — "
                "classic credential-stuffing pattern from a data-breach list."
            )
        if "default_credential" in categories:
            return (
                f"'{username}:{password}' is a well-known device or service default — "
                "automated scanner targeting default credentials."
            )
        if "same_as_username" in categories:
            return (
                f"Password equals the username ('{username}') — "
                "trivial credential reuse; likely automated."
            )
        if "keyboard_walk" in categories:
            return (
                f"Password '{password}' is a keyboard-walk sequence — "
                "low-effort brute-force attempt."
            )
        if "common_password" in categories:
            return (
                f"Password '{password}' appears in the common-password wordlist — "
                "dictionary/brute-force attack."
            )
        if "empty_password" in categories:
            return (
                "Empty password submitted — scanner testing for passwordless access."
            )
        if "complex_password" in categories:
            return (
                "Password is long and complex — may indicate a human operator or "
                "pen-tester using a personal/generated credential."
            )
        return f"Unclassified credential attempt for user '{username}'."
