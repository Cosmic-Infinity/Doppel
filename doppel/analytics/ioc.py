"""
Indicator of Compromise (IOC) Extractor
========================================
Extracts and normalizes URLs, IP addresses (public and private, since private
ones point at lateral movement targets) and hostnames/domains from session
commands for analyst triage and threat intelligence.
"""

import re
import ipaddress
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

# URL regex matching http, https, ftp, tftp
_URL_RE = re.compile(
    r"""\b(?:https?|ftp|tftp)://[^\s'"<>)\]}]+""",
    re.I,
)

# IPv4 regex
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Domain / FQDN regex
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Excluded extensions often mistaken for domains in shell commands
_FILE_EXTENSIONS = frozenset([
    "sh", "py", "pl", "rb", "php", "js", "ts", "json", "yaml", "yml",
    "conf", "config", "txt", "log", "md", "tar", "gz", "zip", "bz2",
    "bak", "old", "swp", "lock", "env", "local", "internal",
    "tgz", "xz", "rar", "7z", "sql", "db", "sqlite", "csv", "xml", "html", "htm",
    "ini", "cfg", "pem", "key", "crt", "pub", "so", "deb", "rpm", "jar", "war",
    "bin", "exe", "dll", "service", "socket", "timer", "mount", "target", "pid",
    "tmp", "orig", "dist", "list", "gpg", "asc", "c", "h", "go", "java", "rs",
])

# Characters around a bare host name when it is a whole shell argument, e.g.
# `ping evil.com`, `ssh user@evil.com`, `nc evil.com 4444`, `curl evil.com/x`
_ARG_BEFORE = " \t@=;|&('\""
_ARG_AFTER = " \t:/;|&)'\""

# Code passed inline to an interpreter (python -c, perl -e, ...)
_INLINE_CODE_RE = re.compile(
    r"""\b(?:python[\d.]*|perl|ruby|php|node)\s+-[ce]\s+(?:"[^"]*"|'[^']*'|\S+)""",
    re.I,
)

# Common benign system domains to suppress from malware IOC panels
_BENIGN_DOMAINS = frozenset([
    "help.ubuntu.com", "landscape.canonical.com", "ubuntu.com",
    "debian.org", "kernel.org", "github.com", "microsoft.com",
])


def _strip_trailing_punct(s: str) -> str:
    return s.rstrip(".,;:)'\"]}")


def extract_urls(text: str) -> List[str]:
    """Extract unique valid URLs from command text."""
    if not text:
        return []
    urls: List[str] = []
    seen: Set[str] = set()
    for match in _URL_RE.finditer(text):
        url = _strip_trailing_punct(match.group(0))
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def extract_ips(text: str, exclude_loopback: bool = True) -> List[str]:
    """Extract unique IPv4 addresses from command text, validating octets."""
    if not text:
        return []
    ips: List[str] = []
    seen: Set[str] = set()

    # Mask URLs to prevent double-counting IPs already in URLs
    masked = _URL_RE.sub(" ", text)

    for match in _IPV4_RE.finditer(masked):
        raw_ip = match.group(0)
        try:
            addr = ipaddress.ip_address(raw_ip)
            if exclude_loopback and (addr.is_loopback or addr.is_unspecified):
                continue
            norm = str(addr)
            if norm not in seen:
                seen.add(norm)
                ips.append(norm)
        except ValueError:
            continue
    return ips


def extract_domains(text: str) -> List[str]:
    """Extract hostnames/domains from URLs and command arguments."""
    if not text:
        return []
    domains: List[str] = []
    seen: Set[str] = set()

    # 1. Extract domains from found URLs
    for url in extract_urls(text):
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host and not _IPV4_RE.match(host):
                norm = host.lower()
                if norm not in seen and norm not in _BENIGN_DOMAINS:
                    seen.add(norm)
                    domains.append(norm)
        except Exception:
            continue

    # 2. Extract bare host names given as arguments (e.g. curl evil.com/x).
    # Inline interpreter code is skipped: `os.path` in `python3 -c "..."` is not a host.
    bare = _INLINE_CODE_RE.sub(" ", text)
    for match in _DOMAIN_RE.finditer(bare):
        start, end = match.span()
        if (start > 0 and bare[start - 1] not in _ARG_BEFORE) or (end < len(bare) and bare[end] not in _ARG_AFTER):
            continue
        raw_domain = _strip_trailing_punct(match.group(0)).lower()
        parts = raw_domain.split(".")
        tld = parts[-1]
        if tld in _FILE_EXTENSIONS:
            continue
        if raw_domain not in seen and raw_domain not in _BENIGN_DOMAINS:
            seen.add(raw_domain)
            domains.append(raw_domain)

    return domains


def extract_session_iocs(commands: List[Any]) -> Dict[str, Any]:
    """
    Parse a list of command records (strings or dicts) and return structured,
    deduplicated IOCs along with indicator counts.
    """
    urls_map: Dict[str, List[str]] = {}
    ips_map: Dict[str, List[str]] = {}
    domains_map: Dict[str, List[str]] = {}

    for item in commands:
        cmd_str = item.get("command", "") if isinstance(item, dict) else str(item)
        if not cmd_str or not cmd_str.strip():
            continue

        for u in extract_urls(cmd_str):
            urls_map.setdefault(u, []).append(cmd_str)

        for ip in extract_ips(cmd_str):
            ips_map.setdefault(ip, []).append(cmd_str)

        for d in extract_domains(cmd_str):
            domains_map.setdefault(d, []).append(cmd_str)

    urls_list = [{"value": k, "commands": v} for k, v in urls_map.items()]
    ips_list = [{"value": k, "commands": v} for k, v in ips_map.items()]
    domains_list = [{"value": k, "commands": v} for k, v in domains_map.items()]

    total = len(urls_list) + len(ips_list) + len(domains_list)

    return {
        "urls": urls_list,
        "ips": ips_list,
        "domains": domains_list,
        "total_count": total,
        "has_iocs": total > 0,
    }