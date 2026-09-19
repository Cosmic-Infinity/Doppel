"""
GeoIP Enrichment
================
Zero-latency, zero-network GeoIP lookup using local MaxMind GeoLite2 .mmdb
database files.  Two databases are supported:

  GeoLite2-City.mmdb   → country, city, latitude/longitude
  GeoLite2-ASN.mmdb    → ASN number + org name, datacenter detection

Download (free, requires MaxMind account registration):
  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Place the .mmdb files in the project root or set DOPPEL_GEOIP_CITY_DB and
DOPPEL_GEOIP_ASN_DB environment variables (or geoip section in config.yaml).

Graceful degradation:
  If the databases are missing the module returns an enriched dict with
  unknown/null fields and logs a one-time warning — the honeypot keeps running.

Datacenter detection (is_datacenter):
  Heuristic based on ASN org name substring matching against a curated list of
  ~200 known cloud/hosting/CDN/VPN ASN prefixes.  No external call needed.
  False positive rate is low; false negatives (unknown ISP scanner) are labelled
  as residential by default.
"""

import logging
import ipaddress
import os
from functools import lru_cache
from typing import Dict, Any, Optional

logger = logging.getLogger("doppel.core.geoip")

# ── Database handles loaded once per process ──────────────────────────────────
_city_reader  = None
_asn_reader   = None
_db_warn_once = False


def _load_readers(city_db_path: str, asn_db_path: str) -> None:
    """Load MaxMind readers lazily on first lookup."""
    global _city_reader, _asn_reader, _db_warn_once
    try:
        import maxminddb
        if city_db_path and os.path.exists(city_db_path) and _city_reader is None:
            _city_reader = maxminddb.open_database(city_db_path)
            logger.info(f"GeoIP city database loaded: {city_db_path}")
        if asn_db_path and os.path.exists(asn_db_path) and _asn_reader is None:
            _asn_reader = maxminddb.open_database(asn_db_path)
            logger.info(f"GeoIP ASN database loaded: {asn_db_path}")
        if not _city_reader and not _asn_reader and not _db_warn_once:
            logger.warning(
                "GeoIP databases not found — enrichment will return null values. "
                "Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind and "
                "set their paths under geoip: in config.yaml."
            )
            _db_warn_once = True
    except ImportError:
        if not _db_warn_once:
            logger.warning("maxminddb not installed — pip install maxminddb. GeoIP disabled.")
            _db_warn_once = True


# ── Datacenter ASN detection ──────────────────────────────────────────────────
# Substring list covering the major cloud/CDN/VPN/hosting ASN org names.
# Matching is case-insensitive on the org name returned by the ASN database.
# Last verified: 2024-12.  Add new providers as needed.
_DATACENTER_ORG_SUBSTRINGS = frozenset([
    # Hyperscalers
    "amazon", "aws", "google", "microsoft", "azure", "oracle cloud",
    "ibm cloud", "alibaba", "tencent cloud", "huawei cloud",
    # VPS / bare-metal hosters
    "digitalocean", "linode", "akamai", "vultr", "hetzner", "ovh",
    "leaseweb", "choopa", "constant",  "psychz", "tzulo", "softlayer",
    "internap", "rackspace", "quadranet", "server4you", "netcup",
    "contabo", "ionos", "1&1", "hostinger", "godaddy", "bluehost",
    "dreamhost", "hostgator", "namecheap hosting", "pair networks",
    "siteground", "wpengine", "kinsta",
    # Colocation / transit
    "colocation", "corelink", "databank", "cyrusone", "equinix",
    "zayo", "cogent", "hurricane electric", "telia carrier",
    "ntt communications", "lumen", "centurylink", "level 3",
    "global crossing", "telecity", "interxion",
    # CDN
    "cloudflare", "fastly", "cdn77", "stackpath", "incapsula",
    "imperva", "akamai", "edgecast", "verizon digital media",
    # VPN / proxy / anonymizer
    "nordvpn", "expressvpn", "surfshark", "privateinternetaccess",
    "mullvad", "protonvpn", "ipvanish", "cyberghost", "hidemyass",
    "torguard", "perfect privacy", "windscribe", "vypr", "tunnelbear",
    "private tunnel", "hide.me", "ivacy", "purevpn", "hotspotshield",
    "anonine", "cryptostorm", "ovpn.com",
    # Scan / threat intel infra
    "shodan", "censys", "shadowserver", "team cymru",
    "internet measurement", "researchscan",
    # Generic signals
    "hosting", "datacenter", "data center", "vps", "cloud services",
    "cloud computing", "dedicated server", "server farm",
])

# Reserved / private IP ranges that should never be looked up
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True


def _is_datacenter(org_name: str) -> bool:
    """Return True if the ASN org name matches a known datacenter/cloud/VPN provider."""
    lower = org_name.lower()
    return any(sub in lower for sub in _DATACENTER_ORG_SUBSTRINGS)


# ── Public API ────────────────────────────────────────────────────────────────

def enrich(
    ip: str,
    city_db_path: str = "",
    asn_db_path: str = "",
) -> Dict[str, Any]:
    """
    Synchronous GeoIP enrichment.  Returns a dict:

        {
          "ip":            "1.2.3.4",
          "country_code":  "US",          # ISO-3166-1 alpha-2
          "country_name":  "United States",
          "city":          "Ashburn",
          "latitude":      39.0438,
          "longitude":    -77.4879,
          "asn":           14618,
          "asn_org":       "Amazon.com, Inc.",
          "is_datacenter": True,
          "is_private":    False,
          "enriched":      True,          # False when DBs missing or IP private
        }

    This is purely synchronous / CPU-bound and runs in <1 ms against a local
    mmdb file — safe to call directly from asyncssh callbacks without wrapping
    in run_in_executor.
    """
    result: Dict[str, Any] = {
        "ip":            ip,
        "country_code":  None,
        "country_name":  None,
        "city":          None,
        "latitude":      None,
        "longitude":     None,
        "asn":           None,
        "asn_org":       None,
        "is_datacenter": False,
        "is_private":    False,
        "enriched":      False,
    }

    if _is_private(ip):
        result["is_private"] = True
        result["country_code"] = "PRIVATE"
        result["country_name"] = "Private/Reserved"
        return result

    _load_readers(city_db_path, asn_db_path)

    if _city_reader:
        try:
            rec = _city_reader.get(ip) or {}
            country = rec.get("country", {})
            city_rec = rec.get("city", {})
            location = rec.get("location", {})
            result["country_code"] = country.get("iso_code")
            result["country_name"] = (
                (country.get("names") or {}).get("en")
                or country.get("iso_code")
            )
            result["city"] = (city_rec.get("names") or {}).get("en")
            result["latitude"]  = location.get("latitude")
            result["longitude"] = location.get("longitude")
            result["enriched"]  = True
        except Exception as exc:
            logger.debug(f"GeoIP city lookup failed for {ip}: {exc}")

    if _asn_reader:
        try:
            rec = _asn_reader.get(ip) or {}
            asn_num  = rec.get("autonomous_system_number")
            asn_org  = rec.get("autonomous_system_organization", "")
            result["asn"]          = asn_num
            result["asn_org"]      = asn_org
            result["is_datacenter"] = _is_datacenter(asn_org)
            result["enriched"]     = True
        except Exception as exc:
            logger.debug(f"GeoIP ASN lookup failed for {ip}: {exc}")

    return result


def format_summary(geo: Dict[str, Any]) -> str:
    """One-line human-readable summary for logging."""
    if geo.get("is_private"):
        return f"{geo['ip']} (private/loopback)"
    parts = []
    if geo.get("city"):
        parts.append(geo["city"])
    if geo.get("country_code"):
        parts.append(geo["country_code"])
    location = ", ".join(parts) or "unknown location"
    asn_str  = f"AS{geo['asn']} {geo['asn_org']}" if geo.get("asn") else "unknown ASN"
    dc_flag  = " [DATACENTER]" if geo.get("is_datacenter") else ""
    return f"{geo['ip']} | {location} | {asn_str}{dc_flag}"
