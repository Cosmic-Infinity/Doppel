"""
Local GeoLite-based IP Geolocation Service
===========================================
Offline, zero-latency GeoIP resolution using local MaxMind GeoLite2 .mmdb files.

Guarantees:
  - No request-time outbound network calls.
  - Thread-safe reader reuse and memory-mapped file access.
  - Safe handling of invalid, private, loopback, IPv4-mapped, CGNAT, and IPv6 addresses.
  - Graceful degradation when databases are absent, unreadable, or corrupt.

Download (free, requires MaxMind account):
  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Configure via config.yaml:
  geoip:
    city_db_path: /opt/geoip/GeoLite2-City.mmdb
    asn_db_path:  /opt/geoip/GeoLite2-ASN.mmdb
"""

import ipaddress
import logging
import os
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger("doppel.core.geoip")

_DATACENTER_ORG_SUBSTRINGS = frozenset([
    # Hyperscalers
    "amazon", "aws", "google", "microsoft", "azure", "oracle cloud",
    "ibm cloud", "alibaba", "tencent cloud", "huawei cloud",
    # VPS / bare-metal hosters
    "digitalocean", "linode", "akamai", "vultr", "hetzner", "ovh",
    "leaseweb", "choopa", "constant", "psychz", "tzulo", "softlayer",
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
    "imperva", "edgecast",
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


class GeoIPService:
    """
    Thread-safe, offline MaxMind GeoLite2 lookup service.

    Lifecycle::

        svc = GeoIPService(city_db_path="...", asn_db_path="...")
        svc.initialize()
        geo = svc.lookup("1.2.3.4")
        svc.close()   # releases memory-mapped .mmdb file handles
    """

    def __init__(self, city_db_path: str = "", asn_db_path: str = ""):
        self.city_db_path = city_db_path
        self.asn_db_path = asn_db_path
        self._city_reader = None
        self._asn_reader = None
        self._lock = threading.Lock()
        self._warned_missing = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(
        self,
        city_db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
    ) -> None:
        """
        (Re-)open the .mmdb readers under the class lock.

        Safe to call multiple times; previous readers are closed first.
        No-op (with a one-time warning) when maxminddb is not installed or
        database paths are missing/empty.
        """
        with self._lock:
            if city_db_path is not None:
                self.city_db_path = city_db_path
            if asn_db_path is not None:
                self.asn_db_path = asn_db_path

            self._close_readers_unlocked()

            try:
                import maxminddb  # type: ignore
            except ImportError:
                if not self._warned_missing:
                    logger.warning(
                        "maxminddb library not installed — pip install maxminddb. "
                        "Local GeoIP enrichment disabled."
                    )
                    self._warned_missing = True
                return

            if self.city_db_path and os.path.exists(self.city_db_path):
                try:
                    self._city_reader = maxminddb.open_database(self.city_db_path)
                    logger.info(f"GeoIP City database loaded: {self.city_db_path}")
                except Exception as exc:
                    logger.error(
                        f"Failed to open GeoLite2-City database at "
                        f"{self.city_db_path}: {exc}"
                    )

            if self.asn_db_path and os.path.exists(self.asn_db_path):
                try:
                    self._asn_reader = maxminddb.open_database(self.asn_db_path)
                    logger.info(f"GeoIP ASN database loaded: {self.asn_db_path}")
                except Exception as exc:
                    logger.error(
                        f"Failed to open GeoLite2-ASN database at "
                        f"{self.asn_db_path}: {exc}"
                    )

            if not self._city_reader and not self._asn_reader and not self._warned_missing:
                logger.info(
                    "GeoLite2 databases not configured or not found. "
                    "Running in offline zero-enrichment mode."
                )
                self._warned_missing = True

    def close(self) -> None:
        """Release memory-mapped .mmdb file handles cleanly."""
        with self._lock:
            self._close_readers_unlocked()

    def _close_readers_unlocked(self) -> None:
        """Must be called with self._lock held."""
        if self._city_reader is not None:
            try:
                self._city_reader.close()
            except Exception:
                pass
            self._city_reader = None
        if self._asn_reader is not None:
            try:
                self._asn_reader.close()
            except Exception:
                pass
            self._asn_reader = None

    # ------------------------------------------------------------------
    # IP parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_ip(
        ip_str: str,
    ) -> Optional["ipaddress.IPv4Address | ipaddress.IPv6Address"]:
        """
        Validate and normalise an IP string.

        * Strips surrounding whitespace and brackets (IPv6 literal form).
        * Unwraps IPv4-mapped IPv6 addresses (``::ffff:1.2.3.4`` → ``1.2.3.4``).
        * Returns ``None`` for empty, non-string, or unparseable input.
        """
        if not ip_str or not isinstance(ip_str, str):
            return None
        cleaned = ip_str.strip().strip("[]")
        try:
            addr = ipaddress.ip_address(cleaned)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                return addr.ipv4_mapped
            return addr
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, ip_str: str) -> Dict[str, Any]:
        """
        Perform a fully local lookup — zero outbound network calls.

        Returns a dict with keys:
            ip, country_code, country_name, city, latitude, longitude,
            asn, asn_org, is_datacenter, is_private, enriched

        Addresses that are loopback, unspecified, private, link-local,
        CGNAT (100.64/10), reserved, or multicast are flagged with
        ``is_private=True``; they are still passed to the readers (MaxMind
        may have records for RFC 6598 CGNAT space) but the flag is always set.
        """
        result: Dict[str, Any] = {
            "ip": ip_str,
            "country_code": None,
            "country_name": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "asn_org": None,
            "is_datacenter": False,
            "is_private": False,
            "enriched": False,
        }

        addr = self.parse_ip(ip_str)
        if addr is None:
            return result

        norm_ip = str(addr)
        result["ip"] = norm_ip

        # Short-circuit for addresses that can never appear in GeoIP DBs
        if addr.is_loopback:
            result["is_private"] = True
            result["country_code"] = "LOOPBACK"
            result["country_name"] = "Loopback"
            return result

        if addr.is_unspecified:
            result["is_private"] = True
            result["country_code"] = "UNSPECIFIED"
            result["country_name"] = "Unspecified"
            return result

        # RFC 6598 Carrier-Grade NAT (100.64.0.0/10) — Python's stdlib does not
        # mark this range as .is_private (changed in 3.11), so we check manually.
        _CGNAT = ipaddress.ip_network("100.64.0.0/10")
        is_cgnat = isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT

        is_internal = (
            addr.is_private
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or is_cgnat
        )

        # Snapshot readers under the lock — the actual DB calls run outside it
        # so we do not block other threads during I/O.
        with self._lock:
            city_reader = self._city_reader
            asn_reader = self._asn_reader

        found_city = False
        if city_reader is not None:
            try:
                rec = city_reader.get(norm_ip)
                if rec:
                    country = rec.get("country", {})
                    city_rec = rec.get("city", {})
                    location = rec.get("location", {})
                    result["country_code"] = country.get("iso_code")
                    result["country_name"] = (
                        (country.get("names") or {}).get("en")
                        or country.get("iso_code")
                    )
                    result["city"] = (city_rec.get("names") or {}).get("en")
                    result["latitude"] = location.get("latitude")
                    result["longitude"] = location.get("longitude")
                    result["enriched"] = True
                    found_city = True
            except Exception as exc:
                logger.debug(f"GeoLite2-City lookup error for {norm_ip}: {exc}")

        if asn_reader is not None:
            try:
                rec = asn_reader.get(norm_ip)
                if rec:
                    asn_num = rec.get("autonomous_system_number")
                    asn_org = rec.get("autonomous_system_organization", "")
                    result["asn"] = asn_num
                    result["asn_org"] = asn_org
                    if asn_org:
                        lower = asn_org.lower()
                        result["is_datacenter"] = any(
                            sub in lower for sub in _DATACENTER_ORG_SUBSTRINGS
                        )
                    result["enriched"] = True
            except Exception as exc:
                logger.debug(f"GeoLite2-ASN lookup error for {norm_ip}: {exc}")

        if is_internal:
            result["is_private"] = True
            if not found_city:
                result["country_code"] = "PRIVATE"
                result["country_name"] = "Private/Internal"

        return result


# ---------------------------------------------------------------------------
# Module-level singleton (backward-compatible helpers)
# ---------------------------------------------------------------------------

_DEFAULT_SERVICE: Optional[GeoIPService] = None
_SERVICE_LOCK = threading.Lock()


def get_geoip_service(city_db_path: str = "", asn_db_path: str = "") -> GeoIPService:
    """
    Return (and lazily create) the process-wide GeoIPService singleton.

    Calling with new paths re-initializes the readers transparently.
    """
    global _DEFAULT_SERVICE
    with _SERVICE_LOCK:
        if _DEFAULT_SERVICE is None:
            _DEFAULT_SERVICE = GeoIPService(city_db_path, asn_db_path)
            _DEFAULT_SERVICE.initialize()
        elif (city_db_path and city_db_path != _DEFAULT_SERVICE.city_db_path) or (
            asn_db_path and asn_db_path != _DEFAULT_SERVICE.asn_db_path
        ):
            _DEFAULT_SERVICE.initialize(city_db_path, asn_db_path)
        return _DEFAULT_SERVICE


def enrich(ip: str, city_db_path: str = "", asn_db_path: str = "") -> Dict[str, Any]:
    """
    Backward-compatible synchronous GeoIP enrichment.

    Returns the same dict shape as ``GeoIPService.lookup()``.
    Safe to call directly from asyncssh callbacks — sub-millisecond against
    a local .mmdb file, no executor wrapping needed.
    """
    return get_geoip_service(city_db_path, asn_db_path).lookup(ip)


def format_summary(geo: Dict[str, Any]) -> str:
    """One-line human-readable summary suitable for log lines."""
    if geo.get("is_private") and not geo.get("enriched"):
        return f"{geo['ip']} (private/loopback)"
    parts = []
    if geo.get("city"):
        parts.append(str(geo["city"]))
    if geo.get("country_code"):
        parts.append(str(geo["country_code"]))
    location = ", ".join(parts) or "unknown location"
    asn_str = (
        f"AS{geo['asn']} {geo['asn_org']}" if geo.get("asn") else "unknown ASN"
    )
    dc_flag = " [DATACENTER]" if geo.get("is_datacenter") else ""
    priv_flag = " [INTERNAL]" if geo.get("is_private") else ""
    return f"{geo['ip']} | {location} | {asn_str}{dc_flag}{priv_flag}"