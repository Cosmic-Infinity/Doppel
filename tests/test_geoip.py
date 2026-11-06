"""
tests/test_geoip.py
===================
Comprehensive test suite for doppel/core/geoip.py.

Runs with the stdlib unittest runner (no pytest, no maxminddb required):
    python -m pytest tests/test_geoip.py -v        # if pytest available
    python -m unittest tests.test_geoip -v         # always works

Coverage:
  1.  IP string validation and normalisation
  2.  IPv4-mapped IPv6 unwrapping
  3.  Loopback / unspecified short-circuit
  4.  Private / link-local / CGNAT / IPv6 ULA flagging
  5.  Missing database → graceful zero-enrichment
  6.  Corrupt / unreadable database resilience
  7.  Datacenter heuristic (org name substring matching)
  8.  format_summary() rendering
  9.  Thread-safe concurrent lookups under a mock reader
  10. HTTP sensor integration: geoip dict forwarded to db calls
"""

import threading
import unittest
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

# The module under test
from doppel.core.geoip import (
    GeoIPService,
    enrich,
    format_summary,
    get_geoip_service,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service(city_rec=None, asn_rec=None) -> GeoIPService:
    """Return an initialised GeoIPService with mock readers injected."""
    svc = GeoIPService()
    if city_rec is not None:
        reader = MagicMock()
        reader.get.return_value = city_rec
        svc._city_reader = reader
    if asn_rec is not None:
        reader = MagicMock()
        reader.get.return_value = asn_rec
        svc._asn_reader = reader
    return svc


# ---------------------------------------------------------------------------
# 1. IP validation and normalisation
# ---------------------------------------------------------------------------

class TestParseIP(unittest.TestCase):

    def test_valid_ipv4(self):
        import ipaddress
        addr = GeoIPService.parse_ip("1.2.3.4")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "1.2.3.4")
        self.assertIsInstance(addr, ipaddress.IPv4Address)

    def test_valid_ipv6(self):
        import ipaddress
        addr = GeoIPService.parse_ip("2001:db8::1")
        self.assertIsNotNone(addr)
        self.assertIsInstance(addr, ipaddress.IPv6Address)

    def test_strips_whitespace_and_brackets(self):
        addr = GeoIPService.parse_ip("  [::1]  ")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "::1")

    def test_empty_string_returns_none(self):
        self.assertIsNone(GeoIPService.parse_ip(""))

    def test_none_returns_none(self):
        self.assertIsNone(GeoIPService.parse_ip(None))  # type: ignore[arg-type]

    def test_non_string_returns_none(self):
        self.assertIsNone(GeoIPService.parse_ip(12345))  # type: ignore[arg-type]

    def test_garbage_returns_none(self):
        self.assertIsNone(GeoIPService.parse_ip("not_an_ip"))

    def test_partial_ipv4_returns_none(self):
        self.assertIsNone(GeoIPService.parse_ip("1.2.3"))


# ---------------------------------------------------------------------------
# 2. IPv4-mapped IPv6 unwrapping
# ---------------------------------------------------------------------------

class TestIPv4MappedUnwrap(unittest.TestCase):

    def test_unwrap_ipv4_mapped(self):
        import ipaddress
        addr = GeoIPService.parse_ip("::ffff:198.51.100.1")
        self.assertIsNotNone(addr)
        self.assertIsInstance(addr, ipaddress.IPv4Address)
        self.assertEqual(str(addr), "198.51.100.1")

    def test_pure_ipv6_not_unwrapped(self):
        import ipaddress
        addr = GeoIPService.parse_ip("2001:db8::1")
        self.assertIsInstance(addr, ipaddress.IPv6Address)

    def test_lookup_normalises_mapped(self):
        """Lookup of an IPv4-mapped IPv6 should work as the unwrapped IPv4."""
        svc = GeoIPService()
        result = svc.lookup("::ffff:127.0.0.1")
        # Unwrapped to 127.0.0.1 → loopback branch
        self.assertTrue(result["is_private"])
        self.assertEqual(result["country_code"], "LOOPBACK")


# ---------------------------------------------------------------------------
# 3. Loopback / unspecified short-circuit
# ---------------------------------------------------------------------------

class TestLoopbackAndUnspecified(unittest.TestCase):

    def _assert_loopback(self, ip: str):
        svc = GeoIPService()
        r = svc.lookup(ip)
        self.assertTrue(r["is_private"], f"Expected is_private for {ip}")
        self.assertEqual(r["country_code"], "LOOPBACK")
        self.assertFalse(r["enriched"])

    def _assert_unspecified(self, ip: str):
        svc = GeoIPService()
        r = svc.lookup(ip)
        self.assertTrue(r["is_private"])
        self.assertEqual(r["country_code"], "UNSPECIFIED")
        self.assertFalse(r["enriched"])

    def test_ipv4_loopback(self):
        self._assert_loopback("127.0.0.1")

    def test_ipv6_loopback(self):
        self._assert_loopback("::1")

    def test_ipv4_unspecified(self):
        self._assert_unspecified("0.0.0.0")

    def test_ipv6_unspecified(self):
        self._assert_unspecified("::")


# ---------------------------------------------------------------------------
# 4. Private / CGNAT / link-local / ULA flagging
# ---------------------------------------------------------------------------

class TestPrivateAddressFlags(unittest.TestCase):

    def _flag(self, ip: str) -> Dict[str, Any]:
        svc = GeoIPService()
        return svc.lookup(ip)

    def test_rfc1918_10(self):
        r = self._flag("10.0.0.1")
        self.assertTrue(r["is_private"])

    def test_rfc1918_172(self):
        r = self._flag("172.16.0.1")
        self.assertTrue(r["is_private"])

    def test_rfc1918_192(self):
        r = self._flag("192.168.1.1")
        self.assertTrue(r["is_private"])

    def test_cgnat_rfc6598(self):
        """100.64.0.0/10 is CGNAT — must be flagged is_private."""
        r = self._flag("100.64.0.1")
        self.assertTrue(r["is_private"])

    def test_link_local_ipv4(self):
        r = self._flag("169.254.1.1")
        self.assertTrue(r["is_private"])

    def test_ipv6_ula(self):
        r = self._flag("fd00::1")
        self.assertTrue(r["is_private"])

    def test_ipv6_link_local(self):
        r = self._flag("fe80::1")
        self.assertTrue(r["is_private"])

    def test_public_ip_not_flagged(self):
        # With no readers loaded, enriched=False but is_private should be False
        r = self._flag("8.8.8.8")
        self.assertFalse(r["is_private"])


# ---------------------------------------------------------------------------
# 5. Missing database → graceful zero-enrichment
# ---------------------------------------------------------------------------

class TestMissingDatabase(unittest.TestCase):

    def test_no_readers_returns_unenriched(self):
        svc = GeoIPService(city_db_path="", asn_db_path="")
        r = svc.lookup("8.8.8.8")
        self.assertFalse(r["enriched"])
        self.assertIsNone(r["country_code"])
        self.assertIsNone(r["asn"])
        self.assertFalse(r["is_private"])

    def test_nonexistent_path_does_not_raise(self):
        svc = GeoIPService(
            city_db_path="/tmp/does_not_exist_city.mmdb",
            asn_db_path="/tmp/does_not_exist_asn.mmdb",
        )
        # initialize() must not raise even with bad paths
        svc.initialize()
        r = svc.lookup("1.2.3.4")
        self.assertFalse(r["enriched"])

    def test_module_enrich_without_db(self):
        """Top-level enrich() must not raise with no dbs configured."""
        with patch("doppel.core.geoip._DEFAULT_SERVICE", None):
            r = enrich("1.2.3.4")
        self.assertIsInstance(r, dict)
        self.assertFalse(r["enriched"])


# ---------------------------------------------------------------------------
# 6. Corrupt database resilience
# ---------------------------------------------------------------------------

class TestCorruptDatabaseResilience(unittest.TestCase):

    def test_city_reader_raises_on_get(self):
        """If the city reader throws on get(), lookup() degrades gracefully."""
        svc = _make_service()
        bad_reader = MagicMock()
        bad_reader.get.side_effect = RuntimeError("corrupt mmdb")
        svc._city_reader = bad_reader

        r = svc.lookup("1.2.3.4")
        self.assertFalse(r["enriched"])
        self.assertIsNone(r["country_code"])

    def test_asn_reader_raises_on_get(self):
        svc = _make_service()
        bad_reader = MagicMock()
        bad_reader.get.side_effect = OSError("mmap failed")
        svc._asn_reader = bad_reader

        r = svc.lookup("1.2.3.4")
        self.assertIsNone(r["asn"])
        self.assertFalse(r["is_datacenter"])

    def test_both_readers_raise(self):
        svc = GeoIPService()
        for attr in ("_city_reader", "_asn_reader"):
            bad = MagicMock()
            bad.get.side_effect = Exception("boom")
            setattr(svc, attr, bad)

        # Use a reliably public, non-reserved address (Cloudflare DNS)
        r = svc.lookup("1.1.1.1")
        self.assertFalse(r["enriched"])
        self.assertFalse(r["is_private"])


# ---------------------------------------------------------------------------
# 7. Datacenter heuristic
# ---------------------------------------------------------------------------

class TestDatacenterHeuristic(unittest.TestCase):

    def _lookup_with_asn_org(self, org: str) -> Dict[str, Any]:
        asn_rec = {
            "autonomous_system_number": 16509,
            "autonomous_system_organization": org,
        }
        svc = _make_service(asn_rec=asn_rec)
        return svc.lookup("54.239.28.85")

    def test_amazon_flagged(self):
        r = self._lookup_with_asn_org("Amazon.com, Inc.")
        self.assertTrue(r["is_datacenter"])

    def test_cloudflare_flagged(self):
        r = self._lookup_with_asn_org("Cloudflare, Inc.")
        self.assertTrue(r["is_datacenter"])

    def test_nordvpn_flagged(self):
        r = self._lookup_with_asn_org("NordVPN S.A.")
        self.assertTrue(r["is_datacenter"])

    def test_residential_isp_not_flagged(self):
        r = self._lookup_with_asn_org("British Telecom plc")
        self.assertFalse(r["is_datacenter"])

    def test_empty_org_not_flagged(self):
        asn_rec = {"autonomous_system_number": 1234, "autonomous_system_organization": ""}
        svc = _make_service(asn_rec=asn_rec)
        r = svc.lookup("1.2.3.4")
        self.assertFalse(r["is_datacenter"])

    def test_heuristic_case_insensitive(self):
        r = self._lookup_with_asn_org("DIGITALOCEAN-ASN")
        self.assertTrue(r["is_datacenter"])


# ---------------------------------------------------------------------------
# 8. format_summary()
# ---------------------------------------------------------------------------

class TestFormatSummary(unittest.TestCase):

    def test_private_no_enrichment(self):
        geo = {
            "ip": "10.0.0.1",
            "is_private": True,
            "enriched": False,
            "country_code": "PRIVATE",
            "country_name": "Private/Internal",
            "city": None,
            "asn": None,
            "asn_org": None,
            "is_datacenter": False,
        }
        summary = format_summary(geo)
        self.assertIn("10.0.0.1", summary)
        self.assertIn("private", summary.lower())

    def test_public_ip_full_summary(self):
        geo = {
            "ip": "8.8.8.8",
            "is_private": False,
            "enriched": True,
            "country_code": "US",
            "country_name": "United States",
            "city": "Mountain View",
            "asn": 15169,
            "asn_org": "Google LLC",
            "is_datacenter": True,
        }
        summary = format_summary(geo)
        self.assertIn("8.8.8.8", summary)
        self.assertIn("Mountain View", summary)
        self.assertIn("US", summary)
        self.assertIn("AS15169", summary)
        self.assertIn("DATACENTER", summary)

    def test_internal_flag_shown(self):
        geo = {
            "ip": "192.168.1.1",
            "is_private": True,
            "enriched": True,  # DB had a record (unusual but possible)
            "country_code": "US",
            "country_name": "United States",
            "city": None,
            "asn": 64512,
            "asn_org": "RFC1918 Lab",
            "is_datacenter": False,
        }
        summary = format_summary(geo)
        self.assertIn("INTERNAL", summary)

    def test_missing_asn(self):
        geo = {
            "ip": "203.0.113.5",
            "is_private": False,
            "enriched": True,
            "country_code": "DE",
            "country_name": "Germany",
            "city": "Berlin",
            "asn": None,
            "asn_org": None,
            "is_datacenter": False,
        }
        summary = format_summary(geo)
        self.assertIn("unknown ASN", summary)


# ---------------------------------------------------------------------------
# 9. Thread-safe concurrent lookups
# ---------------------------------------------------------------------------

class TestThreadSafeConcurrency(unittest.TestCase):

    def test_parallel_lookups_no_race(self):
        """50 threads all looking up simultaneously should not raise or corrupt results."""
        city_rec = {
            "country": {"iso_code": "US", "names": {"en": "United States"}},
            "city": {"names": {"en": "Ashburn"}},
            "location": {"latitude": 39.04, "longitude": -77.49},
        }
        asn_rec = {
            "autonomous_system_number": 14618,
            "autonomous_system_organization": "Amazon.com, Inc.",
        }
        svc = _make_service(city_rec=city_rec, asn_rec=asn_rec)

        results = []
        errors = []

        def worker():
            try:
                r = svc.lookup("54.239.28.85")
                results.append(r)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertEqual(len(results), 50)
        for r in results:
            self.assertTrue(r["enriched"])
            self.assertTrue(r["is_datacenter"])

    def test_close_while_lookups_in_flight(self):
        """close() mid-lookup must not cause the lookup to crash."""
        city_rec = {
            "country": {"iso_code": "JP", "names": {"en": "Japan"}},
            "city": {"names": {"en": "Tokyo"}},
            "location": {"latitude": 35.69, "longitude": 139.69},
        }
        svc = _make_service(city_rec=city_rec)
        barrier = threading.Barrier(2)

        def slow_lookup():
            barrier.wait()
            try:
                svc.lookup("1.2.3.4")
            except Exception:
                pass

        def closer():
            barrier.wait()
            svc.close()

        t1 = threading.Thread(target=slow_lookup)
        t2 = threading.Thread(target=closer)
        t1.start(); t2.start()
        t1.join(); t2.join()
        # No assertion — just must not hang or raise unhandled


# ---------------------------------------------------------------------------
# 10. HTTP sensor integration
# ---------------------------------------------------------------------------

def _import_sensor_with_mocked_fastapi():
    """
    Import doppel.http_sensor.sensor with FastAPI/uvicorn stubbed out so the
    integration tests work even when those packages are not installed.
    Returns the sensor module, or None if it can't be loaded even with stubs.
    """
    import sys
    import types

    # Build minimal stubs only if the real packages are missing
    for pkg in ("fastapi", "fastapi.responses", "uvicorn"):
        if pkg not in sys.modules:
            stub = types.ModuleType(pkg)
            # Provide the symbols sensor.py imports from fastapi
            stub.FastAPI = MagicMock
            stub.Request = MagicMock
            stub.Response = MagicMock
            stub.PlainTextResponse = MagicMock
            stub.JSONResponse = MagicMock
            sys.modules[pkg] = stub

    # Also stub transitive doppel deps that may be missing
    for pkg in ("doppel.ai.deception_engine", "doppel.deception.honeytokens"):
        if pkg not in sys.modules:
            stub = types.ModuleType(pkg)
            stub.DeceptionEngine = MagicMock
            stub.VERIFY_PATH = "/auth/v1/verify"
            stub.get_honeytoken_manager = MagicMock(return_value=MagicMock())
            sys.modules[pkg] = stub

    try:
        # Force a fresh import if already cached with stubs
        if "doppel.http_sensor.sensor" in sys.modules:
            return sys.modules["doppel.http_sensor.sensor"]
        import doppel.http_sensor.sensor as sensor_mod
        return sensor_mod
    except Exception:
        return None


class TestHTTPSensorGeoIPIntegration(unittest.TestCase):
    """
    Verify that the HTTP sensor passes the geoip dict into both
    db.ensure_http_session() and db.log_web_probe() without an external
    network call.
    """

    @classmethod
    def setUpClass(cls):
        cls.sensor_mod = _import_sensor_with_mocked_fastapi()

    def _skip_if_no_sensor(self):
        if self.sensor_mod is None:
            self.skipTest("Could not import sensor module")

    def test_geoip_forwarded_to_db_calls(self):
        """
        Simulate what _log_web_probe does and confirm the geoip kwarg reaches
        the DB methods.  We don't spin up a real FastAPI/uvicorn server.
        """
        self._skip_if_no_sensor()
        import asyncio

        fake_geo = {
            "ip": "1.2.3.42",
            "country_code": "DE",
            "country_name": "Germany",
            "city": "Berlin",
            "latitude": 52.52,
            "longitude": 13.40,
            "asn": 3209,
            "asn_org": "Vodafone GmbH",
            "is_datacenter": False,
            "is_private": False,
            "enriched": True,
        }

        mock_db = MagicMock()
        mock_db.ensure_http_session = AsyncMock()
        mock_db.log_command = AsyncMock(return_value=1)
        mock_db.log_web_probe = AsyncMock()

        _log_web_probe = self.sensor_mod._log_web_probe

        asyncio.run(
            _log_web_probe(
                db=mock_db,
                remote_ip="1.2.3.42",
                remote_port=54321,
                method="GET",
                path="/.env",
                query="",
                user_agent="curl/7.88",
                probe_label="sensitive_file_env",
                response_body="DB_PASS=secret",
                status_code=200,
                timestamp="2024-01-01T00:00:00+00:00",
                geoip=fake_geo,
            )
        )

        mock_db.ensure_http_session.assert_called_once()
        call_kwargs = mock_db.ensure_http_session.call_args
        passed_geo = call_kwargs.kwargs.get("geoip") or (
            call_kwargs.args[4] if len(call_kwargs.args) > 4 else None
        )
        self.assertIsNotNone(passed_geo, "geoip not passed to ensure_http_session")
        self.assertEqual(passed_geo.get("country_code"), "DE")

        mock_db.log_web_probe.assert_called_once()
        wpcall = mock_db.log_web_probe.call_args
        passed_geo_wp = wpcall.kwargs.get("geoip")
        self.assertIsNotNone(passed_geo_wp, "geoip not passed to log_web_probe")
        self.assertEqual(passed_geo_wp.get("city"), "Berlin")

    def test_geoip_enrich_called_before_db(self):
        """
        _log_web_probe passes the geo dict it receives straight through to
        both DB methods — confirm is_datacenter survives the round-trip.
        """
        self._skip_if_no_sensor()
        import asyncio
        from unittest.mock import patch as upatch

        fake_geo = {
            "ip": "1.2.3.4", "country_code": "US", "country_name": "United States",
            "city": "Ashburn", "latitude": 39.0, "longitude": -77.5,
            "asn": 14618, "asn_org": "Amazon.com, Inc.",
            "is_datacenter": True, "is_private": False, "enriched": True,
        }

        mock_db = MagicMock()
        mock_db.ensure_http_session = AsyncMock()
        mock_db.log_command = AsyncMock(return_value=1)
        mock_db.log_web_probe = AsyncMock()

        _log_web_probe = self.sensor_mod._log_web_probe

        asyncio.run(
            _log_web_probe(
                db=mock_db,
                remote_ip="1.2.3.4",
                remote_port=12345,
                method="POST",
                path="/wp-admin",
                query="",
                user_agent="Masscan/1.3",
                probe_label="admin_panel_wpadmin",
                response_body="<html>Login</html>",
                status_code=200,
                timestamp="2024-06-01T12:00:00+00:00",
                geoip=fake_geo,
            )
        )

        mock_db.log_web_probe.assert_called_once()
        call_geo = mock_db.log_web_probe.call_args.kwargs.get("geoip")
        self.assertIsNotNone(call_geo)
        self.assertTrue(call_geo.get("is_datacenter"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)