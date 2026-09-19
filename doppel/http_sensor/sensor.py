"""
HTTP Honeypot Sensor
=====================
Mounts an additional FastAPI sub-application on port 8080 (configurable)
that responds to common web-attacker probes with LLM-synthesized content.

Covered probe categories
------------------------
  • Sensitive file reads:  /.env, /.git/config, /wp-config.php, /config.json …
  • Admin panels:          /wp-admin, /admin, /phpmyadmin, /manager/html …
  • API enumeration:       /api/v1/users, /api/v1/keys, /v1/admin …
  • Path traversal:        /../../../../etc/passwd style
  • SQLi in query params:  ?id=1' OR '1'='1
  • Shell injection hints: ?cmd=id, ?exec=whoami
  • Generic 404 catch-all: unknown paths (still logged + LLM-responded)

Each hit is:
  1. Classified by probe type.
  2. Passed to the DeceptionEngine for an LLM-synthesized HTTP response body.
  3. Logged to the TelemetryDB as a web_probe event.
  4. Broadcast over the controller's WebSocket/SSE stream.
"""

import re
import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional, Callable, Awaitable

from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse, JSONResponse

from doppel.ai.deception_engine import DeceptionEngine
from doppel.analytics.db import TelemetryDB

logger = logging.getLogger("doppel.http_sensor")


# ---------------------------------------------------------------------------
# Probe classification
# ---------------------------------------------------------------------------

# (label, compiled pattern)
_PROBE_ROUTES = [
    # Sensitive files
    ("sensitive_file_env",        re.compile(r"^/\.env")),
    ("sensitive_file_git",        re.compile(r"^/\.git")),
    ("sensitive_file_wpconfig",   re.compile(r"wp-config\.php", re.I)),
    ("sensitive_file_config",     re.compile(r"/(config|settings|secrets?)\.(json|ya?ml|php|ini|xml)", re.I)),
    ("sensitive_file_aws",        re.compile(r"\.aws/(credentials|config)", re.I)),
    ("sensitive_file_ssh",        re.compile(r"id_(rsa|ed25519|dsa)|authorized_keys", re.I)),
    ("sensitive_file_backup",     re.compile(r"\.(bak|backup|old|orig|swp|gz|tar|zip)$", re.I)),
    ("sensitive_file_htpasswd",   re.compile(r"\.htpasswd")),
    ("sensitive_file_dockerenv",  re.compile(r"/\.dockerenv")),
    ("sensitive_file_procfs",     re.compile(r"/proc/(version|cpuinfo|self/environ|1/cgroup)")),

    # Admin panels
    ("admin_panel_wpadmin",       re.compile(r"^/wp-admin", re.I)),
    ("admin_panel_phpmyadmin",    re.compile(r"phpmyadmin|pma", re.I)),
    ("admin_panel_adminer",       re.compile(r"adminer", re.I)),
    ("admin_panel_generic",       re.compile(r"^/(admin|administrator|manage|management|backend|panel|cp|controlpanel)", re.I)),
    ("admin_panel_tomcat",        re.compile(r"^/(manager|host-manager)/html", re.I)),
    ("admin_panel_jenkins",       re.compile(r"^/jenkins", re.I)),
    ("admin_panel_grafana",       re.compile(r"^/grafana", re.I)),
    ("admin_panel_kibana",        re.compile(r"^/kibana|/app/kibana", re.I)),

    # API enumeration
    ("api_enum_users",            re.compile(r"/api(/v\d+)?/(users?|accounts?|members?)", re.I)),
    ("api_enum_keys",             re.compile(r"/api(/v\d+)?/(keys?|tokens?|secrets?|credentials?)", re.I)),
    ("api_enum_admin",            re.compile(r"/api(/v\d+)?/admin", re.I)),
    ("api_enum_debug",            re.compile(r"/api(/v\d+)?/(debug|test|info|health|status)", re.I)),
    ("api_swagger",               re.compile(r"/(swagger|openapi|redoc|docs?|api-docs?)", re.I)),

    # Path traversal
    ("path_traversal",            re.compile(r"(\.\./){2,}")),

    # Shell / code injection via path
    ("injection_path",            re.compile(r"(cmd|exec|command|shell|eval|system)\s*=", re.I)),
]

# Query-parameter injection patterns
_SQLI_RE = re.compile(
    r"('|--|;|/\*|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bUPDATE\b)",
    re.I,
)
_CMDI_RE = re.compile(r"\b(id|whoami|uname|cat|ls|pwd|wget|curl)\b", re.I)


def classify_probe(request: Request) -> str:
    """Return a short label describing the probe type."""
    path = request.url.path
    query = str(request.url.query)

    for label, pattern in _PROBE_ROUTES:
        if pattern.search(path):
            return label

    if _SQLI_RE.search(query):
        return "sqli_probe"
    if _CMDI_RE.search(query):
        return "cmdi_probe"

    return "generic_probe"


# ---------------------------------------------------------------------------
# Response content-type inference
# ---------------------------------------------------------------------------

def _infer_content_type(path: str, probe_label: str) -> str:
    if probe_label.startswith("api_") or path.endswith(".json"):
        return "application/json"
    if path.endswith((".yaml", ".yml")):
        return "text/yaml"
    if path.endswith(".xml"):
        return "application/xml"
    return "text/plain"


# ---------------------------------------------------------------------------
# Sensor app factory
# ---------------------------------------------------------------------------

def create_http_sensor(
    deception_engine: DeceptionEngine,
    db: TelemetryDB,
    persona: str = "ubuntu_web_server",
    event_callback: Optional[Callable[[str, dict], Awaitable[None]]] = None,
) -> FastAPI:
    """
    Returns a standalone FastAPI app that acts as the HTTP honeypot sensor.
    Mount it on a separate port (e.g. 8080) via uvicorn in the controller.
    """
    sensor = FastAPI(title="Doppel HTTP Sensor", docs_url=None, redoc_url=None)

    @sensor.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    )
    async def catch_all(request: Request, full_path: str):
        remote_ip   = request.client.host if request.client else "unknown"
        remote_port = request.client.port if request.client else 0
        method      = request.method
        path        = request.url.path
        query       = str(request.url.query)
        ua          = request.headers.get("user-agent", "")
        ts          = datetime.now(timezone.utc).isoformat()

        probe_label = classify_probe(request)
        content_type = _infer_content_type(path, probe_label)

        logger.warning(
            f"[HTTP PROBE] {method} {path}{'?' + query if query else ''} "
            f"from {remote_ip} | probe={probe_label} | ua={ua[:80]}"
        )

        # Build a pseudo-command that the deception engine can work with
        pseudo_cmd = _build_pseudo_command(method, path, query, probe_label, ua)

        # LLM-generate the response body
        try:
            raw_body = await deception_engine.generate_command_output(
                command=pseudo_cmd,
                cwd="/var/www/html",
                user="www-data",
                session_history=None,
            )
            body = raw_body.strip()
        except Exception as exc:
            logger.error(f"HTTP sensor LLM error: {exc}")
            body = _fallback_body(probe_label, path)

        # Determine HTTP status code
        status_code = _probe_status_code(probe_label)

        # Log to telemetry DB
        await _log_web_probe(
            db=db,
            remote_ip=remote_ip,
            remote_port=remote_port,
            method=method,
            path=path,
            query=query,
            user_agent=ua,
            probe_label=probe_label,
            response_body=body,
            status_code=status_code,
            timestamp=ts,
        )

        # Broadcast to dashboard
        if event_callback:
            try:
                await event_callback("web_probe", {
                    "remote_ip":   remote_ip,
                    "remote_port": remote_port,
                    "method":      method,
                    "path":        path,
                    "query":       query,
                    "user_agent":  ua,
                    "probe_label": probe_label,
                    "status_code": status_code,
                    "timestamp":   ts,
                })
            except Exception as exc:
                logger.debug(f"HTTP sensor event callback error: {exc}")

        return Response(
            content=body,
            status_code=status_code,
            media_type=content_type,
            headers={
                "Server":        "nginx/1.18.0",
                "X-Powered-By":  "PHP/8.1.0",
                "Cache-Control": "no-store",
            },
        )

    return sensor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_pseudo_command(
    method: str, path: str, query: str, probe_label: str, ua: str
) -> str:
    """
    Translate the HTTP probe into a shell-like command that the deception engine
    understands.  This lets us reuse the existing LLM system prompt without a
    separate HTTP-specific prompt.
    """
    if probe_label.startswith("sensitive_file"):
        return f"cat {path}"
    if probe_label.startswith("admin_panel"):
        return f"curl -s http://localhost{path}"
    if probe_label.startswith("api_"):
        return f"curl -s -X {method} http://localhost{path}{'?' + query if query else ''}"
    if probe_label == "path_traversal":
        # Resolve the traversal target for a more realistic response
        target = re.sub(r"(\.\./)+", "", path).lstrip("/") or "etc/passwd"
        return f"cat /{target}"
    if probe_label in ("sqli_probe", "cmdi_probe", "injection_path"):
        return f"# Web probe: {method} {path}?{query}"
    return f"cat {path}"


def _probe_status_code(probe_label: str) -> int:
    """Return a plausible HTTP status for each probe type."""
    # Sensitive files and traversal get 200 to bait the attacker
    if probe_label.startswith("sensitive_file") or probe_label == "path_traversal":
        return 200
    # Admin panels return 200 (fake login page) or 403
    if probe_label.startswith("admin_panel"):
        return 200
    # API endpoints return 200 with fake JSON
    if probe_label.startswith("api_"):
        return 200
    # Injection probes get 200 (to encourage further exploration)
    if probe_label in ("sqli_probe", "cmdi_probe", "injection_path"):
        return 200
    # Generic probes get 404
    return 404


def _fallback_body(probe_label: str, path: str) -> str:
    """Static fallback when the LLM is unavailable."""
    if probe_label == "sensitive_file_env":
        return (
            "APP_ENV=production\n"
            "DB_HOST=10.0.4.50\n"
            "DB_DATABASE=app_production\n"
            "DB_PASSWORD=P@ssw0rdProd2026!\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
    if probe_label.startswith("api_enum"):
        return '{"error": "Unauthorized", "code": 401}'
    if probe_label.startswith("admin_panel"):
        return "<html><body><h1>Login</h1><form method='post'><input name='user'/><input name='pass' type='password'/><button>Login</button></form></body></html>"
    return f"Not found: {path}"


async def _log_web_probe(
    db: TelemetryDB,
    remote_ip: str,
    remote_port: int,
    method: str,
    path: str,
    query: str,
    user_agent: str,
    probe_label: str,
    response_body: str,
    status_code: int,
    timestamp: str,
) -> None:
    """
    Persist the web probe into the telemetry DB using the existing
    `commands` table with a synthetic session_id so it appears in reports.
    A web-probe session row is created if it does not exist.
    """
    session_id = f"http_{remote_ip.replace('.', '_')}_{remote_port}"
    full_request = f"{method} {path}{'?' + query if query else ''}"

    try:
        # Ensure a session row exists for this HTTP source
        await db.log_session_start(
            session_id=session_id,
            remote_ip=remote_ip,
            remote_port=remote_port,
            username="http_probe",
            password=user_agent[:64],
        )
    except Exception:
        pass  # row likely already exists — INSERT OR REPLACE handles it

    try:
        await db.log_command(
            session_id=session_id,
            cwd="/var/www/html",
            command=full_request,
            output=response_body[:512],
            route_decision="http_sensor",
            threat_meta={
                "tactics":        ["Initial Access"],
                "technique_id":   "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "threat_score":   _probe_threat_score(probe_label),
                "attacker_intent": probe_label.replace("_", " ").title(),
                "is_automated":   True,
                "confidence":     0.85,
                "iocs":           [remote_ip, path],
            },
        )
    except Exception as exc:
        logger.error(f"Failed to log web probe: {exc}")


def _probe_threat_score(label: str) -> int:
    scores = {
        "sensitive_file_env":       85,
        "sensitive_file_git":       70,
        "sensitive_file_wpconfig":  80,
        "sensitive_file_aws":       90,
        "sensitive_file_ssh":       90,
        "sensitive_file_backup":    60,
        "path_traversal":           80,
        "sqli_probe":               75,
        "cmdi_probe":               85,
        "injection_path":           85,
        "admin_panel_wpadmin":      65,
        "admin_panel_phpmyadmin":   70,
        "admin_panel_generic":      60,
        "api_enum_users":           55,
        "api_enum_keys":            75,
        "api_enum_admin":           70,
        "api_swagger":              40,
        "generic_probe":            20,
    }
    return scores.get(label, 30)
