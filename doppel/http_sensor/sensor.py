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
  • Generic 404 catch-all: unknown paths get nginx's 404 page (still logged)
  • Canary verification:  /auth/v1/verify, the tripwire for leaked decoy credentials

Each hit is:
  1. Classified by probe type.
  2. Passed to the DeceptionEngine for an LLM-synthesized HTTP response body.
  3. Logged to the TelemetryDB (per-IP web session + web_probes table).
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
from doppel.deception.honeytokens import VERIFY_PATH, get_honeytoken_manager

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
    if probe_label.startswith("admin_panel"):
        return "text/html"
    if path.endswith((".yaml", ".yml")):
        return "text/yaml"
    if path.endswith(".xml"):
        return "application/xml"
    return "text/plain"


# nginx's built-in error page, byte for byte apart from the version line
_NGINX_404 = (
    "<html>\r\n"
    "<head><title>404 Not Found</title></head>\r\n"
    "<body>\r\n"
    "<center><h1>404 Not Found</h1></center>\r\n"
    "<hr><center>{server}</center>\r\n"
    "</body>\r\n"
    "</html>\r\n"
)

# Generated bodies that read like a shell error rather than a file or page;
# a web server would answer those paths with its 404 page instead.
_SHELL_ERROR_RE = re.compile(
    r"(?im)^(?:-?bash: |sh: |cat: |curl: |ls: )|no such file or directory|command not found|permission denied"
)


def _http_session_id(remote_ip: str, timestamp: str) -> str:
    """One session per source IP per UTC day groups a scanner's requests."""
    day = timestamp[:10].replace("-", "")
    return f"http_{re.sub(r'[^0-9A-Za-z]', '_', remote_ip)}_{day}"


# ---------------------------------------------------------------------------
# Sensor app factory
# ---------------------------------------------------------------------------

def create_http_sensor(
    deception_engine: DeceptionEngine,
    db: TelemetryDB,
    persona: str = "ubuntu_web_server",
    event_callback: Optional[Callable[[str, dict], Awaitable[None]]] = None,
    server_header: str = "nginx/1.18.0 (Ubuntu)",
) -> FastAPI:
    """
    Returns a standalone FastAPI app that acts as the HTTP honeypot sensor.
    Mount it on a separate port (e.g. 8080) via uvicorn in the controller.
    """
    # No generated docs or schema: /docs, /redoc and /openapi.json must look
    # like any other unknown path on a real web server.
    sensor = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    base_headers = {"Server": server_header}
    not_found_body = _NGINX_404.format(server=server_header)

    @sensor.api_route(VERIFY_PATH, methods=["GET", "POST"])
    async def verify_canary(request: Request):
        return await _handle_canary(request, db, event_callback, base_headers)

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

        logger.warning(
            f"[HTTP PROBE] {method} {path}{'?' + query if query else ''} "
            f"from {remote_ip} | probe={probe_label} | ua={ua[:80]}"
        )

        body = ""
        if probe_label != "generic_probe":
            # Only bait paths get a generated body; everything else is a plain 404
            pseudo_cmd = _build_pseudo_command(method, path, query, probe_label, ua)
            try:
                raw_body = await deception_engine.generate_command_output(
                    command=pseudo_cmd,
                    cwd="/var/www/html",
                    user="www-data",
                    session_history=None,
                )
                body = (raw_body or "").strip()
            except Exception as exc:
                logger.error(f"HTTP sensor LLM error: {exc}")
                body = _fallback_body(probe_label)

        if body and not _SHELL_ERROR_RE.search(body):
            status_code = _probe_status_code(probe_label)
            content_type = _infer_content_type(path, probe_label)
        else:
            status_code = 404
            content_type = "text/html"
            body = not_found_body

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

        if status_code == 404:
            # nginx sends a bare "text/html" for its error pages (no charset)
            return Response(
                content=body,
                status_code=404,
                headers={**base_headers, "Content-Type": "text/html"},
            )
        return Response(
            content=body,
            status_code=status_code,
            media_type=content_type,
            headers=base_headers,
        )

    return sensor


# ---------------------------------------------------------------------------
# Canary verification endpoint
# ---------------------------------------------------------------------------

async def _extract_token(request: Request) -> str:
    token = request.query_params.get("token") or request.query_params.get("key") or ""
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
        elif request.headers.get("x-api-key"):
            token = request.headers.get("x-api-key", "")
    if not token and request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict):
                token = str(body.get("token") or body.get("api_key") or body.get("key") or "")
        except Exception:
            pass
    return token[:256]


async def _handle_canary(
    request: Request,
    db: TelemetryDB,
    event_callback: Optional[Callable[[str, dict], Awaitable[None]]],
    headers: dict,
) -> JSONResponse:
    """
    Tripwire for leaked decoy credentials: anyone presenting one of the
    issued tokens here is using data stolen from a honeypot session.
    """
    remote_ip   = request.client.host if request.client else "unknown"
    remote_port = request.client.port if request.client else 0
    ua          = request.headers.get("user-agent", "")
    ts          = datetime.now(timezone.utc).isoformat()
    token       = await _extract_token(request)

    manager = get_honeytoken_manager()
    stored = None
    if token and not manager.lookup(token):
        try:
            stored = await db.get_honeytoken(token)
        except Exception as exc:
            logger.debug(f"Honeytoken lookup failed: {exc}")

    activation = manager.verify_and_log_activation(
        token_identifier=token or "probe_without_token",
        remote_ip=remote_ip,
        user_agent=ua,
        method=request.method,
        stored=stored,
    )
    label = (
        f"honeytoken_activated:{activation['token_type']}"
        if activation["matched_honeytoken"] else "honeytoken_probe"
    )

    await _log_web_probe(
        db=db,
        remote_ip=remote_ip,
        remote_port=remote_port,
        method=request.method,
        path=request.url.path,
        query=str(request.url.query),
        user_agent=ua,
        probe_label=label,
        response_body="invalid_credentials",
        status_code=401,
        timestamp=ts,
    )

    if event_callback:
        try:
            await event_callback("honeytoken_activated", activation)
        except Exception as exc:
            logger.debug(f"Canary event callback error: {exc}")

    return JSONResponse(
        status_code=401,
        content={
            "status": "error",
            "code": "invalid_credentials",
            "message": "Token verification failed. Credential has expired or is invalid.",
        },
        headers=headers,
    )


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
    """Status for a probe that produced a believable body."""
    if probe_label.startswith("sensitive_file") or probe_label == "path_traversal":
        return 200
    if probe_label.startswith("admin_panel"):
        return 200
    if probe_label.startswith("api_"):
        return 200
    if probe_label in ("sqli_probe", "cmdi_probe", "injection_path"):
        return 200
    return 404


def _fallback_body(probe_label: str) -> str:
    """Static body when the LLM is unavailable; empty means serve the 404 page."""
    if probe_label.startswith("api_enum"):
        return '{"message":"Unauthenticated."}'
    if probe_label.startswith("admin_panel"):
        return (
            "<!DOCTYPE html><html><head><title>Log In</title></head><body>"
            "<form method=\"post\" action=\"\"><label>Username<input name=\"log\" type=\"text\"></label>"
            "<label>Password<input name=\"pwd\" type=\"password\"></label>"
            "<button type=\"submit\">Log In</button></form></body></html>"
        )
    return ""


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
    Record a probe in three places: the per-IP-per-day web session (so it
    appears in the dashboard and reports), its command list, and web_probes.
    """
    session_id = _http_session_id(remote_ip, timestamp)
    full_request = f"{method} {path}{'?' + query if query else ''}"

    try:
        await db.ensure_http_session(session_id, remote_ip, remote_port, timestamp)
        await db.log_command(
            session_id=session_id,
            cwd="/var/www/html",
            command=full_request[:2048],
            output=response_body[:512],
            route_decision="http_sensor",
            timestamp=timestamp,
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
        logger.error(f"Failed to log web probe session: {exc}")

    try:
        await db.log_web_probe(
            timestamp=timestamp,
            remote_ip=remote_ip,
            remote_port=remote_port,
            method=method,
            path=path,
            query=query,
            user_agent=user_agent,
            probe_label=probe_label,
            status_code=status_code,
            response_snippet=response_body,
        )
    except Exception as exc:
        logger.error(f"Failed to log web probe: {exc}")


def _probe_threat_score(label: str) -> int:
    if label.startswith("honeytoken_activated"):
        return 95
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
        "honeytoken_probe":         50,
        "generic_probe":            20,
    }
    return scores.get(label, 30)
