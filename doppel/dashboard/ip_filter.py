"""IP allow-list firewall for the Doppel dashboard (HTTP, SSE and WebSocket)."""
import ipaddress
import logging
from typing import Callable, Iterable, List, Optional, Tuple, Union

logger = logging.getLogger("doppel.dashboard.firewall")

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Used when the allow-list is empty: fail closed, but never lock out the local machine.
LOOPBACK_ONLY = ["127.0.0.1", "::1"]


def parse_networks(entries: Iterable[str]) -> List[IPNetwork]:
    """Parse single IPs ('10.0.0.5') and CIDR ranges ('10.0.0.0/24') into networks."""
    networks: List[IPNetwork] = []
    for raw in entries:
        entry = str(raw).strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.error("Ignoring invalid dashboard_allowed_ips entry: %r", raw)
    return networks


def is_ip_allowed(client_ip: Optional[str], networks: List[IPNetwork]) -> bool:
    if not client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    # Treat ::ffff:1.2.3.4 as 1.2.3.4
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr.version == net.version and addr in net for net in networks)


class IPAllowlistMiddleware:
    """Pure-ASGI middleware (covers http + websocket, unlike BaseHTTPMiddleware).

    `get_allowed` is called per request so config reloads take effect immediately.
    """

    def __init__(self, app, get_allowed: Callable[[], List[str]]):
        self.app = app
        self.get_allowed = get_allowed
        self._cache: Tuple[Tuple[str, ...], List[IPNetwork]] = ((), [])

    def _networks(self) -> List[IPNetwork]:
        entries = tuple(self.get_allowed() or LOOPBACK_ONLY)
        if entries != self._cache[0]:
            self._cache = (entries, parse_networks(entries))
        return self._cache[1]

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):  # lifespan etc.
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        client_ip = client[0] if client else None

        if is_ip_allowed(client_ip, self._networks()):
            await self.app(scope, receive, send)
            return

        logger.warning("Dashboard access denied for %s (%s)", client_ip, scope.get("path"))

        if scope["type"] == "websocket":
            await receive()  # consume websocket.connect
            await send({"type": "websocket.close", "code": 1008})
            return

        body = b"403 Forbidden"
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
