import uuid
import asyncio
import secrets
import string
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("doppel.deception.honeytokens")

VERIFY_PATH = "/auth/v1/verify"


def _random_alnum(length: int, uppercase_only: bool = False) -> str:
    chars = string.ascii_uppercase if uppercase_only else string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


@dataclass
class CanaryToken:
    token_id: str
    token_type: str  # "aws", "api_key", "canary_url"
    identifier: str  # Access key ID or token value that appears in the leak
    secret: str
    canary_url: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_files: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    activated: bool = False
    activation_count: int = 0
    last_activated_at: Optional[str] = None
    last_activated_by: Optional[str] = None


class HoneytokenManager:
    """
    Generates per-session decoy credentials and recognises them when they are
    used against the verification endpoint.

    Canary URLs point at the HTTP decoy (`base_url`), which serves
    `/auth/v1/verify` publicly. Tokens are kept in memory and, when a
    persistence callback is configured, stored in the telemetry DB so they are
    still recognised after a restart.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip("/")
        self.tokens: Dict[str, CanaryToken] = {}
        self.activations: List[Dict[str, Any]] = []
        self._persist: Optional[Callable[[CanaryToken], Awaitable[None]]] = None
        self._persist_tasks: set = set()

    def configure(
        self,
        base_url: Optional[str] = None,
        persist: Optional[Callable[[CanaryToken], Awaitable[None]]] = None,
    ):
        if base_url:
            self.base_url = base_url.rstrip("/")
        self._persist = persist

    @property
    def verify_url(self) -> str:
        return f"{self.base_url}{VERIFY_PATH}"

    def _register(self, token: CanaryToken):
        self.tokens[token.identifier] = token
        if not self._persist:
            return
        try:
            task = asyncio.get_running_loop().create_task(self._persist(token))
        except RuntimeError:
            return  # no running loop (e.g. synchronous tests); memory only
        self._persist_tasks.add(task)
        task.add_done_callback(self._persist_tasks.discard)

    def generate_session_honeytokens(self, session_id: str) -> Dict[str, CanaryToken]:
        """Generate a correlated set of decoy credentials for one session."""
        verify_url = self.verify_url

        aws_id = "AKIA" + _random_alnum(16, uppercase_only=True)
        aws_token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="aws",
            identifier=aws_id,
            secret=_random_alnum(40),
            canary_url=f"{verify_url}?token={aws_id}&type=aws",
            target_files=[".aws/credentials", ".env", "config.json"],
            session_id=session_id,
        )

        api_key = "live_" + _random_alnum(32)
        api_token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="api_key",
            identifier=api_key,
            secret=_random_alnum(32),
            canary_url=f"{verify_url}?token={api_key}&type=api_key",
            target_files=[".env", "config.json", "wp-config.php"],
            session_id=session_id,
        )

        webhook_id = "cb_" + _random_alnum(12)
        canary_token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="canary_url",
            identifier=webhook_id,
            secret="",
            canary_url=f"{verify_url}?token={webhook_id}&type=webhook",
            target_files=[".env", "settings.py", "database.yml"],
            session_id=session_id,
        )

        for t in (aws_token, api_token, canary_token):
            self._register(t)

        return {"aws": aws_token, "api_key": api_token, "canary": canary_token}

    def build_injection_prompt_block(self, session_id: str) -> str:
        """Construct the decoy-credentials block appended to the model prompt."""
        session_tokens = [t for t in self.tokens.values() if t.session_id == session_id]
        by_type = {t.token_type: t for t in session_tokens}
        if not all(k in by_type for k in ("aws", "api_key", "canary_url")):
            generated = self.generate_session_honeytokens(session_id)
            by_type = {"aws": generated["aws"], "api_key": generated["api_key"], "canary_url": generated["canary"]}
        aws_tok, api_tok, canary_tok = by_type["aws"], by_type["api_key"], by_type["canary_url"]

        lines = [
            "DYNAMIC HONEYTOKENS (when attacker reads sensitive config/credentials files, leak these exact values; "
            "they replace any AWS keys, API keys or verification URLs listed earlier in the persona):",
            "Target .env file contents:",
            f"  AWS_ACCESS_KEY_ID={aws_tok.identifier}",
            f"  AWS_SECRET_ACCESS_KEY={aws_tok.secret}",
            f"  API_GATEWAY_KEY={api_tok.identifier}",
            f"  PAYMENT_WEBHOOK_URL={canary_tok.canary_url}",
            f"  AUTH_VERIFICATION_ENDPOINT={canary_tok.canary_url}",
            "",
            "Target ~/.aws/credentials file contents:",
            "  [default]",
            f"  aws_access_key_id = {aws_tok.identifier}",
            f"  aws_secret_access_key = {aws_tok.secret}",
            "  region = us-east-1",
            "",
            "Target config.json file contents:",
            f'  "apiKey": "{api_tok.identifier}",',
            f'  "verifyEndpoint": "{canary_tok.canary_url}",',
            f'  "awsKey": "{aws_tok.identifier}"',
        ]
        return "\n".join(lines)

    def lookup(self, identifier: str) -> Optional[CanaryToken]:
        return self.tokens.get(identifier)

    def verify_and_log_activation(
        self,
        token_identifier: str,
        remote_ip: str,
        user_agent: str = "",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        stored: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a hit on the verification endpoint. `stored` is the persisted
        token row, for tokens issued before the current process started.
        """
        token_obj = self.tokens.get(token_identifier)
        now_iso = datetime.now(timezone.utc).isoformat()

        if token_obj:
            token_type, session_id = token_obj.token_type, token_obj.session_id
        elif stored:
            token_type, session_id = stored.get("token_type") or "unknown", stored.get("session_id")
        else:
            token_type, session_id = "unknown", None
        matched = token_obj is not None or stored is not None

        activation_record = {
            "token": token_identifier,
            "matched_honeytoken": matched,
            "token_type": token_type,
            "session_id": session_id,
            "remote_ip": remote_ip,
            "user_agent": user_agent,
            "method": method,
            "timestamp": now_iso,
        }
        self.activations.append(activation_record)

        if token_obj:
            token_obj.activated = True
            token_obj.activation_count += 1
            token_obj.last_activated_at = now_iso
            token_obj.last_activated_by = remote_ip

        if matched:
            logger.warning(
                f"[CANARY TRIPWIRE] Honeytoken '{token_identifier}' ({token_type}) "
                f"ACTIVATED by {remote_ip}! Original session: {session_id}"
            )
        else:
            logger.warning(
                f"[CANARY TRIPWIRE] Verification endpoint queried with unrecognized token: {token_identifier} from {remote_ip}"
            )

        return activation_record

    def get_all_tokens(self) -> List[Dict[str, Any]]:
        return [asdict(t) for t in self.tokens.values()]

    def get_all_activations(self) -> List[Dict[str, Any]]:
        return list(self.activations)


def derive_canary_base_url(config: Any, preset: Optional[Dict[str, Any]] = None) -> str:
    """
    Address of the HTTP decoy as it should appear in leaked canary URLs:
    `deception.canary_base_url` when set, otherwise the honeypot bind address
    (or the persona hostname when bound to all interfaces) and decoy port.
    """
    configured = (getattr(config.deception, "canary_base_url", "") or "").strip()
    if configured:
        return configured.rstrip("/")
    port = getattr(config, "http_sensor_port", 8080) or 8080
    host = config.honeypot.host
    if not host or host in ("0.0.0.0", "::"):
        host = (preset or {}).get("hostname") or config.honeypot.hostname
        logger.warning(
            f"deception.canary_base_url is not set; leaked canary URLs will point at {host}:{port}. "
            "Set it to the HTTP decoy's public address so stolen tokens can trip the alarm."
        )
    return f"http://{host}:{port}"


_GLOBAL_HONEYTOKEN_MANAGER: Optional[HoneytokenManager] = None


def get_honeytoken_manager() -> HoneytokenManager:
    global _GLOBAL_HONEYTOKEN_MANAGER
    if _GLOBAL_HONEYTOKEN_MANAGER is None:
        _GLOBAL_HONEYTOKEN_MANAGER = HoneytokenManager()
    return _GLOBAL_HONEYTOKEN_MANAGER
