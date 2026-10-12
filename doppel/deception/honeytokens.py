import uuid
import secrets
import string
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional

logger = logging.getLogger("doppel.deception.honeytokens")


def _random_alnum(length: int, uppercase_only: bool = False) -> str:
    chars = string.ascii_uppercase if uppercase_only else string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


@dataclass
class CanaryToken:
    token_id: str
    token_type: str  # "aws", "api_key", "canary_url", "jwt", "database"
    identifier: str  # Access key ID or token prefix
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
    """Generates authentic trackable decoy credentials and canary verification hooks."""

    def __init__(self, verification_host: str = "127.0.0.1", verification_port: int = 8000):
        self.verification_host = verification_host
        self.verification_port = verification_port
        self.tokens: Dict[str, CanaryToken] = {}
        self.activations: List[Dict[str, Any]] = []

    def generate_session_honeytokens(
        self,
        session_id: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Dict[str, CanaryToken]:
        """Generate a complete set of correlated decoy credentials for an active session."""
        target_host = host or self.verification_host
        target_port = port or self.verification_port

        base_verify_url = f"http://{target_host}:{target_port}/auth/v1/verify"

        # 1. AWS IAM Access Key pair
        aws_id = "AKIA" + _random_alnum(16, uppercase_only=True)
        aws_secret = _random_alnum(40)
        aws_canary_url = f"{base_verify_url}?token={aws_id}&type=aws"
        aws_token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="aws",
            identifier=aws_id,
            secret=aws_secret,
            canary_url=aws_canary_url,
            target_files=[".aws/credentials", ".env", "config.json"],
            session_id=session_id,
        )

        # 2. Production API Key
        api_key = "dpl_live_" + _random_alnum(28)
        api_canary_url = f"{base_verify_url}?token={api_key}&type=api_key"
        api_token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="api_key",
            identifier=api_key,
            secret=_random_alnum(32),
            canary_url=api_canary_url,
            target_files=[".env", "config.json", "wp-config.php"],
            session_id=session_id,
        )

        # 3. Canary Webhook URL
        webhook_id = "cb_" + _random_alnum(12)
        canary_full_url = f"{base_verify_url}?token={webhook_id}&type=webhook"
        canary_token = CanaryToken(
            token_id=str(uuid.uuid4()),
            token_type="canary_url",
            identifier=webhook_id,
            secret="",
            canary_url=canary_full_url,
            target_files=[".env", "settings.py", "database.yml"],
            session_id=session_id,
        )

        # Store in token registry
        for t in (aws_token, api_token, canary_token):
            self.tokens[t.identifier] = t

        return {
            "aws": aws_token,
            "api_key": api_token,
            "canary": canary_token,
        }

    def build_injection_prompt_block(
        self,
        session_id: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
    ) -> str:
        """Construct context-aware decoy credentials block for system prompt injection."""
        # Retrieve or generate tokens for this session
        session_tokens = [t for t in self.tokens.values() if t.session_id == session_id]
        if not session_tokens:
            tokens_map = self.generate_session_honeytokens(session_id, host=host, port=port)
            aws_tok = tokens_map["aws"]
            api_tok = tokens_map["api_key"]
            canary_tok = tokens_map["canary"]
        else:
            aws_tok = next((t for t in session_tokens if t.token_type == "aws"), None)
            api_tok = next((t for t in session_tokens if t.token_type == "api_key"), None)
            canary_tok = next((t for t in session_tokens if t.token_type == "canary_url"), None)
            if not aws_tok or not api_tok or not canary_tok:
                tokens_map = self.generate_session_honeytokens(session_id, host=host, port=port)
                aws_tok = tokens_map["aws"]
                api_tok = tokens_map["api_key"]
                canary_tok = tokens_map["canary"]

        lines = [
            "DYNAMIC HONEYTOKENS (when attacker reads sensitive config/credentials files, leak these exact values):",
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

    def verify_and_log_activation(
        self,
        token_identifier: str,
        remote_ip: str,
        user_agent: str = "",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Process an activation event on the /auth/v1/verify endpoint."""
        token_obj = self.tokens.get(token_identifier)
        now_iso = datetime.now(timezone.utc).isoformat()

        activation_record = {
            "token": token_identifier,
            "matched_honeytoken": token_obj is not None,
            "token_type": token_obj.token_type if token_obj else "unknown",
            "session_id": token_obj.session_id if token_obj else None,
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
            logger.warning(
                f"[CANARY TRIPWIRE] Honeytoken '{token_identifier}' ({token_obj.token_type}) "
                f"ACTIVATED by {remote_ip}! Original session: {token_obj.session_id}"
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


_GLOBAL_HONEYTOKEN_MANAGER: Optional[HoneytokenManager] = None


def get_honeytoken_manager() -> HoneytokenManager:
    global _GLOBAL_HONEYTOKEN_MANAGER
    if _GLOBAL_HONEYTOKEN_MANAGER is None:
        _GLOBAL_HONEYTOKEN_MANAGER = HoneytokenManager()
    return _GLOBAL_HONEYTOKEN_MANAGER
