from pathlib import Path
from typing import Optional, Dict, Any
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class HoneypotSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 2222
    server_banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    hostname: str = "prod-api-node-01"
    default_user: str = "ubuntu"
    accept_any_password: bool = True
    # Where SSH host keys are kept; keep it on persistent storage so the
    # server's fingerprint does not change between deployments.
    host_key_dir: str = "."
    motd: str = (
        "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n"
        " * Documentation:  https://help.ubuntu.com\n"
        " * Management:     https://landscape.canonical.com\n"
        " * Support:        https://ubuntu.com/pro\n\n"
        "0 updates can be applied immediately.\n"
    )


class LLMSettings(BaseModel):
    base_url: str = "http://127.0.0.1:11434/v1"
    model: str = "qwen2.5-coder:7b"
    api_key: str = "ollama"
    timeout_seconds: float = 45.0
    temperature: float = 0.2
    mock_mode: bool = False
    # Model for background analysis (ATT&CK tagging, incident reports).
    # Empty: same as `model`. A slower reasoning model is fine here because
    # nothing waits on it, while the terminal needs fast replies.
    analysis_model: str = ""
    # Analysis runs in the background, so it can wait longer than the terminal
    analysis_timeout_seconds: float = 120.0
    # Ask reasoning models to skip their reasoning step for terminal output
    # (sends reasoning_effort "none"). Models without reasoning ignore it.
    terminal_no_think: bool = False


class DeceptionSettings(BaseModel):
    persona: str = "ubuntu_web_server"
    tar_pit_delay_ms: int = 0
    intercept_sensitive_files: bool = True
    intercept_missing_tools: bool = True
    dynamic_honeytokens: bool = True
    # Base URL of the HTTP decoy as attackers can reach it, used in leaked canary
    # URLs (e.g. "http://203.0.113.10:8080"). Empty: derived from the honeypot
    # host and HTTP sensor port.
    canary_base_url: str = ""
    # Latency harmonization & jitter simulation
    simulate_latency: bool = True
    min_latency_ms: int = 120
    max_latency_ms: int = 2200
    jitter_percent: int = 25
    spike_probability: float = 0.10
    spike_min_ms: int = 600
    spike_max_ms: int = 1400


class SandboxSettings(BaseModel):
    enabled: bool = True
    image: str = "doppel-sandbox:ubuntu-22.04"
    network_disabled: bool = True
    memory_limit: str = "256m"
    cpu_quota: int = 50000
    timeout_seconds: float = 10.0


class AnalyticsSettings(BaseModel):
    db_path: str = "doppel_telemetry.db"
    enable_mitre_tagging: bool = True
    reports_dir: str = "reports"
    # Incident reports are LLM-generated when sessions close; cap how many run at
    # once so a burst of short bot sessions cannot starve live deception replies.
    max_concurrent_reports: int = 2


class AccessSettings(BaseModel):
    """Operator access control."""
    # IPs / CIDR ranges allowed to reach the web dashboard. Empty = loopback only.
    dashboard_allowed_ips: list[str] = Field(default_factory=list)


class GeoIPSettings(BaseModel):
    """Paths to local MaxMind GeoLite2 .mmdb files.  Leave empty to disable enrichment."""
    city_db_path: str = ""   # e.g. /opt/geoip/GeoLite2-City.mmdb
    asn_db_path:  str = ""   # e.g. /opt/geoip/GeoLite2-ASN.mmdb


class EmailAlertSettings(BaseModel):
    enabled: bool = False
    smtp_server: str = "smtp.example.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    sender_email: str = "doppel@example.com"
    receiver_email: str = "alerts@example.com"
    min_threat_score: int = 60


class AlertsSettings(BaseModel):
    email: EmailAlertSettings = Field(default_factory=EmailAlertSettings)


from pydantic_settings import BaseSettings, SettingsConfigDict, YamlConfigSettingsSource


class DoppelConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DOPPEL_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    active_preset: str = "ubuntu_web_server"
    honeypot: HoneypotSettings = Field(default_factory=HoneypotSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    deception: DeceptionSettings = Field(default_factory=DeceptionSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    analytics: AnalyticsSettings = Field(default_factory=AnalyticsSettings)
    access: AccessSettings = Field(default_factory=AccessSettings)
    alerts: AlertsSettings = Field(default_factory=AlertsSettings)
    benign_commands: list[str] = Field(default_factory=list)
    http_sensor_port: int = 8080  # 0 = disabled
    geoip: GeoIPSettings = Field(default_factory=GeoIPSettings)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "DoppelConfig":
        """Load configuration from config.yaml if available, overlaid with env vars."""
        return cls(_yaml_file=config_path or "config.yaml")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        yaml_file = init_settings.init_kwargs.pop("_yaml_file", "config.yaml")
        sources = [init_settings, env_settings, dotenv_settings]
        if Path(yaml_file).exists():
            sources.append(YamlConfigSettingsSource(settings_cls, yaml_file=yaml_file))
        return tuple(sources)


_CONFIG_INSTANCE: Optional[DoppelConfig] = None
_PRESETS_CACHE: Optional[Dict[str, Any]] = None
_PRESETS_MTIME: Optional[float] = None

DEFAULT_PERSONA = "ubuntu_web_server"


def _presets_file() -> Optional[Path]:
    for p in (
        Path(__file__).parent / "config" / "presets.yaml",
        Path("doppel/config/presets.yaml"),
        Path("presets.yaml"),
    ):
        if p.exists():
            return p
    return None


def _load_presets_file() -> Dict[str, Any]:
    """presets.yaml contents, re-read only when the file changes."""
    global _PRESETS_CACHE, _PRESETS_MTIME
    path = _presets_file()
    if path is None:
        return {}
    try:
        mtime = path.stat().st_mtime
        if _PRESETS_CACHE is None or mtime != _PRESETS_MTIME:
            with open(path, "r", encoding="utf-8") as f:
                _PRESETS_CACHE = yaml.safe_load(f) or {}
            _PRESETS_MTIME = mtime
    except Exception:
        return _PRESETS_CACHE or {}
    return _PRESETS_CACHE


def get_presets_dict() -> Dict[str, Any]:
    """Host identities keyed by persona name."""
    return _load_presets_file().get("presets", {}) or {}


def get_preset_aliases() -> Dict[str, str]:
    return _load_presets_file().get("aliases", {}) or {}


def resolve_persona_key(config: Optional[DoppelConfig] = None) -> str:
    """
    The persona in effect. `active_preset` is authoritative; `deception.persona`
    is honoured when no preset is selected. Legacy preset names map through
    the aliases table.
    """
    cfg = config or get_config()
    presets = get_presets_dict()
    aliases = get_preset_aliases()
    for candidate in (getattr(cfg, "active_preset", None), getattr(cfg.deception, "persona", None)):
        if not candidate:
            continue
        key = aliases.get(candidate, candidate)
        if key in presets:
            return key
    return DEFAULT_PERSONA


def get_active_preset(config: Optional[DoppelConfig] = None) -> Dict[str, Any]:
    """Host identity of the persona in effect (see resolve_persona_key)."""
    cfg = config or get_config()
    presets = get_presets_dict()
    key = resolve_persona_key(cfg)
    if key in presets:
        return {"key": key, "persona_context": key, **presets[key]}
    return {
        "key": DEFAULT_PERSONA,
        "name": "Ubuntu 22.04 LTS Web Server",
        "server_banner": cfg.honeypot.server_banner,
        "hostname": cfg.honeypot.hostname,
        "default_user": cfg.honeypot.default_user,
        "motd": cfg.honeypot.motd,
        "prompt_format": "{user}@{hostname}:{cwd}$ ",
        "root_prompt_format": "{user}@{hostname}:{cwd}# ",
        "persona_context": DEFAULT_PERSONA,
    }


def get_config(config_path: Optional[str] = None) -> DoppelConfig:
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = DoppelConfig.load(config_path)
    return _CONFIG_INSTANCE


def reload_config(config_path: Optional[str] = None) -> DoppelConfig:
    global _CONFIG_INSTANCE
    _CONFIG_INSTANCE = DoppelConfig.load(config_path)
    return _CONFIG_INSTANCE
