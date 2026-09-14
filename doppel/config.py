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
    timeout_seconds: float = 15.0
    temperature: float = 0.2
    mock_mode: bool = False


class DeceptionSettings(BaseModel):
    persona: str = "ubuntu_web_server"
    tar_pit_delay_ms: int = 0
    intercept_sensitive_files: bool = True
    intercept_missing_tools: bool = True
    dynamic_honeytokens: bool = True


class SandboxSettings(BaseModel):
    enabled: bool = True
    image: str = "alpine:latest"
    network_disabled: bool = True
    memory_limit: str = "256m"
    cpu_quota: int = 50000


class AnalyticsSettings(BaseModel):
    db_path: str = "doppel_telemetry.db"
    enable_mitre_tagging: bool = True
    reports_dir: str = "reports"


class DoppelConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DOPPEL_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    honeypot: HoneypotSettings = Field(default_factory=HoneypotSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    deception: DeceptionSettings = Field(default_factory=DeceptionSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    analytics: AnalyticsSettings = Field(default_factory=AnalyticsSettings)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "DoppelConfig":
        """Load configuration from config.yaml if available, overlaid with env vars."""
        file_path = Path(config_path or "config.yaml")
        file_data: Dict[str, Any] = {}
        if file_path.exists():
            with open(file_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
                if isinstance(content, dict):
                    file_data = content

        return cls(**file_data)


_CONFIG_INSTANCE: Optional[DoppelConfig] = None


def get_config(config_path: Optional[str] = None) -> DoppelConfig:
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = DoppelConfig.load(config_path)
    return _CONFIG_INSTANCE
