from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_host: str = "127.0.0.1"
    app_port: int = 8080
    policy_file: Path = Path("config/policy.yaml")
    database_url: str = "postgresql://cybercore:change_me@127.0.0.1:5432/cybercore"
    database_connect_timeout_seconds: int = 3
    budget_request_window_seconds: int = 3600
    budget_lease_grace_seconds: int = 30
    budget_key: str = "global"
    api_credentials_json: str = "[]"
    approval_max_ttl_seconds: int = 3600
    llm_provider: Literal["ollama", "llamacpp"] = "llamacpp"
    llamacpp_base_url: str = "http://localhost:8081"
    llamacpp_request_timeout_seconds: int = 180
    llamacpp_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"
    ollama_request_timeout_seconds: int = 180
    ollama_context_tokens: int = 8192
    orchestrator_model: str = "qwen3.5:9b"
    analyst_model: str = "foundation-sec-8b-reasoning"
    nvd_api_key: str = ""
    nuclei_templates_dir: Path = Path("~/nuclei-templates")
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: SecretStr = SecretStr("")
    wazuh_verify_tls: bool = True
    wazuh_ca_bundle: str = ""
    greenbone_user: str = ""
    greenbone_password: SecretStr = SecretStr("")
    greenbone_socket_path: str = ""
    greenbone_host: str = ""
    greenbone_port: int = 9390
    greenbone_cafile: str = ""
    defectdojo_url: str = ""
    defectdojo_api_token: SecretStr = SecretStr("")
    defectdojo_product_type: str = "CyberCore"
    defectdojo_product: str = "CyberCore Lab"
    defectdojo_engagement: str = "CyberCore automated"
    defectdojo_verify_tls: bool = True
    defectdojo_ca_bundle: str = ""
    nuclei_allowlist_file: Path = Path("config/nuclei_templates.yaml")
    tool_mode: Literal["mock", "local"] = "mock"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
