from functools import lru_cache
from pathlib import Path
from typing import Literal

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
    ollama_base_url: str = "http://localhost:11434"
    ollama_request_timeout_seconds: int = 120
    ollama_context_tokens: int = 8192
    orchestrator_model: str = "qwen3.5:9b"
    analyst_model: str = "foundation-sec-8b-reasoning"
    tool_mode: Literal["mock"] = "mock"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
