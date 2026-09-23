from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field


class LLMClientError(RuntimeError):
    """Raised when a local model backend is unavailable or answers invalidly."""


class ModelCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    model: str
    total_duration_ns: int | None = Field(default=None, ge=0)
    load_duration_ns: int | None = Field(default=None, ge=0)
    prompt_eval_count: int | None = Field(default=None, ge=0)
    eval_count: int | None = Field(default=None, ge=0)
    eval_duration_ns: int | None = Field(default=None, ge=0)


class ChatClient(Protocol):
    """Structured-output chat contract shared by every local backend."""

    async def available_models(self) -> list[str]: ...

    async def chat_structured(
        self,
        model: str,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
        *,
        think: bool = False,
        num_predict: int = 256,
        num_ctx: int | None = None,
    ) -> ModelCompletion: ...

    async def aclose(self) -> None: ...
