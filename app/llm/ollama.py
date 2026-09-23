from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.llm.base import LLMClientError, ModelCompletion

__all__ = ["ModelCompletion", "OllamaChatClient", "OllamaClientError"]


class OllamaClientError(LLMClientError):
    """Raised when Ollama is unavailable or returns an invalid response."""


class _ChatMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role: str
    content: str


class _ChatResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model: str
    message: _ChatMessage
    done: bool
    total_duration: int | None = Field(default=None, ge=0)
    load_duration: int | None = Field(default=None, ge=0)
    prompt_eval_count: int | None = Field(default=None, ge=0)
    eval_count: int | None = Field(default=None, ge=0)
    eval_duration: int | None = Field(default=None, ge=0)


class _ModelDetails(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str


class _TagsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    models: list[_ModelDetails]


class OllamaChatClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 120,
        context_tokens: int = 8192,
        http_client: httpx.AsyncClient | None = None,
    ):
        if timeout_seconds <= 0:
            raise ValueError("El timeout de Ollama debe ser positivo")
        if not 1024 <= context_tokens <= 32768:
            raise ValueError("El contexto de Ollama debe estar entre 1024 y 32768")
        parsed_url = httpx.URL(base_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.host:
            raise ValueError("OLLAMA_BASE_URL debe ser una URL HTTP válida")

        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.context_tokens = context_tokens
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout_seconds,
        )

    async def available_models(self) -> list[str]:
        response = await self._request("GET", "/api/tags")
        try:
            tags = _TagsResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise OllamaClientError(
                "Ollama devolvió una lista de modelos inválida"
            ) from exc
        return sorted(model.name for model in tags.models)

    async def chat_structured(
        self,
        model: str,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
        *,
        think: bool = False,
        num_predict: int = 256,
        num_ctx: int | None = None,
    ) -> ModelCompletion:
        if not model or len(model) > 200:
            raise ValueError("El nombre del modelo es inválido")
        if not messages:
            raise ValueError("La conversación no puede estar vacía")

        ctx = num_ctx or self.context_tokens
        response = await self._request(
            "POST",
            "/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "think": think,
                "format": response_schema,
                "options": {
                    "temperature": 0,
                    "num_ctx": ctx,
                    "num_predict": num_predict,
                },
            },
        )
        try:
            parsed = _ChatResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise OllamaClientError("Ollama devolvió una respuesta inválida") from exc
        if not parsed.done:
            raise OllamaClientError("Ollama no marcó la respuesta como terminada")

        return ModelCompletion(
            content=parsed.message.content,
            model=parsed.model,
            total_duration_ns=parsed.total_duration,
            load_duration_ns=parsed.load_duration,
            prompt_eval_count=parsed.prompt_eval_count,
            eval_count=parsed.eval_count,
            eval_duration_ns=parsed.eval_duration,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "OllamaChatClient":
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self._client.request(method, path, **kwargs)
            response.raise_for_status()
            return response
        except httpx.TimeoutException as exc:
            raise OllamaClientError("Ollama superó el timeout configurado") from exc
        except httpx.HTTPStatusError as exc:
            raise OllamaClientError(
                f"Ollama respondió con HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise OllamaClientError("No se pudo conectar con Ollama") from exc
