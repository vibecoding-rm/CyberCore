from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.llm.base import LLMClientError, ModelCompletion


class LlamaCppClientError(LLMClientError):
    """Raised when llama-server is unavailable or returns an invalid response."""


class _Message(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role: str
    content: str | None = None


class _Choice(BaseModel):
    model_config = ConfigDict(extra="ignore")

    message: _Message
    finish_reason: str | None = None


class _Usage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)


class _Timings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    prompt_ms: float | None = Field(default=None, ge=0)
    predicted_ms: float | None = Field(default=None, ge=0)


class _ChatResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    model: str
    choices: list[_Choice] = Field(min_length=1)
    usage: _Usage | None = None
    timings: _Timings | None = None


class _ModelEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str


class _ModelsResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data: list[_ModelEntry]


def _ms_to_ns(value: float | None) -> int | None:
    return None if value is None else int(value * 1_000_000)


class LlamaCppChatClient:
    """Client for llama.cpp's llama-server through its OpenAI-compatible API.

    llama-server loads one GGUF model at startup with a fixed context (`-c`), so
    `num_ctx` is accepted for interface parity but cannot change per request.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 120,
        api_key: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        if timeout_seconds <= 0:
            raise ValueError("El timeout de llama.cpp debe ser positivo")
        parsed_url = httpx.URL(base_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.host:
            raise ValueError("LLAMACPP_BASE_URL debe ser una URL HTTP válida")

        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout_seconds,
            headers=headers,
        )

    async def available_models(self) -> list[str]:
        response = await self._request("GET", "/v1/models")
        try:
            models = _ModelsResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise LlamaCppClientError(
                "llama.cpp devolvió una lista de modelos inválida"
            ) from exc
        return sorted(model.id for model in models.data)

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

        response = await self._request(
            "POST",
            "/v1/chat/completions",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "temperature": 0,
                "max_tokens": num_predict,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "cybercore_response",
                        "strict": True,
                        "schema": response_schema,
                    },
                },
                "chat_template_kwargs": {"enable_thinking": think},
            },
        )
        try:
            parsed = _ChatResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise LlamaCppClientError(
                "llama.cpp devolvió una respuesta inválida"
            ) from exc

        choice = parsed.choices[0]
        if choice.finish_reason == "length":
            raise LlamaCppClientError(
                "llama.cpp cortó la respuesta por límite de tokens"
            )
        if choice.message.content is None:
            raise LlamaCppClientError("llama.cpp devolvió una respuesta vacía")

        timings = parsed.timings or _Timings()
        usage = parsed.usage or _Usage()
        prompt_ns = _ms_to_ns(timings.prompt_ms)
        eval_ns = _ms_to_ns(timings.predicted_ms)
        total_ns = (
            prompt_ns + eval_ns
            if prompt_ns is not None and eval_ns is not None
            else None
        )
        return ModelCompletion(
            content=choice.message.content,
            model=parsed.model,
            total_duration_ns=total_ns,
            prompt_eval_count=usage.prompt_tokens,
            eval_count=usage.completion_tokens,
            eval_duration_ns=eval_ns,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "LlamaCppChatClient":
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self._client.request(method, path, **kwargs)
            response.raise_for_status()
            return response
        except httpx.TimeoutException as exc:
            raise LlamaCppClientError(
                "llama.cpp superó el timeout configurado"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise LlamaCppClientError(
                f"llama.cpp respondió con HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise LlamaCppClientError("No se pudo conectar con llama.cpp") from exc
