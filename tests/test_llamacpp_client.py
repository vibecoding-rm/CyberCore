import json

import httpx
import pytest

from app.llm.base import LLMClientError
from app.llm.factory import create_chat_client
from app.llm.llamacpp import LlamaCppChatClient, LlamaCppClientError
from app.llm.ollama import OllamaChatClient
from app.settings import Settings


def _client(handler) -> tuple[LlamaCppChatClient, httpx.AsyncClient]:
    http_client = httpx.AsyncClient(
        base_url="http://llama.test",
        transport=httpx.MockTransport(handler),
    )
    return LlamaCppChatClient("http://llama.test", http_client=http_client), http_client


def _completion(content: str | None, finish_reason: str = "stop") -> dict:
    return {
        "model": "qwen3.5:9b",
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        "timings": {"prompt_ms": 500.0, "predicted_ms": 1000.0},
    }


@pytest.mark.asyncio
async def test_chat_uses_json_schema_without_exposing_tools():
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "qwen3.5:9b"}]})
        observed.update(json.loads(request.content))
        return httpx.Response(200, json=_completion('{"outcome":"deny"}'))

    client, http_client = _client(handler)
    try:
        assert await client.available_models() == ["qwen3.5:9b"]
        completion = await client.chat_structured(
            "qwen3.5:9b",
            [{"role": "user", "content": "prueba"}],
            {"type": "object", "properties": {"outcome": {"type": "string"}}},
            num_predict=64,
        )
    finally:
        await http_client.aclose()

    assert completion.content == '{"outcome":"deny"}'
    assert completion.prompt_eval_count == 100
    assert completion.eval_count == 20
    assert completion.eval_duration_ns == 1_000_000_000
    assert completion.total_duration_ns == 1_500_000_000
    assert observed["stream"] is False
    assert observed["temperature"] == 0
    assert observed["max_tokens"] == 64
    assert observed["response_format"]["type"] == "json_schema"
    assert observed["response_format"]["json_schema"]["schema"]["type"] == "object"
    assert observed["chat_template_kwargs"] == {"enable_thinking": False}
    assert "tools" not in observed


@pytest.mark.asyncio
async def test_truncated_output_is_rejected():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_completion('{"outc', "length"))

    client, http_client = _client(handler)
    try:
        with pytest.raises(LlamaCppClientError, match="límite de tokens"):
            await client.chat_structured(
                "m", [{"role": "user", "content": "x"}], {"type": "object"}
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_http_errors_are_sanitized():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "sensitive backend detail"})

    client, http_client = _client(handler)
    try:
        with pytest.raises(LLMClientError) as exc_info:
            await client.available_models()
    finally:
        await http_client.aclose()

    assert "HTTP 500" in str(exc_info.value)
    assert "sensitive" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_invalid_payload_is_rejected():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "m", "choices": []})

    client, http_client = _client(handler)
    try:
        with pytest.raises(LlamaCppClientError, match="respuesta inválida"):
            await client.chat_structured(
                "m", [{"role": "user", "content": "x"}], {"type": "object"}
            )
    finally:
        await http_client.aclose()


def test_rejects_invalid_base_url():
    with pytest.raises(ValueError):
        LlamaCppChatClient("ftp://llama.test")


@pytest.mark.asyncio
async def test_factory_selects_provider():
    llama = create_chat_client(Settings(llm_provider="llamacpp", _env_file=None))
    ollama = create_chat_client(Settings(llm_provider="ollama", _env_file=None))
    try:
        assert isinstance(llama, LlamaCppChatClient)
        assert isinstance(ollama, OllamaChatClient)
    finally:
        await llama.aclose()
        await ollama.aclose()


@pytest.mark.asyncio
async def test_temperature_is_configurable_and_bounded():
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.update(json.loads(request.content))
        return httpx.Response(200, json=_completion('{"outcome":"deny"}'))

    http_client = httpx.AsyncClient(
        base_url="http://llama.test", transport=httpx.MockTransport(handler)
    )
    client = LlamaCppChatClient("http://llama.test", http_client=http_client, temperature=0.8)
    try:
        await client.chat_structured("m", [{"role": "user", "content": "x"}], {"type": "object"})
    finally:
        await http_client.aclose()

    assert observed["temperature"] == 0.8
    with pytest.raises(ValueError):
        LlamaCppChatClient("http://llama.test", temperature=3)
