import json

import httpx
import pytest

from app.llm.ollama import OllamaChatClient, OllamaClientError


@pytest.mark.asyncio
async def test_chat_uses_schema_without_exposing_tools():
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={"models": [{"name": "qwen3.5:9b", "size": 123}]},
            )
        observed.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "qwen3.5:9b",
                "message": {"role": "assistant", "content": '{"outcome":"deny"}'},
                "done": True,
                "total_duration": 2_000_000_000,
                "prompt_eval_count": 100,
                "eval_count": 20,
                "eval_duration": 1_000_000_000,
            },
        )

    http_client = httpx.AsyncClient(
        base_url="http://ollama.test",
        transport=httpx.MockTransport(handler),
    )
    client = OllamaChatClient("http://ollama.test", http_client=http_client)
    try:
        assert await client.available_models() == ["qwen3.5:9b"]
        completion = await client.chat_structured(
            "qwen3.5:9b",
            [{"role": "user", "content": "prueba"}],
            {"type": "object", "properties": {"outcome": {"type": "string"}}},
        )
    finally:
        await http_client.aclose()

    assert completion.eval_count == 20
    assert observed["stream"] is False
    assert observed["options"]["temperature"] == 0
    assert observed["options"]["num_ctx"] == 8192
    assert observed["format"]["type"] == "object"
    assert "tools" not in observed


@pytest.mark.asyncio
async def test_http_errors_are_sanitized():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "sensitive backend detail"})

    http_client = httpx.AsyncClient(
        base_url="http://ollama.test",
        transport=httpx.MockTransport(handler),
    )
    client = OllamaChatClient("http://ollama.test", http_client=http_client)
    try:
        with pytest.raises(OllamaClientError, match="HTTP 404") as error:
            await client.available_models()
    finally:
        await http_client.aclose()

    assert "sensitive backend detail" not in str(error.value)


def test_rejects_non_http_base_url():
    with pytest.raises(ValueError, match="URL HTTP válida"):
        OllamaChatClient("file:///tmp/ollama.sock")
