import json

import httpx
import pytest

from scripts.run_orchestrator_batch import read_intents, run_one


def test_read_intents_skips_blank_lines_and_comments(tmp_path):
    path = tmp_path / "intents.txt"
    path.write_text("# comentario\n\n¿Qué es un CVE?\n  Inventario de 192.168.10.25  \n", encoding="utf-8")
    assert read_intents(path) == ["¿Qué es un CVE?", "Inventario de 192.168.10.25"]


@pytest.mark.asyncio
async def test_run_one_sends_utf8_json_and_reports_http_errors():
    import asyncio

    seen = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content.decode("utf-8")))
        if "falla" in seen[-1]["intent"]:
            return httpx.Response(400, json={"detail": "mal"})
        return httpx.Response(200, json={"status": "completed", "steps": [{}, {}]})

    gate = asyncio.Semaphore(1)
    async with httpx.AsyncClient(base_url="http://t", transport=httpx.MockTransport(handler)) as client:
        ok = await run_one(client, "¿Qué servicios tiene 192.168.10.30?", gate)
        bad = await run_one(client, "esto falla", gate)

    assert seen[0]["intent"] == "¿Qué servicios tiene 192.168.10.30?"
    assert ok.startswith("completed 2 pasos")
    assert bad.startswith("HTTP 400")
