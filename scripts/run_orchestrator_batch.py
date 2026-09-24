"""Send a batch of operator intents to the orchestrator API to collect traces.

    CYBERCORE_API_KEY=<operator key> python -m scripts.run_orchestrator_batch intents.txt

One intent per line (blank lines and lines starting with # are ignored).
Every run is recorded as a trace and then waits for human review in /review;
nothing here approves anything.
"""

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

import httpx


def read_intents(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


async def run_one(client: httpx.AsyncClient, intent: str, gate: asyncio.Semaphore) -> str:
    async with gate:
        started = time.monotonic()
        try:
            response = await client.post("/v1/orchestrator/run", json={"intent": intent})
        except httpx.HTTPError as exc:
            return f"ERROR {type(exc).__name__} | {intent}"
        elapsed = time.monotonic() - started
        if response.status_code != 200:
            return f"HTTP {response.status_code} {elapsed:.0f}s | {intent} | {response.text[:200]}"
        body = response.json()
        return f"{body['status']} {len(body['steps'])} pasos {elapsed:.0f}s | {intent}"


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("intents", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args()

    key = os.environ.get("CYBERCORE_API_KEY")
    if not key:
        print("Define CYBERCORE_API_KEY con una clave de rol operator", file=sys.stderr)
        return 1
    intents = read_intents(args.intents)
    gate = asyncio.Semaphore(max(1, args.concurrency))
    async with httpx.AsyncClient(
        base_url=args.base_url,
        timeout=args.timeout,
        headers={"Authorization": f"Bearer {key}"},
    ) as client:
        tasks = [asyncio.create_task(run_one(client, intent, gate)) for intent in intents]
        failures = 0
        for done in asyncio.as_completed(tasks):
            line = await done
            failures += not line.startswith(("completed", "approval_required", "denied", "error"))
            print(line, flush=True)
    print(f"FIN: {len(intents)} peticiones, {failures} fallos de transporte o HTTP", flush=True)
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
