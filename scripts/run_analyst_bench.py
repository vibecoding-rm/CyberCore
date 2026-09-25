"""Run Analyst-Bench systems over the signed evidence cases of one split.

    # C0 (template) and C1 (LLM) in one run
    python -m scripts.run_analyst_bench --split development \
        --llm C1=qwen3.5:9b --base-url http://localhost:8081 --run-id 2026-09-25-dev-9b

    # a prompt version per system: C2=qwen3.5:9b@v2 (default v1)
    # add another system to an existing run (same cases, same blinding salt)
    python -m scripts.run_analyst_bench --add-to reports/analyst/runs/<run>.json \
        --llm C2=qwen3.5:4b --base-url ...

Every answer is checked with the automatic gate; answers are kept even when
they fail, so the report shows why. After fixing a false positive in the
gate, re-check a run without calling any model:

    python -m scripts.run_analyst_bench --regate reports/analyst/runs/<run>.json

Holdout runs need --reason and are appended to reports/analyst/HOLDOUT_LOG.md
before any answer is produced.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from app.analyst.bench import AnalystRun, AnswerRecord, CaseResult, SystemInfo
from app.analyst.contract import AnalystOutput, analyst_gate_violations
from app.analyst.prompt import ANALYST_PROMPTS, case_view, run_llm_analyst
from app.analyst.template import template_analysis
from app.api.models import EvidenceCaseBundle
from app.llm.llamacpp import LlamaCppChatClient
from app.settings import get_settings

CASES_DIR = Path("config/analyst_bench")
RUNS_DIR = Path("reports/analyst/runs")
HOLDOUT_LOG = Path("reports/analyst/HOLDOUT_LOG.md")


def load_cases(split: str) -> tuple[list[dict], str]:
    manifest = json.loads((CASES_DIR / "manifest.json").read_text(encoding="utf-8"))
    path = CASES_DIR / f"{split}.jsonl"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != manifest["splits"][split]["sha256"]:
        raise SystemExit(f"{path}: el hash no coincide con manifest.json")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line], digest


def gated(record: dict, bundle: EvidenceCaseBundle) -> AnswerRecord:
    answer = AnswerRecord(**record)
    if answer.output is not None:
        output = AnalystOutput.model_validate(answer.output)
        answer.violations = analyst_gate_violations(bundle, output)
    return answer


async def answer_llm(
    system: str, model: str, prompt: str, cases: list[dict], args
) -> dict[str, AnswerRecord]:
    settings = get_settings()
    client = LlamaCppChatClient(
        args.base_url or settings.llamacpp_base_url,
        args.timeout,
        api_key=os.environ.get("LLAMACPP_API_KEY") or settings.llamacpp_api_key or None,
    )
    semaphore = asyncio.Semaphore(args.concurrency)
    answers: dict[str, AnswerRecord] = {}

    async def one(case: dict) -> None:
        bundle = EvidenceCaseBundle.model_validate(case["bundle"])
        async with semaphore:
            record = await run_llm_analyst(
                client, model, bundle, num_predict=args.num_predict, prompt=prompt
            )
        answers[case["case_id"]] = gated(record, bundle)
        done = len(answers)
        status = "error" if record["error"] else f"{len(answers[case['case_id']].violations)} violaciones"
        print(f"[{system}] {done}/{len(cases)} {case['case_id']}: {status}", flush=True)

    try:
        if model not in await client.available_models():
            raise SystemExit(f"El modelo {model!r} no está disponible en el endpoint")
        await asyncio.gather(*(one(case) for case in cases))
    finally:
        await client.aclose()
    return answers


def template_answers(cases: list[dict]) -> dict[str, AnswerRecord]:
    answers = {}
    for case in cases:
        bundle = EvidenceCaseBundle.model_validate(case["bundle"])
        record = {"output": template_analysis(bundle).model_dump(), "latency_ms": 0.0}
        answers[case["case_id"]] = gated(record, bundle)
    return answers


def log_holdout(run_id: str, systems: list[str], reason: str) -> None:
    if not HOLDOUT_LOG.exists():
        HOLDOUT_LOG.write_text(
            "# Registro de uso del holdout de Analyst-Bench\n\n"
            "Cada ejecución sobre `config/analyst_bench/holdout.jsonl` se anota aquí antes\n"
            "de producir respuestas. Si un resultado motiva cambiar prompt, modelo o datos,\n"
            "el holdout queda gastado y se genera otro con familias nuevas.\n\n"
            "| Fecha | Run | Sistemas | Motivo |\n|---|---|---|---|\n",
            encoding="utf-8", newline="\n",
        )
    with HOLDOUT_LOG.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"| {datetime.now(timezone.utc):%Y-%m-%d} | {run_id} | {', '.join(systems)} | {reason} |\n")


def regate(path: Path) -> int:
    run = AnalystRun.model_validate_json(path.read_text(encoding="utf-8"))
    cases, digest = load_cases(run.split)
    if digest != run.cases_sha256:
        raise SystemExit("Los casos cambiaron desde que se creó esta ejecución")
    bundles = {c["case_id"]: EvidenceCaseBundle.model_validate(c["bundle"]) for c in cases}
    for result in run.results:
        for system, answer in result.answers.items():
            result.answers[system] = gated(answer.model_dump(exclude={"violations"}), bundles[result.case_id])
    path.write_text(run.model_dump_json(indent=1), encoding="utf-8", newline="\n")
    for system in sorted(run.systems):
        answers = [r.answers[system] for r in run.results if system in r.answers]
        print(f"{system}: {sum(a.passed_gate for a in answers)}/{len(answers)} pasan la puerta automática")
    return 0


def parse_llm(values: list[str]) -> dict[str, tuple[str, str]]:
    """C<n>=<model>[@<prompt version>], e.g. C2=qwen3.5:9b@v2 (default prompt v1)."""
    systems = {}
    for value in values:
        name, _, spec = value.partition("=")
        model, _, prompt = spec.partition("@")
        prompt = prompt or "v1"
        if not name.startswith("C") or not name[1:].isdigit() or name == "C0" or not model:
            raise SystemExit(f"--llm {value!r}: usa C<n>=<modelo>[@<prompt>], con n >= 1")
        if prompt not in ANALYST_PROMPTS:
            raise SystemExit(f"--llm {value!r}: prompt desconocido; opciones {sorted(ANALYST_PROMPTS)}")
        systems[name] = (model, prompt)
    return systems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=["development", "holdout"])
    parser.add_argument("--run-id")
    parser.add_argument("--add-to", type=Path, help="Añade sistemas a una ejecución existente")
    parser.add_argument("--llm", action="append", default=[], metavar="C<n>=<modelo>")
    parser.add_argument("--base-url")
    parser.add_argument("--hardware", default=None, help="Descripción del equipo del endpoint LLM")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--num-predict", type=int, default=1500)
    parser.add_argument("--limit", type=int, default=None, help="Sólo los N primeros casos (pruebas)")
    parser.add_argument("--reason", default="", help="Obligatorio en el holdout")
    parser.add_argument("--regate", type=Path, help="Reaplica la puerta a una ejecución guardada")
    args = parser.parse_args()

    if args.regate:
        return regate(args.regate)

    llm_systems = parse_llm(args.llm)
    if args.add_to:
        run = AnalystRun.model_validate_json(args.add_to.read_text(encoding="utf-8"))
        cases, digest = load_cases(run.split)
        if digest != run.cases_sha256:
            raise SystemExit("Los casos cambiaron desde que se creó esta ejecución")
        clash = set(llm_systems) & set(run.systems)
        if clash:
            raise SystemExit(f"La ejecución ya contiene {sorted(clash)}")
        output = args.add_to
    else:
        if not args.split or not args.run_id:
            raise SystemExit("Indica --split y --run-id, o --add-to")
        cases, digest = load_cases(args.split)
        run = AnalystRun(
            run_id=args.run_id, split=args.split, cases_sha256=digest,
            created_at=datetime.now(timezone.utc), salt=secrets.token_hex(16),
            systems={"C0": SystemInfo(kind="template")},
            results=[
                CaseResult(
                    case_id=c["case_id"], family=c["family"], finding_status=c["finding_status"],
                    view=case_view(EvidenceCaseBundle.model_validate(c["bundle"])), answers={},
                )
                for c in cases
            ],
        )
        output = RUNS_DIR / f"{args.run_id}.json"
        if output.exists():
            raise SystemExit(f"{output} ya existe")
    if args.limit:
        if args.add_to:
            raise SystemExit("--limit no se combina con --add-to")
        if run.split == "holdout":
            raise SystemExit("--limit no se permite en el holdout")
        cases = cases[: args.limit]
        run.results = [r for r in run.results if r.case_id in {c["case_id"] for c in cases}]
    if run.split == "holdout":
        if not args.reason:
            raise SystemExit("El holdout exige --reason (queda registrado)")
        log_holdout(run.run_id, sorted(llm_systems) or ["C0"], args.reason)

    new_answers: dict[str, dict[str, AnswerRecord]] = {}
    if not args.add_to:
        new_answers["C0"] = template_answers(cases)
    for system, (model, prompt) in llm_systems.items():
        new_answers[system] = asyncio.run(answer_llm(system, model, prompt, cases, args))
        endpoint = urlsplit(args.base_url or get_settings().llamacpp_base_url).hostname
        run.systems[system] = SystemInfo(kind="llm", model=model, prompt=prompt,
                                         endpoint=endpoint, hardware=args.hardware)
    for result in run.results:
        for system, answers in new_answers.items():
            result.answers[system] = answers[result.case_id]

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    output.write_text(run.model_dump_json(indent=1), encoding="utf-8", newline="\n")
    for system, answers in new_answers.items():
        passed = sum(a.passed_gate for a in answers.values())
        print(f"{system}: {passed}/{len(answers)} pasan la puerta automática")
    print(f"Ejecución guardada en {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
