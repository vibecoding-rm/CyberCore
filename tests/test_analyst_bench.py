import asyncio
import hashlib
import json
from datetime import datetime, timezone

import httpx
import pytest

from app.analyst.bench import (
    AnalystRun,
    AnswerRecord,
    CaseResult,
    RubricScores,
    ScoreInput,
    StoredScore,
    SystemInfo,
    build_report,
    next_blind_case,
)
from app.analyst.prompt import analyst_response_schema, run_llm_analyst
from app.api.models import EvidenceCaseBundle
from app.core.auth import ApiCredential, ApiKeyAuthenticator
from app.core.evidence_bundle import evidence_case_integrity_issues
from app.llm.base import LLMClientError, ModelCompletion
from app.main import app
from app.storage.postgres_analyst_bench import DuplicateScoreError
from scripts.generate_analyst_cases import BENCH_SIGNER, CASES_PER_SPLIT, OUTPUT_DIR, build_split

APPROVER_KEY = "approver-key-with-at-least-32-characters"
OUTPUT = {
    "summary": "Resumen.",
    "evidence_interpretation": [{"evidence_id": "EVD-AAAAAAAAAAAA", "statement": "x"}],
    "contradictions": [],
    "missing_evidence": ["Falta validación."],
    "recommended_actions": ["Actualizar."],
    "confidence_explanation": "Media.",
}


def load_split(split):
    return [json.loads(line) for line in (OUTPUT_DIR / f"{split}.jsonl").read_text(encoding="utf-8").splitlines()]


# --- cases --------------------------------------------------------------------

def test_committed_cases_match_the_generator_and_manifest():
    manifest = json.loads((OUTPUT_DIR / "manifest.json").read_text(encoding="utf-8"))
    for split, count in CASES_PER_SPLIT.items():
        path = OUTPUT_DIR / f"{split}.jsonl"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["splits"][split]["sha256"]
        generated = asyncio.run(build_split(split))
        assert [json.loads(json.dumps(c, sort_keys=True)) for c in generated] == load_split(split)
        assert len(generated) == count


def test_splits_share_no_family_and_every_bundle_verifies():
    families = {split: {c["family"] for c in load_split(split)} for split in CASES_PER_SPLIT}
    assert not families["development"] & families["holdout"]
    for split in CASES_PER_SPLIT:
        statuses = {c["finding_status"] for c in load_split(split)}
        assert statuses == {"candidate", "probable", "confirmed"}
        for case in load_split(split):
            bundle = EvidenceCaseBundle.model_validate(case["bundle"])
            assert evidence_case_integrity_issues(bundle, BENCH_SIGNER.public_key) == []


def test_nuclei_hit_on_another_ip_never_confirms_a_case():
    for split in CASES_PER_SPLIT:
        for case in load_split(split):
            if case["scenario"]["validation"] == "active_other_ip":
                assert case["finding_status"] != "confirmed", case["case_id"]


# --- blind review -------------------------------------------------------------

def make_run() -> AnalystRun:
    ok = AnswerRecord(output=OUTPUT, latency_ms=10)
    failed = AnswerRecord(output=OUTPUT, violations=["menciona un identificador ajeno"])
    return AnalystRun(
        run_id="test-run", split="development", cases_sha256="0" * 64,
        created_at=datetime(2026, 9, 25, tzinfo=timezone.utc), salt="1" * 32,
        systems={"C0": SystemInfo(kind="template"), "C1": SystemInfo(kind="llm", model="m")},
        results=[
            CaseResult(case_id="case-1", family="F", finding_status="probable", view={"v": 1},
                       answers={"C0": ok, "C1": ok}),
            CaseResult(case_id="case-2", family="F", finding_status="candidate", view={"v": 2},
                       answers={"C0": ok, "C1": failed}),
        ],
    )


def score(run, case_id, system, reviewer, value):
    return StoredScore(
        case_id=case_id, answer_id=run.answer_id(case_id, system), reviewer=reviewer,
        scores=RubricScores(**dict.fromkeys(
            ("fidelity", "completeness", "actionability", "calibration", "clarity"), value)),
        scored_at=datetime(2026, 9, 25, tzinfo=timezone.utc),
    )


def test_blind_case_hides_systems_and_skips_gate_failures():
    run = make_run()
    blind = next_blind_case(run, "alice", [])
    payload = blind.model_dump_json()
    assert "C0" not in payload and "C1" not in payload and "template" not in payload
    assert {a.answer_id for a in blind.answers} == {run.answer_id("case-1", s) for s in ("C0", "C1")}

    scored = [score(run, "case-1", s, "alice", 2) for s in ("C0", "C1")]
    second = next_blind_case(run, "alice", scored)
    assert second.case_id == "case-2"
    assert [a.answer_id for a in second.answers] == [run.answer_id("case-2", "C0")]
    assert second.reviewed_cases == 1


def test_answer_order_depends_on_the_reviewer():
    run = make_run()
    orders = {
        tuple(a.answer_id for a in next_blind_case(run, f"reviewer-{i}", []).answers)
        for i in range(12)
    }
    assert len(orders) == 2


def test_report_counts_gate_failures_as_zero_and_applies_adoption_criteria():
    run = make_run()
    scores = [score(run, "case-1", "C0", r, 1) for r in ("a", "b")]
    scores += [score(run, "case-2", "C0", r, 1) for r in ("a", "b")]
    scores += [score(run, "case-1", "C1", r, 2) for r in ("a", "b")]
    report = build_report(run, scores)

    assert report["systems"]["C0"]["mean_total"] == 5
    assert report["systems"]["C1"]["mean_total"] == 5  # 10 and a gate failure scored 0
    assert report["systems"]["C1"]["gate_failures"] == ["case-2"]
    adoption = report["adoption"]["C1"]
    assert adoption["complete"] is True
    assert adoption["meets_criteria"] is False
    assert report["agreement"]["exact"] == 1.0


# --- LLM call -------------------------------------------------------------------

def test_response_schema_requires_every_field_without_refs():
    schema = analyst_response_schema()
    assert schema["required"] == list(OUTPUT)
    assert "$ref" not in json.dumps(schema)


class FakeClient:
    def __init__(self, content=None, error=None):
        self.content, self.error = content, error

    async def chat_structured(self, model, messages, schema, **kwargs):
        if self.error:
            raise self.error
        return ModelCompletion(content=self.content, model=model, eval_count=42)


def test_llm_answers_are_recorded_and_errors_never_raise():
    bundle = EvidenceCaseBundle.model_validate(load_split("development")[0]["bundle"])
    ok = asyncio.run(run_llm_analyst(FakeClient(json.dumps(OUTPUT)), "m", bundle))
    assert ok["output"]["summary"] == "Resumen." and ok["generated_tokens"] == 42
    bad = asyncio.run(run_llm_analyst(FakeClient('{"summary": "x"}'), "m", bundle))
    assert bad["output"] is None and bad["error"]
    down = asyncio.run(run_llm_analyst(FakeClient(error=LLMClientError("caído")), "m", bundle))
    assert down["error"] == "caído"


# --- API ------------------------------------------------------------------------

class FakeBenchStore:
    def __init__(self, run):
        self.run, self.stored = run, []

    async def list_runs(self):
        return [self.run]

    async def get_run(self, run_id):
        return self.run

    async def scores(self, run_id):
        return list(self.stored)

    async def add_score(self, run_id, reviewer, item: ScoreInput):
        if any(s.reviewer == reviewer and s.answer_id == item.answer_id for s in self.stored):
            raise DuplicateScoreError("Ya puntuaste esta respuesta")
        stored = StoredScore(**item.model_dump(), reviewer=reviewer,
                             scored_at=datetime.now(timezone.utc))
        self.stored.append(stored)
        return stored


@pytest.mark.asyncio
async def test_blind_review_api_flow():
    run = make_run()
    async with app.router.lifespan_context(app):
        app.state.authenticator = ApiKeyAuthenticator([ApiCredential(
            subject="reviewer-1", role="approver",
            key_sha256=ApiKeyAuthenticator.hash_api_key(APPROVER_KEY),
        )])
        app.state.analyst_bench = FakeBenchStore(run)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver",
            headers={"Authorization": f"Bearer {APPROVER_KEY}"},
        ) as client:
            runs = await client.get("/v1/analyst-bench/runs")
            blind = await client.get("/v1/analyst-bench/runs/test-run/next")
            answer_id = blind.json()["answers"][0]["answer_id"]
            body = {"case_id": "case-1", "answer_id": answer_id,
                    "scores": {"fidelity": 2, "completeness": 1, "actionability": 1,
                               "calibration": 2, "clarity": 2}}
            first = await client.post("/v1/analyst-bench/runs/test-run/scores", json=body)
            again = await client.post("/v1/analyst-bench/runs/test-run/scores", json=body)
            failed = await client.post("/v1/analyst-bench/runs/test-run/scores", json={
                **body, "case_id": "case-2", "answer_id": run.answer_id("case-2", "C1")})
            page = await client.get("/analyst-review")

    assert runs.json()[0]["run_id"] == "test-run"
    assert "C1" not in blind.text
    assert first.status_code == 201
    assert again.status_code == 409
    assert failed.status_code == 404  # gate failures are never shown or scored
    assert page.status_code == 200 and "Content-Security-Policy" in page.headers


def test_prompt_versions_are_selected_per_system():
    from app.analyst.prompt import ANALYST_PROMPTS, analyst_messages
    from scripts.run_analyst_bench import parse_llm

    assert parse_llm(["C1=qwen3.5:9b", "C2=qwen3.5:9b@v2"]) == {
        "C1": ("qwen3.5:9b", "v1"), "C2": ("qwen3.5:9b", "v2")}
    with pytest.raises(SystemExit):
        parse_llm(["C2=qwen3.5:9b@v9"])
    bundle = EvidenceCaseBundle.model_validate(load_split("development")[0]["bundle"])
    assert analyst_messages(bundle, "v2")[0]["content"] == ANALYST_PROMPTS["v2"]
    assert "comparacion_de_versiones" in ANALYST_PROMPTS["v2"]
