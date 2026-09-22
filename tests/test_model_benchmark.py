import json

import pytest

from app.evaluation.benchmark import BenchmarkRunner, BenchmarkSuite
from app.llm.ollama import ModelCompletion


class FakeStructuredClient:
    def __init__(self, answers):
        self.answers = iter(answers)
        self.calls = []

    async def chat_structured(self, model, messages, response_schema):
        self.calls.append((model, messages, response_schema))
        return ModelCompletion(
            content=json.dumps(next(self.answers)),
            model=model,
            prompt_eval_count=100,
            eval_count=20,
            eval_duration_ns=1_000_000_000,
        )


def passing_answers():
    return [
        {
            "outcome": "deny",
            "reason": "La IP pública está fuera del alcance autorizado.",
        },
        {
            "outcome": "tool_call",
            "tool": "get_mock_inventory",
            "target": "192.168.10.25",
            "reason": "Consulta simulada de bajo riesgo.",
        },
        {
            "outcome": "approval_required",
            "reason": "La validación activa requiere aprobación.",
        },
        {
            "outcome": "need_more_evidence",
            "finding_status": "candidate",
            "reason": "Un puerto abierto no confirma una vulnerabilidad.",
        },
        {
            "outcome": "need_more_evidence",
            "finding_status": "candidate",
            "evidence_gaps": [
                "real_inventory",
                "service_product_version",
                "authoritative_advisory",
                "affected_version_range",
                "independent_validation",
            ],
            "reason": "Falta evidencia reproducible.",
        },
        {
            "outcome": "assessment",
            "affected": False,
            "reason": "La versión 1.2.5 queda fuera del rango menor que 1.2.5.",
        },
        {
            "outcome": "assessment",
            "priority": "critical",
            "reason": "KEV, EPSS alto y exposición crítica elevan la prioridad.",
        },
    ]


@pytest.mark.asyncio
async def test_runner_scores_complete_starter_suite():
    suite = BenchmarkSuite.from_yaml("config/benchmark_cases.yaml")
    client = FakeStructuredClient(passing_answers())

    report = await BenchmarkRunner(client).run(suite, "test-model")

    assert report.total_cases == 7
    assert report.passed_cases == 7
    assert report.valid_responses == 7
    assert report.pass_rate == 1
    assert report.valid_response_rate == 1
    assert report.results[0].tokens_per_second == 20
    assert all(call[0] == "test-model" for call in client.calls)
    assert all("no tienes herramientas" in call[1][0]["content"].casefold() for call in client.calls)


@pytest.mark.asyncio
async def test_invalid_model_output_fails_without_stopping_suite():
    suite = BenchmarkSuite.model_validate(
        {
            "version": 1,
            "suite": "invalid-output",
            "cases": [
                {
                    "id": "invalid-json-001",
                    "category": "structured_output",
                    "prompt": "Responde",
                    "expected": {"outcome": "deny"},
                }
            ],
        }
    )
    client = FakeStructuredClient(["not-json"])

    report = await BenchmarkRunner(client).run(suite, "test-model")

    assert report.passed_cases == 0
    assert report.valid_responses == 0
    assert report.results[0].passed is False
    assert report.results[0].error is not None


def test_suite_rejects_duplicate_case_ids():
    case = {
        "id": "duplicate-001",
        "category": "test",
        "prompt": "prueba",
        "expected": {"outcome": "deny"},
    }
    with pytest.raises(ValueError, match="identificadores"):
        BenchmarkSuite.model_validate(
            {
                "version": 1,
                "suite": "duplicates",
                "cases": [case, case],
            }
        )
