import json

import pytest
import yaml

from app.evaluation.benchmark import BenchmarkRunner, BenchmarkSuite
from app.evaluation.rules import contextual_priority
from app.llm.base import ModelCompletion
from scripts.generate_benchmark import OUTPUT, build_suite

SUITE_PATH = "config/benchmark_cybercam.yaml"


def test_committed_suite_matches_generator():
    committed = yaml.safe_load(OUTPUT.read_text(encoding="utf-8"))
    assert committed == build_suite(), "Regenera con: python -m scripts.generate_benchmark"


def test_suite_has_planned_shape_and_valid_cases():
    suite = BenchmarkSuite.from_yaml(SUITE_PATH)
    categories: dict[str, int] = {}
    for case in suite.cases:
        categories[case.category] = categories.get(case.category, 0) + 1
    assert len(suite.cases) == 150
    assert categories == {
        "tool_selection": 40,
        "scope_compliance": 20,
        "version_accuracy": 30,
        "finding_status": 20,
        "contradictory_evidence": 20,
        "prioritization": 20,
    }
    assert {case.split for case in suite.cases} == {"train", "development", "test"}
    assert len({case.prompt for case in suite.cases}) == 150


def test_system_prompt_does_not_leak_case_content():
    suite = BenchmarkSuite.from_yaml(SUITE_PATH)
    system = BenchmarkRunner._messages(suite.cases[0], {})[0]["content"]
    for case in suite.cases:
        assert case.prompt not in system
    for leaked in ("1.2.5", "8.8.8.8", "CVE-", "192.168.10.25"):
        assert leaked not in system


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"cvss": 7.5, "epss": 0.85, "kev": True, "exposure": "public", "asset_criticality": 5}, "critical"),
        ({"cvss": 5.0, "epss": 0.01, "kev": True, "exposure": "internal", "asset_criticality": 4}, "critical"),
        ({"cvss": 5.0, "epss": 0.6, "kev": False, "exposure": "internal", "asset_criticality": 2}, "high"),
        ({"cvss": 9.8, "epss": 0.01, "kev": False, "exposure": "public", "asset_criticality": 5}, "high"),
        ({"cvss": 7.0, "epss": 0.01, "kev": False, "exposure": "public", "asset_criticality": 5}, "medium"),
        ({"cvss": 4.0, "epss": 0.1, "kev": False, "exposure": "internal", "asset_criticality": 1}, "medium"),
        ({"cvss": 6.9, "epss": 0.09, "kev": False, "exposure": "public", "asset_criticality": 5}, "low"),
    ],
)
def test_contextual_priority(kwargs, expected):
    assert contextual_priority(**kwargs) == expected


def test_contextual_priority_rejects_out_of_range():
    with pytest.raises(ValueError):
        contextual_priority(cvss=11, epss=0.1, kev=False, exposure="public", asset_criticality=3)


class EchoDenyClient:
    async def chat_structured(self, model, messages, response_schema):
        return ModelCompletion(
            content=json.dumps({"outcome": "deny", "reason": "fuera del alcance"}),
            model=model,
        )


@pytest.mark.asyncio
async def test_runner_filters_split_and_reports_by_category():
    suite = BenchmarkSuite.from_yaml(SUITE_PATH)
    report = await BenchmarkRunner(EchoDenyClient()).run(suite, "m", split="development")

    development = [case for case in suite.cases if case.split == "development"]
    assert report.split == "development"
    assert report.total_cases == len(development)
    assert sum(entry["total"] for entry in report.by_category.values()) == len(development)
    # A model that always denies must not pass the suite.
    assert report.pass_rate < 0.5
