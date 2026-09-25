import json
from datetime import datetime, timezone

import pytest

from app.evaluation.benchmark import BenchmarkAnswer, BenchmarkCaseResult, BenchmarkReport, BenchmarkSuite
from scripts.build_mixed_dataset import BENCHMARK, parse_weights, replay_examples, weighted

SUITE = BenchmarkSuite.from_yaml(BENCHMARK)


def report(case_ids, passed=True):
    results = [
        BenchmarkCaseResult(
            case_id=cid, category="x", passed=passed, valid_response=True, checks={}, latency_ms=1,
            answer=BenchmarkAnswer(outcome="deny", reason="fuera del alcance"),
        )
        for cid in case_ids
    ]
    return BenchmarkReport(
        suite=SUITE.suite, model="m", created_at=datetime.now(timezone.utc), total_cases=len(results),
        passed_cases=len(results) if passed else 0, valid_responses=len(results), pass_rate=1.0,
        valid_response_rate=1.0, average_latency_ms=1, split="train", results=results,
    )


def ids(split):
    return [case.id for case in SUITE.cases if case.split == split]


def test_replay_uses_passed_train_answers_in_grammar_field_order():
    [example] = replay_examples(report(ids("train")[:1]), SUITE)
    assert example["messages"][0]["role"] == "system"
    assert example["messages"][1]["content"] == next(c.prompt for c in SUITE.cases if c.id == ids("train")[0])
    target = example["messages"][-1]
    assert target["role"] == "assistant"
    # Same keys and order the constrained model emits for "deny".
    assert list(json.loads(target["content"])) == ["reason", "outcome"]


def test_failed_answers_are_skipped_and_other_splits_rejected():
    assert replay_examples(report(ids("train")[:3], passed=False), SUITE) == []
    with pytest.raises(SystemExit):
        replay_examples(report(ids("test")[:1]), SUITE)


def test_category_weights_override_the_default_replay_weight():
    examples = [{"meta": {"category": "finding_status"}}, {"meta": {"category": "scope_compliance"}}]
    repeated = weighted(examples, 2, parse_weights(["finding_status=4"]))
    assert [e["meta"]["category"] for e in repeated].count("finding_status") == 4
    assert [e["meta"]["category"] for e in repeated].count("scope_compliance") == 2
    with pytest.raises(SystemExit):
        parse_weights(["finding_status=0"])
