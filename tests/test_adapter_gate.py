from pathlib import Path

from app.evaluation.benchmark import BenchmarkReport
from app.evaluation.gate import evaluate_adapter

BASELINE = Path("reports/benchmarks/2026-09-24-qwen3.5-9b-q4km-test-v2.json")


def baseline() -> BenchmarkReport:
    return BenchmarkReport.model_validate_json(BASELINE.read_text(encoding="utf-8"))


def with_results(report: BenchmarkReport, **changes) -> BenchmarkReport:
    """Flip case outcomes: case_id=(passed, checks_override)."""
    results = []
    for result in report.results:
        if result.case_id in changes:
            passed, checks = changes[result.case_id]
            result = result.model_copy(update={"passed": passed, "checks": checks or result.checks})
        results.append(result)
    passed_cases = sum(r.passed for r in results)
    return report.model_copy(update={"results": results, "passed_cases": passed_cases})


def test_identical_reports_are_accepted():
    assert evaluate_adapter(baseline(), baseline()).accepted


def test_fixing_analyst_errors_is_accepted_and_listed():
    candidate = with_results(baseline(), **{"version-013": (True, {"outcome": True})})
    result = evaluate_adapter(baseline(), candidate)
    assert result.accepted
    assert result.improved == ["version-013"]


def test_any_safety_regression_rejects_even_if_total_improves():
    candidate = with_results(
        baseline(),
        **{
            "version-013": (True, {"outcome": True}),
            "version-026": (True, {"outcome": True}),
            "scope-016": (False, {"outcome": False}),
        },
    )
    result = evaluate_adapter(baseline(), candidate)
    assert not result.accepted
    assert any("seguridad" in reason and "scope-016" in reason for reason in result.reasons)


def test_new_forbidden_claim_rejects_even_on_a_case_baseline_failed():
    # version-013 already fails in the baseline (wrong outcome) without a
    # forbidden claim; the candidate now also claims what it must not.
    candidate = with_results(
        baseline(), **{"version-013": (False, {"outcome": False, "forbidden_claim": False})}
    )
    result = evaluate_adapter(baseline(), candidate)
    assert not result.accepted
    assert any("version-013" in reason for reason in result.reasons)


def test_forbidden_claims_inherited_from_baseline_are_reported_not_blocking():
    result = evaluate_adapter(baseline(), baseline())
    assert result.accepted
    assert result.inherited_forbidden_claims == ["contradiction-016"]


def test_invalid_json_rate_and_mismatched_reports_reject():
    candidate = baseline().model_copy(update={"valid_response_rate": 0.97})
    assert not evaluate_adapter(baseline(), candidate).accepted

    other_split = baseline().model_copy(update={"split": "development"})
    assert not evaluate_adapter(baseline(), other_split).accepted

    fewer = baseline().model_copy(update={"results": baseline().results[:-1]})
    assert not evaluate_adapter(baseline(), fewer).accepted
