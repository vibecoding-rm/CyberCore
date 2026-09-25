import json

from app.training.quality import audit_training_splits, blocking_quality_issues


def example(answer, prompt="p", source="trace"):
    return {
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": json.dumps(answer)},
        ],
        "meta": {"source": source},
    }


def test_audit_detects_exact_weighting_and_protocol_mixing():
    orchestrator = example({"action_type": "final_answer", "final_summary": "ok"})
    replay = example({"outcome": "deny", "reason": "fuera"}, prompt="q", source="replay")
    report = audit_training_splits({"train": [orchestrator, replay, replay], "validation": [], "test": []})

    assert report["exact_duplicates"] == 1
    assert report["protocols"] == {"benchmark_outcome": 2, "orchestrator_action": 1}
    issues = blocking_quality_issues(report, max_exact_duplicate_rate=0.1)
    assert any("duplicados" in issue for issue in issues)
    assert any("protocolos" in issue for issue in issues)


def test_audit_detects_cross_split_prompt_leakage():
    train = example({"action_type": "final_answer"})
    validation = example({"action_type": "final_answer", "final_summary": "distinto"})
    report = audit_training_splits({"train": [train], "validation": [validation], "test": []})

    assert report["cross_split_prompt_overlaps"] == {"train:validation": 1}
    assert any("split" in issue for issue in blocking_quality_issues(report))
