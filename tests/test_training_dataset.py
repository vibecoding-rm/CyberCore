import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.agent.prompts import ORCHESTRATOR_SYSTEM_PROMPT
from app.agent.traces import AgentTrace, TraceReview, TraceStep
from app.core.policy import PolicyEngine
from app.training.dataset import (
    TraceSanitizer,
    build_dataset,
    normalize_intent,
    split_for_family,
)

POLICY = PolicyEngine("config/policy.yaml")


def in_scope(target: str) -> bool:
    return POLICY._validate_scope(target) is None


def action(**fields) -> str:
    return json.dumps({"thought": "t", "action_type": "final_answer", "final_summary": "s"} | fields)


def trace(intent: str, outputs: list[str | None], observations: list[str] | None = None) -> AgentTrace:
    now = datetime.now(timezone.utc)
    observations = observations or ["obs"] * len(outputs)
    return AgentTrace(
        run_id=uuid4(), requested_by="op", operator_intent=intent, model="m", status="completed",
        final_report="r", response_schema={}, started_at=now, completed_at=now,
        steps=[
            TraceStep(
                step_number=i + 1,
                messages=[
                    {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Intención del operador: {intent}"},
                    {"role": "user", "content": observations[i]},
                ],
                raw_output=out,
            )
            for i, out in enumerate(outputs)
        ],
    )


def approve(t: AgentTrace, corrections=None) -> TraceReview:
    return TraceReview(
        run_id=t.run_id, reviewer="rev", verdict="approved",
        corrections=corrections or {}, reviewed_at=datetime.now(timezone.utc),
    )


def all_examples(splits):
    return [example for examples in splits.values() for example in examples]


def test_sanitizer_keeps_lab_and_scope_class_but_hides_real_addresses():
    sanitize = TraceSanitizer(in_scope)
    text = (
        "Hosts 192.168.10.25 y 127.0.0.1; externo 8.8.8.8 y 8.8.8.8 otra vez; "
        "interno 10.20.30.40; red 172.16.0.0/12. Hostname: srv-nominas | Hostname: desconocido. "
        "Contacto admin@empresa.es, token=abc123secret, Authorization: Bearer eyJhbGciOi"
    )

    clean = sanitize(text)

    assert "192.168.10.25" in clean and "127.0.0.1" in clean
    for leaked in ("8.8.8.8", "10.20.30.40", "172.16.0.0", "srv-nominas", "empresa.es",
                   "abc123secret", "eyJhbGciOi"):
        assert leaked not in clean
    # Same address -> same pseudonym; out-of-scope stays out of scope, private
    # stays private and public stays public; networks are never widened.
    assert clean.count("203.0.113.10") == 2       # 8.8.8.8 (public)
    assert "10.255.0.10" in clean                 # 10.20.30.40 (private)
    assert "10.255.0.0/24" in clean               # 172.16.0.0/12 (private network)
    assert not in_scope("203.0.113.10") and not in_scope("10.255.0.10")
    assert "Hostname: host-01" in clean and "Hostname: desconocido" in clean


def test_rejects_unapproved_traces():
    t = trace("Inventario", [action()])
    review = approve(t).model_copy(update={"verdict": "rejected"})
    with pytest.raises(ValueError):
        build_dataset([(t, review)], in_scope)


def test_target_is_canonical_json_and_invalid_uncorrected_outputs_are_dropped():
    t = trace("Inventario de 10.1.1.1", [action(final_summary="Visto 10.1.1.1"), "{roto", None])

    splits, stats = build_dataset([(t, approve(t))], in_scope)

    [example] = all_examples(splits)
    target = json.loads(example["messages"][-1]["content"])
    assert target["action_type"] == "final_answer"
    assert target["final_summary"] == "Visto 10.255.0.10"
    assert "10.1.1.1" not in json.dumps(example)
    assert example["messages"][0]["content"] == ORCHESTRATOR_SYSTEM_PROMPT
    assert stats.dropped["invalid_output"] == 2


def test_correction_replaces_target_and_drops_later_steps():
    t = trace("Descubre hosts", ["{roto", action(), action()])
    correction = {"thought": "Primero descubro.", "action_type": "call_tool",
                  "tool": "discover_hosts", "arguments": {"target": "192.168.10.0/24"}}

    splits, stats = build_dataset([(t, approve(t, {1: correction}))], in_scope)

    [example] = all_examples(splits)
    assert example["meta"]["corrected"] is True
    assert json.loads(example["messages"][-1]["content"])["tool"] == "discover_hosts"
    assert stats.dropped["after_correction"] == 2


def test_duplicates_merge_and_conflicting_targets_are_dropped():
    a, b = trace("Pregunta A", [action()]), trace("Pregunta A", [action()])
    c, d = trace("Pregunta B", [action(final_summary="x")]), trace("Pregunta B", [action(final_summary="y")])

    splits, stats = build_dataset([(t, approve(t)) for t in (a, b, c, d)], in_scope)

    assert len(all_examples(splits)) == 1
    assert stats.dropped["duplicate"] == 1
    assert stats.dropped["ambiguous"] == 2


def test_families_never_cross_splits_and_benchmark_intents_are_excluded():
    traces = [trace(f"Inventario del host 192.168.10.{n}", [action(final_summary=str(n))]) for n in range(2, 40)]
    traces += [trace(f"Pregunta distinta número {w}", [action()]) for w in ("uno", "dos", "tres")]
    benchmark = trace("Descubre qué hosts están activos en 192.168.10.0/24.", [action()])

    splits, stats = build_dataset(
        [(t, approve(t)) for t in traces + [benchmark]], in_scope,
        excluded_intents=["Descubre qué hosts están activos en 127.0.0.0/24."],
    )

    families_by_split = {
        name: {example["meta"]["family"] for example in examples} for name, examples in splits.items()
    }
    for first in families_by_split:
        for second in families_by_split:
            if first != second:
                assert not families_by_split[first] & families_by_split[second]
    # All 38 "Inventario del host ..." intents are one family.
    assert normalize_intent(traces[0].operator_intent) == normalize_intent(traces[5].operator_intent)
    assert stats.dropped["benchmark_overlap"] == 1
    assert split_for_family("x") in {"train", "validation", "test"}


def test_current_system_prompt_replaces_the_recorded_one():
    t = trace("Pregunta conceptual", [action()])
    t.steps[0].messages[0]["content"] = "prompt antiguo"

    splits, stats = build_dataset([(t, approve(t))], in_scope, system_prompt="prompt actual")
    [example] = all_examples(splits)

    assert example["messages"][0] == {"role": "system", "content": "prompt actual"}
    assert stats.system_prompt_replaced == 1
    # Without an explicit prompt the recorded one is kept verbatim.
    splits, stats = build_dataset([(t, approve(t))], in_scope)
    assert all_examples(splits)[0]["messages"][0]["content"] == "prompt antiguo"
    assert stats.system_prompt_replaced == 0


def test_out_of_scope_tool_calls_can_be_dropped_with_later_steps():
    call_out = json.dumps({"thought": "t", "action_type": "call_tool", "tool": "inspect_services",
                           "arguments": {"target": "172.16.1.50"}})
    call_in = json.dumps({"thought": "t", "action_type": "call_tool", "tool": "get_mock_inventory",
                          "arguments": {"target": "192.168.10.25"}})
    steps = ["paso 1", "paso 2"]
    corrected = trace("Escanea 172.16.1.50", ["{roto", action()], steps)
    plain = trace("Inventario de 192.168.10.25", [call_in, action()], steps)
    uncorrected = trace("Servicios de 172.16.3.20", [call_out, action()], steps)
    reviewed = [
        (corrected, approve(corrected, {1: json.loads(call_out)})),
        (plain, approve(plain)),
        (uncorrected, approve(uncorrected)),
    ]

    kept, _ = build_dataset(reviewed, in_scope)
    assert len(all_examples(kept)) == 5  # 1 (corrected, then stop) + 2 + 2

    splits, stats = build_dataset(reviewed, in_scope, drop_out_of_scope_calls=True)
    examples = all_examples(splits)
    assert stats.dropped["out_of_scope_call"] == 2
    # The corrected out-of-scope step goes, and so does the step after it.
    assert stats.dropped["after_correction"] == 1
    assert len(examples) == 3
