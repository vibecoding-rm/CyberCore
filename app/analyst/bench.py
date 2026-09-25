"""Analyst-Bench runs, blind review views and the comparative report.

A run holds every system's answer to every case. Reviewers only ever see
opaque answer ids derived from a per-run random salt, in an order that
differs per reviewer, so they cannot tell the template from a model.
"""

from __future__ import annotations

import hashlib
import statistics
from datetime import datetime
from itertools import combinations
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

CRITERIA = ("fidelity", "completeness", "actionability", "calibration", "clarity")
RUN_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,99}$"
SYSTEM_PATTERN = r"^C[0-9]{1,2}$"


class AnswerRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output: dict[str, Any] | None
    error: str | None = None
    raw: str | None = None
    violations: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    generated_tokens: int | None = None

    @property
    def passed_gate(self) -> bool:
        return self.output is not None and not self.violations


class CaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    family: str
    finding_status: str
    view: dict[str, Any]
    answers: dict[str, AnswerRecord]


class SystemInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["template", "llm"]
    model: str | None = None
    endpoint: str | None = None
    hardware: str | None = None


class AnalystRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(pattern=RUN_ID_PATTERN)
    split: Literal["development", "holdout"]
    cases_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    salt: str = Field(pattern=r"^[0-9a-f]{32}$")
    systems: dict[str, SystemInfo]
    results: list[CaseResult]

    def answer_id(self, case_id: str, system: str) -> str:
        return hashlib.sha256(f"{self.salt}|{case_id}|{system}".encode()).hexdigest()[:16]

    def system_of(self, case_id: str, answer_id: str) -> str | None:
        for result in self.results:
            if result.case_id == case_id:
                for system in result.answers:
                    if self.answer_id(case_id, system) == answer_id:
                        return system
        return None


class RubricScores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fidelity: int = Field(ge=0, le=2)
    completeness: int = Field(ge=0, le=2)
    actionability: int = Field(ge=0, le=2)
    calibration: int = Field(ge=0, le=2)
    clarity: int = Field(ge=0, le=2)


class ScoreInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1, max_length=100)
    answer_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    scores: RubricScores
    comment: str = Field(default="", max_length=2000)


class StoredScore(ScoreInput):
    reviewer: str
    scored_at: datetime


class BlindAnswer(BaseModel):
    answer_id: str
    output: dict[str, Any]


class BlindCase(BaseModel):
    run_id: str
    case_id: str
    view: dict[str, Any]
    answers: list[BlindAnswer]
    reviewed_cases: int
    total_cases: int


class RunSummary(BaseModel):
    run_id: str
    split: str
    created_at: datetime
    cases: int
    systems: list[str]


def summarize(run: AnalystRun) -> RunSummary:
    return RunSummary(
        run_id=run.run_id, split=run.split, created_at=run.created_at,
        cases=len(run.results), systems=sorted(run.systems),
    )


def next_blind_case(run: AnalystRun, reviewer: str, scores: list[StoredScore]) -> BlindCase | None:
    """First case with a gate-passing answer this reviewer has not scored yet."""
    done = {(s.case_id, s.answer_id) for s in scores if s.reviewer == reviewer}
    reviewable = [
        (result, [
            BlindAnswer(answer_id=run.answer_id(result.case_id, system), output=answer.output)
            for system, answer in result.answers.items() if answer.passed_gate
        ])
        for result in run.results
    ]
    reviewable = [(result, answers) for result, answers in reviewable if answers]
    reviewed = sum(
        all((result.case_id, a.answer_id) in done for a in answers)
        for result, answers in reviewable
    )
    for result, answers in reviewable:
        pending = [a for a in answers if (result.case_id, a.answer_id) not in done]
        if pending:
            # Stable per reviewer, different between reviewers.
            pending.sort(key=lambda a: hashlib.sha256(f"{reviewer}|{a.answer_id}".encode()).digest())
            return BlindCase(
                run_id=run.run_id, case_id=result.case_id, view=result.view, answers=pending,
                reviewed_cases=reviewed, total_cases=len(reviewable),
            )
    return None


def reviewable_answer(run: AnalystRun, case_id: str, answer_id: str) -> bool:
    system = run.system_of(case_id, answer_id)
    if system is None:
        return False
    result = next(r for r in run.results if r.case_id == case_id)
    return result.answers[system].passed_gate


# --- report -----------------------------------------------------------------

def _mean(values: list[float]) -> float | None:
    return round(statistics.mean(values), 3) if values else None


def build_report(run: AnalystRun, scores: list[StoredScore]) -> dict[str, Any]:
    by_answer: dict[tuple[str, str], list[StoredScore]] = {}
    for score in scores:
        system = run.system_of(score.case_id, score.answer_id)
        if system is not None:
            by_answer.setdefault((score.case_id, system), []).append(score)

    systems: dict[str, Any] = {}
    for system, info in sorted(run.systems.items()):
        answers = [(r.case_id, r.answers[system]) for r in run.results if system in r.answers]
        gate_fail = [case_id for case_id, a in answers if not a.passed_gate]
        per_case: dict[str, dict[str, float]] = {}
        reviewers_per_case: list[int] = []
        for case_id, answer in answers:
            reviews = by_answer.get((case_id, system), [])
            if answer.passed_gate and reviews:
                reviewers_per_case.append(len(reviews))
                per_case[case_id] = {
                    c: statistics.mean(getattr(r.scores, c) for r in reviews) for c in CRITERIA
                }
        criteria = {c: _mean([v[c] for v in per_case.values()]) for c in CRITERIA}
        # Gate failures score 0 in the total: they would not reach an operator.
        totals = [sum(v.values()) for v in per_case.values()] + [0.0] * len(gate_fail)
        latencies = [a.latency_ms for _, a in answers if a.latency_ms is not None]
        systems[system] = {
            "info": info.model_dump(exclude_none=True),
            "cases": len(answers),
            "gate_passed": len(answers) - len(gate_fail),
            "gate_failures": gate_fail,
            "errors": [case_id for case_id, a in answers if a.output is None],
            "scored_cases": len(per_case),
            "min_reviewers": min(reviewers_per_case) if reviewers_per_case else 0,
            "criteria": criteria,
            "mean_total": _mean(totals),
            "fidelity_zero": sorted(
                case_id for (case_id, s), reviews in by_answer.items()
                if s == system and any(r.scores.fidelity == 0 for r in reviews)
            ),
            "mean_latency_ms": _mean(latencies),
        }
    return {
        "run_id": run.run_id,
        "split": run.split,
        "systems": systems,
        "agreement": _agreement(scores),
        "adoption": {
            name: _adoption(systems[name], systems.get("C0"), len(run.results))
            for name in systems if name != "C0"
        },
    }


def _agreement(scores: list[StoredScore]) -> dict[str, Any]:
    by_answer: dict[tuple[str, str], list[StoredScore]] = {}
    for score in scores:
        by_answer.setdefault((score.case_id, score.answer_id), []).append(score)
    exact = within_one = pairs = 0
    for reviews in by_answer.values():
        for a, b in combinations(reviews, 2):
            for criterion in CRITERIA:
                diff = abs(getattr(a.scores, criterion) - getattr(b.scores, criterion))
                pairs += 1
                exact += diff == 0
                within_one += diff <= 1
    return {
        "compared_scores": pairs,
        "exact": round(exact / pairs, 3) if pairs else None,
        "within_one": round(within_one / pairs, 3) if pairs else None,
    }


def _adoption(candidate: dict[str, Any], control: dict[str, Any] | None, cases: int) -> dict[str, Any]:
    """docs/09 criteria; 'complete' is false until every case has two reviewers."""
    reasons = []
    complete = candidate["scored_cases"] + len(candidate["gate_failures"]) == cases and (
        candidate["min_reviewers"] >= 2
    )
    if candidate["gate_failures"]:
        reasons.append(f"{len(candidate['gate_failures'])} respuestas no pasan la puerta automática")
    if candidate["fidelity_zero"]:
        reasons.append(f"fidelidad 0 en {len(candidate['fidelity_zero'])} casos")
    if control is None or control["mean_total"] is None or candidate["mean_total"] is None:
        reasons.append("faltan puntuaciones del control C0 o del candidato")
    else:
        if candidate["mean_total"] < control["mean_total"] + 1:
            reasons.append("no supera a C0 en al menos 1 punto de media")
        better = sum(
            (candidate["criteria"][c] or 0) > (control["criteria"][c] or 0) for c in CRITERIA
        )
        if better < 3:
            reasons.append(f"mejora a C0 sólo en {better} de 5 criterios")
    return {"complete": complete, "meets_criteria": not reasons, "reasons": reasons}
