-- Analyst-Bench (docs/09_ANALYST_BENCH.md): published runs with every
-- system's answers, and blind rubric scores. Both are append-only; a reviewer
-- scores each answer once.
CREATE TABLE IF NOT EXISTS analyst_bench_runs (
    run_id TEXT PRIMARY KEY,
    split TEXT NOT NULL CHECK (split IN ('development', 'holdout')),
    payload JSONB NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS analyst_bench_scores (
    id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES analyst_bench_runs(run_id),
    case_id TEXT NOT NULL,
    answer_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    fidelity SMALLINT NOT NULL CHECK (fidelity BETWEEN 0 AND 2),
    completeness SMALLINT NOT NULL CHECK (completeness BETWEEN 0 AND 2),
    actionability SMALLINT NOT NULL CHECK (actionability BETWEEN 0 AND 2),
    calibration SMALLINT NOT NULL CHECK (calibration BETWEEN 0 AND 2),
    clarity SMALLINT NOT NULL CHECK (clarity BETWEEN 0 AND 2),
    comment TEXT NOT NULL DEFAULT '',
    scored_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, case_id, answer_id, reviewer)
);

DROP TRIGGER IF EXISTS analyst_bench_runs_append_only ON analyst_bench_runs;
CREATE TRIGGER analyst_bench_runs_append_only
    BEFORE UPDATE OR DELETE ON analyst_bench_runs
    FOR EACH ROW EXECUTE FUNCTION cybercore_reject_trace_change();

DROP TRIGGER IF EXISTS analyst_bench_scores_append_only ON analyst_bench_scores;
CREATE TRIGGER analyst_bench_scores_append_only
    BEFORE UPDATE OR DELETE ON analyst_bench_scores
    FOR EACH ROW EXECUTE FUNCTION cybercore_reject_trace_change();
