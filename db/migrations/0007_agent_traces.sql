-- Orchestrator traces for Phase 6: exact messages sent to the model, its raw
-- output and the link to the audited tool execution. Runs and steps are
-- append-only; human reviews are added as new rows (the latest one wins).
CREATE TABLE IF NOT EXISTS agent_runs (
    id UUID PRIMARY KEY,
    requested_by TEXT NOT NULL,
    operator_intent TEXT NOT NULL,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    final_report TEXT NOT NULL,
    response_schema JSONB NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_steps (
    run_id UUID NOT NULL REFERENCES agent_runs(id),
    step_number INTEGER NOT NULL CHECK (step_number >= 1),
    messages JSONB NOT NULL,
    raw_output TEXT,
    error TEXT,
    observation TEXT,
    execution_id UUID REFERENCES executions(id),
    prompt_tokens INTEGER CHECK (prompt_tokens >= 0),
    generated_tokens INTEGER CHECK (generated_tokens >= 0),
    PRIMARY KEY (run_id, step_number)
);

CREATE TABLE IF NOT EXISTS agent_trace_reviews (
    id BIGSERIAL PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES agent_runs(id),
    reviewer TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('approved', 'rejected')),
    notes TEXT NOT NULL DEFAULT '',
    corrections JSONB NOT NULL DEFAULT '{}'::jsonb,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (verdict = 'approved' OR corrections = '{}'::jsonb)
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_started_at ON agent_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_trace_reviews_run
    ON agent_trace_reviews (run_id, reviewed_at DESC, id DESC);

CREATE OR REPLACE FUNCTION cybercore_reject_trace_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'La tabla % es de sólo inserción: % no permitido', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS agent_runs_append_only ON agent_runs;
CREATE TRIGGER agent_runs_append_only
    BEFORE UPDATE OR DELETE ON agent_runs
    FOR EACH ROW EXECUTE FUNCTION cybercore_reject_trace_change();

DROP TRIGGER IF EXISTS agent_steps_append_only ON agent_steps;
CREATE TRIGGER agent_steps_append_only
    BEFORE UPDATE OR DELETE ON agent_steps
    FOR EACH ROW EXECUTE FUNCTION cybercore_reject_trace_change();

DROP TRIGGER IF EXISTS agent_trace_reviews_append_only ON agent_trace_reviews;
CREATE TRIGGER agent_trace_reviews_append_only
    BEFORE UPDATE OR DELETE ON agent_trace_reviews
    FOR EACH ROW EXECUTE FUNCTION cybercore_reject_trace_change();
