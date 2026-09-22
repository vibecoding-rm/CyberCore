ALTER TABLE executions
    ADD COLUMN IF NOT EXISTS original_arguments JSONB;

UPDATE executions
SET original_arguments = normalized_arguments
WHERE original_arguments IS NULL;

ALTER TABLE executions
    ALTER COLUMN original_arguments SET NOT NULL,
    ALTER COLUMN normalized_arguments DROP NOT NULL;

ALTER TABLE executions
    ADD COLUMN IF NOT EXISTS error TEXT;

ALTER TABLE executions
    DROP CONSTRAINT IF EXISTS executions_status_check;

ALTER TABLE executions
    ADD CONSTRAINT executions_status_check CHECK (status IN (
        'running', 'completed', 'denied', 'approval_required', 'failed'
    ));

ALTER TABLE evidence
    DROP CONSTRAINT IF EXISTS evidence_source_target_sha256_key;

ALTER TABLE evidence
    DROP CONSTRAINT IF EXISTS evidence_execution_id_sha256_key;

ALTER TABLE evidence
    ALTER COLUMN execution_id SET NOT NULL;

ALTER TABLE evidence
    ADD CONSTRAINT evidence_execution_id_sha256_key UNIQUE (execution_id, sha256);

CREATE INDEX IF NOT EXISTS idx_executions_started_at ON executions (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_executions_status ON executions (status);
CREATE INDEX IF NOT EXISTS idx_evidence_execution_id ON evidence (execution_id);
