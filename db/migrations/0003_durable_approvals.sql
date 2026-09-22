CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY,
    token_sha256 CHAR(64) UNIQUE NOT NULL,
    requested_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    normalized_arguments JSONB NOT NULL,
    arguments_sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_by_request_id UUID,
    CHECK (expires_at > created_at),
    CHECK (requested_by <> approved_by),
    CHECK (
        (consumed_at IS NULL AND consumed_by_request_id IS NULL)
        OR (consumed_at IS NOT NULL AND consumed_by_request_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_approvals_requested_by
    ON approvals (requested_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_expires_at
    ON approvals (expires_at) WHERE consumed_at IS NULL;
