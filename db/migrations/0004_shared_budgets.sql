CREATE TABLE IF NOT EXISTS request_budget_reservations (
    budget_key TEXT NOT NULL,
    request_id UUID NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (budget_key, request_id)
);

CREATE TABLE IF NOT EXISTS concurrency_leases (
    budget_key TEXT NOT NULL,
    lease_id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (budget_key, request_id),
    CHECK (expires_at > acquired_at)
);

CREATE INDEX IF NOT EXISTS idx_request_budget_requested_at
    ON request_budget_reservations (budget_key, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_concurrency_leases_expires_at
    ON concurrency_leases (budget_key, expires_at);
