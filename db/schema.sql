CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    asset_key TEXT UNIQUE NOT NULL,
    display_name TEXT,
    criticality SMALLINT NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
    owner TEXT,
    environment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS asset_addresses (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    address INET NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, address)
);

CREATE TABLE IF NOT EXISTS services (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    service_name TEXT,
    product TEXT,
    version TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    vulnerability_id TEXT UNIQUE NOT NULL,
    source TEXT NOT NULL,
    title TEXT,
    description TEXT,
    cvss NUMERIC(3,1),
    epss NUMERIC(8,7),
    kev BOOLEAN,
    cwe_ids TEXT[] NOT NULL DEFAULT '{}',
    source_updated_at TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS executions (
    id UUID PRIMARY KEY,
    requested_by TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    original_arguments JSONB NOT NULL,
    normalized_arguments JSONB,
    policy_decision JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'running', 'completed', 'denied', 'approval_required', 'failed'
    )),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    error TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES executions(id),
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    raw_data JSONB NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    UNIQUE (execution_id, sha256)
);

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id),
    vulnerability_id BIGINT REFERENCES vulnerabilities(id),
    status TEXT NOT NULL CHECK (status IN (
        'candidate', 'probable', 'confirmed', 'false_positive',
        'accepted_risk', 'remediated', 'verified'
    )),
    confidence NUMERIC(4,3) CHECK (confidence BETWEEN 0 AND 1),
    contextual_risk NUMERIC(5,2),
    summary TEXT NOT NULL,
    recommendation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    relation TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS documents (
    id BIGSERIAL PRIMARY KEY,
    source_uri TEXT NOT NULL,
    title TEXT,
    authority_tier SMALLINT NOT NULL CHECK (authority_tier BETWEEN 1 AND 5),
    content TEXT NOT NULL,
    embedding VECTOR(768),
    content_sha256 CHAR(64) NOT NULL,
    published_at TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_uri, content_sha256)
);

CREATE INDEX IF NOT EXISTS idx_asset_addresses_address ON asset_addresses USING gist (address inet_ops);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_identifier ON vulnerabilities (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_executions_started_at ON executions (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_executions_status ON executions (status);
CREATE INDEX IF NOT EXISTS idx_evidence_execution_id ON evidence (execution_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);
CREATE INDEX IF NOT EXISTS idx_documents_fts ON documents USING gin (to_tsvector('simple', content));
