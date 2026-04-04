CREATE TABLE IF NOT EXISTS finding_triage_states (
    finding_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    assignee TEXT NOT NULL DEFAULT '',
    suppression_expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT NOT NULL DEFAULT '',
    CONSTRAINT chk_finding_triage_status CHECK (status IN ('open', 'ack', 'suppressed', 'resolved'))
);

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_status
    ON finding_triage_states (status);

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_assignee
    ON finding_triage_states (assignee);

CREATE TABLE IF NOT EXISTS finding_triage_events (
    id UUID PRIMARY KEY,
    finding_id TEXT NOT NULL,
    action TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    assignee TEXT NOT NULL DEFAULT '',
    suppression_expires_at TIMESTAMPTZ,
    comment TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_finding_triage_events_from_status CHECK (from_status IN ('open', 'ack', 'suppressed', 'resolved')),
    CONSTRAINT chk_finding_triage_events_to_status CHECK (to_status IN ('open', 'ack', 'suppressed', 'resolved'))
);

CREATE INDEX IF NOT EXISTS idx_finding_triage_events_finding_created
    ON finding_triage_events (finding_id, created_at DESC);
