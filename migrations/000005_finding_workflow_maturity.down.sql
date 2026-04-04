DROP INDEX IF EXISTS idx_finding_triage_events_finding_created;
DROP TABLE IF EXISTS finding_triage_events;

DROP INDEX IF EXISTS idx_finding_triage_states_assignee;
DROP INDEX IF EXISTS idx_finding_triage_states_status;
DROP TABLE IF EXISTS finding_triage_states;
