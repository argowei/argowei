-- Append-only record of administrative actions.
--
-- `actor` is a plain string rather than a foreign key on purpose: entries
-- must stay meaningful for failed logins (unknown username), for the
-- scheduler ("system"), and after an account is gone.
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor VARCHAR NOT NULL,
    action VARCHAR NOT NULL,
    target_type VARCHAR,
    target_id VARCHAR,
    outcome VARCHAR NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    -- Client address as seen by the API (may be a proxy address).
    remote_addr VARCHAR,
    -- Structured details / change diff. Secrets are redacted before insert.
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_audit_log_occurred_at ON audit_log (occurred_at DESC, id DESC);
CREATE INDEX ix_audit_log_actor ON audit_log (actor);
CREATE INDEX ix_audit_log_action ON audit_log (action);

-- The application has no update/delete path; this enforces it in the
-- database as well. TRUNCATE is covered by a separate statement-level trigger.
CREATE FUNCTION audit_log_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_reject_mutation();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_mutation();
