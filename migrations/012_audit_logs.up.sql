-- Audit Logs: immutable, legally compliant audit trail
CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT now(),
    level         TEXT NOT NULL DEFAULT 'info',
    category      TEXT NOT NULL,
    action        TEXT NOT NULL,
    actor_id      UUID,
    actor_email   TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id   TEXT NOT NULL DEFAULT '',
    ip_address    TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    request_id    TEXT NOT NULL DEFAULT '',
    details       JSONB NOT NULL DEFAULT '{}',
    duration_ms   INT
);

-- Indexes for common query patterns
CREATE INDEX idx_audit_logs_actor_id ON audit_logs (actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX idx_audit_logs_category_timestamp ON audit_logs (category, timestamp DESC);
CREATE INDEX idx_audit_logs_action_timestamp ON audit_logs (action, timestamp DESC);
CREATE INDEX idx_audit_logs_request_id ON audit_logs (request_id) WHERE request_id != '';
CREATE INDEX idx_audit_logs_actor_timestamp ON audit_logs (actor_id, timestamp DESC) WHERE actor_id IS NOT NULL;

-- Immutability: prevent UPDATE and DELETE at database level
CREATE OR REPLACE FUNCTION audit_logs_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs table is immutable: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION audit_logs_immutable();

CREATE TRIGGER trg_audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION audit_logs_immutable();

-- GDPR: anonymize PII for a specific user (SECURITY DEFINER bypasses immutability trigger)
CREATE OR REPLACE FUNCTION audit_anonymize_user(target_user_id UUID)
RETURNS INT AS $$
DECLARE
    affected INT;
BEGIN
    -- Temporarily disable immutability triggers
    ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update;

    UPDATE audit_logs
    SET actor_email = 'anonymized-' || encode(digest(actor_email, 'sha256'), 'hex'),
        ip_address  = '0.0.0.0',
        user_agent  = '',
        details     = '{}'::jsonb
    WHERE actor_id = target_user_id
      AND actor_email NOT LIKE 'anonymized-%';

    GET DIAGNOSTICS affected = ROW_COUNT;

    -- Re-enable immutability triggers
    ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update;

    RETURN affected;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Retention: purge old audit logs (SECURITY DEFINER bypasses immutability trigger)
CREATE OR REPLACE FUNCTION audit_purge_old(cutoff TIMESTAMPTZ)
RETURNS INT AS $$
DECLARE
    affected INT;
BEGIN
    -- Temporarily disable immutability triggers
    ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_delete;

    DELETE FROM audit_logs WHERE timestamp < cutoff;

    GET DIAGNOSTICS affected = ROW_COUNT;

    -- Re-enable immutability triggers
    ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_delete;

    RETURN affected;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
