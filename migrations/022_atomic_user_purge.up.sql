-- Remove identifiers without requiring pgcrypto. The caller holds the user
-- row lock and calls this before deleting the identity in the same transaction.
CREATE OR REPLACE FUNCTION audit_anonymize_user(target_user_id UUID)
RETURNS INT AS $$
DECLARE
    affected INT;
BEGIN
    ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update;
    UPDATE audit_logs
    SET actor_id = NULL,
        actor_email = '',
        resource_id = '',
        ip_address = '',
        user_agent = '',
        request_id = '',
        details = '{}'::jsonb
    WHERE actor_id = target_user_id
       OR (resource_type = 'user' AND resource_id = target_user_id::text)
       -- Email addresses can be reused after an account changes its mailbox.
       -- An explicit actor identity takes precedence over email-only matching.
       OR (actor_id IS NULL AND (
           actor_email = (SELECT email FROM users WHERE id = target_user_id)
           OR details->>'email' = (SELECT email FROM users WHERE id = target_user_id)
       ));
    GET DIAGNOSTICS affected = ROW_COUNT;
    ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update;
    RETURN affected;
END;
$$ LANGUAGE plpgsql SECURITY INVOKER SET search_path FROM CURRENT;

-- Repair privacy for installations that already ran the old migration 020,
-- including failed-auth entries without an actor_id.
ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update;
UPDATE audit_logs SET ip_address = '' WHERE ip_address <> '';
UPDATE audit_logs SET details = (details - 'email' - 'error') || '{"email":"[redacted]"}'::jsonb
WHERE category = 'auth' AND details ? 'email';
ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update;
