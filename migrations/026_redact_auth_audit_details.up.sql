-- Migration 022 matched lowercase synthetic categories, while the runtime has
-- always persisted authentication entries as AUTH. Repair existing upgrades.
ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update;

UPDATE audit_logs
SET details = CASE
    WHEN details ? 'email'
        THEN (details - 'email' - 'error') || '{"email":"[redacted]"}'::jsonb
    ELSE details - 'error'
END
WHERE UPPER(category) = 'AUTH'
  AND (details ? 'email' OR details ? 'error');

ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update;
