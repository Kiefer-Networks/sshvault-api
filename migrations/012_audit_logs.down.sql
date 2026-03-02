DROP FUNCTION IF EXISTS audit_purge_old(TIMESTAMPTZ);
DROP FUNCTION IF EXISTS audit_anonymize_user(UUID);
DROP TRIGGER IF EXISTS trg_audit_logs_no_delete ON audit_logs;
DROP TRIGGER IF EXISTS trg_audit_logs_no_update ON audit_logs;
DROP FUNCTION IF EXISTS audit_logs_immutable();
DROP TABLE IF EXISTS audit_logs;
