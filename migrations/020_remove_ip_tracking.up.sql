-- Remove plaintext IP storage from devices (zero-knowledge privacy).
-- IP hashes are still stored in login_attempts for brute-force protection.
ALTER TABLE devices DROP COLUMN IF EXISTS last_ip;

-- Clear any existing plaintext IPs from audit logs.
-- Migration statements execute in one transaction; trigger state also rolls
-- back if clearing legacy rows fails.
ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update;
UPDATE audit_logs SET ip_address = '' WHERE ip_address != '';
ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update;
