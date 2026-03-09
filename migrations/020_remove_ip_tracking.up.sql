-- Remove plaintext IP storage from devices (zero-knowledge privacy).
-- IP hashes are still stored in login_attempts for brute-force protection.
ALTER TABLE devices DROP COLUMN IF EXISTS last_ip;

-- Clear any existing plaintext IPs from audit logs.
UPDATE audit_logs SET ip_address = '' WHERE ip_address != '' AND ip_address != '0.0.0.0';
