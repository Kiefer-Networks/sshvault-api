-- Restore only the old schema shape, never discarded requester credentials.
-- 023 down still refuses to erase the provenance of new unverified accounts.
SELECT pg_advisory_xact_lock(734862190201);
ALTER TABLE verification_tokens ADD COLUMN IF NOT EXISTS registration_password_hash TEXT NOT NULL DEFAULT '';
