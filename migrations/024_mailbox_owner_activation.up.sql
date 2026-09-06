-- Cleanup for databases that applied the earlier unpublished 023 draft.
-- Keep live mailbox tokens; activation now requires an owner-chosen password.
SELECT pg_advisory_xact_lock(734862190201);
UPDATE users SET password='!unverified:' || gen_random_uuid()::text
WHERE NOT verified AND NOT verification_grandfathered;
ALTER TABLE verification_tokens DROP COLUMN IF EXISTS registration_password_hash;
