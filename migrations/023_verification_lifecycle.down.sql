-- Match the maintenance-before-table-lock order and make the provenance check stable.
SELECT pg_advisory_xact_lock(734862190201);
LOCK TABLE users IN ACCESS EXCLUSIVE MODE;
-- Refuse to erase provenance that a later upgrade would mistake for a legacy account.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM users WHERE NOT verified AND NOT verification_grandfathered) THEN
  RAISE EXCEPTION 'cannot downgrade verification enforcement while new unverified accounts exist';
 END IF;
END $$;
DROP TABLE mail_send_budgets;
DROP INDEX verification_tokens_one_active;
ALTER TABLE verification_tokens DROP COLUMN IF EXISTS registration_password_hash;
ALTER TABLE users DROP COLUMN pending_email, DROP COLUMN verification_grandfathered;
