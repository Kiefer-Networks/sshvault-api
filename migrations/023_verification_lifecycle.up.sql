ALTER TABLE users ADD COLUMN verification_grandfathered BOOLEAN NOT NULL DEFAULT FALSE;
-- Compatibility only: preserve the actual verified state of upgraded accounts.
UPDATE users SET verification_grandfathered=TRUE;
ALTER TABLE users ADD COLUMN pending_email TEXT NOT NULL DEFAULT '';
