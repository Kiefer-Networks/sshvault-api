ALTER TABLE users ADD COLUMN verification_grandfathered BOOLEAN NOT NULL DEFAULT FALSE;
-- Compatibility only: preserve the actual verified state of upgraded accounts.
UPDATE users SET verification_grandfathered=TRUE;
ALTER TABLE users ADD COLUMN pending_email TEXT NOT NULL DEFAULT '';

-- Retain at most one effective token per account and purpose on upgrade.
WITH ranked AS (
 SELECT id, row_number() OVER (PARTITION BY user_id,kind ORDER BY created_at DESC,id DESC) AS position
 FROM verification_tokens WHERE NOT used
)
UPDATE verification_tokens SET used=TRUE WHERE id IN (SELECT id FROM ranked WHERE position>1);
CREATE UNIQUE INDEX verification_tokens_one_active ON verification_tokens(user_id,kind) WHERE NOT used;
CREATE TABLE mail_send_budgets (
 recipient_digest TEXT NOT NULL,
 purpose TEXT NOT NULL,
 next_send_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (recipient_digest,purpose)
);
