DROP INDEX IF EXISTS idx_devices_user_id;
DROP INDEX IF EXISTS idx_subscriptions_user_id;
DROP INDEX IF EXISTS idx_refresh_tokens_user_id;
DROP INDEX IF EXISTS idx_verification_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth_accounts_user_id;

ALTER TABLE subscriptions DROP COLUMN IF EXISTS provider_customer_id;
