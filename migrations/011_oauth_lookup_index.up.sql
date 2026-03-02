-- Composite index for OAuth login lookups (provider + provider_id)
CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_provider_id ON oauth_accounts(provider, provider_id);
