CREATE TABLE vault_history (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id    UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    blob        BYTEA NOT NULL,
    checksum    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vault_history_vault ON vault_history(vault_id, version DESC);
