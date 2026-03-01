CREATE TABLE vaults (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL DEFAULT 0,
    blob        BYTEA,
    checksum    TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
