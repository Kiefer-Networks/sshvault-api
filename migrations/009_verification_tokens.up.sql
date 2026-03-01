CREATE TABLE verification_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,          -- 'email_verify', 'password_reset'
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_verification_tokens_hash ON verification_tokens(token_hash) WHERE NOT used;
CREATE INDEX idx_verification_tokens_user ON verification_tokens(user_id, kind);
