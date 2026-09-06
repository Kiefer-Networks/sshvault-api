-- Preserve existing live refresh credentials while assigning each its own family.
ALTER TABLE refresh_tokens
    ADD COLUMN family_id UUID,
    ADD COLUMN parent_id UUID,
    ADD COLUMN consumed_at TIMESTAMPTZ,
    ADD COLUMN session_version BIGINT;
UPDATE refresh_tokens t SET family_id=t.id, session_version=u.session_version
FROM users u WHERE u.id=t.user_id;
ALTER TABLE refresh_tokens
    ALTER COLUMN family_id SET NOT NULL,
    ALTER COLUMN family_id SET DEFAULT gen_random_uuid(),
    ALTER COLUMN session_version SET NOT NULL,
    ALTER COLUMN session_version SET DEFAULT 0;
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE UNIQUE INDEX idx_refresh_tokens_parent ON refresh_tokens(parent_id) WHERE parent_id IS NOT NULL;

-- Pending reservations count as failures until authentication completes.
ALTER TABLE login_attempts
    ADD COLUMN admission_sequence BIGINT GENERATED ALWAYS AS IDENTITY,
    ADD COLUMN completed_at TIMESTAMPTZ;
UPDATE login_attempts SET completed_at=created_at;
