-- Teleport integration: one-time purchase flag and cluster/session management.

ALTER TABLE users ADD COLUMN teleport_unlocked BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE teleport_clusters (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    proxy_addr  TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'local',
    identity    BYTEA,
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, proxy_addr)
);

CREATE INDEX idx_teleport_clusters_user ON teleport_clusters(user_id);

CREATE TABLE teleport_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id    UUID NOT NULL REFERENCES teleport_clusters(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token BYTEA NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_teleport_sessions_cluster ON teleport_sessions(cluster_id);
CREATE INDEX idx_teleport_sessions_user ON teleport_sessions(user_id);
CREATE INDEX idx_teleport_sessions_expiry ON teleport_sessions(expires_at);
