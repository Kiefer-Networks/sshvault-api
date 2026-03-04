CREATE TABLE coupons (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT NOT NULL UNIQUE,
    -- What the coupon grants
    grant_sync       BOOLEAN NOT NULL DEFAULT false,
    grant_teleport   BOOLEAN NOT NULL DEFAULT false,
    sync_days        INT NOT NULL DEFAULT 0,
    -- Usage limits
    max_uses    INT NOT NULL DEFAULT 1,
    used_count  INT NOT NULL DEFAULT 0,
    -- Validity
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE coupon_redemptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coupon_id   UUID NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redeemed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(coupon_id, user_id)
);

CREATE INDEX idx_coupons_code ON coupons(code);
CREATE INDEX idx_coupon_redemptions_user ON coupon_redemptions(user_id);
CREATE INDEX idx_coupon_redemptions_coupon ON coupon_redemptions(coupon_id);
