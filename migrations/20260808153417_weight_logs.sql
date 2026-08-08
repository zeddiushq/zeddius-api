CREATE TABLE weight_logs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recorded_at    TIMESTAMPTZ NOT NULL,
    weight_kg      NUMERIC NOT NULL,
    body_fat_pct   NUMERIC,
    muscle_mass_kg NUMERIC,
    water_pct      NUMERIC,
    bone_mass_kg   NUMERIC,
    source         TEXT NOT NULL,
    source_uuid    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- serves both the common list query (user_id + recorded_at range) and
-- the FK column, which postgres does not index automatically
CREATE INDEX idx_weight_logs_user_id_recorded_at ON weight_logs(user_id, recorded_at DESC);
