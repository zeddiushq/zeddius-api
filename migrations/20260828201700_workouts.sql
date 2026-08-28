-- `type` is validated against the documented enum in the handler, not a DB
-- CHECK constraint — matches the pure-application-validation convention
-- already used by weight_logs/sleep_logs/food_entries.
CREATE TABLE workouts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    ended_at    TIMESTAMPTZ,
    notes       TEXT,
    source      TEXT NOT NULL,
    source_uuid TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workouts_user_id_started_at ON workouts(user_id, started_at DESC);
