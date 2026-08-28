-- `food_id`/`recipe_id` from PLAN.md §7 are omitted here: they'd FK into
-- `foods`/`recipes` tables that don't exist yet (deferred — no food search,
-- no recipes in this manual-entry sprint). Add them in a later migration
-- once those tables land, rather than carrying meaningless placeholder
-- columns now.
CREATE TABLE food_entries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consumed_at   TIMESTAMPTZ NOT NULL,
    name          TEXT NOT NULL,
    kcal          NUMERIC,
    protein_g     NUMERIC,
    carbs_g       NUMERIC,
    fat_g         NUMERIC,
    source        TEXT NOT NULL,
    portion_count NUMERIC,
    meal_slot     TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_food_entries_user_id_consumed_at ON food_entries(user_id, consumed_at DESC);
