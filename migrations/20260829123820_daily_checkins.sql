-- Close Day: a per-date confirmation that logging is done for the day.
-- Deliberately not the mood/focus/energy shape originally sketched in
-- PLAN.md §7 — dropped per Joshua's explicit call, not part of this build.
-- tomorrow_focus is the "one important task" set the night before, shown
-- prominently on Home the next day.
CREATE TABLE daily_checkins (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date            DATE NOT NULL,
    tomorrow_focus  TEXT,
    closed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, date)
);
