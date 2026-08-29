-- Manual recurring tasks (laundry, cat boxes, dishwasher, water trees,
-- dinner) for the daily discipline checklist — no other data trail exists
-- for these, unlike the auto-derived goals (calories, sleep, run cadence,
-- etc.) computed from data already logged elsewhere.
--
-- Deliberately no server-side "today"/"this week" computation: the client
-- fetches daily_task_completions for a date range and buckets it itself
-- with Calendar.current, same as every other day-scoped feature in this
-- app (FoodEntryListView's day/week filtering, HomeModel's today totals).
CREATE TABLE daily_tasks (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title                  TEXT NOT NULL,
    recurrence             TEXT NOT NULL,   -- 'daily' | 'weekly'
    target_count_per_week  SMALLINT,        -- required for 'weekly', null for 'daily'
    active                 BOOLEAN NOT NULL DEFAULT true,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE daily_task_completions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         UUID NOT NULL REFERENCES daily_tasks(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    completed_date  DATE NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (task_id, completed_date)
);
