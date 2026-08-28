-- One-to-one with workouts: `workout_id UNIQUE` (and its implicit index)
-- backs POST /workouts/:id/run-session's create-or-replace upsert.
-- gps_path_url stays unused for now — no GPS capture in this manual-entry
-- sprint, but the column matches PLAN.md's documented schema for whenever
-- HealthKit/Watch-sourced runs land.
CREATE TABLE run_sessions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workout_id              UUID NOT NULL UNIQUE REFERENCES workouts(id) ON DELETE CASCADE,
    distance_meters         NUMERIC NOT NULL,
    duration_seconds        INT NOT NULL,
    avg_pace_seconds_per_km INT,
    avg_heart_rate          SMALLINT,
    max_heart_rate          SMALLINT,
    elevation_gain_meters   NUMERIC,
    gps_path_url            TEXT
);
