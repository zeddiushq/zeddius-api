-- No user_id column: ownership is scoped transitively through workout_id ->
-- workouts.user_id (checked in the handler/repo), same as lift_sets has no
-- direct owner in PLAN.md's schema either.
CREATE TABLE lift_sets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workout_id       UUID NOT NULL REFERENCES workouts(id) ON DELETE CASCADE,
    exercise_id      UUID NOT NULL REFERENCES exercises(id) ON DELETE RESTRICT,
    set_number       SMALLINT NOT NULL,
    target_reps_min  SMALLINT,
    target_reps_max  SMALLINT,
    target_weight_kg NUMERIC,
    actual_reps      SMALLINT,
    actual_weight_kg NUMERIC,
    rpe              NUMERIC,
    notes            TEXT
);

CREATE INDEX idx_lift_sets_workout_id ON lift_sets(workout_id);
