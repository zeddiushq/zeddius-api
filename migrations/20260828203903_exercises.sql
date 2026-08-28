-- Global exercise library, per PLAN.md §5's seed list. `muscle_groups`/
-- `equipment`/`default_set_scheme` aren't individually specified per exercise
-- in PLAN.md — derived here from §5's Upper A/Lower A/Upper B/Lower B tables
-- (first-appearance set/rep scheme when an exercise appears in more than one
-- session) plus standard categorization for the untabled library alternates
-- (db-bench-press, incline-db-press, db-row, chest-supported-row,
-- barbell-row), which get a generic 3x8-12 hypertrophy default.
-- `progression_type` is 'linear' for every seed row: PLAN.md's progression
-- rules describe double_progression as a state a lift *earns* by stalling
-- twice, not a starting classification any exercise begins in.
CREATE TABLE exercises (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT NOT NULL,
    slug               TEXT NOT NULL UNIQUE,
    muscle_groups      TEXT[] NOT NULL,
    equipment          TEXT[] NOT NULL,
    default_set_scheme JSONB,
    progression_type   TEXT NOT NULL
);

INSERT INTO exercises (name, slug, muscle_groups, equipment, default_set_scheme, progression_type) VALUES
('Bench Press', 'bench-press', ARRAY['chest','triceps','shoulders'], ARRAY['barbell','bench'], '{"sets":4,"reps_min":5,"reps_max":8}', 'linear'),
('Overhead Press', 'overhead-press', ARRAY['shoulders','triceps'], ARRAY['barbell'], '{"sets":3,"reps_min":6,"reps_max":10}', 'linear'),
('Back Squat', 'back-squat', ARRAY['quads','glutes','hamstrings'], ARRAY['barbell'], '{"sets":4,"reps_min":5,"reps_max":8}', 'linear'),
('Deadlift', 'deadlift', ARRAY['hamstrings','glutes','back'], ARRAY['barbell'], '{"sets":3,"reps_min":3,"reps_max":5}', 'linear'),
('Front Squat', 'front-squat', ARRAY['quads','glutes'], ARRAY['barbell'], '{"sets":3,"reps_min":8,"reps_max":8}', 'linear'),
('Romanian Deadlift', 'romanian-deadlift', ARRAY['hamstrings','glutes'], ARRAY['barbell'], '{"sets":3,"reps_min":8,"reps_max":10}', 'linear'),
('Bulgarian Split Squat', 'bulgarian-split-squat', ARRAY['quads','glutes'], ARRAY['dumbbell','bench'], '{"sets":3,"reps_min":8,"reps_max":8,"per_leg":true}', 'linear'),
('Walking Lunge', 'walking-lunge', ARRAY['quads','glutes'], ARRAY['dumbbell'], '{"sets":3,"reps_min":10,"reps_max":10,"per_leg":true}', 'linear'),
('Hip Thrust', 'hip-thrust', ARRAY['glutes','hamstrings'], ARRAY['barbell','bench'], '{"sets":3,"reps_min":10,"reps_max":10}', 'linear'),
('Pull-Up', 'pull-up', ARRAY['back','biceps'], ARRAY['pull-up-bar'], '{"sets":4,"reps_min":6,"reps_max":10}', 'linear'),
('Weighted Chin-Up', 'weighted-chin-up', ARRAY['back','biceps'], ARRAY['pull-up-bar'], '{"sets":4,"reps_min":6,"reps_max":10}', 'linear'),
('Lat Pulldown', 'lat-pulldown', ARRAY['back','biceps'], ARRAY['cable'], '{"sets":3,"reps_min":8,"reps_max":12}', 'linear'),
('Cable Seated Row', 'cable-seated-row', ARRAY['back','biceps'], ARRAY['cable'], '{"sets":3,"reps_min":8,"reps_max":12}', 'linear'),
('Chest-Supported Row', 'chest-supported-row', ARRAY['back','biceps'], ARRAY['dumbbell','bench'], '{"sets":3,"reps_min":8,"reps_max":12}', 'linear'),
('Barbell Row', 'barbell-row', ARRAY['back','biceps'], ARRAY['barbell'], '{"sets":3,"reps_min":8,"reps_max":12}', 'linear'),
('Face Pull', 'face-pull', ARRAY['rear-delts','upper-back'], ARRAY['cable'], '{"sets":3,"reps_min":15,"reps_max":15}', 'linear'),
('Lateral Raise', 'lateral-raise', ARRAY['shoulders'], ARRAY['dumbbell'], '{"sets":3,"reps_min":12,"reps_max":15}', 'linear'),
('Dumbbell Curl', 'db-curl', ARRAY['biceps'], ARRAY['dumbbell'], '{"sets":3,"reps_min":10,"reps_max":12}', 'linear'),
('Cable Curl', 'cable-curl', ARRAY['biceps'], ARRAY['cable'], '{"sets":3,"reps_min":10,"reps_max":12}', 'linear'),
('Tricep Pressdown', 'tricep-pressdown', ARRAY['triceps'], ARRAY['cable'], '{"sets":3,"reps_min":10,"reps_max":12}', 'linear'),
('Dumbbell Bench Press', 'db-bench-press', ARRAY['chest','triceps','shoulders'], ARRAY['dumbbell','bench'], '{"sets":3,"reps_min":8,"reps_max":12}', 'linear'),
('Incline Dumbbell Press', 'incline-db-press', ARRAY['chest','shoulders','triceps'], ARRAY['dumbbell','bench'], '{"sets":3,"reps_min":8,"reps_max":12}', 'linear'),
('Dumbbell Row', 'db-row', ARRAY['back','biceps'], ARRAY['dumbbell','bench'], '{"sets":3,"reps_min":8,"reps_max":12}', 'linear'),
('Split Squat', 'split-squat', ARRAY['quads','glutes'], ARRAY['dumbbell'], '{"sets":3,"reps_min":10,"reps_max":10,"per_leg":true}', 'linear'),
('Banded Leg Extension', 'leg-extension-banded', ARRAY['quads'], ARRAY['band'], '{"sets":3,"reps_min":12,"reps_max":12}', 'linear'),
('Banded Leg Curl', 'leg-curl-banded', ARRAY['hamstrings'], ARRAY['band'], '{"sets":3,"reps_min":12,"reps_max":12}', 'linear'),
('Glute Ham Raise', 'ghr', ARRAY['hamstrings','glutes'], ARRAY['bodyweight'], '{"sets":3,"reps_min":12,"reps_max":12}', 'linear'),
('Sissy Squat', 'sissy-squat', ARRAY['quads'], ARRAY['bodyweight'], '{"sets":3,"reps_min":12,"reps_max":12}', 'linear'),
('Standing Calf Raise', 'standing-calf-raise', ARRAY['calves'], ARRAY['bodyweight'], '{"sets":3,"reps_min":12,"reps_max":15}', 'linear'),
('Seated Calf Raise', 'seated-calf-raise', ARRAY['calves'], ARRAY['bodyweight'], '{"sets":3,"reps_min":12,"reps_max":15}', 'linear'),
('Plank', 'plank', ARRAY['core'], ARRAY['bodyweight'], '{"sets":3}', 'linear'),
('Hanging Leg Raise', 'hanging-leg-raise', ARRAY['core'], ARRAY['pull-up-bar'], '{"sets":3}', 'linear'),
('Ab Wheel Rollout', 'ab-wheel', ARRAY['core'], ARRAY['ab-wheel'], '{"sets":3}', 'linear');
