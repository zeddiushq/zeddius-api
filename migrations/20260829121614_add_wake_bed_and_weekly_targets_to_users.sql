ALTER TABLE users
    ADD COLUMN target_wake_time TIME,
    ADD COLUMN target_bed_time TIME,
    ADD COLUMN target_weekly_runs SMALLINT,
    ADD COLUMN target_weekly_lifts SMALLINT;
