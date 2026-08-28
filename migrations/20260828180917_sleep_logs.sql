CREATE TABLE sleep_logs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date             DATE NOT NULL,
    bed_time         TIMESTAMPTZ NOT NULL,
    wake_time        TIMESTAMPTZ NOT NULL,
    duration_minutes INT NOT NULL,
    quality_score    SMALLINT,
    deep_minutes     INT,
    rem_minutes      INT,
    core_minutes     INT,
    awake_minutes    INT,
    source           TEXT NOT NULL,
    source_uuid      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- serves the from/to range query on bed_time, same shape as weight_logs
CREATE INDEX idx_sleep_logs_user_id_bed_time ON sleep_logs(user_id, bed_time DESC);
