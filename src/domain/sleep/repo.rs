use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{CreateSleepLogRequest, SleepLog};

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    req: &CreateSleepLogRequest,
    duration_minutes: i32,
) -> Result<SleepLog, sqlx::Error> {
    sqlx::query_as!(
        SleepLog,
        "INSERT INTO sleep_logs (user_id, date, bed_time, wake_time, duration_minutes, quality_score, source)
         VALUES ($1, $2, $3, $4, $5, $6, 'manual')
         RETURNING id, date, bed_time, wake_time, duration_minutes, quality_score, deep_minutes, rem_minutes, core_minutes, awake_minutes, source, source_uuid, created_at",
        user_id,
        req.date,
        req.bed_time,
        req.wake_time,
        duration_minutes,
        req.quality_score,
    )
    .fetch_one(db)
    .await
}

pub async fn list(
    db: &PgPool,
    user_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<SleepLog>, sqlx::Error> {
    sqlx::query_as!(
        SleepLog,
        "SELECT id, date, bed_time, wake_time, duration_minutes, quality_score, deep_minutes, rem_minutes, core_minutes, awake_minutes, source, source_uuid, created_at
         FROM sleep_logs
         WHERE user_id = $1 AND bed_time BETWEEN $2 AND $3
         ORDER BY bed_time DESC",
        user_id,
        from,
        to,
    )
    .fetch_all(db)
    .await
}

// Ownership-scoped: only deletes if `id` belongs to `user_id`. Returns
// whether a row was actually removed so the handler can 404 rather than
// distinguish "not found" from "not yours."
pub async fn delete(db: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM sleep_logs WHERE id = $1 AND user_id = $2",
        id,
        user_id,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}
