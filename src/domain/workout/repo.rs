use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{CreateWorkoutRequest, UpdateWorkoutRequest, Workout};

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    req: &CreateWorkoutRequest,
) -> Result<Workout, sqlx::Error> {
    sqlx::query_as!(
        Workout,
        r#"INSERT INTO workouts (user_id, type, started_at, ended_at, notes, source)
         VALUES ($1, $2, $3, $4, $5, 'manual')
         RETURNING id, type as "type!", started_at, ended_at, notes, source, source_uuid, created_at"#,
        user_id,
        req.r#type,
        req.started_at,
        req.ended_at,
        req.notes,
    )
    .fetch_one(db)
    .await
}

pub async fn list(
    db: &PgPool,
    user_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<Workout>, sqlx::Error> {
    sqlx::query_as!(
        Workout,
        r#"SELECT id, type as "type!", started_at, ended_at, notes, source, source_uuid, created_at
         FROM workouts
         WHERE user_id = $1 AND started_at BETWEEN $2 AND $3
         ORDER BY started_at DESC"#,
        user_id,
        from,
        to,
    )
    .fetch_all(db)
    .await
}

pub async fn get(db: &PgPool, id: Uuid, user_id: Uuid) -> Result<Option<Workout>, sqlx::Error> {
    sqlx::query_as!(
        Workout,
        r#"SELECT id, type as "type!", started_at, ended_at, notes, source, source_uuid, created_at
         FROM workouts
         WHERE id = $1 AND user_id = $2"#,
        id,
        user_id,
    )
    .fetch_optional(db)
    .await
}

// COALESCE means an omitted field is left unchanged, not cleared. Returns
// `None` if `id` doesn't exist or isn't owned by `user_id`.
pub async fn update(
    db: &PgPool,
    id: Uuid,
    user_id: Uuid,
    req: &UpdateWorkoutRequest,
) -> Result<Option<Workout>, sqlx::Error> {
    sqlx::query_as!(
        Workout,
        r#"UPDATE workouts SET
            type = COALESCE($3, type),
            started_at = COALESCE($4, started_at),
            ended_at = COALESCE($5, ended_at),
            notes = COALESCE($6, notes)
         WHERE id = $1 AND user_id = $2
         RETURNING id, type as "type!", started_at, ended_at, notes, source, source_uuid, created_at"#,
        id,
        user_id,
        req.r#type,
        req.started_at,
        req.ended_at,
        req.notes,
    )
    .fetch_optional(db)
    .await
}

// Ownership-scoped: only deletes if `id` belongs to `user_id`. Returns
// whether a row was actually removed so the handler can 404 rather than
// distinguish "not found" from "not yours."
pub async fn delete(db: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM workouts WHERE id = $1 AND user_id = $2",
        id,
        user_id,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}
