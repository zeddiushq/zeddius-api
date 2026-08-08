use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{CreateWeightLogRequest, WeightLog};

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    req: &CreateWeightLogRequest,
) -> Result<WeightLog, sqlx::Error> {
    sqlx::query_as!(
        WeightLog,
        "INSERT INTO weight_logs (user_id, recorded_at, weight_kg, body_fat_pct, muscle_mass_kg, water_pct, bone_mass_kg, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'manual')
         RETURNING id, recorded_at, weight_kg, body_fat_pct, muscle_mass_kg, water_pct, bone_mass_kg, source, source_uuid, created_at",
        user_id,
        req.recorded_at,
        req.weight_kg,
        req.body_fat_pct,
        req.muscle_mass_kg,
        req.water_pct,
        req.bone_mass_kg,
    )
    .fetch_one(db)
    .await
}

pub async fn list(
    db: &PgPool,
    user_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<WeightLog>, sqlx::Error> {
    sqlx::query_as!(
        WeightLog,
        "SELECT id, recorded_at, weight_kg, body_fat_pct, muscle_mass_kg, water_pct, bone_mass_kg, source, source_uuid, created_at
         FROM weight_logs
         WHERE user_id = $1 AND recorded_at BETWEEN $2 AND $3
         ORDER BY recorded_at DESC",
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
        "DELETE FROM weight_logs WHERE id = $1 AND user_id = $2",
        id,
        user_id,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}
