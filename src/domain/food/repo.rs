use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{CreateFoodEntryRequest, FoodEntry, UpdateFoodEntryRequest};

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    req: &CreateFoodEntryRequest,
) -> Result<FoodEntry, sqlx::Error> {
    sqlx::query_as!(
        FoodEntry,
        "INSERT INTO food_entries (user_id, consumed_at, name, kcal, protein_g, carbs_g, fat_g, portion_count, meal_slot, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'manual')
         RETURNING id, consumed_at, name, kcal, protein_g, carbs_g, fat_g, source, portion_count, meal_slot, created_at",
        user_id,
        req.consumed_at,
        req.name,
        req.kcal,
        req.protein_g,
        req.carbs_g,
        req.fat_g,
        req.portion_count,
        req.meal_slot,
    )
    .fetch_one(db)
    .await
}

pub async fn list(
    db: &PgPool,
    user_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<FoodEntry>, sqlx::Error> {
    sqlx::query_as!(
        FoodEntry,
        "SELECT id, consumed_at, name, kcal, protein_g, carbs_g, fat_g, source, portion_count, meal_slot, created_at
         FROM food_entries
         WHERE user_id = $1 AND consumed_at BETWEEN $2 AND $3
         ORDER BY consumed_at DESC",
        user_id,
        from,
        to,
    )
    .fetch_all(db)
    .await
}

// COALESCE means an omitted field is left unchanged, not cleared — see the
// doc comment on `UpdateFoodEntryRequest`. Returns `None` if `id` doesn't
// exist or isn't owned by `user_id`, so the handler can 404.
pub async fn update(
    db: &PgPool,
    id: Uuid,
    user_id: Uuid,
    req: &UpdateFoodEntryRequest,
) -> Result<Option<FoodEntry>, sqlx::Error> {
    sqlx::query_as!(
        FoodEntry,
        "UPDATE food_entries SET
            consumed_at = COALESCE($3, consumed_at),
            name = COALESCE($4, name),
            kcal = COALESCE($5, kcal),
            protein_g = COALESCE($6, protein_g),
            carbs_g = COALESCE($7, carbs_g),
            fat_g = COALESCE($8, fat_g),
            portion_count = COALESCE($9, portion_count),
            meal_slot = COALESCE($10, meal_slot)
         WHERE id = $1 AND user_id = $2
         RETURNING id, consumed_at, name, kcal, protein_g, carbs_g, fat_g, source, portion_count, meal_slot, created_at",
        id,
        user_id,
        req.consumed_at,
        req.name,
        req.kcal,
        req.protein_g,
        req.carbs_g,
        req.fat_g,
        req.portion_count,
        req.meal_slot,
    )
    .fetch_optional(db)
    .await
}

// Ownership-scoped: only deletes if `id` belongs to `user_id`. Returns
// whether a row was actually removed so the handler can 404 rather than
// distinguish "not found" from "not yours."
pub async fn delete(db: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM food_entries WHERE id = $1 AND user_id = $2",
        id,
        user_id,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}
