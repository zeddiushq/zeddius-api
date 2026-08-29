use chrono::NaiveDate;
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{CreateTaskRequest, DailyTask, TaskCompletion, UpdateTaskRequest};

pub async fn list(db: &PgPool, user_id: Uuid) -> Result<Vec<DailyTask>, sqlx::Error> {
    sqlx::query_as!(
        DailyTask,
        "SELECT id, title, recurrence, target_count_per_week, active, created_at
         FROM daily_tasks
         WHERE user_id = $1 AND active = true
         ORDER BY created_at",
        user_id,
    )
    .fetch_all(db)
    .await
}

// Ownership-scoped fetch, used by routes.rs to 404 before completing/
// uncompleting a task that isn't the caller's.
pub async fn get(db: &PgPool, id: Uuid, user_id: Uuid) -> Result<Option<DailyTask>, sqlx::Error> {
    sqlx::query_as!(
        DailyTask,
        "SELECT id, title, recurrence, target_count_per_week, active, created_at
         FROM daily_tasks
         WHERE id = $1 AND user_id = $2",
        id,
        user_id,
    )
    .fetch_optional(db)
    .await
}

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    req: &CreateTaskRequest,
) -> Result<DailyTask, sqlx::Error> {
    sqlx::query_as!(
        DailyTask,
        "INSERT INTO daily_tasks (user_id, title, recurrence, target_count_per_week)
         VALUES ($1, $2, $3, $4)
         RETURNING id, title, recurrence, target_count_per_week, active, created_at",
        user_id,
        req.title,
        req.recurrence,
        req.target_count_per_week,
    )
    .fetch_one(db)
    .await
}

pub async fn update(
    db: &PgPool,
    id: Uuid,
    user_id: Uuid,
    req: &UpdateTaskRequest,
) -> Result<Option<DailyTask>, sqlx::Error> {
    sqlx::query_as!(
        DailyTask,
        "UPDATE daily_tasks SET
            title = COALESCE($3, title),
            recurrence = COALESCE($4, recurrence),
            target_count_per_week = COALESCE($5, target_count_per_week),
            active = COALESCE($6, active)
         WHERE id = $1 AND user_id = $2
         RETURNING id, title, recurrence, target_count_per_week, active, created_at",
        id,
        user_id,
        req.title,
        req.recurrence,
        req.target_count_per_week,
        req.active,
    )
    .fetch_optional(db)
    .await
}

// Ownership-scoped: only deletes if `id` belongs to `user_id`. Returns
// whether a row was actually removed so the handler can 404 rather than
// distinguish "not found" from "not yours." Completions cascade via FK.
pub async fn delete(db: &PgPool, id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM daily_tasks WHERE id = $1 AND user_id = $2",
        id,
        user_id,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}

// Raw completion rows in range — no server-side "today"/"this week"
// bucketing, the client does that itself.
pub async fn list_completions(
    db: &PgPool,
    user_id: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<TaskCompletion>, sqlx::Error> {
    sqlx::query_as!(
        TaskCompletion,
        "SELECT task_id, completed_date
         FROM daily_task_completions
         WHERE user_id = $1 AND completed_date BETWEEN $2 AND $3
         ORDER BY completed_date",
        user_id,
        from,
        to,
    )
    .fetch_all(db)
    .await
}

// Idempotent: re-completing an already-completed date is a silent no-op,
// not a conflict — the UNIQUE constraint on (task_id, completed_date)
// means a duplicate tap just does nothing.
pub async fn complete(
    db: &PgPool,
    task_id: Uuid,
    user_id: Uuid,
    completed_date: NaiveDate,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO daily_task_completions (task_id, user_id, completed_date)
         VALUES ($1, $2, $3)
         ON CONFLICT (task_id, completed_date) DO NOTHING",
        task_id,
        user_id,
        completed_date,
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn uncomplete(
    db: &PgPool,
    task_id: Uuid,
    user_id: Uuid,
    completed_date: NaiveDate,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM daily_task_completions
         WHERE task_id = $1 AND user_id = $2 AND completed_date = $3",
        task_id,
        user_id,
        completed_date,
    )
    .execute(db)
    .await?;
    Ok(())
}
