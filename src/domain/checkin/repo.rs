use chrono::NaiveDate;
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{DailyCheckin, UpsertDailyCheckinRequest};

pub async fn list(
    db: &PgPool,
    user_id: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<DailyCheckin>, sqlx::Error> {
    sqlx::query_as!(
        DailyCheckin,
        "SELECT id, date, tomorrow_focus, closed_at, created_at, updated_at
         FROM daily_checkins
         WHERE user_id = $1 AND date BETWEEN $2 AND $3
         ORDER BY date DESC",
        user_id,
        from,
        to,
    )
    .fetch_all(db)
    .await
}

// True upsert (create-or-replace), like run_sessions — not a COALESCE
// partial update. There's only one field to set beyond the date, so
// "leave unchanged if omitted" doesn't apply the way it does elsewhere.
pub async fn upsert(
    db: &PgPool,
    user_id: Uuid,
    req: &UpsertDailyCheckinRequest,
) -> Result<DailyCheckin, sqlx::Error> {
    sqlx::query_as!(
        DailyCheckin,
        "INSERT INTO daily_checkins (user_id, date, tomorrow_focus)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, date) DO UPDATE SET
            tomorrow_focus = EXCLUDED.tomorrow_focus,
            updated_at = now()
         RETURNING id, date, tomorrow_focus, closed_at, created_at, updated_at",
        user_id,
        req.date,
        req.tomorrow_focus,
    )
    .fetch_one(db)
    .await
}

// Works even with no prior upsert for that date — Close Day doesn't
// require a tomorrow_focus to already exist.
pub async fn close(
    db: &PgPool,
    user_id: Uuid,
    date: NaiveDate,
) -> Result<DailyCheckin, sqlx::Error> {
    sqlx::query_as!(
        DailyCheckin,
        "INSERT INTO daily_checkins (user_id, date, closed_at)
         VALUES ($1, $2, now())
         ON CONFLICT (user_id, date) DO UPDATE SET
            closed_at = now(),
            updated_at = now()
         RETURNING id, date, tomorrow_focus, closed_at, created_at, updated_at",
        user_id,
        date,
    )
    .fetch_one(db)
    .await
}
