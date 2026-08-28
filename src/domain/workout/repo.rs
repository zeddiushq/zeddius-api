use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{
    CreateLiftSetRequest, CreateRunSessionRequest, CreateWorkoutRequest, LiftSet, RunSession,
    UpdateLiftSetRequest, UpdateWorkoutRequest, Workout,
};

// Mirrors the `workouts` columns exactly (no `lift_sets`/`run_session` —
// neither is a column). `query_as!` maps onto this, then each caller
// attaches both explicitly via `into_workout`.
struct WorkoutRow {
    id: Uuid,
    r#type: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    notes: Option<String>,
    source: String,
    source_uuid: Option<String>,
    created_at: DateTime<Utc>,
}

impl WorkoutRow {
    fn into_workout(self, lift_sets: Vec<LiftSet>, run_session: Option<RunSession>) -> Workout {
        Workout {
            id: self.id,
            r#type: self.r#type,
            started_at: self.started_at,
            ended_at: self.ended_at,
            notes: self.notes,
            source: self.source,
            source_uuid: self.source_uuid,
            created_at: self.created_at,
            lift_sets,
            run_session,
        }
    }
}

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    req: &CreateWorkoutRequest,
) -> Result<Workout, sqlx::Error> {
    let row = sqlx::query_as!(
        WorkoutRow,
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
    .await?;
    Ok(row.into_workout(Vec::new(), None))
}

pub async fn list(
    db: &PgPool,
    user_id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<Workout>, sqlx::Error> {
    let rows = sqlx::query_as!(
        WorkoutRow,
        r#"SELECT id, type as "type!", started_at, ended_at, notes, source, source_uuid, created_at
         FROM workouts
         WHERE user_id = $1 AND started_at BETWEEN $2 AND $3
         ORDER BY started_at DESC"#,
        user_id,
        from,
        to,
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| r.into_workout(Vec::new(), None))
        .collect())
}

// Detail fetch: also populates `lift_sets`/`run_session` with two more
// queries, unlike `list`/`create` which leave both empty/None.
pub async fn get(db: &PgPool, id: Uuid, user_id: Uuid) -> Result<Option<Workout>, sqlx::Error> {
    let row = sqlx::query_as!(
        WorkoutRow,
        r#"SELECT id, type as "type!", started_at, ended_at, notes, source, source_uuid, created_at
         FROM workouts
         WHERE id = $1 AND user_id = $2"#,
        id,
        user_id,
    )
    .fetch_optional(db)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let lift_sets = list_lift_sets(db, id).await?;
    let run_session = get_run_session(db, id).await?;
    Ok(Some(row.into_workout(lift_sets, run_session)))
}

// COALESCE means an omitted field is left unchanged, not cleared. Returns
// `None` if `id` doesn't exist or isn't owned by `user_id`.
pub async fn update(
    db: &PgPool,
    id: Uuid,
    user_id: Uuid,
    req: &UpdateWorkoutRequest,
) -> Result<Option<Workout>, sqlx::Error> {
    let row = sqlx::query_as!(
        WorkoutRow,
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
    .await?;
    Ok(row.map(|r| r.into_workout(Vec::new(), None)))
}

// Ownership-scoped: only deletes if `id` belongs to `user_id`. Returns
// whether a row was actually removed so the handler can 404 rather than
// distinguish "not found" from "not yours." lift_sets/run_session cascade
// via their FKs.
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

pub async fn list_lift_sets(db: &PgPool, workout_id: Uuid) -> Result<Vec<LiftSet>, sqlx::Error> {
    sqlx::query_as!(
        LiftSet,
        r#"SELECT id, workout_id, exercise_id, set_number, target_reps_min, target_reps_max, target_weight_kg, actual_reps, actual_weight_kg, rpe, notes
         FROM lift_sets
         WHERE workout_id = $1
         ORDER BY exercise_id, set_number"#,
        workout_id,
    )
    .fetch_all(db)
    .await
}

// Returns any `exercise_id`s in `ids` that don't exist in the exercise
// library, so the handler can 422 cleanly instead of surfacing a raw FK
// constraint violation as a 500.
pub async fn missing_exercise_ids(db: &PgPool, ids: &[Uuid]) -> Result<Vec<Uuid>, sqlx::Error> {
    let existing: Vec<Uuid> =
        sqlx::query_scalar!("SELECT id FROM exercises WHERE id = ANY($1)", ids)
            .fetch_all(db)
            .await?;
    Ok(ids
        .iter()
        .copied()
        .filter(|id| !existing.contains(id))
        .collect())
}

// Inserted one at a time in a transaction rather than a single bulk-array
// statement — simpler to get right, and a lifting session is at most a few
// dozen sets, so the extra round-trips are not a real cost here.
pub async fn bulk_create_lift_sets(
    db: &PgPool,
    workout_id: Uuid,
    sets: &[CreateLiftSetRequest],
) -> Result<Vec<LiftSet>, sqlx::Error> {
    let mut tx = db.begin().await?;
    let mut created = Vec::with_capacity(sets.len());
    for set in sets {
        let row = sqlx::query_as!(
            LiftSet,
            r#"INSERT INTO lift_sets (workout_id, exercise_id, set_number, target_reps_min, target_reps_max, target_weight_kg, actual_reps, actual_weight_kg, rpe, notes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id, workout_id, exercise_id, set_number, target_reps_min, target_reps_max, target_weight_kg, actual_reps, actual_weight_kg, rpe, notes"#,
            workout_id,
            set.exercise_id,
            set.set_number,
            set.target_reps_min,
            set.target_reps_max,
            set.target_weight_kg,
            set.actual_reps,
            set.actual_weight_kg,
            set.rpe,
            set.notes,
        )
        .fetch_one(&mut *tx)
        .await?;
        created.push(row);
    }
    tx.commit().await?;
    Ok(created)
}

// Ownership scoped transitively through workout_id -> workouts.user_id,
// since lift_sets has no direct user_id column. COALESCE means an omitted
// field is left unchanged.
pub async fn update_lift_set(
    db: &PgPool,
    id: Uuid,
    user_id: Uuid,
    req: &UpdateLiftSetRequest,
) -> Result<Option<LiftSet>, sqlx::Error> {
    sqlx::query_as!(
        LiftSet,
        r#"UPDATE lift_sets SET
            set_number = COALESCE($3, set_number),
            target_reps_min = COALESCE($4, target_reps_min),
            target_reps_max = COALESCE($5, target_reps_max),
            target_weight_kg = COALESCE($6, target_weight_kg),
            actual_reps = COALESCE($7, actual_reps),
            actual_weight_kg = COALESCE($8, actual_weight_kg),
            rpe = COALESCE($9, rpe),
            notes = COALESCE($10, notes)
         WHERE id = $1 AND workout_id IN (SELECT id FROM workouts WHERE user_id = $2)
         RETURNING id, workout_id, exercise_id, set_number, target_reps_min, target_reps_max, target_weight_kg, actual_reps, actual_weight_kg, rpe, notes"#,
        id,
        user_id,
        req.set_number,
        req.target_reps_min,
        req.target_reps_max,
        req.target_weight_kg,
        req.actual_reps,
        req.actual_weight_kg,
        req.rpe,
        req.notes,
    )
    .fetch_optional(db)
    .await
}

pub async fn get_run_session(
    db: &PgPool,
    workout_id: Uuid,
) -> Result<Option<RunSession>, sqlx::Error> {
    sqlx::query_as!(
        RunSession,
        r#"SELECT id, workout_id, distance_meters, duration_seconds, avg_pace_seconds_per_km, avg_heart_rate, max_heart_rate, elevation_gain_meters, gps_path_url
         FROM run_sessions
         WHERE workout_id = $1"#,
        workout_id,
    )
    .fetch_optional(db)
    .await
}

// One run session per workout (workout_id is UNIQUE) — re-posting replaces
// whatever was there, rather than erroring.
pub async fn upsert_run_session(
    db: &PgPool,
    workout_id: Uuid,
    req: &CreateRunSessionRequest,
    avg_pace_seconds_per_km: i32,
) -> Result<RunSession, sqlx::Error> {
    sqlx::query_as!(
        RunSession,
        r#"INSERT INTO run_sessions (workout_id, distance_meters, duration_seconds, avg_pace_seconds_per_km, avg_heart_rate, max_heart_rate, elevation_gain_meters)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (workout_id) DO UPDATE SET
            distance_meters = EXCLUDED.distance_meters,
            duration_seconds = EXCLUDED.duration_seconds,
            avg_pace_seconds_per_km = EXCLUDED.avg_pace_seconds_per_km,
            avg_heart_rate = EXCLUDED.avg_heart_rate,
            max_heart_rate = EXCLUDED.max_heart_rate,
            elevation_gain_meters = EXCLUDED.elevation_gain_meters
         RETURNING id, workout_id, distance_meters, duration_seconds, avg_pace_seconds_per_km, avg_heart_rate, max_heart_rate, elevation_gain_meters, gps_path_url"#,
        workout_id,
        req.distance_meters,
        req.duration_seconds,
        avg_pace_seconds_per_km,
        req.avg_heart_rate,
        req.max_heart_rate,
        req.elevation_gain_meters,
    )
    .fetch_one(db)
    .await
}
