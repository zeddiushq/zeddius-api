use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// Neither `lift_sets` nor `run_session` is a `workouts` column, so neither is
// part of the `query_as!`-mapped row (see `repo::WorkoutRow`) — both are
// attached afterward. `repo::list`/`create` leave them empty/None (keeps
// those to one lightweight query); `repo::get` fetches both in two more
// queries.
#[derive(Debug, Serialize, ToSchema)]
pub struct Workout {
    pub id: Uuid,
    pub r#type: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub source: String,
    pub source_uuid: Option<String>,
    pub created_at: DateTime<Utc>,
    pub lift_sets: Vec<LiftSet>,
    pub run_session: Option<RunSession>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkoutRequest {
    pub r#type: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

// Every field is "leave unchanged if omitted" (via SQL COALESCE in repo::update),
// matching the same tradeoff already accepted for food_entries' PATCH.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWorkoutRequest {
    pub r#type: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct WorkoutQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

pub const WORKOUT_TYPES: [&str; 7] = [
    "lift_upper_a",
    "lift_lower_a",
    "lift_upper_b",
    "lift_lower_b",
    "run_easy",
    "run_long",
    "custom",
];

#[derive(Debug, Serialize, ToSchema)]
pub struct LiftSet {
    pub id: Uuid,
    pub workout_id: Uuid,
    pub exercise_id: Uuid,
    pub set_number: i16,
    pub target_reps_min: Option<i16>,
    pub target_reps_max: Option<i16>,
    pub target_weight_kg: Option<Decimal>,
    pub actual_reps: Option<i16>,
    pub actual_weight_kg: Option<Decimal>,
    pub rpe: Option<Decimal>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLiftSetRequest {
    pub exercise_id: Uuid,
    pub set_number: i16,
    pub target_reps_min: Option<i16>,
    pub target_reps_max: Option<i16>,
    pub target_weight_kg: Option<Decimal>,
    pub actual_reps: Option<i16>,
    pub actual_weight_kg: Option<Decimal>,
    pub rpe: Option<Decimal>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkCreateLiftSetsRequest {
    pub sets: Vec<CreateLiftSetRequest>,
}

// Every field is "leave unchanged if omitted", matching every other PATCH in
// this API.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLiftSetRequest {
    pub set_number: Option<i16>,
    pub target_reps_min: Option<i16>,
    pub target_reps_max: Option<i16>,
    pub target_weight_kg: Option<Decimal>,
    pub actual_reps: Option<i16>,
    pub actual_weight_kg: Option<Decimal>,
    pub rpe: Option<Decimal>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunSession {
    pub id: Uuid,
    pub workout_id: Uuid,
    pub distance_meters: Decimal,
    pub duration_seconds: i32,
    pub avg_pace_seconds_per_km: Option<i32>,
    pub avg_heart_rate: Option<i16>,
    pub max_heart_rate: Option<i16>,
    pub elevation_gain_meters: Option<Decimal>,
    pub gps_path_url: Option<String>,
}

// No `avg_pace_seconds_per_km` field — it's always computed server-side from
// distance/duration (see `routes::compute_pace`), never trusted from the
// client, same spirit as sleep_logs' `duration_minutes`. No `gps_path_url`
// either — unused until a non-manual (HealthKit/Watch) source exists.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRunSessionRequest {
    pub distance_meters: Decimal,
    pub duration_seconds: i32,
    pub avg_heart_rate: Option<i16>,
    pub max_heart_rate: Option<i16>,
    pub elevation_gain_meters: Option<Decimal>,
}
