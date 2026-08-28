use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

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
