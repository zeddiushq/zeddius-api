use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

pub const RECURRENCES: &[&str] = &["daily", "weekly"];

#[derive(Debug, Serialize, ToSchema)]
pub struct DailyTask {
    pub id: Uuid,
    pub title: String,
    pub recurrence: String,
    pub target_count_per_week: Option<i16>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTaskRequest {
    pub title: String,
    pub recurrence: String,
    pub target_count_per_week: Option<i16>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTaskRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub recurrence: Option<String>,
    #[serde(default)]
    pub target_count_per_week: Option<i16>,
    #[serde(default)]
    pub active: Option<bool>,
}

// from/to required, not defaulted — server doesn't know "today" in the client's timezone.
#[derive(Debug, Deserialize, IntoParams)]
pub struct TaskCompletionQuery {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TaskCompletion {
    pub task_id: Uuid,
    pub completed_date: NaiveDate,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CompleteTaskRequest {
    pub completed_date: NaiveDate,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct UncompleteTaskQuery {
    pub date: NaiveDate,
}
