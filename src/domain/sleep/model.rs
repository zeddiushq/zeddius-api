use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct SleepLog {
    pub id: Uuid,
    pub date: NaiveDate,
    pub bed_time: DateTime<Utc>,
    pub wake_time: DateTime<Utc>,
    pub duration_minutes: i32,
    pub quality_score: Option<i16>,
    pub deep_minutes: Option<i32>,
    pub rem_minutes: Option<i32>,
    pub core_minutes: Option<i32>,
    pub awake_minutes: Option<i32>,
    pub source: String,
    pub source_uuid: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSleepLogRequest {
    pub date: NaiveDate,
    pub bed_time: DateTime<Utc>,
    pub wake_time: DateTime<Utc>,
    pub quality_score: Option<i16>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct SleepLogQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}
