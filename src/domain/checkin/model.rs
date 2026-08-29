use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct DailyCheckin {
    pub id: Uuid,
    pub date: NaiveDate,
    pub tomorrow_focus: Option<String>,
    pub closed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertDailyCheckinRequest {
    pub date: NaiveDate,
    pub tomorrow_focus: Option<String>,
}

// Required, not defaulted — same reasoning as TaskCompletionQuery: no
// sensible default range without the server knowing "today" in the
// client's timezone.
#[derive(Debug, Deserialize, IntoParams)]
pub struct DailyCheckinQuery {
    pub from: NaiveDate,
    pub to: NaiveDate,
}
