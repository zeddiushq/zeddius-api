use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, Utc};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::model::{CreateSleepLogRequest, SleepLog, SleepLogQuery};
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

const DEFAULT_RANGE_DAYS: i64 = 30;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list, create, delete))
}

#[utoipa::path(
    get,
    path = "/sleep-logs",
    params(SleepLogQuery),
    responses(
        (status = 200, description = "Recent sleep entries, most recent first. Defaults to the last 30 days when from/to are omitted.", body = Vec<SleepLog>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "sleep",
)]
async fn list(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Query(params): Query<SleepLogQuery>,
) -> Result<Json<Vec<SleepLog>>, AppError> {
    let to = params.to.unwrap_or_else(Utc::now);
    let from = params
        .from
        .unwrap_or_else(|| to - ChronoDuration::days(DEFAULT_RANGE_DAYS));
    let logs = repo::list(&state.db, auth.user_id, from, to).await?;
    Ok(Json(logs))
}

#[utoipa::path(
    post,
    path = "/sleep-logs",
    request_body = CreateSleepLogRequest,
    responses(
        (status = 200, description = "Sleep log created", body = SleepLog),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
        (status = 422, description = "wake_time must be after bed_time; quality_score must be 1-5", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "sleep",
)]
async fn create(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Json(req): Json<CreateSleepLogRequest>,
) -> Result<Json<SleepLog>, AppError> {
    let duration_minutes = validate(&req)?;
    let log = repo::create(&state.db, auth.user_id, &req, duration_minutes).await?;
    Ok(Json(log))
}

#[utoipa::path(
    delete,
    path = "/sleep-logs/{id}",
    params(("id" = Uuid, Path, description = "Sleep log id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "sleep",
)]
async fn delete(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let deleted = repo::delete(&state.db, id, auth.user_id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound("sleep log"))
    }
}

// Returns the computed duration in minutes on success — duration is derived
// from bed_time/wake_time server-side rather than trusted from the client.
fn validate(req: &CreateSleepLogRequest) -> Result<i32, AppError> {
    if req
        .quality_score
        .is_some_and(|score| !(1..=5).contains(&score))
    {
        return Err(AppError::ValidationFailed(
            "quality_score must be between 1 and 5".into(),
        ));
    }
    let duration = req.wake_time - req.bed_time;
    if duration <= ChronoDuration::zero() {
        return Err(AppError::ValidationFailed(
            "wake_time must be after bed_time".into(),
        ));
    }
    Ok(duration.num_minutes() as i32)
}
