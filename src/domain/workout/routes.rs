use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, Utc};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::model::{
    CreateWorkoutRequest, UpdateWorkoutRequest, WORKOUT_TYPES, Workout, WorkoutQuery,
};
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

const DEFAULT_RANGE_DAYS: i64 = 30;

pub fn router() -> OpenApiRouter<AppState> {
    // Two `.routes()` calls, not one: `routes!` can't take two handlers that
    // share an HTTP method (both `list` and `get_workout` are GET), even
    // though they're at different paths — it panics at runtime with
    // "Overlapping method route" if you try. Group by method instead.
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_workout, update, delete))
}

#[utoipa::path(
    get,
    path = "/workouts",
    params(WorkoutQuery),
    responses(
        (status = 200, description = "Recent workouts, most recent first. Defaults to the last 30 days when from/to are omitted.", body = Vec<Workout>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "workouts",
)]
async fn list(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Query(params): Query<WorkoutQuery>,
) -> Result<Json<Vec<Workout>>, AppError> {
    let to = params.to.unwrap_or_else(Utc::now);
    let from = params
        .from
        .unwrap_or_else(|| to - ChronoDuration::days(DEFAULT_RANGE_DAYS));
    let workouts = repo::list(&state.db, auth.user_id, from, to).await?;
    Ok(Json(workouts))
}

#[utoipa::path(
    post,
    path = "/workouts",
    request_body = CreateWorkoutRequest,
    responses(
        (status = 200, description = "Workout created", body = Workout),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
        (status = 422, description = "type must be a recognized value; ended_at must be after started_at", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "workouts",
)]
async fn create(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Json(req): Json<CreateWorkoutRequest>,
) -> Result<Json<Workout>, AppError> {
    validate_type(&req.r#type)?;
    validate_ended_after_started(req.started_at, req.ended_at)?;
    let workout = repo::create(&state.db, auth.user_id, &req).await?;
    Ok(Json(workout))
}

#[utoipa::path(
    get,
    path = "/workouts/{id}",
    params(("id" = Uuid, Path, description = "Workout id")),
    responses(
        (status = 200, description = "Workout detail. Nested lift_sets/run_session arrive in later chunks — this is a plain Workout for now.", body = Workout),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "workouts",
)]
async fn get_workout(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Workout>, AppError> {
    let workout = repo::get(&state.db, id, auth.user_id).await?;
    workout.map(Json).ok_or(AppError::NotFound("workout"))
}

#[utoipa::path(
    patch,
    path = "/workouts/{id}",
    params(("id" = Uuid, Path, description = "Workout id")),
    request_body = UpdateWorkoutRequest,
    responses(
        (status = 200, description = "Workout updated. Omitted fields are left unchanged.", body = Workout),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
        (status = 422, description = "type must be a recognized value; ended_at must be after started_at", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "workouts",
)]
async fn update(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateWorkoutRequest>,
) -> Result<Json<Workout>, AppError> {
    if let Some(ty) = &req.r#type {
        validate_type(ty)?;
    }
    // ended_at needs validating against whichever started_at will actually be in
    // effect after this update — the request's own value if it sets one, otherwise
    // the row's current value (a partial update can patch ended_at alone).
    if req.ended_at.is_some() {
        let effective_started_at = match req.started_at {
            Some(started) => Some(started),
            None => repo::get(&state.db, id, auth.user_id)
                .await?
                .map(|w| w.started_at),
        };
        if let Some(started) = effective_started_at {
            validate_ended_after_started(started, req.ended_at)?;
        }
    }
    let workout = repo::update(&state.db, id, auth.user_id, &req).await?;
    workout.map(Json).ok_or(AppError::NotFound("workout"))
}

#[utoipa::path(
    delete,
    path = "/workouts/{id}",
    params(("id" = Uuid, Path, description = "Workout id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "workouts",
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
        Err(AppError::NotFound("workout"))
    }
}

fn validate_type(ty: &str) -> Result<(), AppError> {
    if !WORKOUT_TYPES.contains(&ty) {
        return Err(AppError::ValidationFailed(format!(
            "type must be one of: {}",
            WORKOUT_TYPES.join(", ")
        )));
    }
    Ok(())
}

fn validate_ended_after_started(
    started_at: chrono::DateTime<Utc>,
    ended_at: Option<chrono::DateTime<Utc>>,
) -> Result<(), AppError> {
    if ended_at.is_some_and(|ended| ended <= started_at) {
        return Err(AppError::ValidationFailed(
            "ended_at must be after started_at".into(),
        ));
    }
    Ok(())
}
