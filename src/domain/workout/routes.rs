use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, Utc};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::model::{
    BulkCreateLiftSetsRequest, CreateWorkoutRequest, LiftSet, UpdateLiftSetRequest,
    UpdateWorkoutRequest, WORKOUT_TYPES, Workout, WorkoutQuery,
};
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

const DEFAULT_RANGE_DAYS: i64 = 30;

pub fn router() -> OpenApiRouter<AppState> {
    // Split by HTTP method within each call: `routes!` panics at runtime
    // ("Overlapping method route") if two handlers in the same call share a
    // method, even at different paths — so `create` (POST /workouts) and
    // `create_lift_sets` (POST .../lift-sets) can't be in the same call,
    // and likewise `update` and `update_lift_set` (both PATCH).
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(get_workout, update, delete))
        .routes(routes!(create_lift_sets))
        .routes(routes!(update_lift_set))
}

#[utoipa::path(
    get,
    path = "/workouts",
    params(WorkoutQuery),
    responses(
        (status = 200, description = "Recent workouts, most recent first. Defaults to the last 30 days when from/to are omitted. lift_sets is always empty here — fetch GET /workouts/{id} for detail.", body = Vec<Workout>),
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
        (status = 200, description = "Workout detail, with its lift_sets populated (run_session nesting arrives in Chunk 5).", body = Workout),
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
    // ended_at needs validating against whichever started_at will actually be
    // in effect after this update — the request's own value if it sets one,
    // otherwise the row's current value (a partial update can patch ended_at
    // alone).
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
        (status = 204, description = "Deleted (lift_sets cascade)"),
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

#[utoipa::path(
    post,
    path = "/workouts/{id}/lift-sets",
    params(("id" = Uuid, Path, description = "Workout id")),
    request_body = BulkCreateLiftSetsRequest,
    responses(
        (status = 200, description = "Sets created, in the same order as the request", body = Vec<LiftSet>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Workout not found, or not owned by the caller", body = ErrorResponse),
        (status = 422, description = "sets must not be empty; every exercise_id must exist in the exercise library", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "workouts",
)]
async fn create_lift_sets(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(workout_id): Path<Uuid>,
    Json(req): Json<BulkCreateLiftSetsRequest>,
) -> Result<Json<Vec<LiftSet>>, AppError> {
    // 404 up front if the workout doesn't exist or isn't the caller's —
    // otherwise a bulk insert against someone else's workout_id would just
    // silently violate the FK and surface as a confusing 500.
    if repo::get(&state.db, workout_id, auth.user_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("workout"));
    }
    if req.sets.is_empty() {
        return Err(AppError::ValidationFailed("sets must not be empty".into()));
    }
    let exercise_ids: Vec<Uuid> = req.sets.iter().map(|s| s.exercise_id).collect();
    let missing = repo::missing_exercise_ids(&state.db, &exercise_ids).await?;
    if !missing.is_empty() {
        return Err(AppError::ValidationFailed(format!(
            "unknown exercise_id(s): {}",
            missing
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let sets = repo::bulk_create_lift_sets(&state.db, workout_id, &req.sets).await?;
    Ok(Json(sets))
}

#[utoipa::path(
    patch,
    path = "/lift-sets/{id}",
    params(("id" = Uuid, Path, description = "Lift set id")),
    request_body = UpdateLiftSetRequest,
    responses(
        (status = 200, description = "Lift set updated. Omitted fields are left unchanged.", body = LiftSet),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or the owning workout isn't the caller's", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "workouts",
)]
async fn update_lift_set(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateLiftSetRequest>,
) -> Result<Json<LiftSet>, AppError> {
    let set = repo::update_lift_set(&state.db, id, auth.user_id, &req).await?;
    set.map(Json).ok_or(AppError::NotFound("lift set"))
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
