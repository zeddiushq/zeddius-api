use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::model::{
    CompleteTaskRequest, CreateTaskRequest, DailyTask, RECURRENCES, TaskCompletion,
    TaskCompletionQuery, UncompleteTaskQuery, UpdateTaskRequest,
};
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

// Split by HTTP method: `routes!` panics at runtime ("Overlapping method
// route") if two handlers in the same call share a method, even at
// different paths — same constraint documented in domain/workout/routes.rs.
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, create, update))
        .routes(routes!(list_completions))
        .routes(routes!(complete))
        .routes(routes!(delete))
        .routes(routes!(uncomplete))
}

#[utoipa::path(
    get,
    path = "/tasks",
    responses(
        (status = 200, description = "Active recurring tasks", body = Vec<DailyTask>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "tasks",
)]
async fn list(
    State(state): State<AppState>,
    auth: VerifiedUser,
) -> Result<Json<Vec<DailyTask>>, AppError> {
    let tasks = repo::list(&state.db, auth.user_id).await?;
    Ok(Json(tasks))
}

#[utoipa::path(
    post,
    path = "/tasks",
    request_body = CreateTaskRequest,
    responses(
        (status = 200, description = "Task created", body = DailyTask),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
        (status = 422, description = "recurrence must be 'daily' or 'weekly'; target_count_per_week required (and positive) for weekly, must be omitted for daily", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "tasks",
)]
async fn create(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Json(req): Json<CreateTaskRequest>,
) -> Result<Json<DailyTask>, AppError> {
    validate_recurrence(&req.recurrence)?;
    validate_target_count(&req.recurrence, req.target_count_per_week)?;
    let task = repo::create(&state.db, auth.user_id, &req).await?;
    Ok(Json(task))
}

#[utoipa::path(
    patch,
    path = "/tasks/{id}",
    params(("id" = Uuid, Path, description = "Task id")),
    request_body = UpdateTaskRequest,
    responses(
        (status = 200, description = "Task updated. Omitted fields are left unchanged.", body = DailyTask),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
        (status = 422, description = "recurrence must be 'daily' or 'weekly'; target_count_per_week required (and positive) for weekly, must be omitted for daily", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "tasks",
)]
async fn update(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTaskRequest>,
) -> Result<Json<DailyTask>, AppError> {
    // recurrence and target_count_per_week must stay consistent as a pair,
    // so a PATCH touching only one of them is validated against the
    // *effective* value of the other (the request's own value if it's
    // changing, otherwise the row's current value) — same "fetch current
    // row for cross-field validation" shape as workout::routes::update's
    // ended_at/started_at check.
    if req.recurrence.is_some() || req.target_count_per_week.is_some() {
        let current = repo::get(&state.db, id, auth.user_id)
            .await?
            .ok_or(AppError::NotFound("task"))?;
        let effective_recurrence = req.recurrence.as_deref().unwrap_or(&current.recurrence);
        validate_recurrence(effective_recurrence)?;
        let effective_target_count = req.target_count_per_week.or(current.target_count_per_week);
        validate_target_count(effective_recurrence, effective_target_count)?;
    }
    let task = repo::update(&state.db, id, auth.user_id, &req).await?;
    task.map(Json).ok_or(AppError::NotFound("task"))
}

#[utoipa::path(
    delete,
    path = "/tasks/{id}",
    params(("id" = Uuid, Path, description = "Task id")),
    responses(
        (status = 204, description = "Deleted (completions cascade)"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "tasks",
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
        Err(AppError::NotFound("task"))
    }
}

#[utoipa::path(
    get,
    path = "/task-completions",
    params(TaskCompletionQuery),
    responses(
        (status = 200, description = "Raw completion rows in range — the client buckets these into 'today'/'this week' itself", body = Vec<TaskCompletion>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "tasks",
)]
async fn list_completions(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Query(params): Query<TaskCompletionQuery>,
) -> Result<Json<Vec<TaskCompletion>>, AppError> {
    let completions =
        repo::list_completions(&state.db, auth.user_id, params.from, params.to).await?;
    Ok(Json(completions))
}

#[utoipa::path(
    post,
    path = "/tasks/{id}/complete",
    params(("id" = Uuid, Path, description = "Task id")),
    request_body = CompleteTaskRequest,
    responses(
        (status = 204, description = "Marked complete for that date. Idempotent — completing an already-completed date is a no-op."),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Task not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "tasks",
)]
async fn complete(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<CompleteTaskRequest>,
) -> Result<StatusCode, AppError> {
    if repo::get(&state.db, id, auth.user_id).await?.is_none() {
        return Err(AppError::NotFound("task"));
    }
    repo::complete(&state.db, id, auth.user_id, req.completed_date).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/tasks/{id}/complete",
    params(("id" = Uuid, Path, description = "Task id"), UncompleteTaskQuery),
    responses(
        (status = 204, description = "Completion for that date removed, if it existed"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Task not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "tasks",
)]
async fn uncomplete(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
    Query(params): Query<UncompleteTaskQuery>,
) -> Result<StatusCode, AppError> {
    if repo::get(&state.db, id, auth.user_id).await?.is_none() {
        return Err(AppError::NotFound("task"));
    }
    repo::uncomplete(&state.db, id, auth.user_id, params.date).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_recurrence(recurrence: &str) -> Result<(), AppError> {
    if !RECURRENCES.contains(&recurrence) {
        return Err(AppError::ValidationFailed(format!(
            "recurrence must be one of: {}",
            RECURRENCES.join(", ")
        )));
    }
    Ok(())
}

fn validate_target_count(
    recurrence: &str,
    target_count_per_week: Option<i16>,
) -> Result<(), AppError> {
    match recurrence {
        "weekly" if target_count_per_week.is_none_or(|v| v <= 0) => {
            Err(AppError::ValidationFailed(
                "target_count_per_week must be a positive number for weekly tasks".into(),
            ))
        }
        "daily" if target_count_per_week.is_some() => Err(AppError::ValidationFailed(
            "target_count_per_week must not be set for daily tasks".into(),
        )),
        _ => Ok(()),
    }
}
