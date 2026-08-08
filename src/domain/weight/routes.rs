use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, Utc};
use rust_decimal::Decimal;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::model::{CreateWeightLogRequest, WeightLog, WeightLogQuery};
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
    path = "/weight-logs",
    params(WeightLogQuery),
    responses(
        (status = 200, description = "Recent weight entries, most recent first. Defaults to the last 30 days when from/to are omitted.", body = Vec<WeightLog>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "weight",
)]
async fn list(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Query(params): Query<WeightLogQuery>,
) -> Result<Json<Vec<WeightLog>>, AppError> {
    let to = params.to.unwrap_or_else(Utc::now);
    let from = params
        .from
        .unwrap_or_else(|| to - ChronoDuration::days(DEFAULT_RANGE_DAYS));
    let logs = repo::list(&state.db, auth.user_id, from, to).await?;
    Ok(Json(logs))
}

#[utoipa::path(
    post,
    path = "/weight-logs",
    request_body = CreateWeightLogRequest,
    responses(
        (status = 200, description = "Weight log created", body = WeightLog),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
        (status = 422, description = "weight_kg must be positive; body_fat_pct/water_pct must be 0-100; muscle_mass_kg/bone_mass_kg must be positive", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "weight",
)]
async fn create(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Json(req): Json<CreateWeightLogRequest>,
) -> Result<Json<WeightLog>, AppError> {
    validate(&req)?;
    let log = repo::create(&state.db, auth.user_id, &req).await?;
    Ok(Json(log))
}

#[utoipa::path(
    delete,
    path = "/weight-logs/{id}",
    params(("id" = Uuid, Path, description = "Weight log id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "weight",
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
        Err(AppError::NotFound("weight log"))
    }
}

fn validate(req: &CreateWeightLogRequest) -> Result<(), AppError> {
    if req.weight_kg <= Decimal::ZERO {
        return Err(AppError::ValidationFailed(
            "weight_kg must be positive".into(),
        ));
    }
    for (name, pct) in [
        ("body_fat_pct", req.body_fat_pct),
        ("water_pct", req.water_pct),
    ] {
        if pct.is_some_and(|p| !(Decimal::ZERO..=Decimal::from(100)).contains(&p)) {
            return Err(AppError::ValidationFailed(format!(
                "{name} must be between 0 and 100"
            )));
        }
    }
    for (name, mass) in [
        ("muscle_mass_kg", req.muscle_mass_kg),
        ("bone_mass_kg", req.bone_mass_kg),
    ] {
        if mass.is_some_and(|m| m <= Decimal::ZERO) {
            return Err(AppError::ValidationFailed(format!(
                "{name} must be positive"
            )));
        }
    }
    Ok(())
}
