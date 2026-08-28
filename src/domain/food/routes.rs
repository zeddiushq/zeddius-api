use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{Duration as ChronoDuration, Utc};
use rust_decimal::Decimal;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::model::{
    CreateFoodEntryRequest, FoodEntry, FoodEntryQuery, MEAL_SLOTS, UpdateFoodEntryRequest,
};
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

const DEFAULT_RANGE_DAYS: i64 = 30;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list, create, update, delete))
}

#[utoipa::path(
    get,
    path = "/food-entries",
    params(FoodEntryQuery),
    responses(
        (status = 200, description = "Recent food entries, most recent first. Defaults to the last 30 days when from/to are omitted.", body = Vec<FoodEntry>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "food",
)]
async fn list(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Query(params): Query<FoodEntryQuery>,
) -> Result<Json<Vec<FoodEntry>>, AppError> {
    let to = params.to.unwrap_or_else(Utc::now);
    let from = params
        .from
        .unwrap_or_else(|| to - ChronoDuration::days(DEFAULT_RANGE_DAYS));
    let entries = repo::list(&state.db, auth.user_id, from, to).await?;
    Ok(Json(entries))
}

#[utoipa::path(
    post,
    path = "/food-entries",
    request_body = CreateFoodEntryRequest,
    responses(
        (status = 200, description = "Food entry created. Only `name` is required — everything else may be omitted for a quick, no-macro log.", body = FoodEntry),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
        (status = 422, description = "name must not be empty; macro/portion fields must not be negative; meal_slot must be a recognized value", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "food",
)]
async fn create(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Json(req): Json<CreateFoodEntryRequest>,
) -> Result<Json<FoodEntry>, AppError> {
    if req.name.trim().is_empty() {
        return Err(AppError::ValidationFailed("name must not be empty".into()));
    }
    validate_macros_and_slot(
        req.kcal,
        req.protein_g,
        req.carbs_g,
        req.fat_g,
        req.portion_count,
        req.meal_slot.as_deref(),
    )?;
    let entry = repo::create(&state.db, auth.user_id, &req).await?;
    Ok(Json(entry))
}

#[utoipa::path(
    patch,
    path = "/food-entries/{id}",
    params(("id" = Uuid, Path, description = "Food entry id")),
    request_body = UpdateFoodEntryRequest,
    responses(
        (status = 200, description = "Food entry updated. Omitted fields are left unchanged.", body = FoodEntry),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
        (status = 422, description = "name must not be empty; macro/portion fields must not be negative; meal_slot must be a recognized value", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "food",
)]
async fn update(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateFoodEntryRequest>,
) -> Result<Json<FoodEntry>, AppError> {
    if req
        .name
        .as_deref()
        .is_some_and(|name| name.trim().is_empty())
    {
        return Err(AppError::ValidationFailed("name must not be empty".into()));
    }
    validate_macros_and_slot(
        req.kcal,
        req.protein_g,
        req.carbs_g,
        req.fat_g,
        req.portion_count,
        req.meal_slot.as_deref(),
    )?;
    let entry = repo::update(&state.db, id, auth.user_id, &req).await?;
    entry.map(Json).ok_or(AppError::NotFound("food entry"))
}

#[utoipa::path(
    delete,
    path = "/food-entries/{id}",
    params(("id" = Uuid, Path, description = "Food entry id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 404, description = "Not found, or not owned by the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "food",
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
        Err(AppError::NotFound("food entry"))
    }
}

fn validate_macros_and_slot(
    kcal: Option<Decimal>,
    protein_g: Option<Decimal>,
    carbs_g: Option<Decimal>,
    fat_g: Option<Decimal>,
    portion_count: Option<Decimal>,
    meal_slot: Option<&str>,
) -> Result<(), AppError> {
    for (name, value) in [
        ("kcal", kcal),
        ("protein_g", protein_g),
        ("carbs_g", carbs_g),
        ("fat_g", fat_g),
        ("portion_count", portion_count),
    ] {
        if value.is_some_and(|v| v < Decimal::ZERO) {
            return Err(AppError::ValidationFailed(format!(
                "{name} must not be negative"
            )));
        }
    }
    if meal_slot.is_some_and(|slot| !MEAL_SLOTS.contains(&slot)) {
        return Err(AppError::ValidationFailed(format!(
            "meal_slot must be one of: {}",
            MEAL_SLOTS.join(", ")
        )));
    }
    Ok(())
}
