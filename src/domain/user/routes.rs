use axum::{Json, extract::State};
use rust_decimal::Decimal;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::model::{UpdateUserRequest, UserResponse};
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(me, update))
}

#[utoipa::path(
    get,
    path = "/users/me",
    responses(
        (status = 200, description = "The authenticated user, with targets and settings", body = UserResponse),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "user",
)]
async fn me(
    State(state): State<AppState>,
    auth: VerifiedUser,
) -> Result<Json<UserResponse>, AppError> {
    let user = repo::find_by_id(&state.db, auth.user_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "user {} not found despite valid access token — cascade delete may have failed",
                auth.user_id
            ))
        })?;
    Ok(Json(UserResponse::from(user)))
}

#[utoipa::path(
    patch,
    path = "/users/me",
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "Profile updated. Omitted fields are left unchanged.", body = UserResponse),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
        (status = 422, description = "target_calories/target_protein_g/target_weight_kg must be positive", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "user",
)]
async fn update(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    if req.target_calories.is_some_and(|v| v <= 0) {
        return Err(AppError::ValidationFailed(
            "target_calories must be positive".into(),
        ));
    }
    if req.target_protein_g.is_some_and(|v| v <= 0) {
        return Err(AppError::ValidationFailed(
            "target_protein_g must be positive".into(),
        ));
    }
    if req.target_weight_kg.is_some_and(|v| v <= Decimal::ZERO) {
        return Err(AppError::ValidationFailed(
            "target_weight_kg must be positive".into(),
        ));
    }
    let user = repo::update(&state.db, auth.user_id, &req).await?;
    Ok(Json(UserResponse::from(user)))
}
