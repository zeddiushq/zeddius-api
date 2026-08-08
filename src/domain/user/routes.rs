use axum::{Json, extract::State};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::model::UserResponse;
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(me))
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
