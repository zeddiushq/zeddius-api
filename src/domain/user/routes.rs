use axum::{Json, Router, extract::State, routing};

use super::model::UserResponse;
use super::repo;
use crate::auth::extractor::AuthUser;
use crate::error::AppError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/users/me", routing::get(me))
}

async fn me(State(state): State<AppState>, auth: AuthUser) -> Result<Json<UserResponse>, AppError> {
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
