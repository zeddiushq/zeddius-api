use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use uuid::Uuid;

use super::service;
use crate::domain::user::repo;
use crate::error::AppError;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub token_hash: String,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        let token_hash = service::hash_token(token);

        let user_id = repo::find_id_by_access_token(&state.db, &token_hash)
            .await
            .map_err(AppError::from)?
            .ok_or(AppError::Unauthorized)?;

        Ok(AuthUser {
            user_id,
            token_hash,
        })
    }
}
