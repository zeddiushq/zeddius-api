use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use uuid::Uuid;

use super::service;
use crate::error::AppError;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
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

        let user_id = sqlx::query_scalar!(
            r#"SELECT user_id as "user_id: Uuid"
               FROM access_tokens
               WHERE token_hash = $1
                 AND revoked_at IS NULL
                 AND expires_at > now()"#,
            token_hash
        )
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

        Ok(AuthUser { user_id })
    }
}
