use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::service;
use crate::domain::user::repo;
use crate::error::AppError;
use crate::state::AppState;

// Proves identity only, not permission — see VerifiedUser below.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub token_hash: String,
    pub email_verified_at: Option<DateTime<Utc>>,
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

        let (user_id, email_verified_at) =
            repo::find_auth_context_by_access_token(&state.db, &token_hash)
                .await
                .map_err(AppError::from)?
                .ok_or(AppError::Unauthorized)?;

        Ok(AuthUser {
            user_id,
            token_hash,
            email_verified_at,
        })
    }
}

// Requires a verified email; using this extractor instead of AuthUser makes the compiler enforce it.
#[derive(Clone, Debug)]
pub struct VerifiedUser(pub AuthUser);

impl std::ops::Deref for VerifiedUser {
    type Target = AuthUser;

    fn deref(&self) -> &AuthUser {
        &self.0
    }
}

impl FromRequestParts<AppState> for VerifiedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        if auth.email_verified_at.is_none() {
            return Err(AppError::Forbidden);
        }
        Ok(VerifiedUser(auth))
    }
}
