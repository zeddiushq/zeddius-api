use axum::http::HeaderMap;
use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

use super::service;
use crate::domain::user::model::{AuthResponse, User, UserResponse};
use crate::domain::user::repo;
use crate::error::AppError;
use crate::state::AppState;

const ACCESS_TOKEN_SECS: i64 = 3600; // 1 hour
const REFRESH_TOKEN_SECS: i64 = 365 * 24 * 3600; // 1 year

pub fn user_agent(headers: &HeaderMap) -> Option<&str> {
    headers.get(axum::http::header::USER_AGENT)?.to_str().ok()
}

pub fn build_auth_response(
    user: User,
    access_token: String,
    refresh_token: String,
) -> AuthResponse {
    AuthResponse {
        access_token,
        refresh_token,
        expires_in: ACCESS_TOKEN_SECS,
        refresh_expires_in: REFRESH_TOKEN_SECS,
        user: UserResponse::from(user),
    }
}

pub async fn issue_token_pair(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    user_id: Uuid,
    user_agent: Option<&str>,
) -> Result<(String, String), AppError> {
    let access_token = service::generate_token("zeddius_ac");
    let refresh_token = service::generate_token("zeddius_rf");

    let now = Utc::now();
    let access_expires = now + ChronoDuration::seconds(ACCESS_TOKEN_SECS);
    let refresh_expires = now + ChronoDuration::seconds(REFRESH_TOKEN_SECS);

    repo::insert_token_pair(
        executor,
        user_id,
        &service::hash_token(&access_token),
        access_expires,
        &service::hash_token(&refresh_token),
        refresh_expires,
        user_agent,
    )
    .await
    .map_err(|e| match &e {
        // user row deleted between lookup and token issuance
        sqlx::Error::Database(db_err)
            if db_err.constraint() == Some("access_tokens_user_id_fkey") =>
        {
            AppError::Unauthorized
        }
        _ => AppError::from(e),
    })?;

    Ok((access_token, refresh_token))
}

// `refresh` needs a transactional executor and calls issue_token_pair directly instead.
pub async fn issue_token_pair_and_build_auth_response(
    state: &AppState,
    user: User,
    user_agent: Option<&str>,
) -> Result<AuthResponse, AppError> {
    let (access_token, refresh_token) = issue_token_pair(&state.db, user.id, user_agent).await?;
    Ok(build_auth_response(user, access_token, refresh_token))
}
