use axum::http::StatusCode;
use axum::{Json, Router, extract::State, routing};
use chrono::{Duration, Utc};
use uuid::Uuid;

use super::extractor::AuthUser;
use super::service;
use crate::domain::user::model::{
    AuthResponse, LoginRequest, RefreshRequest, RegisterRequest, UserResponse,
};
use crate::domain::user::repo;
use crate::error::AppError;
use crate::state::AppState;

const ACCESS_TOKEN_SECS: i64 = 3600; // 1 hour
const REFRESH_TOKEN_SECS: i64 = 365 * 24 * 3600; // 1 year

// Usernames that are blocked from registration. Err on the side of inclusion —
// it is easier to release a reserved username than to reclaim one from a user.
const RESERVED_USERNAMES: &[&str] = &[
    // brand
    "zed",
    "zeddius",
    "zeddiushq",
    "zeddius_official",
    "zeddius_admin",
    "zeddius_support",
    "zeddius_team",
    "zeddius_hq",
    // people
    "henry",
    "julia",
    "norah",
    // admin / system
    "admin",
    "administrator",
    "root",
    "superuser",
    "system",
    "sysadmin",
    "moderator",
    "mod",
    "staff",
    "official",
    "founder",
    "team",
    // auth / account flows
    "login",
    "logout",
    "signup",
    "register",
    "account",
    "accounts",
    "password",
    "onboarding",
    "invite",
    "invited",
    "verify",
    "verification",
    "confirm",
    "username",
    "users",
    "user",
    "me",
    // support / trust & safety
    "support",
    "help",
    "feedback",
    "contact",
    "safety",
    "trust",
    "abuse",
    "report",
    "legal",
    "dmca",
    "privacy",
    "terms",
    // api / infra paths
    "api",
    "v1",
    "v2",
    "v3",
    "health",
    "metrics",
    "status",
    "internal",
    "static",
    "assets",
    "cdn",
    "webhook",
    "webhooks",
    // app sections
    "home",
    "feed",
    "explore",
    "discover",
    "search",
    "settings",
    "profile",
    "app",
    "dashboard",
    "billing",
    "pricing",
    "notes",
    "blog",
    "about",
    "direction",
    "proof",
    "soul",
    // marketing / squatting targets
    "press",
    "media",
    "news",
    "careers",
    "jobs",
    "investor",
    "investors",
    "security",
    "null",
    "undefined",
    "anonymous",
    "everyone",
    "all",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", routing::post(register))
        .route("/auth/login", routing::post(login))
        .route("/auth/refresh", routing::post(refresh))
        .route("/auth/logout", routing::post(logout))
}

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    if body.email.is_empty()
        || body.username.is_empty()
        || body.display_name.is_empty()
        || body.password.is_empty()
    {
        return Err(AppError::ValidationFailed(
            "all fields are required".to_string(),
        ));
    }

    if !is_valid_email(&body.email) {
        return Err(AppError::ValidationFailed(
            "invalid email address".to_string(),
        ));
    }

    if body.password.len() < 8 {
        return Err(AppError::ValidationFailed(
            "password must be at least 8 characters".to_string(),
        ));
    }

    let username_lower = body.username.to_lowercase();
    if RESERVED_USERNAMES.contains(&username_lower.as_str()) {
        return Err(AppError::ValidationFailed(
            "username is reserved".to_string(),
        ));
    }

    let password_hash = service::hash_password(&body.password)?;

    let user = repo::create(
        &state.db,
        &body.email,
        &body.username,
        &body.display_name,
        &password_hash,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err) if db_err.constraint() == Some("users_email_key") => {
            AppError::Conflict("email already registered")
        }
        sqlx::Error::Database(db_err) if db_err.constraint() == Some("users_username_key") => {
            AppError::Conflict("username already taken")
        }
        _ => AppError::from(e),
    })?;

    let (access_token, refresh_token) = issue_token_pair(&state.db, user.id).await?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            access_token,
            refresh_token,
            user: UserResponse::from(user),
        }),
    ))
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let user = repo::find_by_email(&state.db, &body.email)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let hash = user
        .password_hash
        .as_deref()
        .ok_or(AppError::Unauthorized)?;

    if !service::verify_password(&body.password, hash)? {
        return Err(AppError::Unauthorized);
    }

    let (access_token, refresh_token) = issue_token_pair(&state.db, user.id).await?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        user: UserResponse::from(user),
    }))
}

async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let token_hash = service::hash_token(&body.refresh_token);

    let user = repo::find_by_refresh_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let mut tx = state.db.begin().await?;
    repo::revoke_token_pair_by_refresh_hash(&mut *tx, &token_hash).await?;
    let (access_token, refresh_token) = issue_token_pair(&mut *tx, user.id).await?;
    tx.commit().await?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        user: UserResponse::from(user),
    }))
}

async fn logout(State(state): State<AppState>, auth: AuthUser) -> Result<StatusCode, AppError> {
    repo::revoke_token_pair_by_access_hash(&state.db, &auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

// Validates that an email has a local part, an @ symbol, and a domain with at least one dot.
// Intentionally permissive — full RFC 5321 compliance is complex and brittle. True validation
// happens when the user clicks a verification link. A regex crate is deliberately avoided here
// since this check does not warrant the compile-time and runtime overhead.
fn is_valid_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty() && domain.contains('.')
}

async fn issue_token_pair(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(String, String), AppError> {
    let access_token = service::generate_token("zeddius_ac");
    let refresh_token = service::generate_token("zeddius_rf");

    let now = Utc::now();
    let access_expires = now + Duration::seconds(ACCESS_TOKEN_SECS);
    let refresh_expires = now + Duration::seconds(REFRESH_TOKEN_SECS);

    repo::insert_token_pair(
        executor,
        user_id,
        &service::hash_token(&access_token),
        access_expires,
        &service::hash_token(&refresh_token),
        refresh_expires,
    )
    .await?;

    Ok((access_token, refresh_token))
}

#[cfg(test)]
mod tests {
    use super::is_valid_email;

    #[test]
    fn valid_emails_are_accepted() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name+tag@sub.domain.com"));
        assert!(is_valid_email("x@y.z"));
    }

    #[test]
    fn missing_at_is_rejected() {
        assert!(!is_valid_email("notanemail"));
        assert!(!is_valid_email("missingatsign.com"));
    }

    #[test]
    fn missing_local_part_is_rejected() {
        assert!(!is_valid_email("@example.com"));
    }

    #[test]
    fn missing_dot_in_domain_is_rejected() {
        assert!(!is_valid_email("user@localhost"));
        assert!(!is_valid_email("user@nodot"));
    }

    #[test]
    fn empty_string_is_rejected() {
        assert!(!is_valid_email(""));
    }
}
