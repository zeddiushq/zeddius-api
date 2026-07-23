use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing,
};
use chrono::{Duration as ChronoDuration, Utc};
use std::time::Duration as StdDuration;
use tokio::time;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use uuid::Uuid;

use super::apple;
use super::extractor::AuthUser;
use super::service;
use crate::domain::user::model::{
    AppleAuthRequest, AppleCompleteRequest, AppleLinkRequest, AuthResponse, LoginRequest,
    RefreshRequest, RegisterRequest, Session, User, UserResponse, UsernameAvailableResponse,
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
    // Applies to every /auth/* route uniformly rather than tuning per-endpoint
    // limits — login and /oauth/apple/link are the real brute-force targets
    // (they check a submitted password against a known account), but a single
    // conservative limit across the whole router is simpler and still covers
    // them. Keyed by the real client IP (SmartIpKeyExtractor reads standard
    // forwarded headers) since Cloud Run sits behind a load balancer — keying
    // on the raw peer address would key every request on the LB's own IP.
    // In-memory only: state isn't shared across Cloud Run replicas, so the
    // effective limit scales with instance count. Fine at personal scale;
    // would need a shared store (Redis/Memorystore) if that ever matters.
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(10)
        .burst_size(8)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("rate limit config is valid");

    // Prevents the in-memory rate-limit map from growing unbounded over the
    // process's lifetime by periodically dropping entries with no recent activity.
    let limiter = governor_conf.limiter().clone();
    tokio::spawn(async move {
        let mut interval = time::interval(StdDuration::from_secs(60));
        loop {
            interval.tick().await;
            limiter.retain_recent();
        }
    });

    Router::new()
        .route("/auth/register", routing::post(register))
        .route("/auth/login", routing::post(login))
        .route("/auth/refresh", routing::post(refresh))
        .route("/auth/logout", routing::post(logout))
        .route(
            "/auth/sessions",
            routing::get(list_sessions).delete(revoke_sessions),
        )
        .route("/auth/oauth/apple", routing::post(oauth_apple))
        .route(
            "/auth/oauth/apple/complete",
            routing::post(oauth_apple_complete),
        )
        .route("/auth/oauth/apple/link", routing::post(oauth_apple_link))
        .route(
            "/auth/username/{username}/available",
            routing::get(username_available),
        )
        .layer(GovernorLayer::new(governor_conf))
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
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

    Ok((
        StatusCode::CREATED,
        Json(issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers)).await?),
    ))
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
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

    Ok(Json(
        issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers)).await?,
    ))
}

async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let token_hash = service::hash_token(&body.refresh_token);

    let user = repo::find_by_refresh_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let mut tx = state.db.begin().await?;
    repo::revoke_token_pair_by_refresh_hash(&mut *tx, &token_hash).await?;
    let (access_token, refresh_token) =
        issue_token_pair(&mut *tx, user.id, user_agent(&headers)).await?;
    tx.commit().await?;

    Ok(Json(build_auth_response(user, access_token, refresh_token)))
}

async fn logout(State(state): State<AppState>, auth: AuthUser) -> Result<StatusCode, AppError> {
    repo::revoke_token_pair_by_access_hash(&state.db, &auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Session>>, AppError> {
    let sessions = repo::list_active_sessions(&state.db, auth.user_id, &auth.token_hash).await?;
    Ok(Json(sessions))
}

// Revokes every other session — the caller's own session (the one making
// this request) stays logged in. Full logout-everywhere isn't this endpoint;
// it's just calling /auth/logout on each session individually.
async fn revoke_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    repo::revoke_other_sessions(&state.db, auth.user_id, &auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

// 401 if the identity token itself doesn't check out. Otherwise 204 (no
// linked account yet — go onboard), 409 (an account with this email exists
// but only a password backs it — prove that via /auth/oauth/apple/link),
// or 200 with a token pair (known user), distinguished by status code alone
// so the client never has to inspect the body to know which case it's in.
async fn oauth_apple(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppleAuthRequest>,
) -> Result<Response, AppError> {
    let (claims, email) = verify_apple_identity_with_email(&state, &body.identity_token).await?;

    if let Some(user) = repo::find_by_oauth(&state.db, "apple", &claims.sub).await? {
        return Ok(Json(
            issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers)).await?,
        )
        .into_response());
    }

    // No oauth_accounts row for this sub yet. If the email matches an
    // existing user, resolve based on how that account was established.
    if let Some(user) = repo::find_by_email(&state.db, &email).await? {
        if user.password_hash.is_some() {
            // Only a self-typed password backs this account — a matching
            // email claim alone doesn't prove the caller controls it.
            return Err(AppError::Conflict(
                "an account with this email already exists",
            ));
        }

        if repo::has_verified_oauth_email(&state.db, user.id, &user.email).await? {
            repo::link_oauth_account(&state.db, user.id, "apple", &claims.sub, &email).await?;
            return Ok(Json(
                issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers))
                    .await?,
            )
            .into_response());
        }

        tracing::error!(
            user_id = %user.id,
            "passwordless user has no matching oauth_accounts row — refusing to auto-link"
        );
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

// Finishes an Apple sign-in that returned 204: creates the user record and
// links the oauth_accounts row. Authenticated by the identity token itself
// (re-verified here), not a Bearer access token — none exists yet, since no
// user record exists yet. `register` never calls this; it creates its row
// directly in one step.
async fn oauth_apple_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppleCompleteRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    let (claims, email) = verify_apple_identity_with_email(&state, &body.identity_token).await?;

    // Idempotency: a retried/duplicate completion call for an identity that's
    // already linked logs the user in instead of trying to recreate them.
    if let Some(user) = repo::find_by_oauth(&state.db, "apple", &claims.sub).await? {
        let response =
            issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers)).await?;
        return Ok((StatusCode::OK, Json(response)));
    }

    if body.username.is_empty() || body.display_name.is_empty() {
        return Err(AppError::ValidationFailed(
            "all fields are required".to_string(),
        ));
    }

    let username_lower = body.username.to_lowercase();
    if RESERVED_USERNAMES.contains(&username_lower.as_str()) {
        return Err(AppError::ValidationFailed(
            "username is reserved".to_string(),
        ));
    }

    let user = repo::create_with_oauth(
        &state.db,
        &email,
        &body.username,
        &body.display_name,
        "apple",
        &claims.sub,
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

    let response =
        issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers)).await?;

    Ok((StatusCode::CREATED, Json(response)))
}

// Resolves a 409 from /auth/oauth/apple: proves the caller controls the
// existing password-holding account before linking this Apple identity to it.
async fn oauth_apple_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppleLinkRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let (claims, email) = verify_apple_identity_with_email(&state, &body.identity_token).await?;

    // Idempotency: a retried link call for an identity that's already linked
    // just logs the user in instead of re-checking the password.
    if let Some(user) = repo::find_by_oauth(&state.db, "apple", &claims.sub).await? {
        return Ok(Json(
            issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers)).await?,
        ));
    }

    let user = repo::find_by_email(&state.db, &email)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let hash = user
        .password_hash
        .as_deref()
        .ok_or(AppError::Unauthorized)?;

    if !service::verify_password(&body.password, hash)? {
        return Err(AppError::Unauthorized);
    }

    repo::link_oauth_account(&state.db, user.id, "apple", &claims.sub, &email).await?;

    Ok(Json(
        issue_token_pair_and_build_auth_response(&state, user, user_agent(&headers)).await?,
    ))
}

async fn username_available(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<UsernameAvailableResponse>, AppError> {
    let username_lower = username.to_lowercase();
    let available = if RESERVED_USERNAMES.contains(&username_lower.as_str()) {
        false
    } else {
        !repo::username_exists(&state.db, &username).await?
    };

    Ok(Json(UsernameAvailableResponse { available }))
}

// Verifies an Apple identity token and requires it to carry an email claim —
// there is no fallback for a token that lacks one.
async fn verify_apple_identity_with_email(
    state: &AppState,
    identity_token: &str,
) -> Result<(apple::AppleClaims, String), AppError> {
    let valid_audiences = [
        state.config.apple_bundle_id.as_str(),
        state.config.apple_services_id.as_str(),
    ];
    let claims = apple::verify_identity_token(identity_token, &valid_audiences)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "apple identity token verification failed");
            AppError::Unauthorized
        })?;

    let email = claims.email.clone().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "apple identity token for sub {} missing required email claim",
            claims.sub
        ))
    })?;

    Ok((claims, email))
}

// Checks basic shape only — local part, @, a dot in the domain. Not a
// substitute for actually confirming the address is reachable.
fn is_valid_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty() && domain.contains('.')
}

fn user_agent(headers: &HeaderMap) -> Option<&str> {
    headers.get(axum::http::header::USER_AGENT)?.to_str().ok()
}

// Pure assembly — no I/O, reusable regardless of how the tokens were issued
// (plain pool or inside a transaction).
fn build_auth_response(user: User, access_token: String, refresh_token: String) -> AuthResponse {
    AuthResponse {
        access_token,
        refresh_token,
        user: UserResponse::from(user),
    }
}

async fn issue_token_pair(
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
    .await?;

    Ok((access_token, refresh_token))
}

// Issues a fresh token pair against the plain pool and builds the response.
// Covers every path except `refresh`, which needs the transactional executor.
async fn issue_token_pair_and_build_auth_response(
    state: &AppState,
    user: User,
    user_agent: Option<&str>,
) -> Result<AuthResponse, AppError> {
    let (access_token, refresh_token) = issue_token_pair(&state.db, user.id, user_agent).await?;
    Ok(build_auth_response(user, access_token, refresh_token))
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
