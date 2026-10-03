use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{Duration as ChronoDuration, Utc};
use std::sync::LazyLock;
use std::time::Duration as StdDuration;
use tokio::time;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::{GovernorError, GovernorLayer};
use tracing::error;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::apple;
use super::email;
use super::extractor::AuthUser;
use super::service;
use super::tokens;
use crate::domain::user::model::{
    AppleAuthRequest, AppleCompleteRequest, AuthResponse, ForgotPasswordRequest, LoginRequest,
    RefreshRequest, RegisterRequest, ResetPasswordRequest, Session, UsernameAvailableResponse,
    VerifyEmailRequest,
};
use crate::domain::user::repo;
use crate::error::{AppError, ErrorResponse};
use crate::extractor::AppJson;
use crate::state::AppState;

const VERIFICATION_TOKEN_TTL_MINS: i64 = 30;
const PASSWORD_RESET_TOKEN_TTL_MINS: i64 = 30;
// Bounds Argon2's cost, which scales with input size.
const MAX_PASSWORD_LEN: usize = 128;
const MIN_PASSWORD_LEN: usize = 8;
const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 30;
const MAX_DISPLAY_NAME_LEN: usize = 50;

const MSG_EMAIL_ALREADY_REGISTERED: &str = "email already registered";
const MSG_USERNAME_ALREADY_TAKEN: &str = "username already taken";
const MSG_USERNAME_RESERVED: &str = "username is reserved";
const MSG_INVALID_EMAIL: &str = "invalid email address";
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

pub fn router() -> OpenApiRouter<AppState> {
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(10)
        .burst_size(8)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("rate limit config is valid");

    let limiter = governor_conf.limiter().clone();
    tokio::spawn(async move {
        let mut interval = time::interval(StdDuration::from_secs(60));
        loop {
            interval.tick().await;
            limiter.retain_recent();
        }
    });

    OpenApiRouter::new()
        .routes(routes!(register))
        .routes(routes!(login))
        .routes(routes!(forgot_password))
        .routes(routes!(reset_password))
        .routes(routes!(refresh))
        .routes(routes!(logout))
        .routes(routes!(list_sessions, revoke_sessions))
        .routes(routes!(verify_email))
        .routes(routes!(resend_verification))
        .routes(routes!(oauth_apple))
        .routes(routes!(oauth_apple_complete))
        .routes(routes!(username_available))
        .layer(GovernorLayer::new(governor_conf).error_handler(rate_limit_error))
}

// The limiter runs as a layer ahead of the handlers, so its errors never reach AppError on their own.
fn rate_limit_error(e: GovernorError) -> Response {
    match e {
        GovernorError::TooManyRequests { wait_time, .. } => AppError::TooManyRequests {
            retry_after_secs: wait_time,
        },
        other => AppError::Internal(anyhow::anyhow!(other)),
    }
    .into_response()
}

#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account created (unverified — a verification link was emailed)", body = AuthResponse),
        (status = 409, description = "Email already registered to a verified account, or username taken", body = ErrorResponse),
        (status = 422, description = "Missing fields, invalid email, password not 8-128 characters, username invalid/reserved, or display name too long", body = ErrorResponse),
    ),
    tag = "auth",
    description = "Create a new account with email and password.",
)]
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<RegisterRequest>,
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
        return Err(AppError::ValidationFailed(MSG_INVALID_EMAIL.to_string()));
    }

    if body.password.len() < MIN_PASSWORD_LEN {
        return Err(AppError::ValidationFailed(password_too_short_message()));
    }

    if body.password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::ValidationFailed(password_too_long_message()));
    }

    let (normalized_username, display_name) =
        validate_username_and_display_name(&body.username, &body.display_name)?;

    let normalized_email = normalize_email(&body.email);
    let password_hash = service::hash_password(&body.password)?;

    let mut tx = state.db.begin().await?;

    repo::lock_email(&mut *tx, &normalized_email).await?;

    // unverified duplicates may coexist, but never alongside a verified owner
    if repo::find_verified_by_email(&mut *tx, &normalized_email)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(MSG_EMAIL_ALREADY_REGISTERED));
    }

    let user = repo::create(
        &mut *tx,
        &normalized_email,
        &normalized_username,
        display_name,
        &password_hash,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err)
            if db_err.constraint() == Some("users_username_lower_key") =>
        {
            AppError::Conflict(MSG_USERNAME_ALREADY_TAKEN)
        }
        _ => AppError::from(e),
    })?;

    tx.commit().await?;

    issue_verification_link(&state, user.id, &user.email).await?;

    Ok((
        StatusCode::CREATED,
        Json(
            tokens::issue_token_pair_and_build_auth_response(
                &state,
                user,
                tokens::user_agent(&headers),
            )
            .await?,
        ),
    ))
}

#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Signed in", body = AuthResponse),
        (status = 401, description = "Wrong email or password", body = ErrorResponse),
        (status = 422, description = "Missing fields, or invalid email address", body = ErrorResponse),
    ),
    tag = "auth",
    description = "Sign in with email and password.",
)]
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    if body.email.is_empty() {
        return Err(AppError::ValidationFailed("email is required".to_string()));
    }

    if !is_valid_email(&body.email) {
        return Err(AppError::ValidationFailed(MSG_INVALID_EMAIL.to_string()));
    }

    if body.password.len() < MIN_PASSWORD_LEN || body.password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::Unauthorized);
    }

    let normalized_email = normalize_email(&body.email);

    let mut user = None;
    let mut checked_a_password = false;
    for candidate in repo::find_all_by_email(&state.db, &normalized_email).await? {
        if let Some(hash) = candidate.password_hash.as_deref() {
            checked_a_password = true;
            if service::verify_password(&body.password, hash)? {
                user = Some(candidate);
                break;
            }
        }
    }
    if !checked_a_password {
        // Burn the same Argon2 cost so "no account" isn't distinguishable from "wrong password" by timing.
        let _ = service::verify_password(&body.password, dummy_password_hash());
    }
    let user = user.ok_or(AppError::Unauthorized)?;

    Ok(Json(
        tokens::issue_token_pair_and_build_auth_response(
            &state,
            user,
            tokens::user_agent(&headers),
        )
        .await?,
    ))
}

#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 204, description = "Always returned regardless of whether the email matches an account — deliberately no enumeration signal. A reset link is emailed only if a matching, verified, password-holding account exists."),
    ),
    tag = "auth",
    description = "Request a password reset link by email.",
)]
async fn forgot_password(
    State(state): State<AppState>,
    AppJson(body): AppJson<ForgotPasswordRequest>,
) -> Result<StatusCode, AppError> {
    let normalized_email = normalize_email(&body.email);
    if let Some(user) = repo::find_verified_by_email(&state.db, &normalized_email).await?
        && user.password_hash.is_some()
    {
        issue_password_reset_token(&state, user.id, &user.email).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/reset-password",
    request_body = ResetPasswordRequest,
    responses(
        (status = 204, description = "Password reset; every session for the account revoked. No tokens issued — log in fresh."),
        (status = 401, description = "Token invalid, expired, or already used", body = ErrorResponse),
        (status = 422, description = "Password not 8-128 characters", body = ErrorResponse),
    ),
    tag = "auth",
    description = "Reset a password using a token from the emailed link.",
)]
async fn reset_password(
    State(state): State<AppState>,
    AppJson(body): AppJson<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    if body.new_password.len() < MIN_PASSWORD_LEN {
        return Err(AppError::ValidationFailed(password_too_short_message()));
    }

    if body.new_password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::ValidationFailed(password_too_long_message()));
    }

    let token_hash = service::hash_token(&body.token);
    let user_id = repo::find_by_password_reset_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let new_password_hash = service::hash_password(&body.new_password)?;

    let mut tx = state.db.begin().await?;
    repo::reset_password(&mut *tx, user_id, &new_password_hash).await?;
    repo::revoke_all_sessions(&mut *tx, user_id).await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "New token pair issued; the old pair is revoked", body = AuthResponse),
        (status = 401, description = "Refresh token invalid, expired, or revoked", body = ErrorResponse),
    ),
    tag = "auth",
    description = "Exchange a refresh token for a new token pair.",
)]
async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<RefreshRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let token_hash = service::hash_token(&body.refresh_token);

    let user = repo::find_by_refresh_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let mut tx = state.db.begin().await?;
    repo::revoke_token_pair_by_refresh_hash(&mut *tx, &token_hash).await?;
    let (access_token, refresh_token) =
        tokens::issue_token_pair(&mut *tx, user.id, tokens::user_agent(&headers)).await?;
    tx.commit().await?;

    Ok(Json(tokens::build_auth_response(
        user,
        access_token,
        refresh_token,
    )))
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    responses(
        (status = 204, description = "Current access + refresh token pair revoked"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth",
    description = "Revoke the caller's current session.",
)]
async fn logout(State(state): State<AppState>, auth: AuthUser) -> Result<StatusCode, AppError> {
    repo::revoke_token_pair_by_access_hash(&state.db, &auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/auth/sessions",
    responses(
        (status = 200, description = "The caller's active token pairs (sessions)", body = Vec<Session>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth",
    description = "List the caller's active sessions.",
)]
async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Session>>, AppError> {
    let sessions = repo::list_active_sessions(&state.db, auth.user_id, &auth.token_hash).await?;
    Ok(Json(sessions))
}

#[utoipa::path(
    delete,
    path = "/auth/sessions",
    responses(
        (status = 204, description = "Every session except the caller's current one revoked — \"log out all other devices\""),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth",
    description = "Log out all other devices, keeping the caller's current session.",
)]
async fn revoke_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    repo::revoke_other_sessions(&state.db, auth.user_id, &auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/verify-email",
    request_body = VerifyEmailRequest,
    responses(
        (status = 204, description = "Email verified"),
        (status = 401, description = "Token invalid or expired", body = ErrorResponse),
        (status = 409, description = "Email already registered to a different, already-verified account — this row was deleted", body = ErrorResponse),
    ),
    tag = "auth",
    description = "Verify an email using a token from the emailed link.",
)]
async fn verify_email(
    State(state): State<AppState>,
    AppJson(body): AppJson<VerifyEmailRequest>,
) -> Result<StatusCode, AppError> {
    let token_hash = service::hash_token(&body.token);
    let user = repo::find_by_verification_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    match repo::mark_email_verified(&state.db, user.id).await {
        Ok(_) => {
            repo::delete_other_unverified_by_email(&state.db, &user.email, user.id).await?;
            Ok(StatusCode::NO_CONTENT)
        }
        // Lost a race condition with another request that verified this same email
        Err(sqlx::Error::Database(db_err))
            if db_err.constraint() == Some("users_email_verified_unique") =>
        {
            repo::delete_unverified_user(&state.db, user.id).await?;
            Err(AppError::Conflict(MSG_EMAIL_ALREADY_REGISTERED))
        }
        Err(e) => Err(AppError::from(e)),
    }
}

#[utoipa::path(
    post,
    path = "/auth/resend-verification",
    responses(
        (status = 204, description = "A fresh verification link was emailed, or this is a no-op because the account is already verified"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth",
    description = "Resend the account's email verification link.",
)]
async fn resend_verification(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    if auth.email_verified_at.is_none() {
        let user = repo::find_by_id(&state.db, auth.user_id)
            .await?
            .ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!(
                    "authenticated user {} not found during verification resend",
                    auth.user_id
                ))
            })?;
        issue_verification_link(&state, user.id, &user.email).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/oauth/apple",
    request_body = AppleAuthRequest,
    responses(
        (status = 200, description = "Identity already linked to a known user, or newly linked to an existing verified account with the same email", body = AuthResponse),
        (status = 204, description = "No account exists yet — client should call /auth/oauth/apple/complete"),
        (status = 401, description = "The identity token itself doesn't verify (bad signature, claims, or missing email)", body = ErrorResponse),
    ),
    tag = "auth",
    description = "Sign in with Apple for an existing user, linking the identity if the email matches a verified account.",
)]
async fn oauth_apple(
    State(state): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<AppleAuthRequest>,
) -> Result<Response, AppError> {
    let (claims, email) =
        verify_apple_identity_with_email(&state, &body.identity_token, body.nonce.as_deref())
            .await?;

    // Idempotency
    if let Some(user) = repo::find_by_oauth(&state.db, "apple", &claims.sub).await? {
        return Ok(Json(
            tokens::issue_token_pair_and_build_auth_response(
                &state,
                user,
                tokens::user_agent(&headers),
            )
            .await?,
        )
        .into_response());
    }

    let user = match repo::find_verified_by_email(&state.db, &email).await? {
        Some(user) if claims.email_verified => user,
        _ => return Ok(StatusCode::NO_CONTENT.into_response()),
    };

    let user =
        match repo::link_oauth_account(&state.db, user.id, "apple", &claims.sub, &email).await {
            Ok(()) => {
                if let Err(e) = email::send_oauth_linked_notice(
                    &state.http_client,
                    &state.config,
                    &user.email,
                    "Apple",
                )
                .await
                {
                    error!(error = %e, user_id = %user.id, "failed to send oauth-linked notice");
                }
                user
            }
            Err(sqlx::Error::Database(db_err))
                if db_err.constraint() == Some("oauth_accounts_provider_provider_user_id_key") =>
            {
                repo::find_by_oauth(&state.db, "apple", &claims.sub)
                    .await?
                    .ok_or_else(|| {
                        AppError::Internal(anyhow::anyhow!(
                            "oauth identity race resolved but no row found for sub {}",
                            claims.sub
                        ))
                    })?
            }
            Err(e) => return Err(AppError::from(e)),
        };

    Ok(Json(
        tokens::issue_token_pair_and_build_auth_response(
            &state,
            user,
            tokens::user_agent(&headers),
        )
        .await?,
    )
    .into_response())
}

// Finishes an Apple sign-in that returned 204
#[utoipa::path(
    post,
    path = "/auth/oauth/apple/complete",
    request_body = AppleCompleteRequest,
    responses(
        (status = 200, description = "Identity was already linked (retried/duplicate call) — logged in", body = AuthResponse),
        (status = 201, description = "New user created and linked to this Apple identity", body = AuthResponse),
        (status = 401, description = "The identity token itself doesn't verify", body = ErrorResponse),
        (status = 409, description = "Email already registered to a verified account, or username taken", body = ErrorResponse),
        (status = 422, description = "Username invalid/reserved, or display name missing/too long", body = ErrorResponse),
    ),
    tag = "auth",
    description = "Finish a Sign in with Apple flow that returned 204, creating a new account linked to the identity.",
)]
async fn oauth_apple_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    AppJson(body): AppJson<AppleCompleteRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    let (claims, email) =
        verify_apple_identity_with_email(&state, &body.identity_token, body.nonce.as_deref())
            .await?;

    // Idempotency
    if let Some(user) = repo::find_by_oauth(&state.db, "apple", &claims.sub).await? {
        let response = tokens::issue_token_pair_and_build_auth_response(
            &state,
            user,
            tokens::user_agent(&headers),
        )
        .await?;
        return Ok((StatusCode::OK, Json(response)));
    }

    let (normalized_username, display_name) =
        validate_username_and_display_name(&body.username, &body.display_name)?;

    // Otherwise starts unverified, same as a password signup.
    let email_verified_at = claims.email_verified.then(Utc::now);

    let mut tx = state.db.begin().await?;

    repo::lock_email(&mut *tx, &email).await?;

    // A verified insert would instead collide atomically on users_email_verified_unique.
    if email_verified_at.is_none()
        && repo::find_verified_by_email(&mut *tx, &email)
            .await?
            .is_some()
    {
        return Err(AppError::Conflict(MSG_EMAIL_ALREADY_REGISTERED));
    }

    let user = match repo::create_with_oauth(
        &mut tx,
        &email,
        &normalized_username,
        display_name,
        "apple",
        &claims.sub,
        email_verified_at,
    )
    .await
    {
        Ok(user) => user,
        // Lost a race condition with another request
        Err(sqlx::Error::Database(db_err))
            if db_err.constraint() == Some("oauth_accounts_provider_provider_user_id_key") =>
        {
            let user = repo::find_by_oauth(&state.db, "apple", &claims.sub)
                .await?
                .ok_or_else(|| {
                    AppError::Internal(anyhow::anyhow!(
                        "oauth identity race resolved but no row found for sub {}",
                        claims.sub
                    ))
                })?;
            let response = tokens::issue_token_pair_and_build_auth_response(
                &state,
                user,
                tokens::user_agent(&headers),
            )
            .await?;
            return Ok((StatusCode::OK, Json(response)));
        }
        Err(sqlx::Error::Database(db_err))
            if db_err.constraint() == Some("users_email_verified_unique") =>
        {
            return Err(AppError::Conflict(MSG_EMAIL_ALREADY_REGISTERED));
        }
        Err(sqlx::Error::Database(db_err))
            if db_err.constraint() == Some("users_username_lower_key") =>
        {
            return Err(AppError::Conflict(MSG_USERNAME_ALREADY_TAKEN));
        }
        Err(e) => return Err(AppError::from(e)),
    };

    tx.commit().await?;

    if email_verified_at.is_none() {
        issue_verification_link(&state, user.id, &user.email).await?;
    } else {
        repo::delete_other_unverified_by_email(&state.db, &user.email, user.id).await?;
    }

    let response = tokens::issue_token_pair_and_build_auth_response(
        &state,
        user,
        tokens::user_agent(&headers),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    get,
    path = "/auth/username/{username}/available",
    params(("username" = String, Path, description = "Username to check")),
    responses(
        (status = 200, description = "Availability check result", body = UsernameAvailableResponse),
    ),
    tag = "auth",
    description = "Check whether a username is valid and available.",
)]
async fn username_available(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<UsernameAvailableResponse>, AppError> {
    let normalized = username.trim().to_lowercase();
    let available = is_valid_username(&normalized)
        && !RESERVED_USERNAMES.contains(&normalized.as_str())
        && !repo::username_exists(&state.db, &normalized).await?;

    Ok(Json(UsernameAvailableResponse { available }))
}

async fn verify_apple_identity_with_email(
    state: &AppState,
    identity_token: &str,
    nonce: Option<&str>,
) -> Result<(apple::AppleClaims, String), AppError> {
    let valid_audiences = [
        state.config.apple_bundle_id.as_str(),
        state.config.apple_services_id.as_str(),
    ];
    let claims =
        apple::verify_identity_token(&state.http_client, identity_token, &valid_audiences, nonce)
            .await
            .map_err(|_| AppError::Unauthorized)?;

    let email = claims.email.clone().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "apple identity token for sub {} missing required email claim",
            claims.sub
        ))
    })?;
    let normalized_email = normalize_email(&email);

    Ok((claims, normalized_email))
}

// A fixed, valid Argon2 hash with no corresponding real password — verifying
// against it costs the same as a real check, purely to normalize login timing.
fn dummy_password_hash() -> &'static str {
    static HASH: LazyLock<String> = LazyLock::new(|| {
        service::hash_password("zeddius-timing-normalization-not-a-real-password")
            .expect("hashing a fixed string cannot fail")
    });
    &HASH
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn is_valid_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty() && domain.contains('.')
}

// Expects an already-trimmed, already-lowercased username.
fn is_valid_username(username: &str) -> bool {
    (MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&username.len())
        && username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn password_too_short_message() -> String {
    format!("password must be at least {MIN_PASSWORD_LEN} characters")
}

fn password_too_long_message() -> String {
    format!("password must be at most {MAX_PASSWORD_LEN} characters")
}

fn invalid_username_message() -> String {
    format!(
        "username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} characters (lowercase letters, numbers, and underscores only)"
    )
}

fn invalid_display_name_message() -> String {
    format!("display name must be 1-{MAX_DISPLAY_NAME_LEN} characters")
}

fn validate_username_and_display_name<'a>(
    username: &str,
    display_name: &'a str,
) -> Result<(String, &'a str), AppError> {
    let normalized_username = username.trim().to_lowercase();
    if !is_valid_username(&normalized_username) {
        return Err(AppError::ValidationFailed(invalid_username_message()));
    }

    if RESERVED_USERNAMES.contains(&normalized_username.as_str()) {
        return Err(AppError::ValidationFailed(
            MSG_USERNAME_RESERVED.to_string(),
        ));
    }

    let display_name = display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > MAX_DISPLAY_NAME_LEN {
        return Err(AppError::ValidationFailed(invalid_display_name_message()));
    }

    Ok((normalized_username, display_name))
}

async fn issue_verification_link(
    state: &AppState,
    user_id: Uuid,
    email: &str,
) -> Result<(), AppError> {
    let token = service::generate_token("zeddius_ev");
    let expires_at = Utc::now() + ChronoDuration::minutes(VERIFICATION_TOKEN_TTL_MINS);

    repo::set_verification_token(&state.db, user_id, &service::hash_token(&token), expires_at)
        .await?;

    let verify_url = format!("{}/verify-email?token={token}", state.config.web_base_url);
    if let Err(e) =
        email::send_verification_link(&state.http_client, &state.config, email, &verify_url).await
    {
        error!(error = %e, user_id = %user_id, "failed to send verification email");
    }

    Ok(())
}

async fn issue_password_reset_token(
    state: &AppState,
    user_id: Uuid,
    email: &str,
) -> Result<(), AppError> {
    let token = service::generate_token("zeddius_pr");
    let expires_at = Utc::now() + ChronoDuration::minutes(PASSWORD_RESET_TOKEN_TTL_MINS);

    repo::set_password_reset_token(&state.db, user_id, &service::hash_token(&token), expires_at)
        .await?;

    let reset_url = format!("{}/reset-password?token={token}", state.config.web_base_url);
    if let Err(e) =
        email::send_password_reset_link(&state.http_client, &state.config, email, &reset_url).await
    {
        error!(error = %e, user_id = %user_id, "failed to send password reset email");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_valid_email, rate_limit_error};
    use axum::body;
    use axum::http::{StatusCode, header::RETRY_AFTER};
    use tower_governor::GovernorError;

    #[tokio::test]
    async fn rate_limit_response_uses_error_shape() {
        let response = rate_limit_error(GovernorError::TooManyRequests {
            wait_time: 7,
            headers: None,
        });

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "7");

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body is readable");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("body is JSON");
        assert_eq!(json["error"]["code"], "TOO_MANY_REQUESTS");
        assert!(json["error"]["message"].is_string());
    }

    #[test]
    fn unextractable_key_is_an_internal_error() {
        let response = rate_limit_error(GovernorError::UnableToExtractKey);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

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
