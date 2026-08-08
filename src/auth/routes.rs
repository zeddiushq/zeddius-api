use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{Duration as ChronoDuration, Utc};
use std::time::Duration as StdDuration;
use tokio::time;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tracing::{error, warn};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use super::apple;
use super::email;
use super::extractor::AuthUser;
use super::service;
use super::tokens;
use crate::domain::user::model::{
    AppleAuthRequest, AppleCompleteRequest, AppleLinkRequest, AuthResponse, ForgotPasswordRequest,
    LoginRequest, RefreshRequest, RegisterRequest, ResetPasswordRequest, Session,
    UsernameAvailableResponse, VerifyEmailRequest,
};
use crate::domain::user::repo;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

const VERIFICATION_CODE_TTL_MINS: i64 = 15;
const PASSWORD_RESET_TOKEN_TTL_MINS: i64 = 30;
// A code is burned after this many wrong guesses, regardless of whether it's
// still within its TTL — the real defense against brute-forcing a 6-digit
// code, since the IP-keyed rate limiter alone isn't tied to any one code.
const MAX_VERIFICATION_ATTEMPTS: i32 = 5;
// Bounds Argon2's cost, which scales with input size — without this, a
// submitted password of unbounded length is a cheap way to burn CPU on
// every hash/verify call.
const MAX_PASSWORD_LEN: usize = 128;

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

pub fn router() -> OpenApiRouter<AppState> {
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
        .routes(routes!(oauth_apple_link))
        .routes(routes!(username_available))
        .layer(GovernorLayer::new(governor_conf))
}

#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account created (unverified — a verification code was emailed)", body = AuthResponse),
        (status = 409, description = "Email already registered to a verified account, or username taken", body = ErrorResponse),
        (status = 422, description = "Missing fields, invalid email, or password not 8-128 characters", body = ErrorResponse),
    ),
    tag = "auth",
)]
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

    if body.password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::ValidationFailed(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }

    let username_lower = body.username.to_lowercase();
    if RESERVED_USERNAMES.contains(&username_lower.as_str()) {
        return Err(AppError::ValidationFailed(
            "username is reserved".to_string(),
        ));
    }

    // Unverified duplicates under the same email are allowed to coexist (the
    // partial unique index only applies to verified rows) — but once a real
    // owner has actually verified this email, further unverified attempts
    // against it are refused outright rather than silently sending them
    // another code. Whoever holds the verified row necessarily proved
    // ownership to get there, so this can never be the same lockout bug
    // email verification was built to fix; it only caps how many times an
    // unrelated caller can make this address's real owner receive an email.
    if repo::find_verified_by_email(&state.db, &body.email)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("email already registered"));
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
        sqlx::Error::Database(db_err) if db_err.constraint() == Some("users_username_key") => {
            AppError::Conflict("username already taken")
        }
        _ => AppError::from(e),
    })?;

    issue_verification_code(&state, user.id, &user.email).await?;

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
    ),
    tag = "auth",
)]
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    // Rejected the same way as a wrong password (not a distinct validation
    // error) — this is a credential check, and the failure reason shouldn't
    // be distinguishable from "wrong password" to the caller. Bails before
    // ever calling Argon2, which is the actual point: an unbounded password
    // is a cheap way to burn CPU on every candidate checked below.
    if body.password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::Unauthorized);
    }

    // Login must still work pre-verification, so this can't narrow to the
    // single verified owner the way oauth_apple's fallback match does — more
    // than one unverified row can share this email, each with its own
    // password, so the submitted password is checked against every
    // candidate rather than trusting an arbitrarily-chosen single match.
    let mut user = None;
    for candidate in repo::find_all_by_email(&state.db, &body.email).await? {
        if let Some(hash) = candidate.password_hash.as_deref()
            && service::verify_password(&body.password, hash)?
        {
            user = Some(candidate);
            break;
        }
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

// Always 204, regardless of whether the email matches a verified account —
// this is the one place in the app deliberately choosing not to signal
// anything back to the caller, since there's no legitimate UX reason a
// forgot-password form needs to know whether an email is registered.
#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 204, description = "Always returned regardless of whether the email matches an account — deliberately no enumeration signal. A reset link is emailed only if a matching, verified, password-holding account exists."),
    ),
    tag = "auth",
)]
async fn forgot_password(
    State(state): State<AppState>,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<StatusCode, AppError> {
    if let Some(user) = repo::find_verified_by_email(&state.db, &body.email).await?
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
)]
async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    if body.new_password.len() < 8 {
        return Err(AppError::ValidationFailed(
            "password must be at least 8 characters".to_string(),
        ));
    }

    if body.new_password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::ValidationFailed(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }

    let token_hash = service::hash_token(&body.token);
    let user_id = repo::find_by_password_reset_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let new_password_hash = service::hash_password(&body.new_password)?;

    // Same transaction: if revocation failed after the password change alone
    // committed, the reset token would already be burned (no clean retry)
    // while an old session — often exactly what's being recovered from —
    // would silently survive the reset meant to kill it.
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
)]
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
)]
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
#[utoipa::path(
    delete,
    path = "/auth/sessions",
    responses(
        (status = 204, description = "Every session except the caller's current one revoked — \"log out all other devices\""),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth",
)]
async fn revoke_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    repo::revoke_other_sessions(&state.db, auth.user_id, &auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

// Confirms a code sent by /auth/register, /auth/oauth/apple/complete, or
// /auth/resend-verification. If a different, already-verified account holds
// this same email, this proves ownership arrived after that account already
// won it — merge onto that account instead of promoting this one, since a
// still-unverified row can never have accumulated real data of its own.
#[utoipa::path(
    post,
    path = "/auth/verify-email",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified; fresh token pair issued. Merges into an existing verified account under the same email if one exists.", body = AuthResponse),
        (status = 401, description = "Missing/invalid access token, no code pending, code wrong or expired, or the 5-attempt limit was burned", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth",
)]
async fn verify_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: AuthUser,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let user = repo::find_by_id(&state.db, auth.user_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "authenticated user {} not found during email verification",
                auth.user_id
            ))
        })?;

    let code_hash = user
        .email_verification_code_hash
        .as_deref()
        .ok_or(AppError::Unauthorized)?;
    let expires_at = user
        .email_verification_code_expires_at
        .ok_or(AppError::Unauthorized)?;

    // Independent of the IP-keyed rate limiter, which alone isn't enough
    // here — a token is issued unconditionally at registration, so its
    // holder can already call this endpoint freely regardless of which IP
    // they're on. Once burned, only a fresh code (via resend-verification,
    // which resets this counter) can be attempted again.
    if user.email_verification_attempts >= MAX_VERIFICATION_ATTEMPTS {
        return Err(AppError::Unauthorized);
    }

    if service::hash_token(&body.code) != code_hash || expires_at < Utc::now() {
        repo::increment_verification_attempts(&state.db, user.id).await?;
        return Err(AppError::Unauthorized);
    }

    if let Some(existing) =
        repo::find_verified_by_email_excluding(&state.db, &user.email, user.id).await?
    {
        repo::merge_hollow_into_verified(&state.db, user.id, existing.id).await?;
        return Ok(Json(
            tokens::issue_token_pair_and_build_auth_response(
                &state,
                existing,
                tokens::user_agent(&headers),
            )
            .await?,
        ));
    }

    let verified_user = repo::mark_email_verified(&state.db, user.id).await?;
    Ok(Json(
        tokens::issue_token_pair_and_build_auth_response(
            &state,
            verified_user,
            tokens::user_agent(&headers),
        )
        .await?,
    ))
}

// No-op (still 204) if the caller is already verified — nothing to resend.
#[utoipa::path(
    post,
    path = "/auth/resend-verification",
    responses(
        (status = 204, description = "A fresh code was emailed (attempt counter reset), or this is a no-op because the account is already verified"),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth",
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
        issue_verification_code(&state, user.id, &user.email).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

// 401 if the identity token itself doesn't check out. Otherwise 204 (no
// linked account yet — go onboard), 409 (an account with this email exists
// but only a password backs it — prove that via /auth/oauth/apple/link),
// or 200 with a token pair (known user), distinguished by status code alone
// so the client never has to inspect the body to know which case it's in.
#[utoipa::path(
    post,
    path = "/auth/oauth/apple",
    request_body = AppleAuthRequest,
    responses(
        (status = 200, description = "Identity already linked to a known user", body = AuthResponse),
        (status = 204, description = "No account exists yet — client should call /auth/oauth/apple/complete"),
        (status = 401, description = "The identity token itself doesn't verify (bad signature, claims, or missing email)", body = ErrorResponse),
        (status = 409, description = "The email matches an existing account that has a password — prove it via /auth/oauth/apple/link", body = ErrorResponse),
    ),
    tag = "auth",
)]
async fn oauth_apple(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppleAuthRequest>,
) -> Result<Response, AppError> {
    let (claims, email) = verify_apple_identity_with_email(&state, &body.identity_token).await?;

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

    // No oauth_accounts row for this sub yet. If the email matches an
    // existing *verified* user, resolve based on how that account was
    // established. Scoped to the verified owner only — an unrelated,
    // never-verified row squatting on this same email must never be able to
    // trigger a 409 or influence auto-linking; it isn't a real conflict.
    let Some(user) = repo::find_verified_by_email(&state.db, &email).await? else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };

    if user.password_hash.is_some() {
        // Only a self-typed password backs this account — a matching
        // email claim alone doesn't prove the caller controls it.
        return Err(AppError::Conflict(
            "an account with this email already exists",
        ));
    }

    // Only a provider-verified email can grant access to an existing
    // account with no independent proof (no password to fall back on).
    // An unverified claim is treated as if no match were found at all —
    // not an error, just not enough to trust here.
    if !claims.email_verified {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    if repo::has_oauth_email(&state.db, user.id, &user.email).await? {
        repo::link_oauth_account(&state.db, user.id, "apple", &claims.sub, &email).await?;
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

    // An account matching this shape (passwordless + verified) should
    // always have a corresponding oauth_accounts row from whichever
    // provider created/verified it — reaching here means that invariant
    // was somehow violated. Refuse to auto-link rather than trust it.
    error!(
        user_id = %user.id,
        "passwordless user has no matching oauth_accounts row — refusing to auto-link"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Finishes an Apple sign-in that returned 204: creates the user record and
// links the oauth_accounts row. Authenticated by the identity token itself
// (re-verified here), not a Bearer access token — none exists yet, since no
// user record exists yet. `register` never calls this; it creates its row
// directly in one step.
#[utoipa::path(
    post,
    path = "/auth/oauth/apple/complete",
    request_body = AppleCompleteRequest,
    responses(
        (status = 200, description = "Identity was already linked (retried/duplicate call) — logged in", body = AuthResponse),
        (status = 201, description = "New user created and linked to this Apple identity", body = AuthResponse),
        (status = 401, description = "The identity token itself doesn't verify", body = ErrorResponse),
        (status = 409, description = "Email already registered to a verified account, or username taken", body = ErrorResponse),
        (status = 422, description = "Missing username/display_name, or username reserved", body = ErrorResponse),
    ),
    tag = "auth",
)]
async fn oauth_apple_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppleCompleteRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    let (claims, email) = verify_apple_identity_with_email(&state, &body.identity_token).await?;

    // Idempotency: a retried/duplicate completion call for an identity that's
    // already linked logs the user in instead of trying to recreate them.
    if let Some(user) = repo::find_by_oauth(&state.db, "apple", &claims.sub).await? {
        let response = tokens::issue_token_pair_and_build_auth_response(
            &state,
            user,
            tokens::user_agent(&headers),
        )
        .await?;
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

    // Trust the provider's own claim immediately if it asserted verification;
    // otherwise this account starts unverified, same as a password signup,
    // and needs our own code before it can win a contested email.
    let email_verified_at = claims.email_verified.then(Utc::now);

    let user = repo::create_with_oauth(
        &state.db,
        &email,
        &body.username,
        &body.display_name,
        "apple",
        &claims.sub,
        email_verified_at,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err)
            if db_err.constraint() == Some("users_email_verified_unique") =>
        {
            AppError::Conflict("email already registered")
        }
        sqlx::Error::Database(db_err) if db_err.constraint() == Some("users_username_key") => {
            AppError::Conflict("username already taken")
        }
        _ => AppError::from(e),
    })?;

    if email_verified_at.is_none() {
        issue_verification_code(&state, user.id, &user.email).await?;
    }

    let response = tokens::issue_token_pair_and_build_auth_response(
        &state,
        user,
        tokens::user_agent(&headers),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(response)))
}

// Resolves a 409 from /auth/oauth/apple: proves the caller controls the
// existing password-holding account before linking this Apple identity to it.
#[utoipa::path(
    post,
    path = "/auth/oauth/apple/link",
    request_body = AppleLinkRequest,
    responses(
        (status = 200, description = "Password verified; Apple identity linked to the existing account (or was already linked)", body = AuthResponse),
        (status = 401, description = "The identity token doesn't verify, or the password is wrong", body = ErrorResponse),
    ),
    tag = "auth",
)]
async fn oauth_apple_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppleLinkRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let (claims, email) = verify_apple_identity_with_email(&state, &body.identity_token).await?;

    // Same reasoning as login: rejected identically to a wrong password, and
    // bails before ever calling Argon2.
    if body.password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::Unauthorized);
    }

    // Idempotency: a retried link call for an identity that's already linked
    // just logs the user in instead of re-checking the password.
    if let Some(user) = repo::find_by_oauth(&state.db, "apple", &claims.sub).await? {
        return Ok(Json(
            tokens::issue_token_pair_and_build_auth_response(
                &state,
                user,
                tokens::user_agent(&headers),
            )
            .await?,
        ));
    }

    // Scoped to the verified owner, same reasoning as oauth_apple's fallback
    // match — this is resolving that endpoint's 409, which is only ever
    // raised against a verified account, so this lookup should agree.
    let user = repo::find_verified_by_email(&state.db, &email)
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
        tokens::issue_token_pair_and_build_auth_response(
            &state,
            user,
            tokens::user_agent(&headers),
        )
        .await?,
    ))
}

#[utoipa::path(
    get,
    path = "/auth/username/{username}/available",
    params(("username" = String, Path, description = "Username to check")),
    responses(
        (status = 200, description = "Availability check result", body = UsernameAvailableResponse),
    ),
    tag = "auth",
)]
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
    let claims = apple::verify_identity_token(&state.http_client, identity_token, &valid_audiences)
        .await
        .map_err(|e| {
            warn!(error = %e, "apple identity token verification failed");
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

// Generates a code, stores its hash, and emails it. A send failure is logged
// and swallowed rather than failing the caller's request — the code is
// already stored, so /auth/resend-verification can recover from it.
async fn issue_verification_code(
    state: &AppState,
    user_id: Uuid,
    email: &str,
) -> Result<(), AppError> {
    let code = service::generate_verification_code();
    let expires_at = Utc::now() + ChronoDuration::minutes(VERIFICATION_CODE_TTL_MINS);

    repo::set_verification_code(&state.db, user_id, &service::hash_token(&code), expires_at)
        .await?;

    if let Err(e) =
        email::send_verification_code(&state.http_client, &state.config, email, &code).await
    {
        error!(error = %e, user_id = %user_id, "failed to send verification email");
    }

    Ok(())
}

// Generates a full-entropy token (not a short code — this is clicked from a
// link, never manually typed back), stores its hash, and emails a reset
// link. Same log-and-swallow behavior on a Resend failure as verification
// codes: the token is already stored, so a repeat /auth/forgot-password
// call recovers from a failed send.
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
