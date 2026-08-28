use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{Session, UpdateUserRequest, User};

// Joins to `users` so the extractor can check email_verified_at on every
// authenticated request without a second round trip.
pub async fn find_auth_context_by_access_token(
    db: &PgPool,
    token_hash: &str,
) -> Result<Option<(Uuid, Option<DateTime<Utc>>)>, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT at.user_id as "user_id: Uuid", u.email_verified_at
           FROM access_tokens at
           JOIN users u ON u.id = at.user_id
           WHERE at.token_hash = $1
             AND at.revoked_at IS NULL
             AND at.expires_at > now()"#,
        token_hash
    )
    .fetch_optional(db)
    .await?;

    Ok(row.map(|r| (r.user_id, r.email_verified_at)))
}

pub async fn find_by_id(db: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
        .fetch_optional(db)
        .await
}

pub async fn update(
    db: &PgPool,
    user_id: Uuid,
    req: &UpdateUserRequest,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        "UPDATE users SET
            target_calories = COALESCE($2, target_calories),
            target_protein_g = COALESCE($3, target_protein_g),
            target_weight_kg = COALESCE($4, target_weight_kg),
            updated_at = now()
         WHERE id = $1
         RETURNING *",
        user_id,
        req.target_calories,
        req.target_protein_g,
        req.target_weight_kg,
    )
    .fetch_one(db)
    .await
}

// Multiple unverified rows can share an email (only verified rows are
// unique), so this can return more than one candidate. Used by login, which
// must still work pre-verification and so can't narrow to the verified row
// alone — callers check the password against each candidate instead of
// trusting a single arbitrarily-chosen match.
pub async fn find_all_by_email(db: &PgPool, email: &str) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
        .fetch_all(db)
        .await
}

// The single verified owner of an email, if one exists — safe to treat as
// unambiguous since verified rows are unique per email by construction
// (users_email_verified_unique). Use this, never find_all_by_email, wherever
// a lookup should only ever see a real, confirmed owner and must ignore any
// unrelated unverified rows squatting on the same email.
pub async fn find_verified_by_email(db: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1 AND email_verified_at IS NOT NULL",
        email
    )
    .fetch_optional(db)
    .await
}

pub async fn find_by_oauth(
    db: &PgPool,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        "SELECT u.*
         FROM users u
         JOIN oauth_accounts oa ON oa.user_id = u.id
         WHERE oa.provider = $1 AND oa.provider_user_id = $2",
        provider,
        provider_user_id
    )
    .fetch_optional(db)
    .await
}

// Links an already-existing user to a new OAuth identity. Only ever called
// with an email that came from the provider's own verified claim, never one
// supplied by the client.
pub async fn link_oauth_account(
    db: &PgPool,
    user_id: Uuid,
    provider: &str,
    provider_user_id: &str,
    email: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email)
         VALUES ($1, $2, $3, $4)",
        user_id,
        provider,
        provider_user_id,
        email,
    )
    .execute(db)
    .await?;
    Ok(())
}

// True if some prior OAuth link recorded this exact email for this user.
// Says nothing about whether that user's email is currently verified — this
// only checks oauth_accounts existence. Callers relying on this to gate
// auto-linking must independently ensure `user_id` refers to a verified row
// (e.g. via find_verified_by_email) before calling; an unverified account's
// oauth_accounts row must never count as grounds to auto-link a different,
// newly-arriving identity onto it, but that precondition is the caller's
// responsibility, not something this function checks.
pub async fn has_oauth_email(db: &PgPool, user_id: Uuid, email: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS(
               SELECT 1 FROM oauth_accounts WHERE user_id = $1 AND email = $2
           ) as "exists!""#,
        user_id,
        email,
    )
    .fetch_one(db)
    .await
}

pub async fn username_exists(db: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM users WHERE username = $1) as "exists!""#,
        username
    )
    .fetch_one(db)
    .await
}

pub async fn find_by_refresh_token(
    db: &PgPool,
    token_hash: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        "SELECT u.*
         FROM users u
         JOIN refresh_tokens rt ON rt.user_id = u.id
         WHERE rt.token_hash = $1
           AND rt.revoked_at IS NULL
           AND rt.expires_at > now()",
        token_hash
    )
    .fetch_optional(db)
    .await
}

pub async fn create(
    db: &PgPool,
    email: &str,
    username: &str,
    display_name: &str,
    password_hash: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        "INSERT INTO users (email, username, display_name, password_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING *",
        email,
        username,
        display_name,
        password_hash,
    )
    .fetch_one(db)
    .await
}

// Creates a new user and links it to an OAuth identity atomically — the two
// inserts must succeed together, or the user would exist with no way to ever
// be found by that identity again on a future sign-in. `email_verified_at`
// is set immediately only when the provider's own claim already asserted the
// email was verified; otherwise the row is created unverified, same as a
// password registration, and needs our own code verification.
pub async fn create_with_oauth(
    db: &PgPool,
    email: &str,
    username: &str,
    display_name: &str,
    provider: &str,
    provider_user_id: &str,
    email_verified_at: Option<DateTime<Utc>>,
) -> Result<User, sqlx::Error> {
    let mut tx = db.begin().await?;

    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (email, username, display_name, email_verified_at)
         VALUES ($1, $2, $3, $4)
         RETURNING *",
        email,
        username,
        display_name,
        email_verified_at,
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email)
         VALUES ($1, $2, $3, $4)",
        user.id,
        provider,
        provider_user_id,
        email,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(user)
}

pub async fn insert_token_pair(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    user_id: Uuid,
    access_token_hash: &str,
    access_expires_at: DateTime<Utc>,
    refresh_token_hash: &str,
    refresh_expires_at: DateTime<Utc>,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "WITH new_access AS (
             INSERT INTO access_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, $3)
             RETURNING id
         )
         INSERT INTO refresh_tokens (user_id, token_hash, expires_at, access_token_id, user_agent)
         VALUES ($1, $4, $5, (SELECT id FROM new_access), $6)",
        user_id,
        access_token_hash,
        access_expires_at,
        refresh_token_hash,
        refresh_expires_at,
        user_agent,
    )
    .execute(executor)
    .await?;
    Ok(())
}

// Revokes an access token and its paired refresh token. Used by logout.
pub async fn revoke_token_pair_by_access_hash(
    db: &PgPool,
    access_token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "WITH revoked AS (
             UPDATE access_tokens SET revoked_at = now()
             WHERE token_hash = $1
             RETURNING id
         )
         UPDATE refresh_tokens SET revoked_at = now()
         WHERE access_token_id = (SELECT id FROM revoked)",
        access_token_hash,
    )
    .execute(db)
    .await?;
    Ok(())
}

// Revokes a refresh token and its paired access token. Used by the refresh flow.
pub async fn revoke_token_pair_by_refresh_hash(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    refresh_token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "WITH revoked AS (
             UPDATE refresh_tokens SET revoked_at = now()
             WHERE token_hash = $1
             RETURNING access_token_id
         )
         UPDATE access_tokens SET revoked_at = now()
         WHERE id = (SELECT access_token_id FROM revoked)",
        refresh_token_hash,
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn list_active_sessions(
    db: &PgPool,
    user_id: Uuid,
    current_access_token_hash: &str,
) -> Result<Vec<Session>, sqlx::Error> {
    sqlx::query_as!(
        Session,
        r#"SELECT rt.id, rt.created_at, rt.expires_at, rt.user_agent,
               (at.token_hash = $2) as "is_current!"
           FROM refresh_tokens rt
           JOIN access_tokens at ON at.id = rt.access_token_id
           WHERE rt.user_id = $1 AND rt.revoked_at IS NULL AND rt.expires_at > now()
           ORDER BY rt.created_at DESC"#,
        user_id,
        current_access_token_hash,
    )
    .fetch_all(db)
    .await
}

// Revokes every session for `user_id` except the one whose access token
// matches `current_access_token_hash` — "log out all other devices," not a
// full logout of the caller too.
pub async fn revoke_other_sessions(
    db: &PgPool,
    user_id: Uuid,
    current_access_token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "WITH revoked_access AS (
             UPDATE access_tokens SET revoked_at = now()
             WHERE user_id = $1 AND token_hash != $2 AND revoked_at IS NULL
             RETURNING id
         )
         UPDATE refresh_tokens SET revoked_at = now()
         WHERE access_token_id IN (SELECT id FROM revoked_access)",
        user_id,
        current_access_token_hash,
    )
    .execute(db)
    .await?;
    Ok(())
}

// A fresh code always resets the attempt counter — a new code deserves a new
// guessing budget, and this is the only place that hands one out.
pub async fn set_verification_code(
    db: &PgPool,
    user_id: Uuid,
    code_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users
         SET email_verification_code_hash = $2,
             email_verification_code_expires_at = $3,
             email_verification_attempts = 0
         WHERE id = $1",
        user_id,
        code_hash,
        expires_at,
    )
    .execute(db)
    .await?;
    Ok(())
}

// Bounds brute-force guessing of a single code — checked by the caller
// against a max before trusting a submitted code, independent of the
// IP-keyed rate limiter, which alone isn't enough here (a token is issued
// unconditionally at registration, so the holder can already call this
// endpoint freely regardless of which IP they're on).
pub async fn increment_verification_attempts(
    db: &PgPool,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET email_verification_attempts = email_verification_attempts + 1
         WHERE id = $1",
        user_id,
    )
    .execute(db)
    .await?;
    Ok(())
}

// Promotes an unverified row to verified in place — used when no other row
// already holds this email as verified.
pub async fn mark_email_verified(db: &PgPool, user_id: Uuid) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        "UPDATE users
         SET email_verified_at = now(),
             email_verification_code_hash = NULL,
             email_verification_code_expires_at = NULL,
             email_verification_attempts = 0
         WHERE id = $1
         RETURNING *",
        user_id,
    )
    .fetch_one(db)
    .await
}

// A different row already holding this email as verified — the target of a
// merge, if one exists, when `user_id` proves ownership of `email`.
pub async fn find_verified_by_email_excluding(
    db: &PgPool,
    email: &str,
    exclude_user_id: Uuid,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1 AND email_verified_at IS NOT NULL AND id != $2",
        email,
        exclude_user_id,
    )
    .fetch_optional(db)
    .await
}

// Called when a hollow (unverified) row proves ownership of an email that a
// different, already-verified row already holds. A hollow row can never have
// accumulated real data — nothing can be done with it pre-verification — so
// there's nothing to reconcile beyond credentials: move its oauth_accounts
// links onto the verified row, backfill a password onto the verified row
// only if it doesn't already have one, then discard the hollow row (its
// tokens cascade-delete with it).
pub async fn merge_hollow_into_verified(
    db: &PgPool,
    hollow_user_id: Uuid,
    target_user_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;

    sqlx::query!(
        "UPDATE oauth_accounts SET user_id = $1 WHERE user_id = $2",
        target_user_id,
        hollow_user_id,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "UPDATE users
         SET password_hash = (SELECT password_hash FROM users WHERE id = $2)
         WHERE id = $1 AND password_hash IS NULL",
        target_user_id,
        hollow_user_id,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!("DELETE FROM users WHERE id = $1", hollow_user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn set_password_reset_token(
    db: &PgPool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users
         SET password_reset_token_hash = $2, password_reset_token_expires_at = $3
         WHERE id = $1",
        user_id,
        token_hash,
        expires_at,
    )
    .execute(db)
    .await?;
    Ok(())
}

// Reverse lookup by token hash — no email needed, since the token alone
// unambiguously identifies the row. Unlike find_by_refresh_token, the only
// caller ever needs the id, so this returns just that rather than
// constructing a full User for a row whose other fields go unused.
pub async fn find_by_password_reset_token(
    db: &PgPool,
    token_hash: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT id as "id: Uuid" FROM users
           WHERE password_reset_token_hash = $1
             AND password_reset_token_expires_at > now()"#,
        token_hash
    )
    .fetch_optional(db)
    .await
}

// Sets a new password and burns the reset token — single-use, since a
// replayed request with the same token no longer matches once this clears it.
pub async fn reset_password(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    user_id: Uuid,
    new_password_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users
         SET password_hash = $2,
             password_reset_token_hash = NULL,
             password_reset_token_expires_at = NULL
         WHERE id = $1",
        user_id,
        new_password_hash,
    )
    .execute(executor)
    .await?;
    Ok(())
}

// Revokes every session for `user_id` unconditionally — unlike
// revoke_other_sessions, there's no "current" session to exempt here, since
// the caller isn't authenticated at all during a password reset. Deliberate:
// a reset should kick out anyone holding the old password, which is often
// exactly the scenario being recovered from. Takes a generic executor so the
// caller can run it in the same transaction as reset_password — if
// revocation failed silently after the password change already committed,
// an old session would survive exactly the reset meant to kill it.
pub async fn revoke_all_sessions(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "WITH revoked_access AS (
             UPDATE access_tokens SET revoked_at = now()
             WHERE user_id = $1 AND revoked_at IS NULL
             RETURNING id
         )
         UPDATE refresh_tokens SET revoked_at = now()
         WHERE access_token_id IN (SELECT id FROM revoked_access)",
        user_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}
