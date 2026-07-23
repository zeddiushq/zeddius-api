use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::{Session, User};

pub async fn find_id_by_access_token(
    db: &PgPool,
    token_hash: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT user_id as "user_id: Uuid"
           FROM access_tokens
           WHERE token_hash = $1
             AND revoked_at IS NULL
             AND expires_at > now()"#,
        token_hash
    )
    .fetch_optional(db)
    .await
}

pub async fn find_by_id(db: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
        .fetch_optional(db)
        .await
}

pub async fn find_by_email(db: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
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
pub async fn has_verified_oauth_email(
    db: &PgPool,
    user_id: Uuid,
    email: &str,
) -> Result<bool, sqlx::Error> {
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
// be found by that identity again on a future sign-in.
pub async fn create_with_oauth(
    db: &PgPool,
    email: &str,
    username: &str,
    display_name: &str,
    provider: &str,
    provider_user_id: &str,
) -> Result<User, sqlx::Error> {
    let mut tx = db.begin().await?;

    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (email, username, display_name)
         VALUES ($1, $2, $3)
         RETURNING *",
        email,
        username,
        display_name,
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
