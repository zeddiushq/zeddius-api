use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::model::User;

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

pub async fn insert_token_pair(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    user_id: Uuid,
    access_token_hash: &str,
    access_expires_at: DateTime<Utc>,
    refresh_token_hash: &str,
    refresh_expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "WITH new_access AS (
             INSERT INTO access_tokens (user_id, token_hash, expires_at)
             VALUES ($1, $2, $3)
             RETURNING id
         )
         INSERT INTO refresh_tokens (user_id, token_hash, expires_at, access_token_id)
         VALUES ($1, $4, $5, (SELECT id FROM new_access))",
        user_id,
        access_token_hash,
        access_expires_at,
        refresh_token_hash,
        refresh_expires_at,
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
