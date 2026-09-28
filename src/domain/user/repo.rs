use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::model::{Session, UpdateUserRequest, User};

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
            target_wake_time = COALESCE($5, target_wake_time),
            target_bed_time = COALESCE($6, target_bed_time),
            target_weekly_runs = COALESCE($7, target_weekly_runs),
            target_weekly_lifts = COALESCE($8, target_weekly_lifts),
            updated_at = now()
         WHERE id = $1
         RETURNING *",
        user_id,
        req.target_calories,
        req.target_protein_g,
        req.target_weight_kg,
        req.target_wake_time,
        req.target_bed_time,
        req.target_weekly_runs,
        req.target_weekly_lifts,
    )
    .fetch_one(db)
    .await
}

pub async fn find_all_by_email(db: &PgPool, email: &str) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
        .fetch_all(db)
        .await
}

pub async fn find_verified_by_email(
    db: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = $1 AND email_verified_at IS NOT NULL",
        email
    )
    .fetch_optional(db)
    .await
}

pub async fn lock_email(
    db: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    email: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", email)
        .execute(db)
        .await?;
    Ok(())
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
    db: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
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

pub async fn create_with_oauth(
    db: &mut PgConnection,
    email: &str,
    username: &str,
    display_name: &str,
    provider: &str,
    provider_user_id: &str,
    email_verified_at: Option<DateTime<Utc>>,
) -> Result<User, sqlx::Error> {
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
    .fetch_one(&mut *db)
    .await?;

    sqlx::query!(
        "INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email)
         VALUES ($1, $2, $3, $4)",
        user.id,
        provider,
        provider_user_id,
        email,
    )
    .execute(&mut *db)
    .await?;

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

pub async fn set_verification_token(
    db: &PgPool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users
         SET email_verification_token_hash = $2,
             email_verification_token_expires_at = $3
         WHERE id = $1",
        user_id,
        token_hash,
        expires_at,
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn find_by_verification_token(
    db: &PgPool,
    token_hash: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        "SELECT * FROM users
         WHERE email_verification_token_hash = $1
           AND email_verification_token_expires_at > now()",
        token_hash
    )
    .fetch_optional(db)
    .await
}

pub async fn mark_email_verified(db: &PgPool, user_id: Uuid) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        "UPDATE users
         SET email_verified_at = now(),
             email_verification_token_hash = NULL,
             email_verification_token_expires_at = NULL
         WHERE id = $1
         RETURNING *",
        user_id,
    )
    .fetch_one(db)
    .await
}

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
