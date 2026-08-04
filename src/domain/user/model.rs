use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub display_name: String,
    pub password_hash: Option<String>,
    pub onboarding_complete: bool,
    pub height_cm: Option<f32>,
    pub birthdate: Option<NaiveDate>,
    pub target_calories: Option<i32>,
    pub target_protein_g: Option<i32>,
    pub target_sleep_hours: Option<f32>,
    pub timezone: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub email_verification_code_hash: Option<String>,
    pub email_verification_code_expires_at: Option<DateTime<Utc>>,
    pub email_verification_attempts: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub display_name: String,
    pub onboarding_complete: bool,
    pub height_cm: Option<f32>,
    pub birthdate: Option<NaiveDate>,
    pub target_calories: Option<i32>,
    pub target_protein_g: Option<i32>,
    pub target_sleep_hours: Option<f32>,
    pub timezone: String,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            username: u.username,
            display_name: u.display_name,
            onboarding_complete: u.onboarding_complete,
            height_cm: u.height_cm,
            birthdate: u.birthdate,
            target_calories: u.target_calories,
            target_protein_g: u.target_protein_g,
            target_sleep_hours: u.target_sleep_hours,
            timezone: u.timezone,
            email_verified_at: u.email_verified_at,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub display_name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct UsernameAvailableResponse {
    pub available: bool,
}

#[derive(Debug, Deserialize)]
pub struct AppleAuthRequest {
    pub identity_token: String,
}

#[derive(Debug, Deserialize)]
pub struct AppleCompleteRequest {
    pub identity_token: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Deserialize)]
pub struct AppleLinkRequest {
    pub identity_token: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub code: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct Session {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub is_current: bool,
}
