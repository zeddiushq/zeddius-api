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
