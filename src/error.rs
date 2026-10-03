use anyhow::anyhow;
use axum::http::{HeaderValue, StatusCode, header::RETRY_AFTER};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;

// Shared by into_response and the OpenAPI schema so they can't drift apart.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("{0} not found")]
    NotFound(&'static str),

    #[error("conflict: {0}")]
    Conflict(&'static str),

    #[error("validation failed: {0}")]
    ValidationFailed(String),

    #[error("too many requests, try again in {retry_after_secs}s")]
    TooManyRequests { retry_after_secs: u64 },

    #[error("{message}")]
    JsonRejection { status: StatusCode, message: String },

    #[error("an unexpected error occurred")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        let retry_after = match &self {
            AppError::TooManyRequests { retry_after_secs } => Some(*retry_after_secs),
            _ => None,
        };
        let (status, code) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN".to_string()),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND".to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT".to_string()),
            AppError::ValidationFailed(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_FAILED".to_string(),
            ),
            AppError::TooManyRequests { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "TOO_MANY_REQUESTS".to_string(),
            ),
            AppError::JsonRejection { status, .. } => {
                let code = status
                    .canonical_reason()
                    .map(|r| r.to_uppercase().replace(" ", "_").replace("\'", ""))
                    .unwrap_or_else(|| format!("HTTP_{}", status.as_u16()));
                (status, code)
            }
            AppError::Internal(e) => {
                error!(error = %e, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR".to_string(),
                )
            }
        };

        let mut response = (
            status,
            Json(ErrorResponse {
                error: ErrorDetail { code, message },
            }),
        )
            .into_response();

        if let Some(secs) = retry_after {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(secs));
        }
        response
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(anyhow!(e))
    }
}
