use anyhow::anyhow;
use axum::http::StatusCode;
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;

// The one shape every AppError variant serializes to — a single source of
// truth for both the actual response body (into_response, below) and the
// OpenAPI schema referenced by every non-2xx `#[utoipa::path]` response, so
// the two can't silently drift apart.
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

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", self.to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN", self.to_string()),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND", self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT", self.to_string()),
            AppError::ValidationFailed(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_FAILED",
                self.to_string(),
            ),
            AppError::Internal(e) => {
                error!(error = %e, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR",
                    "an unexpected error occurred".to_string(),
                )
            }
        };

        (
            status,
            Json(ErrorResponse {
                error: ErrorDetail {
                    code: code.to_string(),
                    message,
                },
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(anyhow!(e))
    }
}
