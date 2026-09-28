use axum::{
    Json,
    extract::{FromRequest, Request},
};
use serde::de::DeserializeOwned;

use crate::{error::AppError, state::AppState};

pub struct AppJson<T>(pub T);

impl<T> FromRequest<AppState> for AppJson<T>
where
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| AppError::JsonRejection {
                status: rejection.status(),
                message: rejection.body_text(),
            })
    }
}
