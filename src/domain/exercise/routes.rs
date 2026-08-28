use axum::Json;
use axum::extract::State;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::model::Exercise;
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list))
}

#[utoipa::path(
    get,
    path = "/exercises",
    responses(
        (status = 200, description = "The seeded exercise library, alphabetical by name. No custom-exercise support yet — this is read-only.", body = Vec<Exercise>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "exercises",
)]
async fn list(
    State(state): State<AppState>,
    _auth: VerifiedUser,
) -> Result<Json<Vec<Exercise>>, AppError> {
    let exercises = repo::list(&state.db).await?;
    Ok(Json(exercises))
}
