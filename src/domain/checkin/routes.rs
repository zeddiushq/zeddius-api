use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::NaiveDate;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::model::{DailyCheckin, DailyCheckinQuery, UpsertDailyCheckinRequest};
use super::repo;
use crate::auth::extractor::VerifiedUser;
use crate::error::{AppError, ErrorResponse};
use crate::state::AppState;

// `upsert` and `close` are both POST at different paths — same
// "routes! panics on two handlers sharing a method in one call" split
// used throughout every other domain module.
pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list, upsert))
        .routes(routes!(close))
}

#[utoipa::path(
    get,
    path = "/daily-checkins",
    params(DailyCheckinQuery),
    responses(
        (status = 200, description = "Check-ins in range, most recent first", body = Vec<DailyCheckin>),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "checkins",
)]
async fn list(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Query(params): Query<DailyCheckinQuery>,
) -> Result<Json<Vec<DailyCheckin>>, AppError> {
    let checkins = repo::list(&state.db, auth.user_id, params.from, params.to).await?;
    Ok(Json(checkins))
}

#[utoipa::path(
    post,
    path = "/daily-checkins",
    request_body = UpsertDailyCheckinRequest,
    responses(
        (status = 200, description = "Upserted by date — sets tomorrow_focus, does not touch closed_at", body = DailyCheckin),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "checkins",
)]
async fn upsert(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Json(req): Json<UpsertDailyCheckinRequest>,
) -> Result<Json<DailyCheckin>, AppError> {
    let checkin = repo::upsert(&state.db, auth.user_id, &req).await?;
    Ok(Json(checkin))
}

#[utoipa::path(
    post,
    path = "/daily-checkins/{date}/close",
    params(("date" = NaiveDate, Path, description = "Date to close, YYYY-MM-DD")),
    responses(
        (status = 200, description = "Closed. Idempotent — closing an already-closed date just re-stamps closed_at. Works even with no prior POST /daily-checkins for that date.", body = DailyCheckin),
        (status = 401, description = "Missing or invalid access token", body = ErrorResponse),
        (status = 403, description = "Account email not verified", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "checkins",
)]
async fn close(
    State(state): State<AppState>,
    auth: VerifiedUser,
    Path(date): Path<NaiveDate>,
) -> Result<Json<DailyCheckin>, AppError> {
    let checkin = repo::close(&state.db, auth.user_id, date).await?;
    Ok(Json(checkin))
}
