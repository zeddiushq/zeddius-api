mod auth;
mod config;
mod db;
mod domain;
mod error;
mod openapi;
mod state;

use std::net::SocketAddr;

use anyhow::Context;
use axum::{Json, routing};
use serde::Serialize;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_scalar::{Scalar, Servable};

use config::Config;
use openapi::ApiDoc;
use state::AppState;

use crate::error::AppError;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "zeddius_api=debug".into()))
        .init();

    let config = Config::from_env()?;
    let db = db::connect(&config.database_url).await?;
    let state = AppState::new(db, config);
    let port = state.config.port;

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/v1", auth::routes::router())
        .nest("/v1", domain::user::routes::router())
        .nest("/v1", domain::weight::routes::router())
        .split_for_parts();

    let app = router
        .route("/health", routing::get(health))
        .merge(Scalar::with_url("/docs", api))
        .fallback(fallback)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("failed to bind to 0.0.0.0:{port}"))?;
    info!(
        "listening on {}",
        listener
            .local_addr()
            .expect("bound listener has local addr")
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;

    Ok(())
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    name: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn fallback() -> AppError {
    AppError::NotFound("page")
}
