mod config;
mod db;
mod error;
mod state;

use anyhow::Context;
use axum::{Router, routing};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "zeddius_api=debug".into()))
        .init();

    let app = Router::new()
        .route("/health", routing::get(health))
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:8080")
        .await
        .context("failed to bind to 0.0.0.0:8080")?;
    info!(
        "listening on {}",
        listener
            .local_addr()
            .expect("bound listener has local addr")
    );
    axum::serve(listener, app).await.context("server error")?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
