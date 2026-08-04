use crate::config::Config;
use reqwest::Client;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    // Built once and reused: Client holds a connection pool (keep-alive
    // connections, TLS session cache) internally, so cloning it is cheap and
    // shares that pool, but constructing a new one per call would pay for a
    // fresh handshake every time.
    pub http_client: Client,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            config: Arc::new(config),
            // Bounds the whole request (connect + send + receive), not just
            // the connect phase — a stalled Resend or Apple JWKS response
            // would otherwise hang the auth request that's waiting on it
            // indefinitely, since reqwest has no timeout by default.
            http_client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client config is valid"),
        }
    }
}
