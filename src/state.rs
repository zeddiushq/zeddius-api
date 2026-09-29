use crate::config::Config;
use reqwest::Client;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    // Cloning shares the internal connection pool; building one per call would re-handshake.
    pub http_client: Client,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            config: Arc::new(config),
            // reqwest has no default timeout; without this a stalled Resend/Apple call hangs forever.
            http_client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client config is valid"),
        }
    }
}
