use anyhow::{Context, anyhow};

pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub apple_bundle_id: String,
    pub apple_services_id: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            port: optional("PORT", "8080")
                .parse()
                .context("PORT must be a valid port number (0–65535)")?,
            apple_bundle_id: required("APPLE_BUNDLE_ID")?,
            apple_services_id: required("APPLE_SERVICES_ID")?,
        })
    }
}

fn required(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow!("missing required env var: {key}"))
}

fn optional(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
