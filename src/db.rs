use anyhow::anyhow;
use sqlx::PgPool;

pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    PgPool::connect(database_url)
        .await
        .map_err(|e| anyhow!("failed to connect to database: {e}"))
}
