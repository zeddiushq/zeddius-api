use anyhow::Context;
use reqwest::Client;
use serde_json::json;

use crate::config::Config;

const RESEND_URL: &str = "https://api.resend.com/emails";
const FROM_NAME: &str = "Zeddius";

// Plain HTTP call against Resend's REST API — no dedicated SDK. Failure here
// is logged by the caller and does not fail the request that triggered it;
// the code is already stored, so /auth/resend-verification recovers it.
pub async fn send_verification_code(
    client: &Client,
    config: &Config,
    to_email: &str,
    code: &str,
) -> anyhow::Result<()> {
    let response = client
        .post(RESEND_URL)
        .bearer_auth(&config.resend_api_key)
        .json(&json!({
            "from": format!("{FROM_NAME} <{}>", config.resend_from_email),
            "to": to_email,
            "subject": "Your Zeddius verification code",
            "text": format!(
                "Your verification code is {code}. It expires in 15 minutes."
            ),
        }))
        .send()
        .await
        .context("failed to call Resend")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Resend returned {status}: {body}");
    }

    Ok(())
}
