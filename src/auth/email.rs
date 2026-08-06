use anyhow::Context;
use reqwest::Client;
use serde_json::json;

use crate::config::Config;

const RESEND_URL: &str = "https://api.resend.com/emails";
const FROM_NAME: &str = "Zeddius";

pub async fn send_verification_code(
    client: &Client,
    config: &Config,
    to_email: &str,
    code: &str,
) -> anyhow::Result<()> {
    send(
        client,
        config,
        to_email,
        "Your Zeddius verification code",
        &format!("Your verification code is {code}. It expires in 15 minutes."),
    )
    .await
}

pub async fn send_password_reset_link(
    client: &Client,
    config: &Config,
    to_email: &str,
    reset_url: &str,
) -> anyhow::Result<()> {
    send(
        client,
        config,
        to_email,
        "Reset your Zeddius password",
        &format!(
            "Use this link to reset your password: {reset_url}\n\nIt expires in 30 minutes. If you didn't request this, you can ignore this email."
        ),
    )
    .await
}

// Plain HTTP call against Resend's REST API — no dedicated SDK. Failure here
// is logged by the caller and does not fail the request that triggered it;
// whatever token/code prompted the email is already stored, so a resend
// (verification code) or a repeat request (password reset) can recover it.
async fn send(
    client: &Client,
    config: &Config,
    to_email: &str,
    subject: &str,
    text: &str,
) -> anyhow::Result<()> {
    let response = client
        .post(RESEND_URL)
        .bearer_auth(&config.resend_api_key)
        .json(&json!({
            "from": format!("{FROM_NAME} <{}>", config.resend_from_email),
            "to": to_email,
            "subject": subject,
            "text": text,
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
