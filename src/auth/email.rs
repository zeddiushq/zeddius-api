use anyhow::Context;
use reqwest::Client;
use serde_json::json;

use crate::config::Config;

const RESEND_URL: &str = "https://api.resend.com/emails";
const FROM_NAME: &str = "Zeddius";

pub async fn send_verification_link(
    client: &Client,
    config: &Config,
    to_email: &str,
    verify_url: &str,
) -> anyhow::Result<()> {
    send(
        client,
        config,
        to_email,
        "Verify your Zeddius email",
        &format!("Use this link to verify your email: {verify_url}\n\nIt expires in 30 minutes."),
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

pub async fn send_oauth_linked_notice(
    client: &Client,
    config: &Config,
    to_email: &str,
    provider_label: &str,
) -> anyhow::Result<()> {
    send(
        client,
        config,
        to_email,
        "New sign-in method added to your Zeddius account",
        &format!(
            "{provider_label} was just linked to your Zeddius account as a sign-in method. If this wasn't you, please contact support immediately."
        ),
    )
    .await
}

// Caller logs failures without failing the request — the token/code is already stored and recoverable.
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
