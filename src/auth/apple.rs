use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use super::service;

const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600);
const APPLE_ISSUER: &str = "https://appleid.apple.com";

static JWKS_CACHE: LazyLock<RwLock<Option<(Instant, Jwks)>>> = LazyLock::new(|| RwLock::new(None));

// Coalesces concurrent cache misses into one Apple fetch (thundering herd).
// Separate from JWKS_CACHE's RwLock so warm-cache reads never contend with it.
static JWKS_FETCH_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
pub struct AppleClaims {
    pub sub: String,
    pub email: Option<String>,
    // Apple sends this as either a JSON bool or a stringified "true"/"false" depending on client version.
    #[serde(default, deserialize_with = "bool_or_string")]
    pub email_verified: bool,
    // SHA-256 hex of the client's raw nonce, echoed back by Apple.
    pub nonce: Option<String>,
}

fn bool_or_string<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        Str(String),
    }

    Ok(match BoolOrString::deserialize(deserializer)? {
        BoolOrString::Bool(b) => b,
        BoolOrString::Str(s) => s == "true",
    })
}

// `valid_audiences` covers both native (bundle ID) and web (Services ID) clients.
// `expected_nonce`, if the client sent one, must match the token's nonce claim to rule out replay;
// optional for now since not every client sends one yet.
pub async fn verify_identity_token(
    client: &Client,
    identity_token: &str,
    valid_audiences: &[&str],
    expected_nonce: Option<&str>,
) -> anyhow::Result<AppleClaims> {
    let header =
        jsonwebtoken::decode_header(identity_token).context("invalid identity token header")?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow!("identity token missing kid"))?;

    let jwk = find_key(client, &kid).await?;
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .context("failed to build decoding key from Apple JWK")?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(valid_audiences);
    validation.set_issuer(&[APPLE_ISSUER]);

    let data = jsonwebtoken::decode::<AppleClaims>(identity_token, &decoding_key, &validation)
        .context("apple identity token verification failed")?;

    if let Some(raw_nonce) = expected_nonce {
        let expected_hash = service::hash_token(raw_nonce);
        if data.claims.nonce.as_deref() != Some(expected_hash.as_str()) {
            anyhow::bail!("identity token nonce does not match the request's nonce");
        }
    }

    Ok(data.claims)
}

async fn find_key(client: &Client, kid: &str) -> anyhow::Result<Jwk> {
    if let Some(jwk) = cached_key(kid).await {
        return Ok(jwk);
    }

    let _permit = JWKS_FETCH_LOCK.lock().await;
    // Someone else may have refreshed the cache while we waited for the fetch lock.
    if let Some(jwk) = cached_key(kid).await {
        return Ok(jwk);
    }

    let jwks = fetch_jwks(client).await?;
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .cloned()
        .ok_or_else(|| anyhow!("no matching Apple signing key for kid {kid}"))?;

    let mut cache = JWKS_CACHE.write().await;
    *cache = Some((Instant::now(), jwks));

    Ok(jwk)
}

async fn cached_key(kid: &str) -> Option<Jwk> {
    let cache = JWKS_CACHE.read().await;
    let (fetched_at, jwks) = cache.as_ref()?;
    if fetched_at.elapsed() >= JWKS_CACHE_TTL {
        return None;
    }
    jwks.keys.iter().find(|k| k.kid == kid).cloned()
}

async fn fetch_jwks(client: &Client) -> anyhow::Result<Jwks> {
    client
        .get(JWKS_URL)
        .send()
        .await
        .context("failed to fetch Apple JWKS")?
        .json()
        .await
        .context("failed to parse Apple JWKS response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_apple_style_jwks_response() {
        // extra fields (kty, use, alg) not on Jwk should be ignored, not fail
        let body = r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "eXaunmL",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "abcd1234",
                    "e": "AQAB"
                },
                {
                    "kty": "RSA",
                    "kid": "86D88Kf",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "efgh5678",
                    "e": "AQAB"
                }
            ]
        }"#;

        let jwks: Jwks = serde_json::from_str(body).expect("should parse Apple JWKS shape");

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid, "eXaunmL");
        assert_eq!(jwks.keys[0].n, "abcd1234");
        assert_eq!(jwks.keys[0].e, "AQAB");
        assert_eq!(jwks.keys[1].kid, "86D88Kf");
    }

    #[test]
    fn email_verified_accepts_bool_or_string() {
        let bool_form: AppleClaims =
            serde_json::from_str(r#"{"sub":"1","email":"a@b.com","email_verified":true}"#)
                .expect("bool form should parse");
        assert!(bool_form.email_verified);

        let string_form: AppleClaims =
            serde_json::from_str(r#"{"sub":"1","email":"a@b.com","email_verified":"false"}"#)
                .expect("string form should parse");
        assert!(!string_form.email_verified);

        let missing: AppleClaims = serde_json::from_str(r#"{"sub":"1","email":"a@b.com"}"#)
            .expect("missing field should default rather than error");
        assert!(!missing.email_verified);
    }
}
