use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600);
const APPLE_ISSUER: &str = "https://appleid.apple.com";

static JWKS_CACHE: LazyLock<RwLock<Option<(Instant, Jwks)>>> = LazyLock::new(|| RwLock::new(None));

// Serializes JWKS refreshes so concurrent cache misses coalesce into a single
// fetch instead of each firing its own request to Apple (thundering herd).
// Deliberately separate from JWKS_CACHE's RwLock: readers hitting a warm
// cache never contend with this, only requests that also missed do.
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
}

// Verifies an Apple identity token's signature against Apple's JWKS and checks
// standard claims (issuer, audience, expiry — expiry is checked by jsonwebtoken
// automatically). `valid_audiences` accepts tokens minted for any of our own
// registered client identifiers — the iOS App ID's bundle ID (native Sign in
// with Apple) and the web Services ID (the redirect-based OAuth flow) mint
// tokens with different `aud` values for the same physical endpoint.
// Returns the extracted sub + email on success.
pub async fn verify_identity_token(
    identity_token: &str,
    valid_audiences: &[&str],
) -> anyhow::Result<AppleClaims> {
    let header =
        jsonwebtoken::decode_header(identity_token).context("invalid identity token header")?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow!("identity token missing kid"))?;

    let jwk = find_key(&kid).await?;
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .context("failed to build decoding key from Apple JWK")?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(valid_audiences);
    validation.set_issuer(&[APPLE_ISSUER]);

    let data = jsonwebtoken::decode::<AppleClaims>(identity_token, &decoding_key, &validation)
        .context("apple identity token verification failed")?;

    Ok(data.claims)
}

async fn find_key(kid: &str) -> anyhow::Result<Jwk> {
    if let Some(jwk) = cached_key(kid).await {
        return Ok(jwk);
    }

    let _permit = JWKS_FETCH_LOCK.lock().await;
    // Someone else may have refreshed the cache while we waited for the fetch lock.
    if let Some(jwk) = cached_key(kid).await {
        return Ok(jwk);
    }

    let jwks = fetch_jwks().await?;
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

async fn fetch_jwks() -> anyhow::Result<Jwks> {
    reqwest::get(JWKS_URL)
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
        // Shaped like a real response from https://appleid.apple.com/auth/keys —
        // extra fields (kty, use, alg) present on the real thing but not on Jwk
        // should just be ignored, not fail deserialization.
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
}
