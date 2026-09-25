use argon2::password_hash::{
    SaltString,
    rand_core::{OsRng, RngCore},
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use sha2::{Digest, Sha256};

pub fn generate_token(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex::encode(bytes))
}

pub fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> anyhow::Result<bool> {
    let parsed =
        PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("invalid password hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_has_expected_prefix_and_length() {
        let token = generate_token("zeddius_ac");
        let hex_part = token
            .strip_prefix("zeddius_ac_")
            .expect("token should carry the given prefix");
        assert_eq!(hex_part.len(), 64, "32 raw bytes hex-encode to 64 chars");
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_token_is_random() {
        assert_ne!(generate_token("prefix"), generate_token("prefix"));
    }

    #[test]
    fn hash_token_is_deterministic() {
        let raw = "some-raw-token-value";
        assert_eq!(hash_token(raw), hash_token(raw));
    }

    #[test]
    fn hash_token_differs_for_different_input() {
        assert_ne!(hash_token("a"), hash_token("b"));
    }

    #[test]
    fn hash_and_verify_password_round_trip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
    }

    #[test]
    fn verify_password_rejects_wrong_password() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn verify_password_rejects_malformed_hash() {
        assert!(verify_password("anything", "not-a-real-hash").is_err());
    }
}
