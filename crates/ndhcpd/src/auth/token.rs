use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngExt;
use rand_core::OsRng;

const TOKEN_LENGTH: usize = 32;

/// Generate a new random API token
pub fn generate() -> String {
    let mut rng = rand::rng();
    let token_bytes: Vec<u8> = (0..TOKEN_LENGTH).map(|_| rng.random()).collect();
    general_purpose::STANDARD.encode(&token_bytes)
}

/// Hash a token with Argon2, returns (hash, salt)
pub fn hash(token: &str) -> Result<(String, String)> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash token: {}", e))?;

    Ok((password_hash.to_string(), salt.to_string()))
}

/// Verify a token against a stored Argon2 hash
pub fn verify(token: &str, hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| anyhow!("Failed to parse hash: {}", e))?;

    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_returns_nonempty_string() {
        let t = generate();
        assert!(!t.is_empty());
    }

    #[test]
    fn test_generate_tokens_are_unique() {
        let t1 = generate();
        let t2 = generate();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_generate_token_length() {
        // 32 bytes base64-encoded → 44 chars (with padding)
        let t = generate();
        assert_eq!(t.len(), 44);
    }

    #[test]
    fn test_hash_produces_valid_argon2_hash() {
        let (hash_str, salt_str) = hash("mysecrettoken").unwrap();
        assert!(hash_str.starts_with("$argon2"));
        assert!(!salt_str.is_empty());
    }

    #[test]
    fn test_hash_same_token_different_salts() {
        let (h1, _) = hash("token").unwrap();
        let (h2, _) = hash("token").unwrap();
        assert_ne!(h1, h2, "same token should produce different hashes due to random salt");
    }

    #[test]
    fn test_verify_correct_token() {
        let raw = "correct_token";
        let (hash_str, _) = hash(raw).unwrap();
        assert!(verify(raw, &hash_str).unwrap());
    }

    #[test]
    fn test_verify_wrong_token() {
        let (hash_str, _) = hash("correct_token").unwrap();
        assert!(!verify("wrong_token", &hash_str).unwrap());
    }

    #[test]
    fn test_verify_invalid_hash_returns_error() {
        let result = verify("token", "not_a_valid_hash");
        assert!(result.is_err());
    }
}
