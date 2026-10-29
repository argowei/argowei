use std::sync::OnceLock;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

pub const MIN_PASSWORD_LEN: usize = 12;
/// Upper bound so an attacker cannot make us hash megabytes per request.
pub const MAX_PASSWORD_LEN: usize = 128;

/// Hashes with Argon2id (the `argon2` crate default) and a random salt.
/// CPU-heavy: call from `spawn_blocking`.
pub fn hash(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// CPU-heavy: call from `spawn_blocking`.
pub fn verify(password: &str, phc_hash: &str) -> bool {
    PasswordHash::new(phc_hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A valid hash of a random value, verified against when the username does
/// not exist so that response time does not reveal which usernames are real.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash("argowei-dummy-password").expect("hashing a constant cannot fail"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_argon2id_and_verifies() {
        let phc = hash("correct horse battery").unwrap();

        assert!(phc.starts_with("$argon2id$"));
        assert!(verify("correct horse battery", &phc));
        assert!(!verify("wrong password!!", &phc));
    }

    #[test]
    fn hashes_are_salted() {
        assert_ne!(
            hash("same password 123").unwrap(),
            hash("same password 123").unwrap()
        );
    }

    #[test]
    fn malformed_hash_never_verifies() {
        assert!(!verify("anything", "not-a-phc-string"));
    }
}
