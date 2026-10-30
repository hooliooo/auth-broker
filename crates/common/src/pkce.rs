//! PKCE S256 (RFC 7636): used twice, between the hub and the identity provider, and between an edge
//! and the hub.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};

use crate::{
    crypto::constant_time_eq,
    random::{RandomUnavailable, random_token},
};

/// The only challenge method used.
pub const METHOD: &str = "S256";

/// 43 characters from the unreserved set, the shortest verifier RFC 7636 allows.
pub fn new_verifier() -> Result<String, RandomUnavailable> {
    random_token()
}

/// The S256 challenge of `verifier`: its SHA-256, base64url.
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()).as_ref())
}

/// A well-formed S256 challenge: 43 base64url characters.
pub fn is_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `verifier` is well formed and its challenge is `expected_challenge`, compared in
/// constant time.
pub fn verify(verifier: &str, expected_challenge: &str) -> bool {
    let valid_verifier = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    valid_verifier && constant_time_eq(&challenge(verifier), expected_challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_the_rfc7636_example_when_hashing_then_it_matches() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn given_a_verifier_when_checked_against_its_challenge_then_only_it_passes() {
        let verifier = new_verifier().unwrap();
        let other = new_verifier().unwrap();
        assert!(is_challenge(&challenge(&verifier)));
        assert!(verify(&verifier, &challenge(&verifier)));
        assert!(!verify(&other, &challenge(&verifier)));
        assert!(!verify("short", &challenge("short")));
    }
}
