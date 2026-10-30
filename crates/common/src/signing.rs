//! Edge-to-hub request signing with Ed25519.
//!
//! Each app kind has one edge with one key, serving all the kind's sites. Every request the
//! edge sends to the hub carries the site it is for, a timestamp, a random nonce and an Ed25519
//! signature over those plus the method, path and session handle. The hub verifies the
//! signature with the key of the site's kind from its registry, rejects old timestamps and reused
//! nonces, and thereby knows that the kind's edge sent the request, for which site, without
//! trusting anything the browser sent.

use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use thiserror::Error;

use crate::{
    headers,
    random::{RandomUnavailable, random_token},
    registry::{KEY_PREFIX, key_id},
};

/// Domain separation: a signature made for this protocol can never be valid for anything else.
const CONTEXT: &str = "auth-broker-edge-request-v2";

/// What a signature covers. The body is deliberately not included so requests can stream;
/// TLS protects the body in transit, and the signature proves who sent the request.
#[derive(Clone, Copy, Debug)]
pub struct SignatureInput<'a> {
    /// The site the request is for.
    pub site_id: &'a str,
    /// The HTTP method.
    pub method: &'a str,
    /// The path and query exactly as sent.
    pub path_and_query: &'a str,
    /// When the request was signed, in Unix seconds.
    pub timestamp: u64,
    /// A random value used once.
    pub nonce: &'a str,
    /// The session handle sent with the request, if any.
    pub handle: Option<&'a str>,
}

impl SignatureInput<'_> {
    /// The exact text that is signed, one field per line after a fixed context string.
    pub fn canonical(&self) -> String {
        format!(
            "{CONTEXT}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.site_id,
            self.method.to_ascii_uppercase(),
            self.path_and_query,
            self.timestamp,
            self.nonce,
            self.handle.unwrap_or("")
        )
    }
}

/// Why a signing key could not be used.
#[derive(Debug, Error)]
pub enum SigningError {
    /// The key text is not base64url.
    #[error("signing key is not base64url-encoded PKCS#8")]
    Encoding,
    /// The key is not an Ed25519 PKCS#8 document.
    #[error("signing key is not a valid Ed25519 PKCS#8 document")]
    Key,
    /// The random source failed while making a nonce.
    #[error(transparent)]
    Random(#[from] RandomUnavailable),
}

/// An edge's signer: its app kind and the kind's private key.
pub struct EdgeSigner {
    /// The app kind whose sites this edge serves.
    app_id: String,
    /// The kind's edge key.
    key: Ed25519KeyPair,
}

/// The headers that prove a request comes from a kind's edge, for one site.
#[derive(Clone, Debug)]
pub struct SignedHeaders {
    /// The site the request is for.
    pub site_id: String,
    /// When it was signed, in Unix seconds.
    pub timestamp: u64,
    /// The random value signed with it.
    pub nonce: String,
    /// The Ed25519 signature, base64url.
    pub signature: String,
    /// The signing key's id; not part of what is signed: a wrong one only fails verification.
    pub key_id: String,
}

impl SignedHeaders {
    /// Adds these headers to `headers`.
    pub fn apply(&self, headers: &mut HeaderMap) {
        let pairs = [
            (headers::SITE_ID, self.site_id.clone()),
            (headers::SITE_TIMESTAMP, self.timestamp.to_string()),
            (headers::SITE_NONCE, self.nonce.clone()),
            (headers::SITE_SIGNATURE, self.signature.clone()),
            (headers::SITE_KEY_ID, self.key_id.clone()),
        ];
        for (name, value) in pairs {
            // All values are base64url, digits or registry-validated ids: always valid headers.
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(name, value);
            }
        }
    }
}

impl EdgeSigner {
    /// The signer of kind `app_id`'s edge with the key in `pkcs8`: base64url PKCS#8, as
    /// [`generate_key`] or `openssl genpkey -algorithm ed25519 -outform DER` produce it.
    pub fn from_base64(app_id: &str, pkcs8: &str) -> Result<Self, SigningError> {
        let der = URL_SAFE_NO_PAD
            .decode(pkcs8.trim())
            .map_err(|_| SigningError::Encoding)?;
        let key =
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|_| SigningError::Key)?;
        Ok(Self {
            app_id: app_id.to_owned(),
            key,
        })
    }

    /// The app kind this signer signs for.
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// This key's id, as the registry computes it from the public key.
    pub fn key_id(&self) -> String {
        let public: [u8; 32] = self
            .key
            .public_key()
            .as_ref()
            .try_into()
            .expect("an Ed25519 public key is 32 bytes");
        key_id(&public)
    }

    /// The `edge_public_key` value for the kind's registry entry.
    pub fn public_key(&self) -> String {
        format!(
            "{KEY_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref())
        )
    }

    /// Signs a request for site `site_id`, `method`, `path_and_query` and session `handle` at
    /// time `now`, with a fresh nonce.
    pub fn sign(
        &self,
        site_id: &str,
        method: &str,
        path_and_query: &str,
        handle: Option<&str>,
        now: u64,
    ) -> Result<SignedHeaders, SigningError> {
        let nonce = random_token()?;
        Ok(self.sign_with(site_id, method, path_and_query, handle, now, &nonce))
    }

    /// Deterministic variant for tests.
    pub fn sign_with(
        &self,
        site_id: &str,
        method: &str,
        path_and_query: &str,
        handle: Option<&str>,
        timestamp: u64,
        nonce: &str,
    ) -> SignedHeaders {
        let input = SignatureInput {
            site_id,
            method,
            path_and_query,
            timestamp,
            nonce,
            handle,
        };
        let signature = self.key.sign(input.canonical().as_bytes());
        SignedHeaders {
            site_id: site_id.to_owned(),
            timestamp,
            nonce: nonce.to_owned(),
            signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
            key_id: self.key_id(),
        }
    }
}

/// Whether `signature` is `public_key`'s signature over `input`.
pub fn verify(public_key: &[u8; 32], input: &SignatureInput<'_>, signature: &str) -> bool {
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(input.canonical().as_bytes(), &signature)
        .is_ok()
}

/// A nonce as signed: 16-64 base64url characters.
pub fn is_nonce(value: &str) -> bool {
    (16..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A new Ed25519 private key as base64url PKCS#8, for `edge keygen`.
pub fn generate_key() -> Result<String, SigningError> {
    let document =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| RandomUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(document.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::parse_public_key;

    fn signer(app: &str) -> EdgeSigner {
        EdgeSigner::from_base64(app, &generate_key().unwrap()).unwrap()
    }

    fn input<'a>(
        signed: &'a SignedHeaders,
        method: &'a str,
        path: &'a str,
        handle: Option<&'a str>,
    ) -> SignatureInput<'a> {
        SignatureInput {
            site_id: &signed.site_id,
            method,
            path_and_query: path,
            timestamp: signed.timestamp,
            nonce: &signed.nonce,
            handle,
        }
    }

    #[test]
    fn given_a_signed_request_when_verified_with_the_kinds_key_then_it_passes() {
        let s = signer("inspection");
        let key = parse_public_key(&s.public_key()).unwrap();
        let signed = s
            .sign(
                "plant-a",
                "post",
                "/api/orders?x=1",
                Some("h"),
                1_700_000_000,
            )
            .unwrap();
        assert_eq!(signed.site_id, "plant-a");
        assert!(verify(
            &key,
            &input(&signed, "POST", "/api/orders?x=1", Some("h")),
            &signed.signature
        ));
    }

    #[test]
    fn given_any_changed_field_when_verified_then_it_fails() {
        let s = signer("inspection");
        let key = parse_public_key(&s.public_key()).unwrap();
        let signed = s.sign_with(
            "plant-a",
            "GET",
            "/api/a",
            Some("h1"),
            100,
            "nonce-nonce-nonce",
        );
        let base = input(&signed, "GET", "/api/a", Some("h1"));
        assert!(verify(&key, &base, &signed.signature));

        let changed = [
            SignatureInput {
                site_id: "plant-b",
                ..base
            },
            SignatureInput {
                method: "POST",
                ..base
            },
            SignatureInput {
                path_and_query: "/api/b",
                ..base
            },
            SignatureInput {
                timestamp: 101,
                ..base
            },
            SignatureInput {
                nonce: "nonce-nonce-other",
                ..base
            },
            SignatureInput {
                handle: Some("h2"),
                ..base
            },
            SignatureInput {
                handle: None,
                ..base
            },
        ];
        for variant in changed {
            assert!(!verify(&key, &variant, &signed.signature), "{variant:?}");
        }
        assert!(!verify(&key, &base, "not-base64!"));
    }

    #[test]
    fn given_another_kinds_key_when_verifying_then_it_fails() {
        let a = signer("inspection");
        let b = signer("billing");
        let signed = a.sign("plant-a", "GET", "/", None, 1).unwrap();
        let other_key = parse_public_key(&b.public_key()).unwrap();
        assert!(!verify(
            &other_key,
            &input(&signed, "GET", "/", None),
            &signed.signature
        ));
    }

    #[test]
    fn given_a_signature_input_when_made_canonical_then_the_format_is_stable() {
        // Hub and edges may run different versions; this string must never change silently.
        let input = SignatureInput {
            site_id: "plant-a",
            method: "post",
            path_and_query: "/api/orders?x=1",
            timestamp: 1_700_000_000,
            nonce: "nonce-nonce-nonce",
            handle: Some("h"),
        };
        assert_eq!(
            input.canonical(),
            "auth-broker-edge-request-v2\nplant-a\nPOST\n/api/orders?x=1\n1700000000\nnonce-nonce-nonce\nh"
        );
        assert!(
            SignatureInput {
                handle: None,
                ..input
            }
            .canonical()
            .ends_with("nonce-nonce-nonce\n")
        );
    }

    #[test]
    fn given_bad_key_text_when_loading_then_it_is_rejected() {
        assert!(matches!(
            EdgeSigner::from_base64("a", "%%%"),
            Err(SigningError::Encoding)
        ));
        assert!(matches!(
            EdgeSigner::from_base64("a", "AAAA"),
            Err(SigningError::Key)
        ));
    }

    #[test]
    fn given_nonces_when_validated_then_only_well_formed_ones_pass() {
        assert!(is_nonce(&random_token().unwrap()));
        assert!(!is_nonce("short"));
        assert!(!is_nonce("has spaces in it here"));
    }
}
