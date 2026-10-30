//! How the hub proves to the identity provider that it is the hub, on every token, refresh and
//! logout call, for whichever kind's client it acts as. The Rust BFF's (`auth-api`'s
//! `crates/bff/src/client/credentials.rs`), without the BFF's own settings and route.
//!
//! - `client_secret`: a shared secret sent with each call, the kind's own. Simple, but the
//!   provider stores the secret itself, and every call carries it.
//! - `private_key_jwt` (RFC 7523): each call carries a fresh assertion, a JWT the hub signs with
//!   its private key, valid for a minute, usable once and only for this provider. The provider
//!   only knows the public key, which the hub publishes at `/.well-known/jwks.json`; one key
//!   serves every kind's client. Preferred.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    Algorithm, EncodingKey, Header,
    jwk::{Jwk, KeyAlgorithm, PublicKeyUse, ThumbprintHash},
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::random::random_token;

/// How long a client assertion is valid; the provider refuses it afterwards.
const ASSERTION_LIFETIME_SECS: u64 = 60;
/// The `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A key the hub signs client assertions with
#[derive(Clone)]
pub struct SigningKey {
    /// The private key
    key: EncodingKey,
    /// The public key as a JWK.
    public: Jwk,
}

impl SigningKey {
    /// Reads an EC P-256 private key from the PEM file at `path`. Its key id is `key_id`, or the
    /// key's JWK thumbprint (RFC 7638) if `None`.
    pub fn from_file(path: &str, key_id: Option<String>) -> Result<Self, InvalidClientKey> {
        let invalid = || InvalidClientKey(path.to_owned());
        let pem = std::fs::read(path).map_err(|_| invalid())?;
        let key = EncodingKey::from_ec_pem(&pem).map_err(|_| invalid())?;
        Self::from_key(key, key_id).map_err(|()| invalid())
    }

    /// `key`, an EC P-256 private key, with its public half as a JWK whose id is `key_id`, or
    /// the key's JWK thumbprint (RFC 7638) if `None`.
    fn from_key(key: EncodingKey, key_id: Option<String>) -> Result<Self, ()> {
        let mut public = Jwk::from_encoding_key(&key, Algorithm::ES256).map_err(drop)?;
        let key_id = match key_id {
            Some(key_id) => key_id,
            None => public.thumbprint(ThumbprintHash::SHA256).map_err(drop)?,
        };
        public.common.key_id = Some(key_id);
        public.common.key_algorithm = Some(KeyAlgorithm::ES256);
        public.common.public_key_use = Some(PublicKeyUse::Signature);
        Ok(Self { key, public })
    }

    /// This key's id
    fn key_id(&self) -> &str {
        self.public.common.key_id.as_deref().unwrap_or_default()
    }
}

/// Keys are the same if their public halves are: the hub rebuilds a kind's client only when its
/// credentials change.
impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

/// The client key file at the path held is unreadable or not an EC P-256 private key in PEM.
#[derive(Debug, thiserror::Error)]
#[error("{0} is not a readable EC P-256 private key (PEM)")]
pub struct InvalidClientKey(pub String);

/// How the hub authenticates itself to the identity provider as one kind's client.
#[derive(Clone, PartialEq)]
pub enum Credentials {
    /// `client_secret`: sends this secret with every call.
    Secret(String),
    /// `private_key_jwt`: signs a fresh assertion for every call.
    PrivateKeyJwt {
        /// The key assertions are signed with.
        signing: Box<SigningKey>,
        /// A key published ahead of a rotation, not yet used for signing.
        next: Option<Box<SigningKey>>,
    },
}

impl Credentials {
    /// The form fields that authenticate `client_id` on a call to the provider whose issuer is
    /// `issuer`: the secret, or a freshly signed assertion addressed to `issuer`.
    pub fn form_fields(
        &self,
        client_id: &str,
        issuer: &str,
    ) -> Result<Vec<(&'static str, String)>, ClientAssertionError> {
        let mut fields = vec![("client_id", client_id.to_owned())];
        match self {
            Self::Secret(secret) => fields.push(("client_secret", secret.clone())),
            Self::PrivateKeyJwt { signing, .. } => {
                let issued_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let claims = AssertionClaims {
                    iss: client_id,
                    sub: client_id,
                    aud: issuer,
                    jti: random_token().map_err(|_| ClientAssertionError)?,
                    iat: issued_at,
                    exp: issued_at + ASSERTION_LIFETIME_SECS,
                };
                let mut header = Header::new(Algorithm::ES256);
                header.kid = Some(signing.key_id().to_owned());
                let assertion = jsonwebtoken::encode(&header, &claims, &signing.key)
                    .map_err(|_| ClientAssertionError)?;
                fields.push(("client_assertion_type", JWT_BEARER.to_owned()));
                fields.push(("client_assertion", assertion));
            }
        }
        Ok(fields)
    }

    /// The public keys to publish: the signing key and any next key. Empty for a secret.
    pub fn jwks(&self) -> Value {
        let keys: Vec<&Jwk> = match self {
            Self::Secret(_) => Vec::new(),
            Self::PrivateKeyJwt { signing, next } => std::iter::once(signing)
                .chain(next)
                .map(|key| &key.public)
                .collect(),
        };
        json!({ "keys": keys })
    }
}

/// The claims of a client assertion (RFC 7523 §3).
#[derive(Serialize)]
struct AssertionClaims<'a> {
    /// The client, as issuer.
    iss: &'a str,
    /// The client, as subject.
    sub: &'a str,
    /// Who may accept it: the provider's issuer.
    aud: &'a str,
    /// Unique per assertion; the provider accepts each only once.
    jti: String,
    /// When it was made, in Unix seconds.
    iat: u64,
    /// When it stops being valid, in Unix seconds.
    exp: u64,
}

/// A client assertion could not be made (random source or signing failed).
#[derive(Debug, thiserror::Error)]
#[error("could not create a client assertion")]
pub struct ClientAssertionError;

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::*;

    /// Client authentication with a key generated for this test.
    fn private_key_jwt() -> Credentials {
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let key = EncodingKey::from_ec_der(pkcs8.as_ref());
        Credentials::PrivateKeyJwt {
            signing: Box::new(SigningKey::from_key(key, None).unwrap()),
            next: None,
        }
    }

    /// The decoded JSON of base64url `part` of a JWT.
    fn decode(part: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[test]
    fn given_a_secret_then_it_is_sent_as_is() {
        let fields = Credentials::Secret("s3cret".into())
            .form_fields("hub-inspection", "https://idp/realms/test")
            .unwrap();
        assert_eq!(
            fields,
            vec![
                ("client_id", "hub-inspection".into()),
                ("client_secret", "s3cret".into())
            ]
        );
    }

    #[test]
    fn given_a_private_key_then_a_short_lived_assertion_for_the_issuer_is_sent() {
        let fields = private_key_jwt()
            .form_fields("hub-inspection", "https://idp/realms/test")
            .unwrap();
        let field = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| *key == name)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(field("client_assertion_type"), JWT_BEARER);
        assert!(fields.iter().all(|(key, _)| *key != "client_secret"));

        let assertion = field("client_assertion");
        let parts: Vec<&str> = assertion.split('.').collect();
        let (header, claims) = (decode(parts[0]), decode(parts[1]));
        assert_eq!(header["alg"], "ES256");
        assert!(header["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
        assert_eq!(claims["iss"], "hub-inspection");
        assert_eq!(claims["sub"], "hub-inspection");
        assert_eq!(claims["aud"], "https://idp/realms/test");
        let lifetime = claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap();
        assert_eq!(lifetime, ASSERTION_LIFETIME_SECS);
    }

    #[test]
    fn given_two_assertions_then_their_ids_differ() {
        let auth = private_key_jwt();
        let jti = |auth: &Credentials| {
            let fields = auth
                .form_fields("hub-inspection", "https://idp/realms/test")
                .unwrap();
            let assertion = &fields
                .iter()
                .find(|(key, _)| *key == "client_assertion")
                .unwrap()
                .1;
            decode(assertion.split('.').nth(1).unwrap())["jti"].clone()
        };
        assert_ne!(jti(&auth), jti(&auth));
    }

    #[test]
    fn given_a_private_key_then_only_its_public_half_is_published() {
        let jwks = private_key_jwt().jwks();
        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["use"], "sig");
        assert!(key.get("d").is_none(), "no private key material");
        assert_eq!(Credentials::Secret("s".into()).jwks()["keys"], json!([]));
    }
}
