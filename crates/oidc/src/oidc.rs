//! Verification shared by every OpenID Connect provider: discovery, signature checks against
//! the provider's JWKS, and the audience, issuer and expiry validations.

use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::{
    cache::{Cache, HttpJwksSource, SourceError},
    causes::with_causes,
};

/// The path OIDC Discovery 1.0 mandates for the document, relative to the issuer.
const DISCOVERY_PATH: &str = ".well-known/openid-configuration";

/// How long fetched signing keys are trusted before they are refreshed.
const KEY_TTL: Duration = Duration::from_secs(10 * 60);

/// The minimum time between two refetch attempts.
const KEY_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Allowed clock difference with the provider when checking `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: u64 = 30;

/// Claims every accepted token must carry. jsonwebtoken only checks `aud` and `iss` when they
/// are present, so without this a token that simply leaves `aud` out passes the audience check.
/// `sub` is not listed: a back-channel logout token may carry only `sid`. jsonwebtoken cannot
/// require `iat`, so [`OidcJwtVerifier::verify_payload`] checks it.
const REQUIRED_CLAIMS: [&str; 3] = ["exp", "iss", "aud"];

/// The asymmetric algorithms a signing key may use. Which one applies to a token is decided
/// by the key that signed it, never by the token's own header.
///
/// A policy rather than configuration: discovery documents only describe ID tokens, and list
/// every algorithm a provider implements, symmetric ones included. ES512 is absent because
/// jsonwebtoken does not support P-521 keys.
const ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Which URL schemes the provider may use. Over plain HTTP anyone on the network path can
/// swap the signing keys or read tokens, so HTTP is only for local development.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// Only `https://` provider URLs.
    #[default]
    HttpsOnly,
    /// Accepts `http://` provider URLs, e.g. a Keycloak container in a dev stack.
    AllowInsecureHttp,
}

impl Transport {
    /// Refuses `url`, reported as `name`, unless it is HTTPS or this policy allows HTTP.
    fn check(self, name: &'static str, url: &str) -> Result<(), OidcSetupError> {
        let scheme = reqwest::Url::parse(url)
            .map(|url| url.scheme().to_owned())
            .unwrap_or_default();
        match (scheme.as_str(), self) {
            ("https", _) | ("http", Transport::AllowInsecureHttp) => Ok(()),
            _ => Err(OidcSetupError::InsecureUrl {
                name,
                url: url.to_owned(),
            }),
        }
    }
}

/// The claims this service acts on, read from a verified token.
/// Values keep the provider's own format, e.g. `user_id` is whatever the provider uses as
/// the subject.
#[derive(Clone, Debug)]
pub struct StandardClaims {
    /// The client the token was issued to.
    pub azp: String,
    /// The subject: the user, or the client for service accounts.
    pub sub: String,
}

/// Verifies a raw bearer token against an identity provider and reads its claims.
#[async_trait::async_trait]
pub trait JwtVerifier: Send + Sync {
    /// What a verified token is read into.
    type Claims;
    /// Verifies `raw_token` and reads its claims.
    async fn verify(&self, raw_token: &str) -> Result<Self::Claims, JwtVerificationError>;
}

/// Why a token was not accepted, in terms the application can act on. Adapters map their
/// provider's failures onto these and put the specifics in the message.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    /// The token is malformed, forged, expired or meant for another audience
    #[error("Invalid token: {0}")]
    Invalid(String),
    /// The identity provider could not be reached to verify the token
    #[error("Identity provider unavailable: {0}")]
    ProviderUnavailable(String),
    /// A verified token lacks a claim this service needs
    #[error("Missing claim: {0}")]
    MissingClaim(&'static str),
}

/// How a provider's token payload is read into the claims a service acts on: the only thing
/// that differs between providers, so it is what [`OidcJwtVerifier`] is parameterised by.
pub trait ProviderClaims {
    /// What a verified payload is read into.
    type Claims;
    /// Reads a verified token's `payload`.
    fn claims(payload: Value) -> Result<Self::Claims, JwtVerificationError>;
}

/// Verifies tokens against an OpenID Connect provider: the signature against its published
/// keys, then audience, issuer, expiry and issue time. `P` reads the verified payload.
pub struct OidcJwtVerifier<P> {
    /// The provider's discovery document, with server endpoints rebased.
    well_known_endpoint: WellKnownEndpoint,
    /// The provider's signing keys.
    keys: Arc<Cache>,
    /// One per algorithm, built once: the audience and issuer never change after startup.
    validations: HashMap<Algorithm, Validation>,
    /// Which provider's claims reader `P` this verifier uses.
    _marker: PhantomData<fn() -> P>,
    /// The end-session endpoint at the internal address this service reaches the provider at
    /// (the discovery address), for logging a session out server to server; the published one
    /// is for browsers.
    internal_end_session_endpoint: Option<String>,
}

impl<P> OidcJwtVerifier<P> {
    /// Discovers the provider at `issuer_url` with `client`, accepting tokens for `audience`
    /// over the URLs `transport` allows. Fails if the provider cannot be reached.
    pub async fn new(
        issuer_url: &str,
        client: reqwest::Client,
        audience: String,
        transport: Transport,
    ) -> Result<Self, OidcSetupError> {
        Self::with_discovery_url(issuer_url, issuer_url, client, audience, transport).await
    }

    /// Like [`Self::new`], but reads discovery from `discovery_url` (e.g. an in-cluster address)
    /// while tokens name `issuer_url`. Uses `client`, accepts tokens for `audience`, and only
    /// URLs `transport` allows. Fails if the provider cannot be reached.
    pub async fn with_discovery_url(
        issuer_url: &str,
        discovery_url: &str,
        client: reqwest::Client,
        audience: String,
        transport: Transport,
    ) -> Result<Self, OidcSetupError> {
        transport.check("issuer", issuer_url)?;
        transport.check("discovery", discovery_url)?;
        let well_known_endpoint = WellKnownEndpoint::fetch(&client, discovery_url).await?;

        // OIDC Discovery 1.0 §4.3: the document must name the issuer it was fetched for,
        // otherwise the endpoint, not this configuration, decides which tokens are accepted.
        if well_known_endpoint.issuer.trim_end_matches('/') != issuer_url.trim_end_matches('/') {
            return Err(OidcSetupError::IssuerMismatch {
                expected: issuer_url.to_owned(),
                found: well_known_endpoint.issuer,
            });
        }

        let mut well_known_endpoint = well_known_endpoint;
        well_known_endpoint.rebase_server_endpoints(issuer_url, discovery_url);
        well_known_endpoint.check_transport(transport)?;
        let internal_end_session_endpoint = well_known_endpoint
            .end_session_endpoint
            .as_deref()
            .map(|endpoint| rebase(endpoint, issuer_url, discovery_url));

        let source = HttpJwksSource::new(client, well_known_endpoint.jwks_uri.clone());
        let keys = Cache::new(source, KEY_TTL, KEY_MIN_REFRESH_INTERVAL).await?;
        let mut verifier = Self::from_parts(well_known_endpoint, keys, &audience);
        verifier.internal_end_session_endpoint = internal_end_session_endpoint;
        Ok(verifier)
    }

    /// A verifier from an already loaded `well_known_endpoint` and `keys`, accepting tokens
    /// for `audience`.
    fn from_parts(well_known_endpoint: WellKnownEndpoint, keys: Cache, audience: &str) -> Self {
        let validations = ALGORITHMS
            .into_iter()
            .map(|algorithm| {
                let mut validation = Validation::new(algorithm);
                validation.set_audience(&[audience]);
                validation.set_issuer(&[well_known_endpoint.issuer.as_str()]);
                validation.set_required_spec_claims(&REQUIRED_CLAIMS);
                validation.validate_nbf = true;
                validation.leeway = LEEWAY_SECS;
                (algorithm, validation)
            })
            .collect();
        Self {
            internal_end_session_endpoint: well_known_endpoint.end_session_endpoint.clone(),
            well_known_endpoint,
            keys: Arc::new(keys),
            validations,
            _marker: PhantomData,
        }
    }

    /// The provider's endpoints.
    pub fn well_known_endpoint(&self) -> &WellKnownEndpoint {
        &self.well_known_endpoint
    }

    /// Where codes and refresh tokens are exchanged.
    pub fn token_endpoint(&self) -> &str {
        &self.well_known_endpoint.token_endpoint
    }

    /// Where tokens are revoked, if the provider publishes it.
    pub fn revocation_endpoint(&self) -> Option<&str> {
        self.well_known_endpoint.revocation_endpoint.as_deref()
    }

    /// The end-session endpoint at the internal address, for calls from this service itself,
    /// e.g. Keycloak's logout with a refresh token; browsers use
    /// [`WellKnownEndpoint::end_session_endpoint`]. `None` if the provider publishes none.
    pub fn internal_end_session_endpoint(&self) -> Option<&str> {
        self.internal_end_session_endpoint.as_deref()
    }

    /// Verifies `raw_token` and returns its payload untouched.
    ///
    /// Only an unreachable provider is not the token's fault; every other failure means the
    /// token cannot be trusted, so it is reported as invalid with the specific reason.
    async fn verify_payload(&self, raw_token: &str) -> Result<Value, JwtVerificationError> {
        let header = decode_header(raw_token)
            .map_err(|_| JwtVerificationError::Invalid("malformed token header".to_string()))?;

        // The key id selects which JWK signed this token; without one there is nothing to look up.
        let kid = header
            .kid
            .ok_or_else(|| JwtVerificationError::Invalid("token has no key id".to_string()))?;

        let key = self.keys.key(&kid).await?;
        if header.alg != key.algorithm {
            return Err(JwtVerificationError::Invalid(format!(
                "key '{kid}' signs with {:?}, not {:?}",
                key.algorithm, header.alg
            )));
        }
        let validation = self.validations.get(&key.algorithm).ok_or_else(|| {
            JwtVerificationError::Invalid(format!("unsupported algorithm {:?}", header.alg))
        })?;

        let payload = decode::<Value>(raw_token, &key.key, validation)
            .map(|token| token.claims)
            .map_err(|error| JwtVerificationError::Invalid(format!("{:?}", error.into_kind())))?;
        check_issued_at(&payload)?;
        Ok(payload)
    }
}

/// Requires `payload` to have an `iat` that is not in the future: a token "issued" later than
/// now was not made by a provider whose clock agrees with ours.
fn check_issued_at(payload: &Value) -> Result<(), JwtVerificationError> {
    let iat = payload
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(JwtVerificationError::MissingClaim("iat"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if iat > now + LEEWAY_SECS {
        return Err(JwtVerificationError::Invalid(
            "token issued in the future".to_string(),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl<P: ProviderClaims> JwtVerifier for OidcJwtVerifier<P>
where
    P::Claims: Send,
{
    type Claims = P::Claims;
    async fn verify(&self, raw_token: &str) -> Result<P::Claims, JwtVerificationError> {
        let payload = self.verify_payload(raw_token).await?;
        P::claims(payload)
    }
}

/// `url` moved from under `issuer_url` to under `discovery_url`; unchanged if it is not under
/// `issuer_url` or both are the same.
fn rebase(url: &str, issuer_url: &str, discovery_url: &str) -> String {
    let (public, internal) = (
        issuer_url.trim_end_matches('/'),
        discovery_url.trim_end_matches('/'),
    );
    match url.strip_prefix(public) {
        Some(rest) if public != internal && (rest.is_empty() || rest.starts_with('/')) => {
            format!("{internal}{rest}")
        }
        _ => url.to_owned(),
    }
}

/// The discovery document served from `/.well-known/openid-configuration`.
#[derive(Clone, Debug, Deserialize)]
pub struct WellKnownEndpoint {
    /// The issuer tokens must name in `iss`.
    pub issuer: String,
    /// Where the browser signs in.
    pub authorization_endpoint: String,
    /// Where codes and refresh tokens are exchanged.
    pub token_endpoint: String,
    /// Where the browser signs out (RP-Initiated Logout); not every provider publishes one.
    pub end_session_endpoint: Option<String>,
    /// The provider's public signing keys.
    pub jwks_uri: String,
    /// Where tokens are revoked (RFC 7009); not every provider publishes one.
    pub revocation_endpoint: Option<String>,
}

impl WellKnownEndpoint {
    /// Requires every published endpoint to satisfy `transport`, including the ones only the
    /// browser follows.
    fn check_transport(&self, transport: Transport) -> Result<(), OidcSetupError> {
        transport.check("authorization_endpoint", &self.authorization_endpoint)?;
        transport.check("token_endpoint", &self.token_endpoint)?;
        transport.check("jwks_uri", &self.jwks_uri)?;
        for (name, endpoint) in [
            ("end_session_endpoint", &self.end_session_endpoint),
            ("revocation_endpoint", &self.revocation_endpoint),
        ] {
            if let Some(endpoint) = endpoint {
                transport.check(name, endpoint)?;
            }
        }
        Ok(())
    }

    /// Moves the endpoints this service calls itself (token, keys, revocation) from
    /// `issuer_url` to `discovery_url` when published under the former: inside a container
    /// network the public address is often unreachable. Browser-facing endpoints stay.
    fn rebase_server_endpoints(&mut self, issuer_url: &str, discovery_url: &str) {
        let revocation = self.revocation_endpoint.as_mut();
        for endpoint in [&mut self.token_endpoint, &mut self.jwks_uri]
            .into_iter()
            .chain(revocation)
        {
            *endpoint = rebase(endpoint, issuer_url, discovery_url);
        }
    }

    /// Reads the discovery document of `issuer_url` (e.g.
    /// `https://keycloak.example.com/realms/some-realm`) with `client`; the well-known path is
    /// appended here.
    pub async fn fetch(
        client: &reqwest::Client,
        issuer_url: &str,
    ) -> Result<Self, WellKnownEndpointError> {
        let url = format!("{}/{}", issuer_url.trim_end_matches('/'), DISCOVERY_PATH);

        client
            .get(url)
            .send()
            .await
            .map_err(WellKnownEndpointError::Unreachable)?
            .error_for_status()
            .map_err(WellKnownEndpointError::ErrorStatus)?
            .json()
            .await
            .map_err(WellKnownEndpointError::Malformed)
    }
}

/// A failure reading the discovery document at startup.
#[derive(Debug, Error)]
pub enum WellKnownEndpointError {
    /// The connection failed.
    #[error("Could not reach the well-known endpoint: {}", with_causes(.0))]
    Unreachable(reqwest::Error),
    /// The endpoint answered with an error status.
    #[error("The well-known endpoint returned an error: {}", with_causes(.0))]
    ErrorStatus(reqwest::Error),
    /// The body is not a discovery document.
    #[error("The well-known endpoint is not valid JSON: {}", with_causes(.0))]
    Malformed(reqwest::Error),
}

/// A failure setting up the verifier during startup.
#[derive(Debug, Error)]
pub enum OidcSetupError {
    /// The discovery document could not be read.
    #[error(transparent)]
    Discovery(#[from] WellKnownEndpointError),
    /// The discovery document names another issuer than configured.
    #[error("The discovery document is for issuer '{found}', not '{expected}'")]
    IssuerMismatch {
        /// The configured issuer.
        expected: String,
        /// The issuer the document names.
        found: String,
    },
    /// The signing keys could not be loaded.
    #[error("Could not load the signing keys: {0}")]
    SigningKeys(#[from] SourceError),
    /// A provider URL is not HTTPS and plain HTTP was not allowed.
    #[error("The provider's {name} '{url}' is not HTTPS")]
    InsecureUrl {
        /// Which URL, e.g. `jwks_uri`.
        name: &'static str,
        /// The URL itself.
        url: String,
    },
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use async_trait::async_trait;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::jwk::JwkSet;
    use ring::{
        hmac,
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::cache::{Cache, JwksSource, SourceError};

    /// The tests' issuer.
    const ISSUER: &str = "https://idp.example/realms/test";
    /// The tests' audience.
    const AUDIENCE: &str = "api";

    /// The current time in Unix seconds.
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// `value` as base64url JSON, as in a JWT.
    fn encode(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }

    /// A signing key generated per test, published under its `kid`.
    struct TestKey {
        /// The key id tokens name.
        kid: &'static str,
        /// The private and public key.
        pair: Ed25519KeyPair,
    }

    impl TestKey {
        /// A fresh Ed25519 key with id `kid`.
        fn new(kid: &'static str) -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self {
                kid,
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            }
        }

        /// The public key as a JWK.
        fn jwk(&self) -> Value {
            json!({
                "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": self.kid,
                "x": URL_SAFE_NO_PAD.encode(self.pair.public_key().as_ref()),
            })
        }

        /// A JWT of `header` and `claims`, signed with this key.
        fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!("{}.{}", encode(header), encode(claims));
            let signature = self.pair.sign(input.as_bytes());
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
        }

        /// A correctly signed JWT carrying `claims`.
        fn token(&self, claims: &Value) -> String {
            self.sign(
                &json!({ "alg": "EdDSA", "typ": "JWT", "kid": self.kid }),
                claims,
            )
        }
    }

    /// A key source that always returns the same set.
    #[derive(Debug)]
    struct StaticSource(JwkSet);

    #[async_trait]
    impl JwksSource for StaticSource {
        async fn fetch(&self) -> Result<JwkSet, SourceError> {
            Ok(self.0.clone())
        }
    }

    /// Hands payloads back untouched.
    struct Raw;

    impl ProviderClaims for Raw {
        type Claims = Value;
        fn claims(payload: Value) -> Result<Value, JwtVerificationError> {
            Ok(payload)
        }
    }

    /// A verifier for [`ISSUER`] and [`AUDIENCE`] trusting the `published` keys.
    async fn verifier(published: &[&TestKey]) -> OidcJwtVerifier<Raw> {
        let keys: Vec<Value> = published.iter().map(|key| key.jwk()).collect();
        let set: JwkSet = serde_json::from_value(json!({ "keys": keys })).unwrap();
        let cache = Cache::new(StaticSource(set), KEY_TTL, KEY_MIN_REFRESH_INTERVAL)
            .await
            .unwrap();
        let endpoint = |path: &str| format!("{ISSUER}/{path}");
        let well_known = WellKnownEndpoint {
            issuer: ISSUER.to_owned(),
            authorization_endpoint: endpoint("auth"),
            token_endpoint: endpoint("token"),
            end_session_endpoint: Some(endpoint("logout")),
            jwks_uri: endpoint("certs"),
            revocation_endpoint: Some(endpoint("revoke")),
        };
        OidcJwtVerifier::from_parts(well_known, cache, AUDIENCE)
    }

    /// Valid claims for a fresh token.
    fn claims() -> Value {
        let now = now();
        json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "iat": now, "exp": now + 300 })
    }

    /// [`claims`] without `claim`.
    fn without(claim: &str) -> Value {
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove(claim);
        claims
    }

    /// [`claims`] with `claim` set to `value`.
    fn with(claim: &str, value: Value) -> Value {
        let mut claims = claims();
        claims[claim] = value;
        claims
    }

    /// Asserts `verifier` refuses `token` as invalid; `why` names the case on failure.
    async fn assert_refused(verifier: &OidcJwtVerifier<Raw>, token: &str, why: &str) {
        let result = verifier.verify(token).await;
        assert!(
            matches!(result, Err(JwtVerificationError::Invalid(_))),
            "{why}: {result:?}"
        );
    }

    #[test]
    fn given_https_only_then_http_urls_are_refused() {
        let transport = Transport::HttpsOnly;
        assert!(
            transport
                .check("issuer", "https://idp.example/realms/test")
                .is_ok()
        );
        assert!(matches!(
            transport.check("issuer", "http://idp.example/realms/test"),
            Err(OidcSetupError::InsecureUrl { name: "issuer", .. })
        ));
        assert!(transport.check("issuer", "not a url").is_err());
    }

    #[test]
    fn given_insecure_http_allowed_then_http_and_https_are_accepted() {
        let transport = Transport::AllowInsecureHttp;
        assert!(
            transport
                .check("issuer", "http://keycloak:8080/realms/test")
                .is_ok()
        );
        assert!(
            transport
                .check("issuer", "https://idp.example/realms/test")
                .is_ok()
        );
        assert!(transport.check("issuer", "ftp://idp.example").is_err());
    }

    #[tokio::test]
    async fn given_http_urls_without_allowing_them_then_setup_is_refused_before_any_request() {
        let result = OidcJwtVerifier::<Raw>::new(
            "http://unreachable.invalid/realms/test",
            reqwest::Client::new(),
            AUDIENCE.to_owned(),
            Transport::HttpsOnly,
        )
        .await;
        assert!(matches!(result, Err(OidcSetupError::InsecureUrl { .. })));
    }

    #[test]
    fn given_one_http_endpoint_in_the_discovery_document_then_https_only_refuses_it() {
        let endpoint = |path: &str| format!("https://idp.example/realms/test/{path}");
        let mut endpoints = WellKnownEndpoint {
            issuer: "https://idp.example/realms/test".into(),
            authorization_endpoint: endpoint("auth"),
            token_endpoint: endpoint("token"),
            end_session_endpoint: Some(endpoint("logout")),
            jwks_uri: endpoint("certs"),
            revocation_endpoint: Some(endpoint("revoke")),
        };
        assert!(endpoints.check_transport(Transport::HttpsOnly).is_ok());
        endpoints.jwks_uri = "http://idp.example/realms/test/certs".into();
        assert!(matches!(
            endpoints.check_transport(Transport::HttpsOnly),
            Err(OidcSetupError::InsecureUrl {
                name: "jwks_uri",
                ..
            })
        ));
    }

    #[test]
    fn given_a_provider_without_logout_or_revocation_endpoints_then_discovery_accepts_it() {
        let endpoints: WellKnownEndpoint = serde_json::from_value(json!({
            "issuer": "https://idp.example",
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://idp.example/keys",
        }))
        .unwrap();
        assert_eq!(endpoints.end_session_endpoint, None);
        assert_eq!(endpoints.revocation_endpoint, None);
        assert!(endpoints.check_transport(Transport::HttpsOnly).is_ok());
    }

    #[test]
    fn given_a_separate_discovery_address_then_only_server_endpoints_move_to_it() {
        let public = "http://localhost:8080/realms/test";
        let internal = "http://keycloak:8080/realms/test";
        let mut endpoints = WellKnownEndpoint {
            issuer: public.into(),
            authorization_endpoint: format!("{public}/protocol/openid-connect/auth"),
            token_endpoint: format!("{public}/protocol/openid-connect/token"),
            end_session_endpoint: Some(format!("{public}/protocol/openid-connect/logout")),
            jwks_uri: "http://keycloak:8080/realms/test/protocol/openid-connect/certs".into(),
            revocation_endpoint: Some(format!("{public}/protocol/openid-connect/revoke")),
        };
        endpoints.rebase_server_endpoints(public, internal);

        assert_eq!(
            endpoints.token_endpoint,
            format!("{internal}/protocol/openid-connect/token")
        );
        assert_eq!(
            endpoints.revocation_endpoint,
            Some(format!("{internal}/protocol/openid-connect/revoke"))
        );
        assert_eq!(
            endpoints.jwks_uri,
            format!("{internal}/protocol/openid-connect/certs")
        );
        assert_eq!(
            endpoints.authorization_endpoint,
            format!("{public}/protocol/openid-connect/auth")
        );
        assert_eq!(
            endpoints.end_session_endpoint,
            Some(format!("{public}/protocol/openid-connect/logout"))
        );
    }

    #[test]
    fn given_an_endpoint_under_the_issuer_then_rebase_moves_it_to_the_discovery_address() {
        let (public, internal) = (
            "http://localhost:8080/realms/test",
            "http://kc:8080/realms/test",
        );
        assert_eq!(
            rebase(
                &format!("{public}/protocol/openid-connect/logout"),
                public,
                internal
            ),
            format!("{internal}/protocol/openid-connect/logout")
        );
        assert_eq!(
            rebase("https://elsewhere.example/logout", public, internal),
            "https://elsewhere.example/logout"
        );
        assert_eq!(
            rebase(&format!("{public}/x"), public, public),
            format!("{public}/x")
        );
    }

    #[test]
    fn given_a_lookalike_prefix_then_the_endpoint_is_left_alone() {
        let mut endpoints = WellKnownEndpoint {
            issuer: "http://idp/realms/test".into(),
            authorization_endpoint: String::new(),
            token_endpoint: "http://idp/realms/test-other/token".into(),
            end_session_endpoint: None,
            jwks_uri: String::new(),
            revocation_endpoint: None,
        };
        endpoints.rebase_server_endpoints("http://idp/realms/test", "http://internal/realms/test");
        assert_eq!(
            endpoints.token_endpoint,
            "http://idp/realms/test-other/token"
        );
    }

    #[tokio::test]
    async fn given_a_valid_token_then_its_payload_is_returned() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let payload = verifier.verify(&key.token(&claims())).await.unwrap();
        assert_eq!(payload["sub"], "user-1");
    }

    #[tokio::test]
    async fn given_a_missing_or_wrong_audience_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        assert_refused(&verifier, &key.token(&without("aud")), "no aud").await;
        assert_refused(
            &verifier,
            &key.token(&with("aud", json!("other"))),
            "other aud",
        )
        .await;
    }

    #[tokio::test]
    async fn given_a_missing_or_wrong_issuer_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        assert_refused(&verifier, &key.token(&without("iss")), "no iss").await;
        let other = with("iss", json!("https://evil.example/realms/test"));
        assert_refused(&verifier, &key.token(&other), "other iss").await;
    }

    #[tokio::test]
    async fn given_a_missing_iat_or_exp_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        assert!(matches!(
            verifier.verify(&key.token(&without("iat"))).await,
            Err(JwtVerificationError::MissingClaim("iat"))
        ));
        assert_refused(&verifier, &key.token(&without("exp")), "no exp").await;
        let future = with("iat", json!(now() + LEEWAY_SECS + 60));
        assert_refused(&verifier, &key.token(&future), "iat in the future").await;
    }

    #[tokio::test]
    async fn given_an_expired_token_then_only_the_leeway_is_tolerated() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let just_expired = with("exp", json!(now() - LEEWAY_SECS / 2));
        assert!(verifier.verify(&key.token(&just_expired)).await.is_ok());
        let expired = with("exp", json!(now() - LEEWAY_SECS - 5));
        assert_refused(&verifier, &key.token(&expired), "expired").await;
    }

    #[tokio::test]
    async fn given_a_token_that_is_not_valid_yet_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let future = with("nbf", json!(now() + LEEWAY_SECS + 60));
        assert_refused(&verifier, &key.token(&future), "nbf in the future").await;
    }

    #[tokio::test]
    async fn given_alg_none_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let header = encode(&json!({ "alg": "none", "kid": "k1" }));
        let token = format!("{header}.{}.", encode(&claims()));
        assert_refused(&verifier, &token, "alg none").await;
    }

    /// The classic key-confusion attack: an HMAC signature keyed with the public key.
    #[tokio::test]
    async fn given_hs256_signed_with_the_public_key_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let input = format!(
            "{}.{}",
            encode(&json!({ "alg": "HS256", "typ": "JWT", "kid": "k1" })),
            encode(&claims())
        );
        let mac = hmac::Key::new(hmac::HMAC_SHA256, key.pair.public_key().as_ref());
        let signature = hmac::sign(&mac, input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
        assert_refused(&verifier, &token, "HS256 with the public key").await;
    }

    #[tokio::test]
    async fn given_a_signature_by_another_key_then_it_is_refused() {
        let published = TestKey::new("k1");
        let attacker = TestKey::new("k1");
        let verifier = verifier(&[&published]).await;
        assert_refused(
            &verifier,
            &attacker.token(&claims()),
            "foreign key, same kid",
        )
        .await;
    }

    #[tokio::test]
    async fn given_no_or_an_unknown_key_id_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let no_kid = key.sign(&json!({ "alg": "EdDSA" }), &claims());
        assert_refused(&verifier, &no_kid, "no kid").await;
        let unknown = TestKey::new("k2");
        assert_refused(&verifier, &unknown.token(&claims()), "unknown kid").await;
    }

    #[tokio::test]
    async fn given_a_tampered_payload_then_it_is_refused() {
        let key = TestKey::new("k1");
        let verifier = verifier(&[&key]).await;
        let token = key.token(&claims());
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = encode(&with("sub", json!("admin")));
        parts[1] = &forged;
        assert_refused(&verifier, &parts.join("."), "tampered payload").await;
    }
}
