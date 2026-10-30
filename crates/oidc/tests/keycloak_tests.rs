//! Verifies real tokens from the dev stack's Keycloak (`auth-api`'s
//! `crates/bff/docker-compose.yml`). Run with that stack up: `cargo test -p oidc --features e2e`.
#![cfg(feature = "e2e")]

use oidc::{
    OidcJwtVerifier, ProviderClaims, Transport,
    oidc::{JwtVerificationError, JwtVerifier},
};
use serde_json::Value;

const ISSUER: &str = "http://localhost:8080/realms/test";
const API_AUDIENCE: &str = "authentication.layer.api";

/// Hands the verified payload back untouched.
struct Raw;

impl ProviderClaims for Raw {
    type Claims = Value;
    fn claims(payload: Value) -> Result<Value, JwtVerificationError> {
        Ok(payload)
    }
}

/// A verifier for the dev Keycloak, accepting tokens for `audience`.
async fn verifier(audience: &str) -> OidcJwtVerifier<Raw> {
    OidcJwtVerifier::new(
        ISSUER,
        reqwest::Client::new(),
        audience.to_owned(),
        Transport::AllowInsecureHttp,
    )
    .await
    .expect("the dev Keycloak is running")
}

/// A service-account access token for the end-to-end client, from `verifier`'s token
/// endpoint; its audience includes the API.
async fn service_token(verifier: &OidcJwtVerifier<Raw>) -> String {
    let response: Value = reqwest::Client::new()
        .post(verifier.token_endpoint())
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "end.to.end.client"),
            ("client_secret", "end.to.end.client.secret"),
        ])
        .send()
        .await
        .expect("Keycloak is reachable")
        .json()
        .await
        .expect("a token response");
    response["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned()
}

#[tokio::test]
async fn given_an_access_token_for_the_api_then_it_is_accepted() {
    let verifier = verifier(API_AUDIENCE).await;
    let token = service_token(&verifier).await;

    let payload = verifier
        .verify(&token)
        .await
        .expect("Keycloak's token verifies");

    assert_eq!(payload["azp"], "end.to.end.client");
    assert_eq!(payload["typ"], "Bearer");
}

#[tokio::test]
async fn given_an_access_token_for_another_audience_then_it_is_refused() {
    let token = service_token(&verifier(API_AUDIENCE).await).await;
    let other_api = verifier("some.other.api").await;

    let result = other_api.verify(&token).await;

    assert!(
        matches!(result, Err(JwtVerificationError::Invalid(_))),
        "{result:?}"
    );
}
