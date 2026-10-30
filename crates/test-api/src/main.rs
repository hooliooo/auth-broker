//! A stand-in API for tests. Like a real API of one app kind, it verifies every bearer token's
//! signature, issuer and audience with the `oidc` crate, so a token issued for another kind is
//! refused. It then echoes what reached it.
//!
//! `/slow?seconds=N` streams one chunk per second, to prove long responses survive both hops.
//! With `REVEAL_TOKEN=true` (tests only) it also returns the raw token, so tests can present it
//! to another kind's API.
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::provider::{IdentityProvider, StandardOidc};
use oidc::{OidcJwtVerifier, ProviderClaims, Transport, oidc::JwtVerifier};
use ring::digest::{SHA256, digest};
use serde_json::{Map, Value, json};

/// Hands the verified payload back untouched, so the echo can show every claim.
struct RawPayload;

impl ProviderClaims for RawPayload {
    type Claims = Value;

    fn claims(payload: Value) -> Result<Value, oidc::oidc::JwtVerificationError> {
        Ok(payload)
    }
}

/// The API's state.
struct Api {
    /// Verifies bearer tokens for this API's audience.
    verifier: OidcJwtVerifier<RawPayload>,
    /// `REVEAL_TOKEN=true`: echo the raw token too (tests only).
    reveal_token: bool,
    /// `EXPECTED_CLIENT`: the token's `azp` must be this kind's client, if set.
    expected_client: Option<String>,
    /// `EXPECTED_SITE`: for one site's own API, the token must name exactly
    /// this site, if set.
    expected_site: Option<String>,
    /// `IDENTITY_PROVIDER` (`oidc` or `keycloak`): how tokens mark their type and sites.
    provider: Box<dyn IdentityProvider>,
}

/// The value of variable `name`; panics if unset.
fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name}"))
}

/// Serves until asked to stop. As a container's first process it would otherwise ignore SIGTERM
/// and be killed only after the grace period.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::select! {
        result = run() => result,
        () = common::shutdown::signal() => Ok(()),
    }
}

/// Discovers the identity provider (retrying until it is up) and serves the echo.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = var("ISSUER_URI");
    let discovery = std::env::var("DISCOVERY_URI").unwrap_or_else(|_| issuer.clone());
    let audience = var("EXPECTED_AUDIENCE");
    let transport = match std::env::var("ALLOW_INSECURE_HTTP").as_deref() {
        Ok("true") => Transport::AllowInsecureHttp,
        _ => Transport::HttpsOnly,
    };
    // Keycloak may still be starting: retry discovery instead of exiting.
    let verifier = loop {
        match OidcJwtVerifier::with_discovery_url(
            &issuer,
            &discovery,
            reqwest::Client::new(),
            audience.clone(),
            transport,
        )
        .await
        {
            Ok(verifier) => break verifier,
            Err(error) => {
                eprintln!("discovery not ready: {error}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    let api = Arc::new(Api {
        verifier,
        reveal_token: std::env::var("REVEAL_TOKEN").is_ok_and(|v| v == "true"),
        expected_client: std::env::var("EXPECTED_CLIENT").ok(),
        expected_site: std::env::var("EXPECTED_SITE").ok(),
        provider: match std::env::var("IDENTITY_PROVIDER").as_deref() {
            Ok("keycloak") => Box::new(keycloak::Keycloak),
            _ => Box::new(StandardOidc),
        },
    });
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let app = Router::new().fallback(any(echo)).with_state(api);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Verifies `request`'s bearer token with `api`'s verifier, like a real API, and echoes what
/// reached it; `/slow?seconds=N` streams instead.
async fn echo(State(api): State<Arc<Api>>, request: Request) -> Response {
    let mut headers = Map::new();
    let mut bearer = None;
    for (name, value) in request.headers() {
        let value = value.to_str().unwrap_or("<binary>");
        if name == "authorization" {
            bearer = value.strip_prefix("Bearer ").map(str::to_owned);
            continue;
        }
        headers.insert(name.as_str().to_owned(), Value::String(value.to_owned()));
    }
    let Some(token) = bearer else {
        return (StatusCode::UNAUTHORIZED, "no bearer token").into_response();
    };
    let claims = match api.verifier.verify(&token).await {
        Ok(claims) => claims,
        Err(error) => {
            return (StatusCode::UNAUTHORIZED, format!("token refused: {error}")).into_response();
        }
    };
    // Only access tokens: an ID or refresh token is never accepted in their place.
    if !api.provider.is_access_token(&claims) {
        return (
            StatusCode::UNAUTHORIZED,
            "token refused: not an access token",
        )
            .into_response();
    }
    if let Some(client) = &api.expected_client
        && claims["azp"] != client.as_str()
    {
        return (
            StatusCode::UNAUTHORIZED,
            "token refused: issued to another client",
        )
            .into_response();
    }
    if let Some(site) = &api.expected_site
        && api.provider.sites(&claims) != [site.as_str()]
    {
        return (StatusCode::UNAUTHORIZED, "token refused: not for this site").into_response();
    }

    let (method, path, query) = (
        request.method().as_str().to_owned(),
        request.uri().path().to_owned(),
        request.uri().query().map(str::to_owned),
    );
    if path == "/slow" {
        let seconds: u64 = query
            .as_deref()
            .and_then(|q| q.strip_prefix("seconds="))
            .and_then(|n| n.parse().ok())
            .unwrap_or(5);
        let chunks = futures_util::stream::unfold(0u64, move |sent| async move {
            if sent == seconds {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((
                Ok::<_, std::io::Error>(format!("chunk {}\n", sent + 1)),
                sent + 1,
            ))
        });
        return Body::from_stream(chunks).into_response();
    }

    let body_bytes = to_bytes(request.into_body(), 10 * 1024 * 1024)
        .await
        .map_or(0, |b| b.len());
    let mut bearer_info = json!({
        "fingerprint": URL_SAFE_NO_PAD.encode(&digest(&SHA256, token.as_bytes()).as_ref()[..12]),
        "claims": claims,
    });
    if api.reveal_token {
        bearer_info["token"] = Value::String(token);
    }
    Json(json!({
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "bearer": bearer_info,
        "body_bytes": body_bytes,
    }))
    .into_response()
}
