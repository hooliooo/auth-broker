//! Test-only helpers for the e2e tests, in one small service (from the BFF's e2e stack).
//!
//! - Port 8000, the stand-in API behind the service under test: `/echo/...` answers with what it
//!   received, `/slow` streams one chunk a second.
//! - Port 8000, `/relay/backchannel-logout`: records a back-channel logout token and passes the
//!   call on to the service under test, so a test can replay the token afterwards.
//! - Port 8000, `/faults`: arms a one-shot failure for the Keycloak proxy.
//! - Port 8081, a proxy in front of Keycloak for the service's server-to-server calls; answers an
//!   armed fault instead of forwarding the matching request. With `PROXY_TLS_CERT` and
//!   `PROXY_TLS_KEY` it serves HTTPS with that certificate, so a service that resolves Keycloak's
//!   public name to this proxy reaches it at the same `https://` address as everyone else.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Form, Json, Router,
    body::{Body, Bytes},
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use futures_util::stream;
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// A failure the Keycloak proxy returns once, for the first request whose body contains `matches`.
struct Fault {
    matches: String,
    status: StatusCode,
}

struct Shared {
    http: reqwest::Client,
    keycloak: String,
    backchannel_target: String,
    faults: Mutex<Vec<Fault>>,
    logout_tokens: Mutex<Vec<String>>,
}

type AppState = Arc<Shared>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.into());
    let shared = Arc::new(Shared {
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        keycloak: env("KEYCLOAK_URL", "https://keycloak.broker.localhost"),
        backchannel_target: env(
            "BACKCHANNEL_TARGET",
            "http://hub:8090/auth/backchannel-logout/inspection",
        ),
        faults: Mutex::default(),
        logout_tokens: Mutex::default(),
    });

    let api = Router::new()
        .route("/echo", any(echo))
        .route("/echo/{*rest}", any(echo))
        .route("/slow", get(slow))
        .route("/faults", post(arm_fault))
        .route("/relay/backchannel-logout", post(relay_backchannel_logout))
        .route("/relay/logout-tokens", get(recorded_logout_tokens))
        .with_state(shared.clone());
    let keycloak_proxy = Router::new().fallback(proxy_keycloak).with_state(shared);

    let api_listener = TcpListener::bind("0.0.0.0:8000").await?;
    let proxy_address = SocketAddr::from(([0, 0, 0, 0], 8081));
    let proxy = async {
        match (
            std::env::var("PROXY_TLS_CERT"),
            std::env::var("PROXY_TLS_KEY"),
        ) {
            (Ok(cert), Ok(key)) => {
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
                let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
                axum_server::bind_rustls(proxy_address, tls)
                    .serve(keycloak_proxy.into_make_service())
                    .await
            }
            _ => axum::serve(TcpListener::bind(proxy_address).await?, keycloak_proxy).await,
        }
    };
    let servers = async { tokio::try_join!(axum::serve(api_listener, api).into_future(), proxy) };
    // Stops at once when asked to: as a container's first process, SIGTERM would otherwise be
    // ignored, and an old instance would keep serving, with its own armed faults and recorded
    // tokens, beside its replacement until it is killed.
    tokio::select! {
        result = servers => { result?; }
        () = stop_requested() => {}
    }
    Ok(())
}

/// Completes on SIGTERM (Kubernetes stopping the pod) or Ctrl-C.
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn echo(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let headers: BTreeMap<String, String> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let mut response = Json(json!({
        "method": method.as_str(),
        "path": uri.path(),
        "query": uri.query(),
        "headers": headers,
        "body": String::from_utf8_lossy(&body),
    }))
    .into_response();
    // The service under test must strip this before it reaches the browser.
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("planted=1; Path=/"),
    );
    response
        .headers_mut()
        .insert("x-echo", HeaderValue::from_static("1"));
    response
}

/// `?secs=N`: N chunks, one per second, so the total exceeds any short total timeout while
/// the connection is never silent for long.
async fn slow(Query(query): Query<BTreeMap<String, String>>) -> Response {
    let secs: u64 = query.get("secs").and_then(|s| s.parse().ok()).unwrap_or(12);
    let chunks = stream::unfold(0, move |sent| async move {
        if sent == secs {
            return None;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        Some((
            Ok::<_, std::io::Error>(Bytes::from(format!("{sent}\n"))),
            sent + 1,
        ))
    });
    Body::from_stream(chunks).into_response()
}

/// `{"matches": "<text>", "status": 503}`
async fn arm_fault(State(shared): State<AppState>, Json(body): Json<Value>) -> StatusCode {
    let (Some(matches), Some(status)) = (
        body["matches"].as_str(),
        body["status"]
            .as_u64()
            .and_then(|s| StatusCode::from_u16(s as u16).ok()),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    shared.faults.lock().unwrap().push(Fault {
        matches: matches.to_owned(),
        status,
    });
    StatusCode::NO_CONTENT
}

async fn relay_backchannel_logout(
    State(shared): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> StatusCode {
    let Some(token) = form.get("logout_token") else {
        return StatusCode::BAD_REQUEST;
    };
    shared.logout_tokens.lock().unwrap().push(token.clone());
    match shared
        .http
        .post(&shared.backchannel_target)
        .form(&form)
        .send()
        .await
    {
        Ok(response) => {
            StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        Err(_) => StatusCode::BAD_GATEWAY,
    }
}

async fn recorded_logout_tokens(State(shared): State<AppState>) -> Json<Vec<String>> {
    Json(shared.logout_tokens.lock().unwrap().clone())
}

/// Forwards to Keycloak with the original Host, so the URLs Keycloak publishes for server
/// calls keep pointing at this proxy.
async fn proxy_keycloak(State(shared): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, 1 << 20).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let armed = {
        let mut faults = shared.faults.lock().unwrap();
        let text = String::from_utf8_lossy(&body);
        faults
            .iter()
            .position(|fault| text.contains(&fault.matches))
            .map(|index| faults.remove(index).status)
    };
    if let Some(status) = armed {
        return (status, Json(json!({ "error": "injected_fault" }))).into_response();
    }

    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let mut headers = parts.headers;
    headers.remove(header::CONTENT_LENGTH);
    let forwarded = shared
        .http
        .request(parts.method, format!("{}{path}", shared.keycloak))
        .headers(headers)
        .body(body)
        .send()
        .await;
    let Ok(upstream) = forwarded else {
        return StatusCode::BAD_GATEWAY.into_response();
    };

    let status = upstream.status();
    let mut response_headers = upstream.headers().clone();
    response_headers.remove(header::TRANSFER_ENCODING);
    response_headers.remove(header::CONTENT_LENGTH);
    let bytes = upstream.bytes().await.unwrap_or_default();
    let mut response = (status, bytes).into_response();
    response.headers_mut().extend(response_headers);
    response
}
