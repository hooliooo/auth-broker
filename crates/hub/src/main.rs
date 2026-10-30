//! The central auth hub, shared by every app kind. It holds one provider client per kind, signs
//! users in, keeps their tokens (sealed in Redis), refreshes them, and forwards API calls to
//! each kind's API. Browsers only visit it during sign-in and logout; everything else arrives
//! from site edges as signed requests.
//!
//! `hub validate-registry <dir>` checks a registry directory and exits non-zero if it would
//! be refused, so each team can run it in CI before changing its file.
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use common::{metrics::Description, request_id, shutdown};
use reqwest::{Client, redirect};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{
    catalog::Runtime,
    config::{ClientCredentials, HubConfig},
    state::AppState,
};

mod broker;
mod catalog;
mod config;
mod error;
mod health;
mod login;
mod proxy;
mod ratelimit;
mod session;
mod signed;
mod state;
mod tokens;

/// Counts every heap allocation, for the metrics page; measurement builds only.
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOCATOR: common::alloc::Counting = common::alloc::Counting;

/// The hub's own counters, beyond requests and their durations.
const COUNTERS: &[Description] = &[
    (
        "hub_sign_ins_total",
        "counter",
        "Completed and failed sign-ins, by app kind.",
    ),
    (
        "hub_token_refreshes_total",
        "counter",
        "Access token refreshes at the provider, by app kind and outcome.",
    ),
    (
        "hub_logouts_total",
        "counter",
        "Logouts, by app kind and whether the provider's session was ended too.",
    ),
    (
        "hub_backchannel_logouts_total",
        "counter",
        "Back-channel logout calls from the provider, by app kind and outcome.",
    ),
    (
        "hub_tokens_issued_total",
        "counter",
        "Access tokens handed to direct kinds' edges, by app kind.",
    ),
    (
        "hub_rate_limited_total",
        "counter",
        "Sign-in starts refused by a rate limit, by scope.",
    ),
];

/// Runs the hub; a failure is printed with its message, not Rust's debug form, and exits with 1.
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Standard error, not the log: a command, or a failure before logging is set up.
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Reads the settings and registry, connects to Redis, and serves until shut down; or runs
/// `validate-registry`.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [command, dir] = args.as_slice()
        && command == "validate-registry"
    {
        let catalog = catalog::load(dir)?;
        println!(
            "registry {} is valid: {} app kinds, {} sites",
            catalog.version,
            catalog.registry.apps().len(),
            catalog.registry.sites().len()
        );
        return Ok(());
    }

    tracing_subscriber::fmt()
        // `info` unless RUST_LOG says otherwise; the default would drop every warning.
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    common::random::random_token()?;

    let config = HubConfig::from_env()?;
    // The first registry must be valid; later changes that are invalid are ignored and logged.
    let initial = catalog::load(&config.registry_dir)?;
    info!(
        version = %initial.version,
        apps = initial.registry.apps().len(),
        sites = initial.registry.sites().len(),
        "registry loaded"
    );

    let idp = Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let redis = redis::Client::open(config.redis_uri.as_str())?
        .get_connection_manager()
        .await?;
    let (listen, metrics_addr) = (config.listen, config.metrics_addr);

    let state = AppState {
        idp,
        redis,
        runtime: Arc::new(Runtime::new(initial)),
        config: Arc::new(config),
    };
    // Builds every kind's provider client in the background and keeps the registry current;
    // the hub reports not-ready until all clients exist, instead of failing to start.
    tokio::spawn(catalog::maintain(state.clone()));

    let app = Router::new()
        .merge(login::routes())
        .merge(broker::routes())
        .merge(proxy::routes())
        .merge(health::routes())
        .route("/.well-known/jwks.json", get(jwks));
    #[cfg(feature = "metrics")]
    let app = app.layer(middleware::from_fn(common::metrics::track));
    // Outermost, so every response carries an id; an edge's id is kept.
    let app = app
        .layer(middleware::from_fn(request_id::assign))
        .with_state(state);

    #[cfg(feature = "metrics")]
    tokio::spawn(common::metrics::serve(metrics_addr, "hub", COUNTERS));
    #[cfg(not(feature = "metrics"))]
    let _ = (metrics_addr, COUNTERS);

    let listener = TcpListener::bind(listen).await?;
    info!("hub listening on {}", listener.local_addr()?);
    // The peer address is the fallback client IP for the sign-in rate limit.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown::signal())
    .await?;
    Ok(())
}

/// `GET /.well-known/jwks.json`: the public keys the provider checks the hub's client assertions
/// with; 404 when the hub uses client secrets.
async fn jwks(State(state): State<AppState>) -> Response {
    match &state.config.client_credentials {
        ClientCredentials::PrivateKeyJwt(keys) => Json(keys.jwks()).into_response(),
        ClientCredentials::PerKindSecret => StatusCode::NOT_FOUND.into_response(),
    }
}
