//! The per-kind edge: one deployment serves every site of an app kind, each under its own
//! origin, and tells them apart by the request's host.
//!
//! It holds no refresh tokens, talks to no identity provider and stores nothing. It keeps each
//! site's session cookie and CSRF check, hands sign-in off to the hub, and forwards API calls
//! to the hub, or for a direct kind to the site's own API, signing every hub request with the
//! kind's key for the site it is for. It reads the same registry as the hub to know its sites.
//!
//! `edge keygen <app-id> <key-file>` creates the kind's edge key and prints its registry line.
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use axum::{Router, middleware};
use common::{metrics::Description, request_id, shutdown};
use reqwest::{Client, redirect};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{config::EdgeConfig, hub::HubClient, sites::Sites, state::AppState};

mod auth;
mod config;
mod direct;
mod error;
mod health;
mod hub;
mod keygen;
mod proxy;
mod sites;
mod state;

/// Counts every heap allocation, for the metrics page; measurement builds only.
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOCATOR: common::alloc::Counting = common::alloc::Counting;

/// The edge's own counters, beyond requests and their durations.
const COUNTERS: &[Description] = &[(
    "edge_token_cache_total",
    "counter",
    "Access token lookups for direct kinds, by whether the cache answered.",
)];

/// Runs the edge; a failure is printed with its message, not Rust's debug form, and exits with 1.
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

/// Reads the settings and serves until shut down; or runs `keygen`.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("keygen") {
        return keygen::run(&args[1..]);
    }

    tracing_subscriber::fmt()
        // `info` unless RUST_LOG says otherwise; the default would drop every warning.
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    common::random::random_token()?;

    let config = EdgeConfig::from_env()?;
    let signer = config::load_signer(&config)?;
    let public_key = signer.public_key();
    // No cap on total duration, so long downloads and streams through the edge are never cut
    // off; only connecting and silence between bytes are bounded.
    let http = Client::builder()
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(120))
        .build()?;
    let hub = Arc::new(HubClient::new(
        http,
        config.hub_internal_url.clone(),
        signer,
    ));
    // Refuses to start with a key the registry does not list for this kind.
    let sites = Arc::new(Sites::load(
        &config.app_id,
        &config.registry_dir,
        &public_key,
        config.registry_from_hub.then(|| hub.clone()),
    )?);
    if config.registry_from_hub {
        tokio::spawn(sites::follow_hub(
            sites.clone(),
            config.reload_interval,
            config.sync_interval,
        ));
    } else {
        tokio::spawn(sites::maintain(sites.clone(), config.reload_interval));
    }
    let (listen, metrics_addr) = (config.listen, config.metrics_addr);
    info!(app = %config.app_id, sites = sites.count(), "edge configured");

    let api = Client::builder()
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(config.api_read_timeout_secs))
        .build()?;
    let state = AppState {
        api,
        sites,
        tokens: Arc::default(),
        bulkheads: Arc::default(),
        hub,
        config: Arc::new(config),
    };
    let app = Router::new()
        .merge(auth::routes())
        .merge(proxy::routes())
        .merge(health::routes())
        .layer(middleware::from_fn(common::csrf::require_header));
    #[cfg(feature = "metrics")]
    let app = app.layer(middleware::from_fn(common::metrics::track));
    let app = app
        // Outermost, so even requests the CSRF check refuses get an id; it travels on to the hub.
        .layer(middleware::from_fn(request_id::assign))
        .with_state(state);

    #[cfg(feature = "metrics")]
    tokio::spawn(common::metrics::serve(metrics_addr, "edge", COUNTERS));
    #[cfg(not(feature = "metrics"))]
    let _ = (metrics_addr, COUNTERS);

    let listener = TcpListener::bind(listen).await?;
    info!("edge listening on {}", listener.local_addr()?);
    // The peer address is the fallback client IP for the API's X-Forwarded-For.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown::signal())
    .await?;
    Ok(())
}
