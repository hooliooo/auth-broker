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
use registry_store::{InstallationWrite, Store};
use reqwest::{Client, redirect};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{
    catalog::Runtime,
    config::{ClientCredentials, HubConfig},
    state::AppState,
};

mod admin;
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
        "Completed and failed sign-ins, by app kind and installation access type (web or native).",
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
/// `validate-registry <dir>` or `import-registry <dir>`.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [command, dir] = args.as_slice()
        && command == "import-registry"
    {
        return import_registry(dir).await;
    }
    if let [command, dir] = args.as_slice()
        && command == "validate-registry"
    {
        let catalog = catalog::load(dir)?;
        println!(
            "registry {} is valid: {} app kinds, {} sites",
            catalog.version,
            catalog.registry.apps().len(),
            catalog.registry.site_count()
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
    // With a store, the files hold the app kinds and the store the installations.
    let store = match &config.registry_database_url {
        Some(url) => {
            let store = Store::connect(url).await?;
            store.migrate().await?;
            Some(store)
        }
        None => None,
    };
    // The first registry must be valid; later changes that are invalid are ignored and logged.
    let initial = match &store {
        Some(store) => catalog::load_with_store(&config.registry_dir, store).await?,
        None => catalog::load(&config.registry_dir)?,
    };
    info!(
        version = %initial.version,
        apps = initial.registry.apps().len(),
        sites = initial.registry.site_count(),
        "registry loaded"
    );

    let idp = Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let redis = redis::Client::open(config.redis_uri.as_str())?
        .get_connection_manager()
        .await?;
    let (listen, metrics_addr, admin_addr) =
        (config.listen, config.metrics_addr, config.admin_addr);

    let state = AppState {
        idp,
        redis,
        runtime: Arc::new(Runtime::new(initial)),
        config: Arc::new(config),
        store,
        admin_verifier: Arc::default(),
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
        .with_state(state.clone());

    #[cfg(feature = "metrics")]
    tokio::spawn(common::metrics::serve(metrics_addr, "hub", COUNTERS));
    #[cfg(not(feature = "metrics"))]
    let _ = (metrics_addr, COUNTERS);

    // The registry admin API, on its own address and only with a store.
    if let Some(addr) = admin_addr.filter(|_| state.store.is_some()) {
        let admin = admin::routes()
            .layer(middleware::from_fn(request_id::assign))
            .with_state(state.clone());
        let listener = TcpListener::bind(addr).await?;
        info!("registry admin API listening on {}", listener.local_addr()?);
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, admin)
                .with_graceful_shutdown(shutdown::signal())
                .await
            {
                tracing::error!(%error, "registry admin API stopped");
            }
        });
    }

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

/// Seeds the store at `REGISTRY_DATABASE_URL` with the installations in the registry files in
/// `dir`, validated as a whole first: creates or updates each, and adds the keys it lacks.
async fn import_registry(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("REGISTRY_DATABASE_URL")
        .map_err(|_| "import-registry needs REGISTRY_DATABASE_URL")?;
    let registry = catalog::load(dir)?.registry;
    let mut imports = Vec::new();
    for site in registry.sites() {
        let app = registry
            .app(&site.app_id)
            .ok_or("a site without its kind")?;
        let (host, bare_host) = common::registry::web_hosts(site)
            .map_or((None, None), |(host, bare)| (Some(host), bare));
        let write = InstallationWrite {
            id: site.id.clone(),
            kind: site.app_id.clone(),
            tenant: site.tenant.clone(),
            enabled: site.enabled,
            origin: site
                .origin()
                .map(|origin| origin.as_str().trim_end_matches('/').to_owned()),
            host,
            bare_host,
            api_url: site.api_url.as_ref().map(|url| url.as_str().to_owned()),
            login_per_minute: (site.login_per_minute != app.login_per_minute)
                .then(|| i64::try_from(site.login_per_minute).unwrap_or(i64::MAX)),
        };
        let keys = site
            .keys()
            .iter()
            .map(|key| (key.key, key.id.clone()))
            .collect();
        imports.push((write, keys));
    }
    let store = Store::connect(&url).await?;
    store.migrate().await?;
    let version = store.import(&imports).await?;
    println!(
        "imported {} installations from {dir} at version {version}",
        imports.len()
    );
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
