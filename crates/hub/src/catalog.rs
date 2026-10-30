//! The live registry and one provider client per app kind.
//!
//! A background task re-reads the registry directory and the client secret files every few
//! seconds. A valid change is swapped in atomically; an invalid one is logged and ignored, so a
//! team's typo never takes the hub down. Clients are built from discovery in the background too,
//! so a provider hiccup delays readiness instead of stopping startup.
//!
//! With a store, the files hold the app kinds only, and installations come from the store: loaded
//! whole at start, then followed change by change, each change applied on top of the indexed
//! registry. The registry is compacted once enough changes accumulate. If the store cannot be
//! reached, the hub keeps serving the version it has.

use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
    time::{Duration, Instant},
};

use common::{
    client::credentials::Credentials,
    registry::{App, Registry, RegistryError},
};
use oidc::{OidcJwtVerifier, ProviderClaims};
use registry_store::Store;
use reqwest::{Client, Url, redirect};
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::{
    config::{self, ClientCredentials},
    error::AppError,
    state::AppState,
};

/// Hands the verified payload back untouched, so one verifier serves ID tokens and back-channel
/// logout tokens alike; each caller reads the claims it needs.
pub struct RawPayload;

impl ProviderClaims for RawPayload {
    type Claims = Value;

    fn claims(payload: Value) -> Result<Value, oidc::oidc::JwtVerificationError> {
        Ok(payload)
    }
}

/// One registry version.
pub struct Catalog {
    /// Every kind and site.
    pub registry: Registry,
    /// Changes whenever any registry document or, with a store, the store's version does.
    pub version: String,
    /// Changes whenever any registry document changes.
    pub files_version: String,
    /// With a store, the store version the installations are as of.
    pub store_version: Option<i64>,
}

impl Catalog {
    /// `registry`, from documents at `files_version` and, with a store, its `store_version`.
    fn new(registry: Registry, files_version: String, store_version: Option<i64>) -> Self {
        let version = match store_version {
            Some(store_version) => format!("{files_version}.{store_version}"),
            None => files_version.clone(),
        };
        Self {
            registry,
            version,
            files_version,
            store_version,
        }
    }
}

/// How many changed installations the registry carries on top of its snapshot before it is
/// compacted into a new one.
const COMPACT_AT: usize = 20_000;

/// Everything the hub needs to act for one app kind.
pub struct AppClient {
    /// The registry entry this client was built from; rebuilt when it changes.
    pub app: App,
    /// How the hub authenticates as this kind's client.
    credentials: Credentials,
    /// Verifies ID tokens and logout tokens issued to this kind's client.
    pub verifier: OidcJwtVerifier<RawPayload>,
    /// The provider's authorization endpoint, as browsers reach it.
    pub authorization_url: Url,
    /// The provider's logout page, as browsers reach it, if it publishes one; only used when
    /// the hub could not end the session itself.
    pub end_session_url: Option<Url>,
    /// Calls this kind's API: a connect timeout and a read timeout, but no cap on total
    /// duration, so long downloads and streams are never cut off.
    pub api: Client,
    /// Bulkhead: this kind's in-flight API calls on this hub instance.
    pub in_flight: Arc<Semaphore>,
}

impl AppClient {
    /// The provider's token endpoint, as the hub reaches it.
    pub fn token_endpoint(&self) -> &str {
        self.verifier.token_endpoint()
    }

    /// The provider's token revocation endpoint (RFC 7009), as the hub reaches it, if it
    /// publishes one.
    pub fn revocation_endpoint(&self) -> Option<&str> {
        self.verifier.revocation_endpoint()
    }

    /// The provider's end-session endpoint, as the hub reaches it, for logging out server to
    /// server; `None` if it publishes none.
    pub fn internal_end_session_endpoint(&self) -> Option<&str> {
        self.verifier.internal_end_session_endpoint()
    }

    /// The form fields that authenticate this kind's client on a call to the provider whose
    /// issuer `state` names: its secret, or a fresh assertion signed with the hub's key.
    pub fn auth_fields(&self, state: &AppState) -> Result<Vec<(&'static str, String)>, AppError> {
        Ok(self
            .credentials
            .form_fields(&self.app.client_id, &state.config.issuer)?)
    }
}

/// The live registry and the clients built from it.
pub struct Runtime {
    /// The registry being served.
    catalog: RwLock<Arc<Catalog>>,
    /// Each kind's client, by kind id.
    clients: RwLock<HashMap<String, Arc<AppClient>>>,
}

impl Runtime {
    /// Serves `catalog`, with no clients built yet.
    pub fn new(catalog: Catalog) -> Self {
        Self {
            catalog: RwLock::new(Arc::new(catalog)),
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// The registry being served.
    pub fn catalog(&self) -> Arc<Catalog> {
        self.catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The client for app kind `app_id`, if it is built and matches the current registry entry.
    pub fn client(&self, app_id: &str) -> Option<Arc<AppClient>> {
        let catalog = self.catalog();
        let app = catalog.registry.app(app_id)?;
        let clients = self.clients.read().unwrap_or_else(PoisonError::into_inner);
        clients.get(app_id).filter(|c| &c.app == app).cloned()
    }

    /// Ready when every app kind in the registry has a working client.
    pub fn missing_clients(&self) -> Vec<String> {
        let catalog = self.catalog();
        catalog
            .registry
            .apps()
            .iter()
            .filter(|app| self.client(&app.id).is_none())
            .map(|app| app.id.clone())
            .collect()
    }
}

/// The registry in directory `dir`, validated.
pub fn load(dir: &str) -> Result<Catalog, Box<dyn std::error::Error>> {
    let (documents, version) = config::read_documents(dir)?;
    let registry =
        Registry::from_documents(documents.iter().map(|(n, t)| (n.as_str(), t.as_str())))?;
    Ok(Catalog::new(registry, version, None))
}

/// The app kinds in directory `dir` with every installation in `store`. An installation that
/// fails validation is left out and logged; the kinds must be valid.
pub async fn load_with_store(
    dir: &str,
    store: &Store,
) -> Result<Catalog, Box<dyn std::error::Error>> {
    let (documents, files_version) = config::read_documents(dir)?;
    let kinds =
        Registry::kinds_from_documents(documents.iter().map(|(n, t)| (n.as_str(), t.as_str())))?;
    let (store_version, records) = store.load_all().await?;
    let (registry, rejected) = kinds.with_installations(records);
    log_rejected(&rejected);
    Ok(Catalog::new(registry, files_version, Some(store_version)))
}

/// Logs each installation the store holds that the registry refused, and why.
fn log_rejected(rejected: &[(String, RegistryError)]) {
    for (site, error) in rejected {
        warn!(%site, %error, "installation in the store refused; left out");
    }
}

/// Keeps `app`'s registry and per-kind clients current. Runs for the life of the process.
pub async fn maintain(app: AppState) {
    let Some(store) = app.store.clone() else {
        loop {
            reload_registry(&app);
            sync_clients(&app).await;
            tokio::time::sleep(app.config.reload_interval).await;
        }
    };
    let mut files_checked: Option<Instant> = None;
    loop {
        if files_checked.is_none_or(|at| at.elapsed() >= app.config.reload_interval) {
            reload_kinds(&app, &store).await;
            sync_clients(&app).await;
            files_checked = Some(Instant::now());
        }
        follow_store(&app, &store).await;
        tokio::time::sleep(app.config.sync_interval).await;
    }
}

/// Serves `catalog` from now on.
fn swap(app: &AppState, catalog: Catalog) {
    *app.runtime
        .catalog
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Arc::new(catalog);
}

/// With a store: reloads everything if a kind's document changed and is valid.
async fn reload_kinds(app: &AppState, store: &Store) {
    let current = app.runtime.catalog();
    match config::read_documents(&app.config.registry_dir) {
        Ok((_, version)) if version == current.files_version => {}
        Ok(_) => match load_with_store(&app.config.registry_dir, store).await {
            Ok(catalog) => {
                info!(
                    version = %catalog.version,
                    apps = catalog.registry.apps().len(),
                    sites = catalog.registry.site_count(),
                    "registry reloaded"
                );
                swap(app, catalog);
            }
            Err(e) => error!(error = %e, "registry change refused; keeping the previous version"),
        },
        Err(e) => error!(error = %e, "registry unreadable; keeping the previous version"),
    }
}

/// Applies the store's changes since the version served, compacting the registry once enough
/// have accumulated. If the store cannot be reached, keeps serving what it has.
async fn follow_store(app: &AppState, store: &Store) {
    let current = app.runtime.catalog();
    let since = current.store_version.unwrap_or_default();
    let (version, changes) = match store.changes_since(since).await {
        Ok(found) if found.0 > since => found,
        Ok(_) => return,
        Err(e) => {
            warn!(error = %e, "registry store unreachable; serving the version held");
            return;
        }
    };
    let changed = changes.len();
    let (mut registry, rejected) = current.registry.with_changes(changes);
    log_rejected(&rejected);
    if registry.pending_changes() >= COMPACT_AT {
        let started = Instant::now();
        registry = match tokio::task::spawn_blocking(move || registry.compacted()).await {
            Ok(compacted) => compacted,
            Err(e) => {
                error!(error = %e, "registry compaction failed; the changes are fetched again");
                return;
            }
        };
        info!(
            took_ms = started.elapsed().as_millis() as u64,
            "registry compacted"
        );
    }
    debug!(version, changed, "registry store changes applied");
    swap(
        app,
        Catalog::new(registry, current.files_version.clone(), Some(version)),
    );
}

/// Swaps in `app`'s registry directory if it changed and is valid.
fn reload_registry(app: &AppState) {
    let current = app.runtime.catalog();
    match config::read_documents(&app.config.registry_dir) {
        Ok((_, version)) if version == current.version => {}
        Ok(_) => match load(&app.config.registry_dir) {
            Ok(catalog) => {
                info!(
                    version = %catalog.version,
                    apps = catalog.registry.apps().len(),
                    sites = catalog.registry.site_count(),
                    "registry reloaded"
                );
                swap(app, catalog);
            }
            Err(e) => error!(error = %e, "registry change refused; keeping the previous version"),
        },
        Err(e) => error!(error = %e, "registry unreadable; keeping the previous version"),
    }
}

/// Builds a client for every kind in `app`'s registry that has none or an outdated one, and
/// drops the clients of removed kinds.
async fn sync_clients(app: &AppState) {
    let catalog = app.runtime.catalog();
    for entry in catalog.registry.apps() {
        if entry.direct() && app.config.provider.site_scope("probe").is_none() {
            error!(
                app = %entry.id,
                provider = app.config.provider.name(),
                "a direct kind needs a provider that names sites in tokens"
            );
            continue;
        }
        let credentials = match (&app.config.client_credentials, &entry.client_secret_file) {
            (ClientCredentials::PrivateKeyJwt(keys), _) => (**keys).clone(),
            (ClientCredentials::PerKindSecret, Some(file)) => match std::fs::read_to_string(file) {
                Ok(secret) => Credentials::Secret(secret.trim().to_owned()),
                Err(e) => {
                    error!(app = %entry.id, error = %e, "client secret unreadable");
                    continue;
                }
            },
            (ClientCredentials::PerKindSecret, None) => {
                error!(app = %entry.id, "CLIENT_CREDENTIALS=client_secret needs the kind's client_secret_file");
                continue;
            }
        };
        let current = app
            .runtime
            .clients
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&entry.id)
            .cloned();
        if current.is_some_and(|c| &c.app == entry && c.credentials == credentials) {
            continue;
        }
        match build_client(app, entry.clone(), credentials).await {
            Ok(client) => {
                info!(app = %entry.id, client_id = %entry.client_id, "app client ready");
                app.runtime
                    .clients
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(entry.id.clone(), Arc::new(client));
            }
            Err(e) => warn!(app = %entry.id, error = %e, "app client not ready; retrying"),
        }
    }
    // Kinds removed from the registry lose their client.
    app.runtime
        .clients
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|id, _| catalog.registry.app(id).is_some());
}

/// Discovers the provider for kind `entry`, authenticating with `credentials`, and builds its API
/// client; `app` has the settings and the provider HTTP client.
async fn build_client(
    app: &AppState,
    entry: App,
    credentials: Credentials,
) -> Result<AppClient, Box<dyn std::error::Error>> {
    let config = &app.config;
    let verifier = OidcJwtVerifier::with_discovery_url(
        &config.issuer,
        &config.discovery_url,
        app.idp.clone(),
        entry.client_id.clone(),
        config.transport,
    )
    .await?;
    let well_known = verifier.well_known_endpoint();
    let authorization_url = Url::parse(&well_known.authorization_endpoint)?;
    let end_session_url = well_known
        .end_session_endpoint
        .as_deref()
        .map(Url::parse)
        .transpose()?;
    let api = Client::builder()
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(entry.api_read_timeout_secs))
        .build()?;
    Ok(AppClient {
        in_flight: Arc::new(Semaphore::new(entry.max_concurrency)),
        app: entry,
        credentials,
        verifier,
        authorization_url,
        end_session_url,
        api,
    })
}
