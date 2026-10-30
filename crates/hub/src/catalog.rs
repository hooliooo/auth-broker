//! The live registry and one provider client per app kind.
//!
//! A background task re-reads the registry directory and the client secret files every few
//! seconds. A valid change is swapped in atomically; an invalid one is logged and ignored, so a
//! team's typo never takes the hub down. Clients are built from discovery in the background too,
//! so a provider hiccup delays readiness instead of stopping startup.

use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use common::{
    client::credentials::Credentials,
    registry::{App, Registry},
};
use oidc::{OidcJwtVerifier, ProviderClaims};
use reqwest::{Client, Url, redirect};
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

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
    /// Changes whenever any registry document changes.
    pub version: String,
}

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
    Ok(Catalog { registry, version })
}

/// Keeps `app`'s registry and per-kind clients current. Runs for the life of the process.
pub async fn maintain(app: AppState) {
    loop {
        reload_registry(&app);
        sync_clients(&app).await;
        tokio::time::sleep(app.config.reload_interval).await;
    }
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
                    sites = catalog.registry.sites().len(),
                    "registry reloaded"
                );
                *app.runtime
                    .catalog
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = Arc::new(catalog);
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
