//! The sites this edge serves: its app kind's enabled sites in the registry, kept current, and
//! which of them a request is for.
//!
//! The registry files name the kind and, unless the installations live in the hub's store, its
//! sites. With a store (`REGISTRY_FROM_HUB`), the edge fetches its kind's web-app installations
//! from the hub, in requests signed with the kind's key, then only the changes; it never reaches
//! the store itself.
//!
//! Each site has its own origin, and every origin of the kind points at this one edge, so the
//! request's host names the site. A host the registry does not list for this kind is refused
//! before anything else happens. Sending another site's host gains nothing: browsers keep each
//! site's cookies under its own host, and the hub only honours a session for the site it was
//! created at.

use std::{
    sync::{Arc, PoisonError, RwLock},
    time::{Duration, Instant},
};

use axum::{
    extract::FromRequestParts,
    http::{Method, header::HOST, request::Parts},
};
use common::registry::{
    KIND_SIGNER_PREFIX, KindFeed, Registry, Site, parse_public_key, read_documents,
};
use tracing::{debug, error, info, warn};

use crate::{config::ConfigError, error::EdgeError, hub::HubClient, state::AppState};

/// How many changed installations the registry carries before it is compacted.
const COMPACT_AT: usize = 20_000;

/// One loaded version of the registry.
struct Loaded {
    /// The registry, validated with the hub's rules.
    registry: Registry,
    /// Changes whenever any registry file does.
    version: String,
    /// With installations from the hub, the store version they are as of; `None` until the
    /// first fetch.
    store_version: Option<i64>,
}

/// The kind's sites, from the registry directory.
pub struct Sites {
    /// The app kind this edge serves.
    app_id: String,
    /// The registry directory, the same documents the hub reads.
    dir: String,
    /// The current version; replaced only by a valid newer one.
    current: RwLock<Arc<Loaded>>,
}

impl Sites {
    /// Reads `dir` for kind `app_id`, whose edge key must be `edge_public_key`: the first read
    /// must be valid, name the kind, and hold this edge's key, or the edge does not start. With
    /// `from_hub`, the files hold kinds only and the installations follow from [`follow_hub`].
    pub fn load(
        app_id: &str,
        dir: &str,
        edge_public_key: &str,
        from_hub: bool,
    ) -> Result<Self, ConfigError> {
        let loaded = read(dir, app_id, from_hub)?;
        let app = loaded
            .registry
            .app(app_id)
            .ok_or_else(|| ConfigError::UnknownApp(app_id.to_owned()))?;
        if !app.serves_web() {
            return Err(ConfigError::NoWebAccess(app_id.to_owned()));
        }
        match (parse_public_key(edge_public_key), app.edge_public_key) {
            (Some(key), Some(registered)) if key == registered => {}
            _ => return Err(ConfigError::KeyMismatch(app_id.to_owned())),
        }
        Ok(Self {
            app_id: app_id.to_owned(),
            dir: dir.to_owned(),
            current: RwLock::new(Arc::new(loaded)),
        })
    }

    /// Serves `loaded` from now on.
    fn swap(&self, loaded: Loaded) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(loaded);
    }

    /// The current version.
    fn current(&self) -> Arc<Loaded> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The enabled site of this kind whose origin has host `host`.
    pub fn for_host(&self, host: &str) -> Option<Site> {
        self.current()
            .registry
            .site_for_host(&self.app_id, host)
            .cloned()
    }

    /// The kind's `max_concurrency`: the direct API calls each site may have in flight on this
    /// edge. The registry always names this edge's kind: loading and reloading refuse it otherwise.
    pub fn max_concurrency(&self) -> usize {
        self.current()
            .registry
            .app(&self.app_id)
            .map_or(1, |app| app.max_concurrency)
    }

    /// How many enabled web-app installations this edge serves now; the kind's native
    /// installations go to the hub themselves.
    pub fn count(&self) -> usize {
        self.current()
            .registry
            .sites()
            .filter(|s| s.enabled && s.app_id == self.app_id && !s.is_native())
            .count()
    }

    /// Swaps in the registry directory if it changed and is still valid for this kind; an
    /// invalid change is logged and the previous version stays.
    fn reload(&self) {
        let current = self.current();
        match read_documents(&self.dir) {
            Ok((_, version)) if version == current.version => {}
            Ok(_) => match read(&self.dir, &self.app_id, false) {
                Ok(loaded) if loaded.registry.app(&self.app_id).is_some() => {
                    info!(version = %loaded.version, "registry reloaded");
                    self.swap(loaded);
                }
                Ok(_) => {
                    error!(app = %self.app_id, "registry change drops this edge's kind; keeping the previous version")
                }
                Err(e) => {
                    error!(error = %e, "registry change refused; keeping the previous version")
                }
            },
            Err(e) => error!(error = %e, "registry unreadable; keeping the previous version"),
        }
    }
}

impl Sites {
    /// With installations from the hub: the kinds in the files, if they changed since the
    /// version served and are valid for this kind.
    fn changed_kinds(&self) -> Option<Loaded> {
        let current = self.current();
        match read_documents(&self.dir) {
            Ok((_, version)) if version == current.version => None,
            Ok(_) => match read(&self.dir, &self.app_id, true) {
                Ok(loaded) if loaded.registry.app(&self.app_id).is_some() => Some(loaded),
                Ok(_) => {
                    error!(app = %self.app_id, "registry change drops this edge's kind; keeping the previous version");
                    None
                }
                Err(e) => {
                    error!(error = %e, "registry change refused; keeping the previous version");
                    None
                }
            },
            Err(e) => {
                error!(error = %e, "registry unreadable; keeping the previous version");
                None
            }
        }
    }

    /// Fetches the kind's installations from `hub` and swaps them in: everything with
    /// `new_kinds`, or before the first fetch; otherwise the changes since the version served.
    /// If the hub cannot answer, keeps serving what it has.
    async fn sync(&self, hub: &HubClient, new_kinds: Option<Loaded>) {
        let current = self.current();
        let (kinds, files_version, since) = match new_kinds {
            Some(loaded) => (loaded.registry, loaded.version, 0),
            None => (
                current.registry.clone(),
                current.version.clone(),
                current.store_version.unwrap_or_default(),
            ),
        };
        let feed = match fetch(hub, &self.app_id, since).await {
            Ok(feed) => feed,
            Err(error) => {
                warn!(%error, "kind's installations not fetched from the hub; serving those held");
                return;
            }
        };
        if !feed.full && feed.version <= since {
            return;
        }
        let changed = feed.changes.len();
        let (mut registry, rejected) = if feed.full {
            kinds.with_installations(feed.changes.into_iter().filter_map(|(_, record)| record))
        } else {
            kinds.with_changes(feed.changes)
        };
        for (site, error) in rejected {
            warn!(%site, %error, "installation from the hub refused; left out");
        }
        if registry.pending_changes() >= COMPACT_AT {
            registry = match tokio::task::spawn_blocking(move || registry.compacted()).await {
                Ok(compacted) => compacted,
                Err(e) => {
                    error!(error = %e, "registry compaction failed; the changes are fetched again");
                    return;
                }
            };
        }
        debug!(
            version = feed.version,
            changed,
            full = feed.full,
            "kind's installations applied"
        );
        self.swap(Loaded {
            registry,
            version: files_version,
            store_version: Some(feed.version),
        });
    }
}

/// The kind's web-app installations from `hub` after store version `since`, or all with 0.
async fn fetch(
    hub: &HubClient,
    app_id: &str,
    since: i64,
) -> Result<KindFeed, Box<dyn std::error::Error + Send + Sync>> {
    let path = format!("/broker/registry?since={since}");
    let response = hub
        .request(
            &format!("{KIND_SIGNER_PREFIX}{app_id}"),
            Method::GET,
            &path,
            None,
        )?
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("the hub answered {}", response.status()).into());
    }
    Ok(response.json().await?)
}

/// The registry in `dir`, validated as a whole as the hub validates it, then narrowed to kind
/// `app_id`, the only one this edge serves; with `kinds_only`, the kinds without installations,
/// which then come from the hub.
fn read(dir: &str, app_id: &str, kinds_only: bool) -> Result<Loaded, ConfigError> {
    let (documents, version) =
        read_documents(dir).map_err(|e| ConfigError::RegistryDir(dir.to_owned(), e))?;
    let documents = documents.iter().map(|(n, t)| (n.as_str(), t.as_str()));
    let registry = if kinds_only {
        Registry::kinds_from_documents(documents)?
    } else {
        Registry::from_documents(documents)?
    }
    .only_kind(app_id);
    Ok(Loaded {
        registry,
        version,
        store_version: None,
    })
}

/// With installations from the hub: follows them every `sync_interval`, and the kinds in the
/// files every `files_interval`, for the life of the process.
pub async fn follow_hub(
    sites: Arc<Sites>,
    hub: Arc<HubClient>,
    files_interval: Duration,
    sync_interval: Duration,
) {
    let mut files_checked: Option<Instant> = None;
    loop {
        let mut new_kinds = None;
        if files_checked.is_none_or(|at| at.elapsed() >= files_interval) {
            new_kinds = sites.changed_kinds();
            files_checked = Some(Instant::now());
        }
        sites.sync(&hub, new_kinds).await;
        tokio::time::sleep(sync_interval).await;
    }
}

/// Re-reads `sites` every `interval`, for the life of the process, so sites are added and retired
/// without restarting the edge.
pub async fn maintain(sites: Arc<Sites>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        sites.reload();
    }
}

/// The site a request is for, from its host; 404 for any host this edge does not serve.
pub struct CurrentSite(pub Site);

impl FromRequestParts<AppState> for CurrentSite {
    type Rejection = EdgeError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, EdgeError> {
        // HTTP/1.1 sends `Host`; HTTP/2 the request's authority.
        let host = parts
            .headers
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .or_else(|| parts.uri.authority().map(|a| a.as_str().to_owned()))
            .ok_or(EdgeError::UnknownSite)?;
        state
            .sites
            .for_host(&host)
            .map(CurrentSite)
            .ok_or(EdgeError::UnknownSite)
    }
}
