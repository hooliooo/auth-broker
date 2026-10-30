//! The sites this edge serves: its app kind's enabled sites in the registry, kept current, and
//! which of them a request is for.
//!
//! Each site has its own origin, and every origin of the kind points at this one edge, so the
//! request's host names the site. A host the registry does not list for this kind is refused
//! before anything else happens. Sending another site's host gains nothing: browsers keep each
//! site's cookies under its own host, and the hub only honours a session for the site it was
//! created at.

use std::{
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use axum::{
    extract::FromRequestParts,
    http::{header::HOST, request::Parts},
};
use common::registry::{Registry, Site, parse_public_key, read_documents};
use tracing::{error, info};

use crate::{config::ConfigError, error::EdgeError, state::AppState};

/// One loaded version of the registry.
struct Loaded {
    /// The registry, validated with the hub's rules.
    registry: Registry,
    /// Changes whenever any registry file does.
    version: String,
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
    /// must be valid, name the kind, and hold this edge's key, or the edge does not start.
    pub fn load(app_id: &str, dir: &str, edge_public_key: &str) -> Result<Self, ConfigError> {
        let loaded = read(dir, app_id)?;
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
            .iter()
            .filter(|s| s.enabled && s.app_id == self.app_id && !s.is_native())
            .count()
    }

    /// Swaps in the registry directory if it changed and is still valid for this kind; an
    /// invalid change is logged and the previous version stays.
    fn reload(&self) {
        let current = self.current();
        match read_documents(&self.dir) {
            Ok((_, version)) if version == current.version => {}
            Ok(_) => match read(&self.dir, &self.app_id) {
                Ok(loaded) if loaded.registry.app(&self.app_id).is_some() => {
                    info!(version = %loaded.version, "registry reloaded");
                    *self.current.write().unwrap_or_else(PoisonError::into_inner) =
                        Arc::new(loaded);
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

/// The registry in `dir`, validated as a whole as the hub validates it, then narrowed to kind
/// `app_id`, the only one this edge serves.
fn read(dir: &str, app_id: &str) -> Result<Loaded, ConfigError> {
    let (documents, version) =
        read_documents(dir).map_err(|e| ConfigError::RegistryDir(dir.to_owned(), e))?;
    let registry =
        Registry::from_documents(documents.iter().map(|(n, t)| (n.as_str(), t.as_str())))?
            .only_kind(app_id);
    Ok(Loaded { registry, version })
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
