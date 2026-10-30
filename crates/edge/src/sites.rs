//! The sites this edge serves: its app kind's enabled sites in the registry, kept current, and
//! which of them a request is for.
//!
//! The registry files name the kind and, unless the installations live in the hub's store, its
//! sites. With a store (`REGISTRY_FROM_HUB`), the edge looks each host up at the hub the first
//! time it sees it, in a request signed with the kind's key, and caches the answer; it follows
//! the store's changes through the hub to drop what changed, and never reaches the store itself.
//! Its memory then follows the installations in use, not all of them.
//!
//! Each site has its own origin, and every origin of the kind points at this one edge, so the
//! request's host names the site. A host the registry does not list for this kind is refused
//! before anything else happens. Sending another site's host gains nothing: browsers keep each
//! site's cookies under its own host, and the hub only honours a session for the site it was
//! created at.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::{Duration, Instant},
};

use axum::{
    extract::FromRequestParts,
    http::{Method, header::HOST, request::Parts},
};
use common::registry::{
    HostLookup, KIND_SIGNER_PREFIX, KindFeed, Registry, Site, parse_public_key, read_documents,
    validate_installation, web_hosts,
};
use reqwest::Url;
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, warn};

use crate::{config::ConfigError, error::EdgeError, hub::HubClient, state::AppState};

/// How long a found installation is cached; changes drop it sooner.
const FOUND_FOR: Duration = Duration::from_secs(600);
/// How long a host without an installation is cached, so unknown hosts cannot flood the hub.
const MISSING_FOR: Duration = Duration::from_secs(30);
/// The most hosts cached; past it, expired and missing ones go first, then all.
const MOST_CACHED: usize = 100_000;

/// One loaded version of the registry files.
struct Loaded {
    /// The registry, validated with the hub's rules: with installations from the hub, the kind
    /// alone.
    registry: Registry,
    /// Changes whenever any registry file does.
    version: String,
}

/// The hub's answer for one host, and when it came.
struct Cached {
    /// The installation, or `None` if the kind has none there.
    site: Option<Site>,
    /// When the hub answered.
    at: Instant,
}

/// Installations looked up at the hub as hosts arrive.
struct OnDemand {
    /// Signed requests to the hub.
    hub: Arc<HubClient>,
    /// The answers so far, by lowercase host.
    cache: Mutex<HashMap<String, Cached>>,
    /// The store version followed so far; `None` until the hub has answered.
    version: Mutex<Option<i64>>,
}

/// The kind's sites, from the registry directory or, on demand, from the hub.
pub struct Sites {
    /// The app kind this edge serves.
    app_id: String,
    /// The registry directory, the same documents the hub reads.
    dir: String,
    /// The current version; replaced only by a valid newer one.
    current: RwLock<Arc<Loaded>>,
    /// With installations from the hub: the cache and its source.
    on_demand: Option<OnDemand>,
}

impl Sites {
    /// Reads `dir` for kind `app_id`, whose edge key must be `edge_public_key`: the first read
    /// must be valid, name the kind, and hold this edge's key, or the edge does not start. With
    /// `hub`, the files hold the kind only and installations are looked up at the hub.
    pub fn load(
        app_id: &str,
        dir: &str,
        edge_public_key: &str,
        hub: Option<Arc<HubClient>>,
    ) -> Result<Self, ConfigError> {
        let loaded = read(dir, app_id, hub.is_some())?;
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
            on_demand: hub.map(|hub| OnDemand {
                hub,
                cache: Mutex::default(),
                version: Mutex::default(),
            }),
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

    /// The enabled site of this kind whose origin has host `host`: from the files, or from the
    /// cache, asking the hub on a miss. If the hub cannot answer, an expired answer still serves.
    pub async fn for_host(&self, host: &str) -> Option<Site> {
        let Some(on_demand) = &self.on_demand else {
            return self
                .current()
                .registry
                .site_for_host(&self.app_id, host)
                .cloned();
        };
        let host = host.to_ascii_lowercase();
        let stale = {
            let cache = on_demand
                .cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match cache.get(&host) {
                Some(cached) if cached.at.elapsed() < cached.lifetime() => {
                    return cached.site.clone();
                }
                Some(cached) => Some(cached.site.clone()),
                None => None,
            }
        };
        match self.look_up(on_demand, &host).await {
            Ok(site) => {
                on_demand.remember(host, site.clone());
                site
            }
            Err(error) => {
                warn!(%host, %error, "host not looked up at the hub");
                stale.flatten()
            }
        }
    }

    /// The kind's installation at `host`, from the hub.
    async fn look_up(
        &self,
        on_demand: &OnDemand,
        host: &str,
    ) -> Result<Option<Site>, Box<dyn std::error::Error + Send + Sync>> {
        let mut url = Url::parse("http://hub/broker/registry/host")?;
        url.query_pairs_mut().append_pair("name", host);
        let path = format!("{}?{}", url.path(), url.query().unwrap_or_default());
        let lookup: HostLookup = signed_get(&on_demand.hub, &self.app_id, &path).await?;
        let Some(record) = lookup.installation else {
            return Ok(None);
        };
        let current = self.current();
        let app = current
            .registry
            .app(&self.app_id)
            .ok_or("the edge's kind is gone")?;
        let site = validate_installation(&record, app)?;
        Ok(Some(site).filter(|site| site.enabled && !site.is_native()))
    }

    /// The kind's `max_concurrency`: the direct API calls each site may have in flight on this
    /// edge. The registry always names this edge's kind: loading and reloading refuse it otherwise.
    pub fn max_concurrency(&self) -> usize {
        self.current()
            .registry
            .app(&self.app_id)
            .map_or(1, |app| app.max_concurrency)
    }

    /// How many enabled web-app installations this edge knows now: all of the kind's from the
    /// files, or those cached from the hub.
    pub fn count(&self) -> usize {
        match &self.on_demand {
            Some(on_demand) => on_demand
                .cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values()
                .filter(|cached| cached.site.is_some())
                .count(),
            None => self
                .current()
                .registry
                .sites()
                .filter(|s| s.enabled && s.app_id == self.app_id && !s.is_native())
                .count(),
        }
    }

    /// Whether the edge can serve: from the files, with at least one installation; from the hub,
    /// once the hub has answered.
    pub fn ready(&self) -> bool {
        match &self.on_demand {
            Some(on_demand) => on_demand
                .version
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some(),
            None => self.count() > 0,
        }
    }

    /// Swaps in the registry directory if it changed and is still valid for this kind; an
    /// invalid change is logged and the previous version stays. With installations from the hub,
    /// a new kind document also empties the cache.
    fn reload(&self) {
        let current = self.current();
        let kinds_only = self.on_demand.is_some();
        match read_documents(&self.dir) {
            Ok((_, version)) if version == current.version => {}
            Ok(_) => match read(&self.dir, &self.app_id, kinds_only) {
                Ok(loaded) if loaded.registry.app(&self.app_id).is_some() => {
                    info!(version = %loaded.version, "registry reloaded");
                    self.swap(loaded);
                    if let Some(on_demand) = &self.on_demand {
                        on_demand
                            .cache
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .clear();
                    }
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

    /// With installations from the hub: learns the version to follow from, then drops from the
    /// cache every host whose installation changed since. If the hub cannot answer, keeps what it
    /// has.
    async fn follow(&self) {
        let Some(on_demand) = &self.on_demand else {
            return;
        };
        let since = *on_demand
            .version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(since) = since else {
            match signed_get::<serde_json::Value>(
                &on_demand.hub,
                &self.app_id,
                "/broker/registry/head",
            )
            .await
            {
                Ok(head) => {
                    let version = head["version"].as_i64().unwrap_or_default();
                    *on_demand
                        .version
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(version);
                    info!(version, "following the hub's registry");
                }
                Err(error) => warn!(%error, "the hub's registry version not fetched"),
            }
            return;
        };
        let feed: KindFeed = match signed_get(
            &on_demand.hub,
            &self.app_id,
            &format!("/broker/registry?since={since}"),
        )
        .await
        {
            Ok(feed) => feed,
            Err(error) => {
                warn!(%error, "registry changes not fetched from the hub; keeping the cache");
                return;
            }
        };
        if feed.version <= since {
            return;
        }
        let current = self.current();
        let app = current.registry.app(&self.app_id);
        let mut cache = on_demand
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (id, record) in &feed.changes {
            // Its new hosts, which may have been cached as missing, and wherever it was cached.
            let hosts = record
                .as_ref()
                .zip(app)
                .and_then(|(record, app)| validate_installation(record, app).ok())
                .and_then(|site| web_hosts(&site));
            if let Some((host, bare)) = hosts {
                cache.remove(&host);
                if let Some(bare) = bare {
                    cache.remove(&bare);
                }
            }
            cache.retain(|_, cached| cached.site.as_ref().is_none_or(|site| &site.id != id));
        }
        drop(cache);
        *on_demand
            .version
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(feed.version);
        debug!(
            version = feed.version,
            changed = feed.changes.len(),
            "registry changes followed"
        );
    }
}

impl Cached {
    /// How long this answer may serve without asking the hub again.
    fn lifetime(&self) -> Duration {
        if self.site.is_some() {
            FOUND_FOR
        } else {
            MISSING_FOR
        }
    }
}

impl OnDemand {
    /// Caches the hub's answer `site` for `host`, making room first if the cache is full.
    fn remember(&self, host: String, site: Option<Site>) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= MOST_CACHED {
            cache.retain(|_, cached| {
                cached.site.is_some() && cached.at.elapsed() < cached.lifetime()
            });
            if cache.len() >= MOST_CACHED {
                cache.clear();
            }
        }
        cache.insert(
            host,
            Cached {
                site,
                at: Instant::now(),
            },
        );
    }
}

/// `path` at the hub, signed as kind `app_id`'s edge, read as JSON.
async fn signed_get<T: DeserializeOwned>(
    hub: &HubClient,
    app_id: &str,
    path: &str,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    let response = hub
        .request(
            &format!("{KIND_SIGNER_PREFIX}{app_id}"),
            Method::GET,
            path,
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

/// With installations from the hub: follows the store's changes every `sync_interval`, and the
/// kind's document every `files_interval`, for the life of the process.
pub async fn follow_hub(sites: Arc<Sites>, files_interval: Duration, sync_interval: Duration) {
    let mut files_checked = Instant::now();
    loop {
        if files_checked.elapsed() >= files_interval {
            sites.reload();
            files_checked = Instant::now();
        }
        sites.follow().await;
        tokio::time::sleep(sync_interval).await;
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
            .await
            .map(CurrentSite)
            .ok_or(EdgeError::UnknownSite)
    }
}
