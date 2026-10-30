//! The registry: every app kind the hub serves, and every site of each kind.
//!
//! Each team owns one JSON document (one file) describing its app kind and its sites
//! (installations). Each installation runs one of two kinds of application ([`Access`]):
//!
//! - **a web app**, served by the kind's one edge (the kind's `edge_public_key`) under the
//!   installation's own `origin`; the edge signs for it;
//! - **a native app**, a desktop app on the installation's premises (the kind's `native`
//!   settings); the installation signs for itself with its own `keys` (one or more, e.g. one per
//!   workstation), and signs users in through the system browser with a loopback redirect
//!   (RFC 8252).
//!
//! A kind may have installations of both. Onboarding an installation is one entry in that file;
//! adding a kind is one new file and one identity provider client, plus one edge deployment if it
//! has web-app installations. The hub and every edge combine all documents, refuse the whole set
//! if any of them is invalid, and index it so every lookup takes constant time.

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::Path,
    sync::Arc,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use ring::digest::{SHA256, digest};

use crate::crypto::hash_key;

/// Prefix of a kind's `edge_public_key` in the registry.
pub const KEY_PREFIX: &str = "ed25519:";

/// The prefix of the `x-site-id` an edge signs with when it speaks for its whole kind rather than
/// one installation, e.g. `kind:inspection`; never a valid installation id.
pub const KIND_SIGNER_PREFIX: &str = "kind:";

/// One team's registry file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    /// The team's app kind.
    app: AppEntry,
    /// The kind's sites.
    #[serde(default)]
    sites: Vec<SiteEntry>,
}

/// An app kind as written in a registry file; see [`App`] for the fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppEntry {
    /// See [`App::id`].
    id: String,
    /// See [`App::client_id`].
    client_id: String,
    /// See [`App::client_secret_file`].
    #[serde(default)]
    client_secret_file: Option<String>,
    /// See [`App::edge_public_key`], as `ed25519:<base64url>`; for a kind with web-app
    /// installations.
    #[serde(default)]
    edge_public_key: Option<String>,
    /// See [`App::native`]; for a kind with native installations.
    #[serde(default)]
    native: Option<NativeEntry>,
    /// See [`App::api_upstream`]; absent for a kind whose edge calls its sites' APIs directly.
    #[serde(default)]
    api_upstream: Option<String>,
    /// See [`App::api_audience`].
    api_audience: String,
    /// See [`App::scopes`]; `openid` if absent.
    #[serde(default)]
    scopes: Option<String>,
    /// See [`App::required_role`].
    #[serde(default)]
    required_role: Option<String>,
    /// See [`App::api_read_timeout_secs`].
    #[serde(default = "default_read_timeout")]
    api_read_timeout_secs: u64,
    /// See [`App::max_concurrency`].
    #[serde(default = "default_concurrency")]
    max_concurrency: usize,
    /// See [`App::login_per_minute`].
    #[serde(default = "default_login_rate")]
    login_per_minute: u64,
}

/// A kind's native settings as written in a registry file; see [`Native`] for the fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEntry {
    /// See [`Native::redirect_path`].
    #[serde(default = "default_redirect_path")]
    redirect_path: String,
    /// See [`Native::admin_role`]; `<kind>-installation-admin` if absent.
    #[serde(default)]
    admin_role: Option<String>,
}

/// The path of a native app's loopback redirect unless its kind names another.
fn default_redirect_path() -> String {
    "/callback".to_owned()
}

/// Default longest silence from an API, in seconds.
fn default_read_timeout() -> u64 {
    60
}

/// Default in-flight API calls per kind and hub instance.
fn default_concurrency() -> usize {
    256
}

/// Default sign-in starts per site and minute.
fn default_login_rate() -> u64 {
    600
}

/// A site as written in a registry file; see [`Site`] for the fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteEntry {
    /// See [`Site::id`].
    id: String,
    /// See [`Access::Web`]; for a web-app installation.
    #[serde(default)]
    origin: Option<String>,
    /// See [`Access::Native`], each as `ed25519:<base64url>`; for a native installation.
    #[serde(default)]
    keys: Vec<String>,
    /// See [`Site::api_url`]; only for a kind whose edge calls its sites' APIs directly.
    #[serde(default)]
    api_url: Option<String>,
    /// See [`Site::tenant`].
    tenant: String,
    /// See [`Site::enabled`].
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    /// See [`Site::login_per_minute`]; the kind's if absent.
    #[serde(default)]
    login_per_minute: Option<u64>,
}

/// Sites are enabled unless their entry says otherwise.
fn enabled_by_default() -> bool {
    true
}

/// An app kind: one provider client, one API, one owning team.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    /// The kind's id, e.g. `inspection`.
    pub id: String,
    /// The kind's provider client, owned by the hub; unique across kinds.
    pub client_id: String,
    /// Where the client secret is, for a hub authenticating with `client_secret`; unused with
    /// `private_key_jwt`.
    pub client_secret_file: Option<String>,
    /// The Ed25519 public key of the kind's edge: every request the edge sends for any of the
    /// kind's web-app installations must verify against it. Unique across kinds and
    /// installations. `None` for a kind without web-app installations.
    pub edge_public_key: Option<[u8; 32]>,
    /// How the kind's native app signs users in; `None` for a kind without native
    /// installations.
    pub native: Option<Native>,
    /// The kind's API, if the hub forwards its sites' `/api/*` calls there. `None` for a
    /// kind whose edge calls each site's own API ([`Site::api_url`]) with tokens from the hub
    /// (`/broker/token`): each of its sites must be named in its tokens (for Keycloak: an
    /// organization per site).
    pub api_upstream: Option<Url>,
    /// The audience the identity provider must put in this kind's access tokens; its API accepts
    /// only these.
    pub api_audience: String,
    /// The scopes every sign-in for this kind requests, space-separated; always with `openid`,
    /// never `offline_access`, and never chosen by the browser.
    pub scopes: String,
    /// A realm role a user needs to sign in to this kind, if any.
    pub required_role: Option<String>,
    /// Longest silence allowed while reading from the API; there is no cap on total duration.
    pub api_read_timeout_secs: u64,
    /// Requests to this kind's API in flight at once, per hub instance.
    pub max_concurrency: usize,
    /// Sign-in starts allowed per site per minute, unless the site overrides it.
    pub login_per_minute: u64,
}

/// A kind's native settings: how its desktop-app installations sign users in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Native {
    /// The path of the app's loopback redirect, e.g. `/callback`: after sign-in the hub sends the
    /// browser to `http://127.0.0.1:<any port><path>` (or `[::1]`), where the app listens
    /// (RFC 8252 §7.3).
    pub redirect_path: String,
    /// The realm role, beside membership of the installation's organization, a user needs to
    /// approve a new machine of the installation: its app makes a key, the user signs in on it,
    /// and the hub enrolls the key.
    pub admin_role: String,
}

/// What an installation runs, and so how it reaches the hub. Every place the hub and the edge
/// treat the two differently matches on this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// A web app, served by the kind's edge under this origin: scheme, host and port only, e.g.
    /// `https://plant-a.inspection.example.com`. Browsers use it; the edge tells installations
    /// apart by it and signs for them with the kind's key.
    Web {
        /// The installation's origin.
        origin: Url,
    },
    /// A native app that signs for itself with one of these keys; several allow a key per
    /// workstation.
    Native {
        /// The installation's keys, shared: copying a site does not copy them.
        keys: Arc<InstallationKeys>,
    },
}

/// A native installation's keys, found by id in constant time however many it has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationKeys {
    /// The keys, in registry order.
    list: Vec<InstallationKey>,
    /// Index into `list` by key id, from [`InstallationKeys::INDEXED_FROM`] keys on; a shorter
    /// list is searched as fast, without a map per installation.
    by_id: Option<HashMap<String, usize>>,
}

impl InstallationKeys {
    /// How many keys an installation needs before they are indexed.
    const INDEXED_FROM: usize = 9;

    /// Indexes `list`, whose ids validation has made unique.
    fn new(list: Vec<InstallationKey>) -> Self {
        let by_id = (list.len() >= Self::INDEXED_FROM).then(|| {
            list.iter()
                .enumerate()
                .map(|(i, key)| (key.id.clone(), i))
                .collect()
        });
        Self { list, by_id }
    }

    /// Every key, in registry order.
    pub fn as_slice(&self) -> &[InstallationKey] {
        &self.list
    }

    /// The key with id `id`.
    pub fn get(&self, id: &str) -> Option<&[u8; 32]> {
        match &self.by_id {
            Some(by_id) => by_id.get(id).map(|&i| &self.list[i].key),
            None => self
                .list
                .iter()
                .find(|key| key.id == id)
                .map(|key| &key.key),
        }
    }
}

/// One of a native installation's Ed25519 public keys, and its id ([`key_id`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationKey {
    /// The id requests signed with it name.
    pub id: String,
    /// The public key.
    pub key: [u8; 32],
}

/// A site (installation) of one app kind, running a web app or a native app ([`Access`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The site's id, e.g. `plant-7`; unique across kinds.
    pub id: String,
    /// The id of the site's app kind.
    pub app_id: String,
    /// What the installation runs, and how it reaches the hub.
    pub access: Access,
    /// For a kind whose edge calls its sites' APIs directly: this site's API.
    pub api_url: Option<Url>,
    /// The customer the site belongs to; the API receives it as `x-tenant`.
    pub tenant: String,
    /// Whether the site may sign users in and call its API; `false` retires it.
    pub enabled: bool,
    /// Sign-in starts allowed per minute at this site.
    pub login_per_minute: u64,
}

impl App {
    /// Whether the kind's edge calls its sites' APIs directly, with tokens naming the site,
    /// instead of through the hub.
    pub fn direct(&self) -> bool {
        self.api_upstream.is_none()
    }

    /// Whether the kind has, or may have, web-app installations: it has an edge key.
    pub fn serves_web(&self) -> bool {
        self.edge_public_key.is_some()
    }
}

impl Site {
    /// Whether a request whose `Host` header is `host` is for this site: the same host,
    /// ignoring case, and the same port, the scheme's default if none is given.
    pub fn serves_host(&self, host: &str) -> bool {
        let Some(origin) = self.origin() else {
            return false;
        };
        // `[::1]:8080` splits at its last colon; `[::1]` alone leaves `1]`, which is no port.
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) if !port.contains(']') => match port.parse::<u16>() {
                Ok(port) => (name, Some(port)),
                Err(_) => return false,
            },
            _ => (host, None),
        };
        // No port in the header means the scheme's default, not the origin's port.
        let default_port = match origin.scheme() {
            "https" => 443,
            _ => 80,
        };
        let expected = origin.host_str().unwrap_or_default();
        name.eq_ignore_ascii_case(expected)
            && Some(port.unwrap_or(default_port)) == origin.port_or_known_default()
    }

    /// A web-app installation's origin; `None` for a native installation, which has none.
    pub fn origin(&self) -> Option<&Url> {
        match &self.access {
            Access::Web { origin } => Some(origin),
            Access::Native { .. } => None,
        }
    }

    /// A native installation's keys; empty for a web-app installation.
    pub fn keys(&self) -> &[InstallationKey] {
        match &self.access {
            Access::Web { .. } => &[],
            Access::Native { keys } => keys.as_slice(),
        }
    }

    /// The installation as a store's record, with its keys in use.
    pub fn record(&self) -> InstallationRecord {
        InstallationRecord {
            id: self.id.clone(),
            kind: self.app_id.clone(),
            origin: self
                .origin()
                .map(|origin| origin.as_str().trim_end_matches('/').to_owned()),
            keys: self
                .keys()
                .iter()
                .map(|key| format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(key.key)))
                .collect(),
            api_url: self.api_url.as_ref().map(|url| url.as_str().to_owned()),
            tenant: self.tenant.clone(),
            enabled: self.enabled,
            login_per_minute: Some(self.login_per_minute),
        }
    }

    /// Whether the installation runs a native app.
    pub fn is_native(&self) -> bool {
        matches!(self.access, Access::Native { .. })
    }

    /// The installation's access type, `web` or `native`, for metrics and the hub's
    /// `SERVED_ACCESS`.
    pub fn access_kind(&self) -> &'static str {
        if self.is_native() { "native" } else { "web" }
    }

    /// Where the hub sends the browser back to after sign-in at a web-app installation; `None`
    /// for a native installation, whose app names its loopback address at each sign-in.
    pub fn handoff_url(&self) -> Option<Url> {
        let origin = self.origin()?;
        Some(
            origin
                .join("/auth/handoff")
                .expect("origin joins a fixed path"),
        )
    }

    /// The installation's start page; `None` for a native installation.
    pub fn home_url(&self) -> Option<Url> {
        let origin = self.origin()?;
        Some(origin.join("/").expect("origin joins a fixed path"))
    }

    /// The one key a request for this installation must verify against, given the key id it
    /// names: its kind's edge key for a web-app installation, whatever the id; the native
    /// installation's key with that id otherwise. `None`, refused before any cryptography, for
    /// an id it does not have.
    pub fn verifying_key<'a>(&'a self, app: &'a App, key_id: Option<&str>) -> Option<&'a [u8; 32]> {
        match &self.access {
            Access::Web { .. } => app.edge_public_key.as_ref(),
            Access::Native { keys } => keys.get(key_id?),
        }
    }
}

/// Why a registry was refused; every variant names the app kind or site at fault.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    /// A document is not valid JSON or has unknown fields: its name and the parser's message.
    #[error("{0}: not a valid registry document: {1}")]
    Json(String, String),
    /// A kind's id is not a DNS label.
    #[error(
        "app '{0}': id must be 1-63 characters of a-z, 0-9 and '-', not starting or ending with '-'"
    )]
    InvalidAppId(String),
    /// Two documents define the same kind.
    #[error("app '{0}' is defined in more than one document")]
    DuplicateApp(String),
    /// Two kinds share a provider client: the kind and the client id.
    #[error(
        "app '{0}': client_id '{1}' is already used by another app; each kind needs its own client"
    )]
    DuplicateClient(String, String),
    /// A required field is empty: the kind and the field.
    #[error("app '{0}': {1} must not be empty")]
    Empty(String, &'static str),
    /// A kind's API URL is not http(s).
    #[error("app '{0}': api_upstream must be an http(s) URL")]
    InvalidUpstream(String),
    /// A kind's scopes lack `openid` or ask for `offline_access`: the kind and why.
    #[error("app '{0}': scopes {1}")]
    InvalidScopes(String, &'static str),
    /// A limit is zero: the kind and the field.
    #[error("app '{0}': {1} must be greater than zero")]
    Zero(String, &'static str),
    /// A site's id is not a DNS label.
    #[error(
        "site '{0}': id must be 1-63 characters of a-z, 0-9 and '-', not starting or ending with '-'"
    )]
    InvalidId(String),
    /// Two entries share a site id.
    #[error("site '{0}' is listed more than once")]
    DuplicateId(String),
    /// A site's origin is not a bare origin.
    #[error("site '{0}': origin must be scheme://host[:port] with no path, query or credentials")]
    InvalidOrigin(String),
    /// A site's origin is plain HTTP outside localhost.
    #[error("site '{0}': origin must use https (http is only allowed for localhost)")]
    InsecureOrigin(String),
    /// Two sites share an origin.
    #[error("site '{0}': origin is already used by another site")]
    DuplicateOrigin(String),
    /// A record names a kind the registry does not have: the site and the kind.
    #[error("site '{0}': unknown app kind '{1}'")]
    UnknownKind(String, String),
    /// A kind's document lists sites in a registry whose installations come from a store.
    #[error("app '{0}': installations come from the store, so its document must not list sites")]
    SitesInStore(String),
    /// Another site of the same kind answers to the same `Host` header, e.g. `http://x` and
    /// `https://x`: the header has no scheme, so the edge could not tell them apart.
    #[error("site '{0}': another site of its kind has the same host and port")]
    SharedHost(String),
    /// A kind's edge key is malformed.
    #[error("app '{0}': edge_public_key must be 'ed25519:' followed by 32 bytes in base64url")]
    InvalidPublicKey(String),
    /// Two kinds share an edge key: one edge could then sign for both.
    #[error("app '{0}': edge_public_key is already used by another app; each kind needs its own")]
    DuplicateEdgeKey(String),
    /// A kind names neither an edge key nor native settings.
    #[error(
        "app '{0}': needs edge_public_key (for web-app installations), native (for native installations), or both"
    )]
    KindAccess(String),
    /// A kind's native redirect path is not a plain absolute path.
    #[error(
        "app '{0}': native.redirect_path must be an absolute path such as /callback, without query or fragment"
    )]
    InvalidRedirectPath(String),
    /// An installation names neither or both of an origin and keys.
    #[error("site '{0}': needs an origin (a web app) or keys (a native app), not both")]
    SiteAccess(String),
    /// A web-app installation whose kind has no edge key: no edge could serve it.
    #[error("site '{0}': a web-app installation needs its kind's edge_public_key")]
    NoEdgeKey(String),
    /// A native installation whose kind has no native settings.
    #[error("site '{0}': a native installation needs its kind's native settings")]
    NoNativeSettings(String),
    /// A native installation's key is malformed.
    #[error("site '{0}': keys must each be 'ed25519:' followed by 32 bytes in base64url")]
    InvalidInstallationKey(String),
    /// A native installation's key is already another installation's or an edge's.
    #[error(
        "site '{0}': a key is already used by another installation or an edge; each needs its own"
    )]
    DuplicateKey(String),
    /// A direct kind's site has no API, or a proxied kind's site names one.
    #[error("site '{0}': api_url is required for a kind without api_upstream, and only there")]
    ApiUrlPlacement(String),
    /// A site's API URL is not http(s).
    #[error("site '{0}': api_url must be an http(s) URL")]
    InvalidApiUrl(String),
    /// A site's tenant is malformed.
    #[error("site '{0}': tenant must be 1-128 characters of A-Z, a-z, 0-9, '.', '_' and '-'")]
    InvalidTenant(String),
}

/// Every app kind and site the hub serves, validated and indexed: an indexed snapshot, plus the
/// installations changed since it was built ([`Registry::with_changes`]), so applying a change
/// costs as much as the change, not as much as the registry. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    /// The app kinds, one per document.
    apps: Vec<App>,
    /// The sites the registry was built with, indexed.
    base: Arc<Snapshot>,
    /// Installations changed since `base` was built.
    changes: Arc<Changes>,
}

/// Indexed sites.
#[derive(Debug, Default)]
struct Snapshot {
    /// Every site.
    sites: Vec<Site>,
    /// Index into `sites` by id: the hub looks a site up on every signed request.
    by_id: HashMap<String, usize>,
    /// Index into `sites` by kind and `Host` header ([`host_key`]): the edge looks a site up on
    /// every request.
    by_host: HashMap<String, usize>,
}

impl Snapshot {
    /// Indexes `sites`, whose ids and host keys are unique.
    fn new(sites: Vec<Site>) -> Self {
        let mut snapshot = Self {
            sites,
            ..Self::default()
        };
        for (i, site) in snapshot.sites.iter().enumerate() {
            snapshot.by_id.insert(site.id.clone(), i);
            for key in host_keys(site) {
                snapshot.by_host.insert(key, i);
            }
        }
        snapshot
    }
}

/// Installations changed since a snapshot was built.
#[derive(Clone, Debug, Default)]
struct Changes {
    /// Each changed installation by id: its current site, or `None` once removed.
    sites: HashMap<String, Option<Site>>,
    /// The id of the changed site each host key was last given to; checked on lookup, as the
    /// site may have moved since.
    by_host: HashMap<String, String>,
}

/// An installation as a store keeps it, to be validated against its kind: see
/// [`Registry::with_installations`] and [`Registry::with_changes`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationRecord {
    /// See [`Site::id`].
    pub id: String,
    /// See [`Site::app_id`].
    pub kind: String,
    /// See [`Access::Web`]; for a web-app installation.
    #[serde(default)]
    pub origin: Option<String>,
    /// See [`Access::Native`], each as `ed25519:<base64url>`: a native installation's keys
    /// in use.
    #[serde(default)]
    pub keys: Vec<String>,
    /// See [`Site::api_url`].
    #[serde(default)]
    pub api_url: Option<String>,
    /// See [`Site::tenant`].
    pub tenant: String,
    /// See [`Site::enabled`].
    pub enabled: bool,
    /// See [`Site::login_per_minute`].
    #[serde(default)]
    pub login_per_minute: Option<u64>,
}

/// A kind's web-app installations that changed after the version its edge asked from, as the
/// hub sends them: each with its record, or `None` if removed. The edge drops what it cached of
/// them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindFeed {
    /// The store version this is as of; the edge asks from it next.
    pub version: i64,
    /// Each installation by id, with its record or `None` if removed.
    pub changes: Vec<(String, Option<InstallationRecord>)>,
}

/// The hub's answer to an edge looking up a host: the kind's enabled web-app installation there,
/// if any, and the store version the hub serves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLookup {
    /// The store version the hub's registry is as of.
    pub version: i64,
    /// The installation, or `None` if the kind has no enabled one at the host.
    pub installation: Option<InstallationRecord>,
}

impl InstallationRecord {
    /// The file form of this record, for [`validate_site`].
    fn entry(&self) -> SiteEntry {
        SiteEntry {
            id: self.id.clone(),
            origin: self.origin.clone(),
            keys: self.keys.clone(),
            api_url: self.api_url.clone(),
            tenant: self.tenant.clone(),
            enabled: self.enabled,
            login_per_minute: self.login_per_minute,
        }
    }
}

/// `record` validated as an installation of `app`, as a store's writer checks it before
/// writing. Unlike a registry, it accepts a native installation without keys.
pub fn validate_installation(
    record: &InstallationRecord,
    app: &App,
) -> Result<Site, RegistryError> {
    if record.kind != app.id {
        return Err(RegistryError::UnknownKind(
            record.id.clone(),
            record.kind.clone(),
        ));
    }
    validate_site(record.entry(), app, true)
}

/// A web-app installation's hosts as its kind's edge sees them: with its port, and without it
/// when the port is its scheme's default; `None` for a native installation. What a store keeps
/// unique per kind.
pub fn web_hosts(site: &Site) -> Option<(String, Option<String>)> {
    let mut keys = host_keys(site).into_iter().map(|key| {
        key.split_once('\n')
            .map(|(_, host)| host.to_owned())
            .unwrap_or_default()
    });
    Some((keys.next()?, keys.next()))
}

/// The [`Registry::by_host`] key of `host` (lowercase) at kind `app_id`'s edge.
fn host_key(app_id: &str, host: &str) -> String {
    format!("{app_id}\n{host}")
}

/// Every [`Registry::by_host`] key `site` answers to: its host with its port, and also without
/// it when the port is its scheme's default, as browsers send `Host`. None for a native
/// installation. Validation and the index both use this, so they cannot disagree.
fn host_keys(site: &Site) -> Vec<String> {
    let Some(origin) = site.origin() else {
        return Vec::new();
    };
    // The URL parser lowercases the host already.
    let host = origin.host_str().unwrap_or_default();
    let port = origin.port_or_known_default().unwrap_or_default();
    let mut keys = vec![host_key(&site.app_id, &format!("{host}:{port}"))];
    let default_port = if origin.scheme() == "https" { 443 } else { 80 };
    if port == default_port {
        keys.push(host_key(&site.app_id, host));
    }
    keys
}

/// A key's id: the first 16 characters of the base64url SHA-256 of its 32 bytes. Signed requests
/// name it, so the hub verifies with one key however many an installation has.
pub fn key_id(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, key).as_ref())[..16].to_owned()
}

impl Registry {
    /// Combines every team's document; `name` (usually the file name) appears in parse errors.
    pub fn from_documents<'a>(
        documents: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, RegistryError> {
        Self::build(documents, true)
    }

    /// The kinds in every team's document, without installations, for a registry whose
    /// installations come from a store ([`Registry::with_installations`]); a document that lists
    /// sites is refused.
    pub fn kinds_from_documents<'a>(
        documents: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, RegistryError> {
        Self::build(documents, false)
    }

    /// [`Registry::from_documents`], refusing sites unless `allow_sites`.
    fn build<'a>(
        documents: impl IntoIterator<Item = (&'a str, &'a str)>,
        allow_sites: bool,
    ) -> Result<Self, RegistryError> {
        let (mut apps, mut sites) = (Vec::new(), Vec::new());
        // Edge and installation keys share one set, and their ids another: no key, nor any id,
        // may speak for two of them.
        let (mut app_ids, mut clients, mut site_ids, mut origins, mut keys, mut key_ids) = (
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );
        // Every by_host key, so each names exactly one site.
        let mut hosts = HashSet::new();
        for (name, text) in documents {
            let document: Document = serde_json::from_str(text)
                .map_err(|e| RegistryError::Json(name.to_owned(), e.to_string()))?;
            let app = validate_app(document.app)?;
            if !app_ids.insert(app.id.clone()) {
                return Err(RegistryError::DuplicateApp(app.id));
            }
            if !clients.insert(app.client_id.clone()) {
                return Err(RegistryError::DuplicateClient(app.id, app.client_id));
            }
            if let Some(edge_key) = app.edge_public_key
                && !(keys.insert(edge_key) && key_ids.insert(key_id(&edge_key)))
            {
                return Err(RegistryError::DuplicateEdgeKey(app.id));
            }
            if !allow_sites && !document.sites.is_empty() {
                return Err(RegistryError::SitesInStore(app.id));
            }
            for entry in document.sites {
                let site = validate_site(entry, &app, false)?;
                if !site_ids.insert(site.id.clone()) {
                    return Err(RegistryError::DuplicateId(site.id));
                }
                if let Some(origin) = site.origin()
                    && !origins.insert(origin.as_str().to_owned())
                {
                    return Err(RegistryError::DuplicateOrigin(site.id));
                }
                if !host_keys(&site).into_iter().all(|key| hosts.insert(key)) {
                    return Err(RegistryError::SharedHost(site.id));
                }
                if !site
                    .keys()
                    .iter()
                    .all(|key| keys.insert(key.key) && key_ids.insert(key.id.clone()))
                {
                    return Err(RegistryError::DuplicateKey(site.id));
                }
                sites.push(site);
            }
            apps.push(app);
        }
        Ok(Self {
            apps,
            base: Arc::new(Snapshot::new(sites)),
            changes: Arc::default(),
        })
    }

    /// This registry's kinds with exactly `records` as their installations, from a store that
    /// has kept ids, origins, host keys and keys unique. A record that fails validation, names
    /// an unknown kind or repeats what an earlier one holds is left out and returned with the
    /// reason.
    pub fn with_installations(
        &self,
        records: impl IntoIterator<Item = InstallationRecord>,
    ) -> (Self, Vec<(String, RegistryError)>) {
        let (mut sites, mut rejected) = (Vec::new(), Vec::new());
        let (mut ids, mut hosts, mut keys) = (HashSet::new(), HashSet::new(), HashSet::new());
        keys.extend(self.apps.iter().filter_map(|app| app.edge_public_key));
        for record in records {
            let site = match self.validate_record(&record) {
                Ok(site) => site,
                Err(error) => {
                    rejected.push((record.id, error));
                    continue;
                }
            };
            let unique = ids.insert(site.id.clone())
                && host_keys(&site).into_iter().all(|key| hosts.insert(key))
                && site.keys().iter().all(|key| keys.insert(key.key));
            if unique {
                sites.push(site);
            } else {
                rejected.push((site.id.clone(), RegistryError::DuplicateId(site.id)));
            }
        }
        let registry = Self {
            apps: self.apps.clone(),
            base: Arc::new(Snapshot::new(sites)),
            changes: Arc::default(),
        };
        (registry, rejected)
    }

    /// This registry with the installations in `changes` replaced: each by its new record, or
    /// removed with `None`. Copies only the changes so far, never the snapshot. A record that
    /// fails validation removes the installation and is returned with the reason.
    pub fn with_changes(
        &self,
        changes: impl IntoIterator<Item = (String, Option<InstallationRecord>)>,
    ) -> (Self, Vec<(String, RegistryError)>) {
        let mut next = (*self.changes).clone();
        let mut rejected = Vec::new();
        for (id, record) in changes {
            let site = record.and_then(|record| match self.validate_record(&record) {
                Ok(site) => Some(site),
                Err(error) => {
                    rejected.push((id.clone(), error));
                    None
                }
            });
            if let Some(site) = &site {
                for key in host_keys(site) {
                    next.by_host.insert(key, id.clone());
                }
            }
            next.sites.insert(id, site);
        }
        let registry = Self {
            apps: self.apps.clone(),
            base: self.base.clone(),
            changes: Arc::new(next),
        };
        (registry, rejected)
    }

    /// The same registry with its changes folded into a new snapshot.
    pub fn compacted(&self) -> Self {
        Self {
            apps: self.apps.clone(),
            base: Arc::new(Snapshot::new(self.sites().cloned().collect())),
            changes: Arc::default(),
        }
    }

    /// How many installations changed since the snapshot was built.
    pub fn pending_changes(&self) -> usize {
        self.changes.sites.len()
    }

    /// `record` as a site of its kind. A native installation may still await its first key: it
    /// can sign nothing, but an installation admin can enroll a machine for it.
    fn validate_record(&self, record: &InstallationRecord) -> Result<Site, RegistryError> {
        let app = self
            .app(&record.kind)
            .ok_or_else(|| RegistryError::UnknownKind(record.id.clone(), record.kind.clone()))?;
        validate_site(record.entry(), app, true)
    }

    /// This registry narrowed to kind `app_id` and its sites, re-indexed. For an edge, which
    /// validates the whole set as the hub does, so both accept and refuse the same changes, but
    /// serves one kind and need not hold the others.
    pub fn only_kind(&self, app_id: &str) -> Self {
        Self {
            apps: self
                .apps
                .iter()
                .filter(|app| app.id == app_id)
                .cloned()
                .collect(),
            base: Arc::new(Snapshot::new(
                self.sites()
                    .filter(|site| site.app_id == app_id)
                    .cloned()
                    .collect(),
            )),
            changes: Arc::default(),
        }
    }

    /// Every app kind.
    pub fn apps(&self) -> &[App] {
        &self.apps
    }

    /// Every site, enabled or not.
    pub fn sites(&self) -> impl Iterator<Item = &Site> {
        let changes = &self.changes.sites;
        self.base
            .sites
            .iter()
            .filter(|site| !changes.contains_key(&site.id))
            .chain(changes.values().flatten())
    }

    /// How many sites there are, enabled or not.
    pub fn site_count(&self) -> usize {
        self.sites().count()
    }

    /// The app kind `id`.
    pub fn app(&self, id: &str) -> Option<&App> {
        self.apps.iter().find(|a| a.id == id)
    }

    /// Any registered site, enabled or not.
    pub fn get(&self, id: &str) -> Option<&Site> {
        match self.changes.sites.get(id) {
            Some(changed) => changed.as_ref(),
            None => self.base.by_id.get(id).map(|&i| &self.base.sites[i]),
        }
    }

    /// An enabled site and its app: the only sites allowed to sign users in and
    /// call APIs.
    pub fn enabled(&self, id: &str) -> Option<(&Site, &App)> {
        let site = self.get(id).filter(|s| s.enabled)?;
        Some((site, self.app(&site.app_id)?))
    }

    /// The enabled web-app installation of kind `app_id` that a request with `Host` header
    /// `host` is for: the same host, ignoring case, and the same port, the scheme's default if
    /// none is given.
    pub fn site_for_host(&self, app_id: &str, host: &str) -> Option<&Site> {
        let key = host_key(app_id, &host.to_ascii_lowercase());
        // A changed site that still answers to the host...
        let changed = self
            .changes
            .by_host
            .get(&key)
            .and_then(|id| self.get(id))
            .filter(|site| host_keys(site).contains(&key));
        // ...or the snapshot's, unless it has changed since.
        let site = changed.or_else(|| {
            let site = &self.base.sites[*self.base.by_host.get(&key)?];
            (!self.changes.sites.contains_key(&site.id)).then_some(site)
        })?;
        Some(site).filter(|site| site.enabled)
    }
}

/// The registry documents in directory `dir`, `*.json` only, sorted by name, and a version
/// that changes whenever any of them does.
pub fn read_documents(dir: &str) -> io::Result<(Vec<(String, String)>, String)> {
    let mut documents = Vec::new();
    for entry in fs::read_dir(Path::new(dir))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        documents.push((name, fs::read_to_string(&path)?));
    }
    documents.sort();
    let fingerprint: String = documents
        .iter()
        .map(|(name, text)| format!("{name}\n{text}\n"))
        .collect();
    let version = hash_key(&fingerprint)[..12].to_owned();
    Ok((documents, version))
}

/// Whether `id` is a valid kind or site id: a DNS label.
fn valid_id(id: &str) -> bool {
    (1..=63).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

/// `entry` checked and with its defaults filled in.
fn validate_app(entry: AppEntry) -> Result<App, RegistryError> {
    let id = entry.id;
    if !valid_id(&id) {
        return Err(RegistryError::InvalidAppId(id));
    }
    for (value, field) in [
        (&entry.client_id, "client_id"),
        (&entry.api_audience, "api_audience"),
    ] {
        if value.trim().is_empty() {
            return Err(RegistryError::Empty(id, field));
        }
    }
    let api_upstream = entry
        .api_upstream
        .map(|upstream| {
            Url::parse(&upstream)
                .ok()
                .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
                .ok_or_else(|| RegistryError::InvalidUpstream(id.clone()))
        })
        .transpose()?;
    for (value, field) in [
        (entry.api_read_timeout_secs, "api_read_timeout_secs"),
        (entry.max_concurrency as u64, "max_concurrency"),
        (entry.login_per_minute, "login_per_minute"),
    ] {
        if value == 0 {
            return Err(RegistryError::Zero(id, field));
        }
    }
    let scopes: Vec<&str> = entry
        .scopes
        .as_deref()
        .unwrap_or("openid")
        .split_whitespace()
        .collect();
    if !scopes.contains(&"openid") {
        return Err(RegistryError::InvalidScopes(id, "must include openid"));
    }
    if scopes.contains(&"offline_access") {
        return Err(RegistryError::InvalidScopes(
            id,
            "must not include offline_access: sessions end with the provider's",
        ));
    }
    let scopes = scopes.join(" ");
    if entry.edge_public_key.is_none() && entry.native.is_none() {
        return Err(RegistryError::KindAccess(id));
    }
    let edge_public_key = entry
        .edge_public_key
        .map(|key| {
            parse_public_key(&key).ok_or_else(|| RegistryError::InvalidPublicKey(id.clone()))
        })
        .transpose()?;
    let native = entry
        .native
        .map(|native| {
            let path = &native.redirect_path;
            let plain = path.starts_with('/')
                && !path.starts_with("//")
                && path.len() <= 255
                && path
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#'));
            if plain {
                Ok(Native {
                    redirect_path: native.redirect_path,
                    admin_role: native
                        .admin_role
                        .unwrap_or_else(|| format!("{id}-installation-admin")),
                })
            } else {
                Err(RegistryError::InvalidRedirectPath(id.clone()))
            }
        })
        .transpose()?;
    Ok(App {
        id,
        edge_public_key,
        native,
        client_id: entry.client_id,
        client_secret_file: entry.client_secret_file.filter(|f| !f.trim().is_empty()),
        api_upstream,
        api_audience: entry.api_audience,
        scopes,
        required_role: entry.required_role.filter(|r| !r.trim().is_empty()),
        api_read_timeout_secs: entry.api_read_timeout_secs,
        max_concurrency: entry.max_concurrency,
        login_per_minute: entry.login_per_minute,
    })
}

/// `entry`, a site of `app`, checked and with its defaults filled in.
/// `entry` validated as a site of `app`; a native installation without keys only if
/// `allow_no_keys`.
fn validate_site(entry: SiteEntry, app: &App, allow_no_keys: bool) -> Result<Site, RegistryError> {
    let id = entry.id;
    if !valid_id(&id) {
        return Err(RegistryError::InvalidId(id));
    }

    // A web-app installation is an origin its kind's edge serves; a native installation is
    // its keys, under its kind's native settings.
    let access = match (entry.origin, entry.keys.is_empty()) {
        (Some(origin), true) => {
            if app.edge_public_key.is_none() {
                return Err(RegistryError::NoEdgeKey(id));
            }
            Access::Web {
                origin: validate_origin(&id, &origin)?,
            }
        }
        (None, false) => {
            if app.native.is_none() {
                return Err(RegistryError::NoNativeSettings(id));
            }
            let keys = entry
                .keys
                .iter()
                .map(|text| {
                    let key = parse_public_key(text)
                        .ok_or_else(|| RegistryError::InvalidInstallationKey(id.clone()))?;
                    Ok(InstallationKey {
                        id: key_id(&key),
                        key,
                    })
                })
                .collect::<Result<Vec<_>, RegistryError>>()?;
            Access::Native {
                keys: Arc::new(InstallationKeys::new(keys)),
            }
        }
        (None, true) if allow_no_keys => {
            if app.native.is_none() {
                return Err(RegistryError::NoNativeSettings(id));
            }
            Access::Native {
                keys: Arc::new(InstallationKeys::new(Vec::new())),
            }
        }
        _ => return Err(RegistryError::SiteAccess(id)),
    };

    if entry.api_url.is_some() != app.direct() {
        return Err(RegistryError::ApiUrlPlacement(id));
    }
    let api_url = entry
        .api_url
        .map(|url| {
            Url::parse(&url)
                .ok()
                .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
                .ok_or_else(|| RegistryError::InvalidApiUrl(id.clone()))
        })
        .transpose()?;

    let tenant = entry.tenant;
    let tenant_ok = (1..=128).contains(&tenant.len())
        && tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !tenant_ok {
        return Err(RegistryError::InvalidTenant(id));
    }

    Ok(Site {
        id,
        app_id: app.id.clone(),
        access,
        api_url,
        tenant,
        enabled: entry.enabled,
        login_per_minute: entry
            .login_per_minute
            .filter(|n| *n > 0)
            .unwrap_or(app.login_per_minute),
    })
}

/// Site `id`'s `text` as an origin: scheme, host and port only, https except for localhost.
fn validate_origin(id: &str, text: &str) -> Result<Url, RegistryError> {
    let invalid = || RegistryError::InvalidOrigin(id.to_owned());
    let origin = Url::parse(text).map_err(|_| invalid())?;
    let bare = origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none()
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.host_str().is_some()
        && text.trim_end_matches('/').matches('/').count() == 2;
    if !bare {
        return Err(invalid());
    }
    let host = origin.host_str().unwrap_or_default();
    let local = host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1";
    match origin.scheme() {
        "https" => Ok(origin),
        "http" if local => Ok(origin),
        "http" => Err(RegistryError::InsecureOrigin(id.to_owned())),
        _ => Err(invalid()),
    }
}

/// The 32 key bytes of a registry key, `ed25519:<base64url>`.
pub fn parse_public_key(text: &str) -> Option<[u8; 32]> {
    let encoded = text.strip_prefix(KEY_PREFIX)?;
    URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct valid edge key per kind id.
    fn key(app_id: &str) -> String {
        let mut bytes = [0u8; 32];
        bytes[..app_id.len().min(32)].copy_from_slice(&app_id.as_bytes()[..app_id.len().min(32)]);
        format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    fn app(id: &str, client: &str) -> String {
        format!(
            r#""app": {{ "id": "{id}", "client_id": "{client}", "client_secret_file": "/run/secrets/{client}",
                "edge_public_key": "{}", "api_upstream": "http://{id}-api:8080", "api_audience": "{id}-api" }}"#,
            key(id)
        )
    }

    fn site(id: &str, origin: &str) -> String {
        format!(r#"{{ "id": "{id}", "origin": "{origin}", "tenant": "t1" }}"#)
    }

    fn document(app_id: &str, client: &str, sites: &[String]) -> String {
        format!(
            r#"{{ {}, "sites": [ {} ] }}"#,
            app(app_id, client),
            sites.join(", ")
        )
    }

    fn one(sites: &[String]) -> Result<Registry, RegistryError> {
        let doc = document("inspection", "hub-inspection", sites);
        Registry::from_documents([("inspection.json", doc.as_str())])
    }

    #[test]
    fn given_two_teams_documents_when_combined_then_sites_resolve_to_their_app() {
        let inspection = document(
            "inspection",
            "hub-inspection",
            &[
                site("plant-a", "https://plant-a.example"),
                site("plant-b", "http://plant-b.localhost:5202"),
            ],
        );
        let billing = document(
            "billing",
            "hub-billing",
            &[site("plant-c", "https://plant-c.example")],
        );
        let r = Registry::from_documents([
            ("inspection.json", inspection.as_str()),
            ("billing.json", billing.as_str()),
        ])
        .unwrap();

        assert_eq!(r.apps().len(), 2);
        assert_eq!(r.site_count(), 3);
        let (site, app) = r.enabled("plant-c").unwrap();
        assert_eq!(app.id, "billing");
        assert_eq!(app.client_id, "hub-billing");
        assert_eq!(app.api_read_timeout_secs, 60, "default");
        assert_eq!(
            site.handoff_url().unwrap().as_str(),
            "https://plant-c.example/auth/handoff"
        );
        assert_eq!(site.login_per_minute, 600, "inherits the app's limit");
        assert!(r.get("missing").is_none());
    }

    #[test]
    fn given_a_disabled_site_when_looked_up_then_only_get_finds_it() {
        let entry = r#"{ "id": "old", "origin": "https://old.example", "tenant": "t", "enabled": false, "login_per_minute": 3 }"#.to_owned();
        let r = one(&[entry]).unwrap();
        assert_eq!(r.get("old").unwrap().login_per_minute, 3);
        assert!(r.enabled("old").is_none());
    }

    #[test]
    fn given_invalid_sites_when_loading_then_each_is_rejected_with_a_reason() {
        let cases = [
            (
                site("Plant_A", "https://a.example"),
                RegistryError::InvalidId("Plant_A".into()),
            ),
            (
                site("a", "https://a.example/app"),
                RegistryError::InvalidOrigin("a".into()),
            ),
            (
                site("a", "https://a.example/?x=1"),
                RegistryError::InvalidOrigin("a".into()),
            ),
            (
                site("a", "https://user@a.example"),
                RegistryError::InvalidOrigin("a".into()),
            ),
            (
                site("a", "ftp://a.example"),
                RegistryError::InvalidOrigin("a".into()),
            ),
            (
                site("a", "http://a.example"),
                RegistryError::InsecureOrigin("a".into()),
            ),
        ];
        for (entry, expected) in cases {
            assert_eq!(
                one(std::slice::from_ref(&entry)).unwrap_err(),
                expected,
                "{entry}"
            );
        }
        let bad_tenant =
            r#"{ "id": "a", "origin": "https://a.example", "tenant": "a b" }"#.to_owned();
        assert_eq!(
            one(&[bad_tenant]).unwrap_err(),
            RegistryError::InvalidTenant("a".into())
        );
        let api_on_proxied = r#"{ "id": "a", "origin": "https://a.example", "tenant": "t", "api_url": "https://api.a" }"#;
        assert_eq!(
            one(&[api_on_proxied.into()]).unwrap_err(),
            RegistryError::ApiUrlPlacement("a".into())
        );
    }

    #[test]
    fn given_invalid_apps_when_loading_then_each_is_rejected_with_a_reason() {
        let load = |doc: String| Registry::from_documents([("x.json", doc.as_str())]).unwrap_err();
        assert_eq!(
            load(document("Inspection", "c", &[])),
            RegistryError::InvalidAppId("Inspection".into())
        );
        assert_eq!(
            load(document("inspection", "c", &[]).replace(&key("inspection"), "ed25519:abc")),
            RegistryError::InvalidPublicKey("inspection".into())
        );
        assert_eq!(
            load(
                document("inspection", "c", &[]).replace("http://inspection-api:8080", "not a url")
            ),
            RegistryError::InvalidUpstream("inspection".into())
        );
        assert_eq!(
            load(document("inspection", "c", &[]).replace(r#""inspection-api""#, r#""""#)),
            RegistryError::Empty("inspection".into(), "api_audience")
        );
        assert_eq!(
            load(document("inspection", "c", &[]).replace(
                r#""api_audience""#,
                r#""max_concurrency": 0, "api_audience""#
            )),
            RegistryError::Zero("inspection".into(), "max_concurrency")
        );
        assert_eq!(
            load(document("inspection", "c", &[]).replace(
                r#""api_audience""#,
                r#""scopes": "profile", "api_audience""#
            )),
            RegistryError::InvalidScopes("inspection".into(), "must include openid")
        );
        assert!(matches!(
            load(document("inspection", "c", &[]).replace(
                r#""api_audience""#,
                r#""scopes": "openid offline_access", "api_audience""#
            )),
            RegistryError::InvalidScopes(..)
        ));
        // A misspelt field is an error, never silently ignored.
        assert!(matches!(
            load(document("inspection", "c", &[]).replace(r#""api_audience""#, r#""requred_role": "x", "api_audience""#)),
            RegistryError::Json(name, _) if name == "x.json"
        ));
    }

    #[test]
    fn given_clashes_across_teams_when_combined_then_the_set_is_rejected() {
        let a = document(
            "inspection",
            "hub-inspection",
            &[site("plant-a", "https://a.example")],
        );
        let same_app = document("inspection", "hub-other", &[]);
        let same_client = document("billing", "hub-inspection", &[]);
        let same_site = document(
            "billing",
            "hub-billing",
            &[site("plant-a", "https://z.example")],
        );
        let same_origin = document(
            "billing",
            "hub-billing",
            &[site("site-z", "https://a.example/")],
        );
        let same_edge_key =
            document("billing", "hub-billing", &[]).replace(&key("billing"), &key("inspection"));
        let combine = |other: &str| {
            Registry::from_documents([("a.json", a.as_str()), ("b.json", other)]).unwrap_err()
        };

        assert_eq!(
            combine(&same_app),
            RegistryError::DuplicateApp("inspection".into())
        );
        assert_eq!(
            combine(&same_client),
            RegistryError::DuplicateClient("billing".into(), "hub-inspection".into())
        );
        assert_eq!(
            combine(&same_site),
            RegistryError::DuplicateId("plant-a".into())
        );
        assert_eq!(
            combine(&same_origin),
            RegistryError::DuplicateOrigin("site-z".into())
        );
        assert_eq!(
            combine(&same_edge_key),
            RegistryError::DuplicateEdgeKey("billing".into())
        );
    }

    /// A direct kind (no `api_upstream`) with `sites`.
    fn direct(sites: &[String]) -> Result<Registry, RegistryError> {
        let doc = document("maintenance", "hub-maintenance", sites)
            .replace(r#""api_upstream": "http://maintenance-api:8080", "#, "");
        Registry::from_documents([("m.json", doc.as_str())])
    }

    #[test]
    fn given_a_direct_kind_then_each_site_names_its_own_api() {
        let with_api = |id: &str, api: &str| {
            format!(
                r#"{{ "id": "{id}", "origin": "https://{id}.example", "tenant": "t", "api_url": "{api}" }}"#
            )
        };
        let r = direct(&[with_api("plant-d", "https://api.plant-d.example")]).unwrap();
        assert_eq!(
            r.get("plant-d").unwrap().api_url.as_ref().unwrap().as_str(),
            "https://api.plant-d.example/"
        );
        assert_eq!(
            direct(&[site("plant-d", "https://plant-d.example")]).unwrap_err(),
            RegistryError::ApiUrlPlacement("plant-d".into())
        );
        assert_eq!(
            direct(&[with_api("plant-d", "ftp://api")]).unwrap_err(),
            RegistryError::InvalidApiUrl("plant-d".into())
        );
    }

    #[test]
    fn given_a_host_header_then_the_kinds_site_with_that_origin_is_found() {
        let r = one(&[
            site("plant-a", "https://plant-a.example"),
            site("plant-b", "http://plant-b.localhost:5201"),
        ])
        .unwrap();
        let found = |host: &str| r.site_for_host("inspection", host).map(|s| s.id.as_str());
        assert_eq!(found("plant-a.example"), Some("plant-a"));
        assert_eq!(found("PLANT-A.example:443"), Some("plant-a"));
        assert_eq!(found("plant-b.localhost:5201"), Some("plant-b"));
        assert_eq!(
            found("plant-b.localhost"),
            None,
            "port 80 is another origin"
        );
        assert_eq!(found("plant-a.example:8443"), None);
        assert_eq!(found("plant-a.example:x"), None);
        assert_eq!(found("evil.example"), None);
        assert_eq!(
            r.site_for_host("billing", "plant-a.example"),
            None,
            "another kind's edge"
        );
    }

    /// A native kind's document with `sites`; installations' keys come from [`key`].
    fn native(sites: &[String]) -> Result<Registry, RegistryError> {
        let doc = format!(
            r#"{{ "app": {{ "id": "planner", "client_id": "hub-planner", "native": {{}}, "api_audience": "planner-api" }},
                "sites": [ {} ] }}"#,
            sites.join(", ")
        );
        Registry::from_documents([("planner.json", doc.as_str())])
    }

    /// A native installation with `keys`.
    fn installation(id: &str, keys: &[&str]) -> String {
        let keys: Vec<String> = keys.iter().map(|k| format!(r#""{}""#, key(k))).collect();
        format!(
            r#"{{ "id": "{id}", "tenant": "t", "api_url": "https://api.{id}.example", "keys": [ {} ] }}"#,
            keys.join(", ")
        )
    }

    /// The 32 bytes of test key `name`.
    fn key_bytes(name: &str) -> [u8; 32] {
        parse_public_key(&key(name)).unwrap()
    }

    #[test]
    fn given_a_native_installation_then_it_signs_with_its_own_keys() {
        let r = native(&[installation("plant-f", &["f-desk-1", "f-desk-2"])]).unwrap();
        let (site, app) = r.enabled("plant-f").unwrap();
        assert!(site.is_native());
        assert!(!app.serves_web());
        assert_eq!(
            app.native.as_ref().unwrap().redirect_path,
            "/callback",
            "default"
        );
        assert_eq!(site.origin(), None);
        assert_eq!(site.keys().len(), 2, "a key per workstation");
        assert_eq!(
            site.handoff_url(),
            None,
            "the app names its loopback address"
        );
        assert!(!site.serves_host("plant-f.example"), "no edge serves it");
    }

    #[test]
    fn given_a_key_id_then_exactly_that_key_verifies_the_installation() {
        let r = native(&[installation("plant-f", &["f-desk-1", "f-desk-2"])]).unwrap();
        let (site, app) = r.enabled("plant-f").unwrap();
        let desk_2 = key_bytes("f-desk-2");
        assert_eq!(
            site.verifying_key(app, Some(&key_id(&desk_2))),
            Some(&desk_2)
        );
        assert_eq!(
            site.verifying_key(app, Some("unknown-key-id")),
            None,
            "refused before any cryptography"
        );
        assert_eq!(
            site.verifying_key(app, None),
            None,
            "a native installation must name its key"
        );
    }

    /// The inspection kind with an edge key and native settings, and no sites.
    fn kinds() -> Registry {
        let doc = format!(
            r#"{{ "app": {{ "id": "inspection", "client_id": "hub-inspection", "edge_public_key": "{}", "native": {{}}, "api_audience": "i" }} }}"#,
            key("inspection")
        );
        Registry::kinds_from_documents([("i.json", doc.as_str())]).unwrap()
    }

    /// A store's record of a web-app installation at `origin`, or a native one with `keys`.
    fn record(id: &str, origin: Option<&str>, keys: &[&str]) -> InstallationRecord {
        InstallationRecord {
            id: id.into(),
            kind: "inspection".into(),
            origin: origin.map(Into::into),
            keys: keys.iter().map(|name| key(name)).collect(),
            api_url: Some("https://api.example".into()),
            tenant: "t".into(),
            enabled: true,
            login_per_minute: None,
        }
    }

    #[test]
    fn given_store_records_then_the_registry_holds_the_valid_ones() {
        let mut bad_origin = record("plant-x", Some("ftp://x.example"), &[]);
        bad_origin.api_url = None;
        let (r, rejected) = kinds().with_installations([
            record("plant-a", Some("https://plant-a.example"), &[]),
            record("plant-i", None, &["i"]),
            record("plant-new", None, &[]),
            bad_origin,
            InstallationRecord {
                kind: "billing".into(),
                ..record("plant-c", None, &["c"])
            },
        ]);
        assert_eq!(r.site_count(), 3);
        assert!(
            r.get("plant-new").unwrap().keys().is_empty(),
            "awaits its first key"
        );
        let reasons: Vec<&str> = rejected.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(reasons, ["plant-x", "plant-c"]);
        assert_eq!(
            r.site_for_host("inspection", "plant-a.example").unwrap().id,
            "plant-a"
        );
    }

    #[test]
    fn given_documents_with_sites_then_kinds_for_a_store_are_refused() {
        let doc = document(
            "inspection",
            "c",
            &[site("plant-a", "https://plant-a.example")],
        );
        assert_eq!(
            Registry::kinds_from_documents([("i.json", doc.as_str())]).unwrap_err(),
            RegistryError::SitesInStore("inspection".into())
        );
    }

    #[test]
    fn given_changes_then_lookups_see_them_and_the_snapshot_is_shared() {
        let (r, _) = kinds().with_installations([
            record("plant-a", Some("https://plant-a.example"), &[]),
            record("plant-b", Some("https://plant-b.example"), &[]),
            record("plant-i", None, &["i"]),
        ]);
        let (changed, rejected) = r.with_changes([
            // plant-a moves host; plant-b is removed; plant-i gets a second key; plant-n is new.
            (
                "plant-a".into(),
                Some(record("plant-a", Some("https://moved.example"), &[])),
            ),
            ("plant-b".into(), None),
            (
                "plant-i".into(),
                Some(record("plant-i", None, &["i", "i-2"])),
            ),
            (
                "plant-n".into(),
                Some(record("plant-n", Some("https://plant-n.example"), &[])),
            ),
        ]);
        assert!(rejected.is_empty());
        assert!(
            Arc::ptr_eq(&r.base, &changed.base),
            "the snapshot is not copied"
        );
        assert_eq!(changed.pending_changes(), 4);
        assert!(
            changed
                .site_for_host("inspection", "plant-a.example")
                .is_none(),
            "its old host"
        );
        assert_eq!(
            changed
                .site_for_host("inspection", "moved.example")
                .unwrap()
                .id,
            "plant-a"
        );
        assert!(changed.get("plant-b").is_none());
        assert!(
            changed
                .site_for_host("inspection", "plant-b.example")
                .is_none()
        );
        assert_eq!(changed.get("plant-i").unwrap().keys().len(), 2);
        assert_eq!(
            changed
                .site_for_host("inspection", "plant-n.example")
                .unwrap()
                .id,
            "plant-n"
        );
        assert_eq!(changed.site_count(), 3);
        assert_eq!(r.site_count(), 3, "the original is untouched");
        assert!(r.get("plant-b").is_some());

        // Moving again leaves no trace at the intermediate host; compacting changes nothing seen.
        let (again, _) = changed.with_changes([(
            "plant-a".into(),
            Some(record("plant-a", Some("https://third.example"), &[])),
        )]);
        assert!(again.site_for_host("inspection", "moved.example").is_none());
        let compacted = again.compacted();
        assert_eq!(compacted.pending_changes(), 0);
        for host in [
            "plant-a.example",
            "moved.example",
            "third.example",
            "plant-b.example",
            "plant-n.example",
        ] {
            assert_eq!(
                compacted
                    .site_for_host("inspection", host)
                    .map(|s| s.id.clone()),
                again
                    .site_for_host("inspection", host)
                    .map(|s| s.id.clone()),
                "{host}"
            );
        }
        let mut ids: Vec<&str> = compacted.sites().map(|s| s.id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, ["plant-a", "plant-i", "plant-n"]);
    }

    #[test]
    fn given_an_invalid_change_then_the_installation_is_removed_and_the_reason_returned() {
        let (r, _) =
            kinds().with_installations([record("plant-a", Some("https://plant-a.example"), &[])]);
        let (changed, rejected) = r.with_changes([(
            "plant-a".into(),
            Some(record("plant-a", Some("http://plant-a.example"), &[])),
        )]);
        assert_eq!(
            rejected,
            [(
                "plant-a".into(),
                RegistryError::InsecureOrigin("plant-a".into())
            )]
        );
        assert!(
            changed.get("plant-a").is_none(),
            "never kept in a state the rules refuse"
        );
    }

    #[test]
    fn given_a_writer_then_a_native_installation_may_await_its_first_key() {
        let r = kinds();
        let app = r.app("inspection").unwrap();
        let site = validate_installation(&record("plant-new", None, &[]), app).unwrap();
        assert!(site.is_native() && site.keys().is_empty());
        let web = validate_installation(
            &record("plant-a", Some("https://plant-a.example:443"), &[]),
            app,
        )
        .unwrap();
        assert_eq!(
            web_hosts(&web),
            Some(("plant-a.example:443".into(), Some("plant-a.example".into())))
        );
        assert_eq!(web_hosts(&site), None);
    }

    #[test]
    fn given_few_or_many_keys_then_each_is_found_by_its_id() {
        for count in [
            1,
            InstallationKeys::INDEXED_FROM - 1,
            InstallationKeys::INDEXED_FROM,
            40,
        ] {
            let names: Vec<String> = (0..count).map(|n| format!("desk-{n}")).collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let r = native(&[installation("plant-f", &names)]).unwrap();
            let (site, app) = r.enabled("plant-f").unwrap();
            for name in &names {
                let bytes = key_bytes(name);
                assert_eq!(
                    site.verifying_key(app, Some(&key_id(&bytes))),
                    Some(&bytes),
                    "{count} keys"
                );
            }
            assert_eq!(
                site.verifying_key(app, Some("unknown")),
                None,
                "{count} keys"
            );
        }
    }

    #[test]
    fn given_a_copied_installation_then_its_keys_are_shared_not_copied() {
        let r = native(&[installation("plant-f", &["f-desk-1", "f-desk-2"])]).unwrap();
        let site = r.get("plant-f").unwrap();
        assert_eq!(site.clone().keys().as_ptr(), site.keys().as_ptr());
    }

    #[test]
    fn given_one_kind_kept_then_only_its_sites_are_found() {
        let planner = format!(
            r#"{{ "app": {{ "id": "planner", "client_id": "hub-planner", "native": {{}}, "api_audience": "p" }}, "sites": [ {} ] }}"#,
            installation("plant-f", &["f"])
        );
        let inspection = document(
            "inspection",
            "hub-inspection",
            &[site("plant-a", "https://plant-a.example")],
        );
        let r = Registry::from_documents([
            ("a.json", inspection.as_str()),
            ("b.json", planner.as_str()),
        ])
        .unwrap()
        .only_kind("inspection");
        assert_eq!(r.apps().len(), 1);
        assert_eq!(r.site_count(), 1);
        assert_eq!(
            r.site_for_host("inspection", "plant-a.example").unwrap().id,
            "plant-a"
        );
        assert!(r.get("plant-f").is_none(), "another kind's installation");
    }

    #[test]
    fn given_a_mixed_kind_then_web_and_native_installations_each_verify_their_own_way() {
        let doc = format!(
            r#"{{ "app": {{ "id": "inspection", "client_id": "hub-inspection", "edge_public_key": "{}", "native": {{}}, "api_audience": "i" }},
                "sites": [ {{ "id": "plant-a", "origin": "https://plant-a.example", "tenant": "t", "api_url": "https://api.example" }},
                           {} ] }}"#,
            key("inspection"),
            installation("plant-i", &["i-desk"])
        );
        let r = Registry::from_documents([("inspection.json", doc.as_str())]).unwrap();
        let (web, app) = r.enabled("plant-a").unwrap();
        let (desktop, _) = r.enabled("plant-i").unwrap();
        let edge_key = key_bytes("inspection");
        // The kind's edge speaks for its web-app installation, never for its native one.
        assert_eq!(web.verifying_key(app, None), Some(&edge_key));
        assert_eq!(desktop.verifying_key(app, Some(&key_id(&edge_key))), None);
        assert_eq!(
            desktop.verifying_key(app, Some(&key_id(&key_bytes("i-desk")))),
            Some(&key_bytes("i-desk"))
        );
        assert_eq!(
            r.site_for_host("inspection", "plant-a.example").unwrap().id,
            "plant-a"
        );
    }

    #[test]
    fn given_misplaced_origins_and_keys_then_the_installation_is_refused() {
        // Both an origin and keys, or neither.
        let both = installation("plant-f", &["f"])
            .replace(r#""tenant""#, r#""origin": "https://f.example", "tenant""#);
        assert_eq!(
            native(&[both]).unwrap_err(),
            RegistryError::SiteAccess("plant-f".into())
        );
        assert_eq!(
            native(&[
                r#"{ "id": "plant-f", "tenant": "t", "api_url": "https://api.f.example" }"#.into()
            ])
            .unwrap_err(),
            RegistryError::SiteAccess("plant-f".into())
        );
        // A web-app installation in a kind without an edge key, and a native one in a kind without
        // native settings.
        assert_eq!(
            native(&[r#"{ "id": "plant-w", "origin": "https://w.example", "tenant": "t", "api_url": "https://api.example" }"#.into()]).unwrap_err(),
            RegistryError::NoEdgeKey("plant-w".into())
        );
        let keyed = format!(
            r#"{{ "id": "a", "tenant": "t", "keys": ["{}"] }}"#,
            key("a")
        );
        assert_eq!(
            one(&[keyed]).unwrap_err(),
            RegistryError::NoNativeSettings("a".into())
        );
        let bad_key = installation("plant-f", &["f"]).replace(&key("f"), "ed25519:abc");
        assert_eq!(
            native(&[bad_key]).unwrap_err(),
            RegistryError::InvalidInstallationKey("plant-f".into())
        );
        let edge_site_with_empty_keys =
            r#"{ "id": "a", "origin": "https://a.example", "tenant": "t", "keys": [] }"#;
        assert!(
            one(&[edge_site_with_empty_keys.into()]).is_ok(),
            "an empty list is no keys"
        );
    }

    #[test]
    fn given_a_kind_without_either_access_or_a_bad_redirect_path_then_it_is_refused() {
        let load = |doc: String| Registry::from_documents([("x.json", doc.as_str())]).unwrap_err();
        let neither = document("inspection", "c", &[]).replace(
            &format!(r#""edge_public_key": "{}", "#, key("inspection")),
            "",
        );
        assert_eq!(
            load(neither),
            RegistryError::KindAccess("inspection".into())
        );
        for path in ["callback", "//evil", "/cb?x=1", "/cb#x", "/with space"] {
            let doc = format!(
                r#"{{ "app": {{ "id": "planner", "client_id": "c", "native": {{ "redirect_path": "{path}" }}, "api_audience": "a" }} }}"#
            );
            assert_eq!(
                load(doc),
                RegistryError::InvalidRedirectPath("planner".into()),
                "{path}"
            );
        }
    }

    #[test]
    fn given_a_key_used_twice_then_the_set_is_refused() {
        assert_eq!(
            native(&[
                installation("plant-f", &["shared"]),
                installation("plant-g", &["shared"])
            ])
            .unwrap_err(),
            RegistryError::DuplicateKey("plant-g".into())
        );
        let edge = document("inspection", "hub-inspection", &[]);
        let planner = format!(
            r#"{{ "app": {{ "id": "planner", "client_id": "hub-planner", "native": {{}}, "api_audience": "p" }}, "sites": [ {} ] }}"#,
            installation("plant-f", &["inspection"])
        );
        assert_eq!(
            Registry::from_documents([("a.json", edge.as_str()), ("b.json", planner.as_str())])
                .unwrap_err(),
            RegistryError::DuplicateKey("plant-f".into())
        );
    }

    #[test]
    fn given_the_index_then_lookups_match_the_rules_for_hosts() {
        let r = one(&[
            site("plant-a", "https://plant-a.example"),
            site("plant-b", "http://plant-b.localhost:5201"),
        ])
        .unwrap();
        // Every site the index finds, the scan-based rule agrees with, and the reverse.
        for host in [
            "plant-a.example",
            "PLANT-A.example:443",
            "plant-a.example:8443",
            "plant-b.localhost:5201",
            "plant-b.localhost",
            "x",
        ] {
            let indexed = r.site_for_host("inspection", host).map(|s| s.id.clone());
            let scanned = r
                .sites()
                .find(|s| s.serves_host(host))
                .map(|s| s.id.clone());
            assert_eq!(indexed, scanned, "{host}");
        }
        assert_eq!(r.get("plant-b").unwrap().id, "plant-b");
        assert!(r.get("plant-z").is_none());
    }

    #[test]
    fn given_two_sites_of_a_kind_the_edge_cannot_tell_apart_then_the_set_is_refused() {
        // Different origins, same Host header: it carries no scheme.
        for (first, second) in [
            ("http://plant.localhost", "https://plant.localhost"),
            ("https://plant.localhost", "http://plant.localhost:443"),
            ("http://plant.localhost:80", "http://PLANT.localhost"),
        ] {
            let result = one(&[site("first", first), site("second", second)]);
            let expected = if first.ends_with(":80") {
                // The parser drops a default port, so these are the same origin outright.
                RegistryError::DuplicateOrigin("second".into())
            } else {
                RegistryError::SharedHost("second".into())
            };
            assert_eq!(result.unwrap_err(), expected, "{first} and {second}");
        }
        // The same host at another port, or in another kind, is another site.
        assert!(
            one(&[
                site("first", "http://plant.localhost"),
                site("second", "http://plant.localhost:8080")
            ])
            .is_ok()
        );
    }
}
