//! The registry: every app kind the hub serves, and every site of each kind.
//!
//! Each team owns one JSON document (one file) describing its app kind, the public key of the
//! kind's one edge, and its sites. Onboarding a site is one entry in that file; adding a kind
//! is one new file, one edge deployment and one identity provider client. The hub and every
//! edge combine all documents and refuse the whole set if any of them is invalid.

use std::{collections::HashSet, fs, io, path::Path};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde::Deserialize;
use thiserror::Error;

use crate::crypto::hash_key;

/// Prefix of a kind's `edge_public_key` in the registry.
pub const KEY_PREFIX: &str = "ed25519:";

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
    /// See [`App::edge_public_key`], as `ed25519:<base64url>`.
    edge_public_key: String,
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
    /// See [`Site::origin`].
    origin: String,
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
    /// kind's sites must verify against it. Unique across kinds.
    pub edge_public_key: [u8; 32],
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

/// A site (installation) of one app kind, served by the kind's edge under its own origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The site's id, e.g. `plant-7`; unique across kinds.
    pub id: String,
    /// The id of the site's app kind.
    pub app_id: String,
    /// Scheme, host and port only, e.g. `https://plant-a.inspection.example.com`. Browsers use it;
    /// it points at the kind's edge, which tells sites apart by it.
    pub origin: Url,
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
}

impl Site {
    /// Whether a request whose `Host` header is `host` is for this site: the same host,
    /// ignoring case, and the same port, the scheme's default if none is given.
    pub fn serves_host(&self, host: &str) -> bool {
        // `[::1]:8080` splits at its last colon; `[::1]` alone leaves `1]`, which is no port.
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) if !port.contains(']') => match port.parse::<u16>() {
                Ok(port) => (name, Some(port)),
                Err(_) => return false,
            },
            _ => (host, None),
        };
        // No port in the header means the scheme's default, not the origin's port.
        let default_port = match self.origin.scheme() {
            "https" => 443,
            _ => 80,
        };
        let expected = self.origin.host_str().unwrap_or_default();
        name.eq_ignore_ascii_case(expected)
            && Some(port.unwrap_or(default_port)) == self.origin.port_or_known_default()
    }

    /// Where the hub sends the browser back to after sign-in.
    pub fn handoff_url(&self) -> Url {
        self.origin
            .join("/auth/handoff")
            .expect("origin joins a fixed path")
    }

    /// The site's start page.
    pub fn home_url(&self) -> Url {
        self.origin.join("/").expect("origin joins a fixed path")
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
    /// A kind's edge key is malformed.
    #[error("app '{0}': edge_public_key must be 'ed25519:' followed by 32 bytes in base64url")]
    InvalidPublicKey(String),
    /// Two kinds share an edge key: one edge could then sign for both.
    #[error("app '{0}': edge_public_key is already used by another app; each kind needs its own")]
    DuplicateEdgeKey(String),
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

/// Every app kind and site the hub serves, validated together.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    /// The app kinds, one per document.
    apps: Vec<App>,
    /// Every kind's sites.
    sites: Vec<Site>,
}

impl Registry {
    /// Combines every team's document; `name` (usually the file name) appears in parse errors.
    pub fn from_documents<'a>(
        documents: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, RegistryError> {
        let mut registry = Registry::default();
        let (mut app_ids, mut clients, mut site_ids, mut origins, mut edge_keys) = (
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );
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
            if !edge_keys.insert(app.edge_public_key) {
                return Err(RegistryError::DuplicateEdgeKey(app.id));
            }
            for entry in document.sites {
                let site = validate_site(entry, &app)?;
                if !site_ids.insert(site.id.clone()) {
                    return Err(RegistryError::DuplicateId(site.id));
                }
                if !origins.insert(site.origin.as_str().to_owned()) {
                    return Err(RegistryError::DuplicateOrigin(site.id));
                }
                registry.sites.push(site);
            }
            registry.apps.push(app);
        }
        Ok(registry)
    }

    /// Every app kind.
    pub fn apps(&self) -> &[App] {
        &self.apps
    }

    /// Every site, enabled or not.
    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    /// The app kind `id`.
    pub fn app(&self, id: &str) -> Option<&App> {
        self.apps.iter().find(|a| a.id == id)
    }

    /// Any registered site, enabled or not.
    pub fn get(&self, id: &str) -> Option<&Site> {
        self.sites.iter().find(|s| s.id == id)
    }

    /// An enabled site and its app: the only sites allowed to sign users in and
    /// call APIs.
    pub fn enabled(&self, id: &str) -> Option<(&Site, &App)> {
        let site = self.get(id).filter(|s| s.enabled)?;
        Some((site, self.app(&site.app_id)?))
    }

    /// The enabled site of kind `app_id` that a request with `Host` header `host` is for.
    pub fn site_for_host(&self, app_id: &str, host: &str) -> Option<&Site> {
        self.sites
            .iter()
            .find(|s| s.enabled && s.app_id == app_id && s.serves_host(host))
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
    let edge_public_key = parse_public_key(&entry.edge_public_key)
        .ok_or_else(|| RegistryError::InvalidPublicKey(id.clone()))?;
    Ok(App {
        id,
        edge_public_key,
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
fn validate_site(entry: SiteEntry, app: &App) -> Result<Site, RegistryError> {
    let id = entry.id;
    if !valid_id(&id) {
        return Err(RegistryError::InvalidId(id));
    }

    let origin = Url::parse(&entry.origin).map_err(|_| RegistryError::InvalidOrigin(id.clone()))?;
    let bare = origin.path() == "/"
        && origin.query().is_none()
        && origin.fragment().is_none()
        && origin.username().is_empty()
        && origin.password().is_none()
        && origin.host_str().is_some()
        && entry.origin.trim_end_matches('/').matches('/').count() == 2;
    if !bare {
        return Err(RegistryError::InvalidOrigin(id));
    }
    let host = origin.host_str().unwrap_or_default();
    let local = host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1";
    match origin.scheme() {
        "https" => {}
        "http" if local => {}
        "http" => return Err(RegistryError::InsecureOrigin(id)),
        _ => return Err(RegistryError::InvalidOrigin(id)),
    }

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
        origin,
        api_url,
        tenant,
        enabled: entry.enabled,
        login_per_minute: entry
            .login_per_minute
            .filter(|n| *n > 0)
            .unwrap_or(app.login_per_minute),
    })
}

/// The 32 key bytes of a registry `edge_public_key`, `ed25519:<base64url>`.
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
        assert_eq!(r.sites().len(), 3);
        let (site, app) = r.enabled("plant-c").unwrap();
        assert_eq!(app.id, "billing");
        assert_eq!(app.client_id, "hub-billing");
        assert_eq!(app.api_read_timeout_secs, 60, "default");
        assert_eq!(
            site.handoff_url().as_str(),
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
}
