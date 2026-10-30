//! The hub's settings, read once at startup; per-kind settings live in the registry.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use common::{
    client::{
        credentials::{Credentials, InvalidClientKey, SigningKey},
        ip::{ClientIpError, ClientIpSource},
    },
    provider::{IdentityProvider, StandardOidc},
    transport,
};
use oidc::Transport;
use reqwest::Url;
use thiserror::Error;

/// Why the hub refused to start.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("missing env var '{0}'")]
    Missing(&'static str),
    /// A variable is set to something unusable.
    #[error("env var '{0}' is invalid")]
    Invalid(&'static str),
    /// `HUB_PUBLIC_URL` is plain HTTP without `ALLOW_INSECURE_HTTP=true`.
    #[error("HUB_PUBLIC_URL must be https unless ALLOW_INSECURE_HTTP=true")]
    InsecurePublicUrl,
    /// The registry directory cannot be read: its path and the error.
    #[error("cannot read registry directory '{0}': {1}")]
    RegistryDir(String, std::io::Error),
    /// A client key file is unusable.
    #[error(transparent)]
    ClientKey(#[from] InvalidClientKey),
    /// The client IP settings are unusable.
    #[error(transparent)]
    ClientIp(#[from] ClientIpError),
}

/// The identity provider named by `IDENTITY_PROVIDER`: `oidc` (any OpenID Connect provider,
/// standard claims only, the default) or, with the `keycloak` feature, `keycloak`.
fn provider_from_env() -> Result<Arc<dyn IdentityProvider>, ConfigError> {
    match std::env::var("IDENTITY_PROVIDER").as_deref() {
        Err(_) | Ok("oidc") => Ok(Arc::new(StandardOidc)),
        #[cfg(feature = "keycloak")]
        Ok("keycloak") => Ok(Arc::new(keycloak::Keycloak)),
        Ok(_) => Err(ConfigError::Invalid("IDENTITY_PROVIDER")),
    }
}

/// Where each kind's client [`Credentials`] come from.
pub enum ClientCredentials {
    /// `client_secret`: each kind's own secret, read from its registry `client_secret_file`.
    PerKindSecret,
    /// `private_key_jwt`: one key pair for every kind's client; preferred. Always
    /// [`Credentials::PrivateKeyJwt`].
    PrivateKeyJwt(Box<Credentials>),
}

impl ClientCredentials {
    /// Reads `CLIENT_CREDENTIALS` (`client_secret`, the default, or `private_key_jwt`) and, for
    /// the latter, `CLIENT_KEY_FILE`, optionally `CLIENT_KEY_ID`, and optionally
    /// `CLIENT_NEXT_KEY_FILE` / `CLIENT_NEXT_KEY_ID` for a rotation; as the BFF's.
    fn from_env() -> Result<Self, ConfigError> {
        match std::env::var("CLIENT_CREDENTIALS").as_deref() {
            Err(_) | Ok("client_secret") => Ok(Self::PerKindSecret),
            Ok("private_key_jwt") => {
                let signing = SigningKey::from_file(
                    &var("CLIENT_KEY_FILE")?,
                    std::env::var("CLIENT_KEY_ID").ok(),
                )?;
                let next = std::env::var("CLIENT_NEXT_KEY_FILE")
                    .ok()
                    .map(|path| {
                        SigningKey::from_file(&path, std::env::var("CLIENT_NEXT_KEY_ID").ok())
                    })
                    .transpose()?;
                Ok(Self::PrivateKeyJwt(Box::new(Credentials::PrivateKeyJwt {
                    signing: Box::new(signing),
                    next: next.map(Box::new),
                })))
            }
            Ok(_) => Err(ConfigError::Invalid("CLIENT_CREDENTIALS")),
        }
    }
}

/// Settings shared by every app kind.
pub struct HubConfig {
    /// What tokens carry in `iss`, e.g. `https://login.example/realms/apps`.
    pub issuer: String,
    /// Where the hub fetches discovery from; differs from `issuer` inside Docker.
    pub discovery_url: String,
    /// Whether `http://` URLs are accepted for the provider and the hub's own public address.
    pub transport: Transport,
    /// The hub's browser-facing address, e.g. `https://auth.example`.
    pub public_url: Url,
    /// `public_url` + `/auth/callback`: the redirect URI every app kind's client registers.
    pub callback_url: Url,
    /// How the hub authenticates to the provider as each kind's client.
    pub client_credentials: ClientCredentials,
    /// The identity provider's specifics.
    pub provider: Arc<dyn IdentityProvider>,
    /// Redis, for sessions, sign-ins, handoffs, nonces and rate counters.
    pub redis_uri: String,
    /// Directory of registry documents, one JSON file per app kind.
    pub registry_dir: String,
    /// How often the registry and client secrets are re-read.
    pub reload_interval: Duration,
    /// How far an edge's clock may drift before its signatures are refused.
    pub max_clock_skew_secs: u64,
    /// Sign-in starts per client IP per minute, across all sites.
    pub login_per_minute_per_ip: u64,
    /// Where a browser's address comes from on sign-in starts.
    pub client_ip: ClientIpSource,
    /// The public address to listen on.
    pub listen: SocketAddr,
    /// Where Prometheus metrics are served, apart from the public port.
    pub metrics_addr: SocketAddr,
    /// `REGISTRY_DATABASE_URL`: where installations and their keys are kept, if not in the
    /// registry files; the files then hold the app kinds only.
    pub registry_database_url: Option<String>,
    /// `REGISTRY_SYNC_MILLIS`: how often the hub follows the store's changes.
    pub sync_interval: Duration,
    /// `ADMIN_ADDR`: where the registry admin API listens, apart from the public port; only with
    /// a store. Off if unset.
    pub admin_addr: Option<SocketAddr>,
    /// `ADMIN_AUDIENCE`: the audience provisioning clients' access tokens must carry.
    pub admin_audience: String,
    /// `ADMIN_ROLE`: the realm role provisioning clients' access tokens must carry.
    pub admin_role: String,
    /// `SERVED_ACCESS`: the access types this deployment serves, `web` and `native` by default;
    /// a deployment for one type only refuses installations of the other as unknown.
    pub served_access: ServedAccess,
}

/// The installation access types a hub deployment serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServedAccess {
    /// Web-app installations, through their kind's edge.
    pub web: bool,
    /// Native installations, signing for themselves.
    pub native: bool,
}

impl ServedAccess {
    /// Parses a comma-separated list of `web` and `native`; at least one.
    pub fn parse(value: &str) -> Option<Self> {
        let mut served = Self {
            web: false,
            native: false,
        };
        for part in value.split(',').map(str::trim) {
            match part {
                "web" => served.web = true,
                "native" => served.native = true,
                _ => return None,
            }
        }
        (served.web || served.native).then_some(served)
    }

    /// Whether this deployment serves `site`.
    pub fn serves(&self, site: &common::registry::Site) -> bool {
        if site.is_native() {
            self.native
        } else {
            self.web
        }
    }
}

/// The value of variable `name`.
fn var(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::Missing(name))
}

/// Variable `name` parsed as a `T`, or `default` if unset.
fn number<T: std::str::FromStr>(name: &'static str, default: T) -> Result<T, ConfigError> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| ConfigError::Invalid(name)),
        Err(_) => Ok(default),
    }
}

impl HubConfig {
    /// Reads and validates the settings; HTTP URLs only with `ALLOW_INSECURE_HTTP=true`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer = var("ISSUER_URI")?;
        let transport = transport::from_env().ok_or(ConfigError::Invalid("ALLOW_INSECURE_HTTP"))?;
        let public_url = Url::parse(&var("HUB_PUBLIC_URL")?)
            .map_err(|_| ConfigError::Invalid("HUB_PUBLIC_URL"))?;
        if !transport::allows(transport, &public_url) {
            return Err(ConfigError::InsecurePublicUrl);
        }
        let callback_url =
            callback_url(&public_url).ok_or(ConfigError::Invalid("HUB_PUBLIC_URL"))?;
        Ok(Self {
            discovery_url: std::env::var("DISCOVERY_URI").unwrap_or_else(|_| issuer.clone()),
            issuer,
            transport,
            public_url,
            callback_url,
            client_credentials: ClientCredentials::from_env()?,
            provider: provider_from_env()?,
            redis_uri: var("REDIS_URI")?,
            registry_dir: var("REGISTRY_DIR")?,
            reload_interval: Duration::from_secs(number("REGISTRY_RELOAD_SECS", 10)?),
            max_clock_skew_secs: number("MAX_CLOCK_SKEW_SECS", 30)?,
            login_per_minute_per_ip: number("LOGIN_PER_MINUTE_PER_IP", 30)?,
            client_ip: ClientIpSource::from_settings(
                std::env::var("CLIENT_IP_HEADER").ok().as_deref(),
                std::env::var("TRUSTED_PROXIES").ok().as_deref(),
            )?,
            listen: number(
                "LISTEN_ADDR",
                "0.0.0.0:8090".parse().expect("valid address"),
            )?,
            metrics_addr: number(
                "METRICS_ADDR",
                "0.0.0.0:9100".parse().expect("valid address"),
            )?,
            registry_database_url: std::env::var("REGISTRY_DATABASE_URL").ok(),
            sync_interval: Duration::from_millis(number("REGISTRY_SYNC_MILLIS", 1_000)?),
            admin_addr: std::env::var("ADMIN_ADDR")
                .ok()
                .map(|addr| addr.parse().map_err(|_| ConfigError::Invalid("ADMIN_ADDR")))
                .transpose()?,
            admin_audience: std::env::var("ADMIN_AUDIENCE")
                .unwrap_or_else(|_| "registry-admin".into()),
            admin_role: std::env::var("ADMIN_ROLE").unwrap_or_else(|_| "registry-admin".into()),
            served_access: ServedAccess::parse(
                &std::env::var("SERVED_ACCESS").unwrap_or_else(|_| "web,native".into()),
            )
            .ok_or(ConfigError::Invalid("SERVED_ACCESS"))?,
        })
    }

    /// Where the provider sends the browser after logout for `site_id`; the hub then
    /// forwards it to the site.
    pub fn logged_out_url(&self, site_id: &str) -> Url {
        self.public_url
            .join(&format!("/broker/logged-out/{site_id}"))
            .expect("site ids are URL-safe")
    }
}

/// The one redirect URI registered for every app kind's client, under `public_url`.
pub fn callback_url(public_url: &Url) -> Option<Url> {
    public_url.join("/auth/callback").ok()
}

/// Every `*.json` file in `dir`, sorted by name, plus a version that changes with any of them.
pub fn read_documents(dir: &str) -> Result<(Vec<(String, String)>, String), ConfigError> {
    common::registry::read_documents(dir).map_err(|e| ConfigError::RegistryDir(dir.to_owned(), e))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn given_served_access_lists_then_only_web_and_native_parse() {
        let both = ServedAccess {
            web: true,
            native: true,
        };
        assert_eq!(ServedAccess::parse("web,native"), Some(both));
        assert_eq!(ServedAccess::parse(" native , web "), Some(both));
        assert_eq!(
            ServedAccess::parse("native"),
            Some(ServedAccess {
                web: false,
                native: true
            })
        );
        for bad in ["", "web,", "mobile", "web;native"] {
            assert_eq!(ServedAccess::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn given_a_public_url_when_deriving_endpoints_then_one_callback_serves_every_kind() {
        let public_url = Url::parse("https://auth.example/ignored/").unwrap();
        assert_eq!(
            callback_url(&public_url).unwrap().as_str(),
            "https://auth.example/auth/callback"
        );
    }

    #[test]
    fn given_a_registry_directory_when_read_then_only_json_files_count_and_the_version_tracks_content()
     {
        let dir = std::env::temp_dir().join(format!("hub-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("b.json"), "{}").unwrap();
        fs::write(dir.join("a.json"), "{}").unwrap();
        fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let path = dir.to_str().unwrap();

        let (documents, first) = read_documents(path).unwrap();
        assert_eq!(
            documents
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
            ["a.json", "b.json"]
        );
        assert_eq!(
            read_documents(path).unwrap().1,
            first,
            "stable while unchanged"
        );
        fs::write(dir.join("b.json"), "{ }").unwrap();
        assert_ne!(
            read_documents(path).unwrap().1,
            first,
            "changes with content"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
