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
