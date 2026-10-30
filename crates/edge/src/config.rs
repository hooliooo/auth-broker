//! The edge's settings, read once at startup.

use std::{net::SocketAddr, time::Duration};

use common::{
    client::ip::{ClientIpError, ClientIpSource},
    registry::RegistryError,
    signing::{EdgeSigner, SigningError},
    transport::{self, Transport},
};
use reqwest::Url;
use thiserror::Error;

/// Why the edge refused to start.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("missing env var '{0}'")]
    Missing(&'static str),
    /// A variable is set to something unusable.
    #[error("env var '{0}' is invalid")]
    Invalid(&'static str),
    /// A URL is plain HTTP without `ALLOW_INSECURE_HTTP=true`.
    #[error("{0} must be https unless ALLOW_INSECURE_HTTP=true")]
    Insecure(&'static str),
    /// The signing key file cannot be read: its path and the error.
    #[error("cannot read signing key '{0}': {1}")]
    KeyFile(String, std::io::Error),
    /// The signing key is unusable.
    #[error("signing key: {0}")]
    Key(#[from] SigningError),
    /// The client IP settings are unusable.
    #[error(transparent)]
    ClientIp(#[from] ClientIpError),
    /// The registry directory cannot be read: its path and the error.
    #[error("cannot read registry directory '{0}': {1}")]
    RegistryDir(String, std::io::Error),
    /// The registry is invalid.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The registry has no kind `APP_ID`.
    #[error("the registry has no app kind '{0}'")]
    UnknownApp(String),
    /// The edge's key is not the one the registry lists for its kind.
    #[error("EDGE_KEY does not match the edge_public_key of app '{0}' in the registry")]
    KeyMismatch(String),
    /// `APP_ID` has native installations only, which sign for themselves: no edge serves it.
    #[error("app '{0}' has no edge key: its installations are native and sign for themselves")]
    NoWebAccess(String),
}

/// The edge's settings.
pub struct EdgeConfig {
    /// `APP_ID`: the app kind whose sites this edge serves.
    pub app_id: String,
    /// `REGISTRY_DIR`: the registry documents, the same the hub reads.
    pub registry_dir: String,
    /// `REGISTRY_RELOAD_SECS`: how often the registry is re-read (default 10).
    pub reload_interval: Duration,
    /// `REGISTRY_FROM_HUB=true`: the registry files hold the app kinds only, and the kind's
    /// installations come from the hub, which keeps them in its store.
    pub registry_from_hub: bool,
    /// `REGISTRY_SYNC_MILLIS`: how often the edge asks the hub for changes, with
    /// `REGISTRY_FROM_HUB`.
    pub sync_interval: Duration,
    /// The hub as browsers reach it (sign-in redirects).
    pub hub_url: Url,
    /// The hub as this edge reaches it (signed requests); differs inside Docker.
    pub hub_internal_url: String,
    /// Where the kind's edge key comes from.
    signing_key: SigningKeySource,
    /// Where a browser's address comes from.
    pub client_ip: ClientIpSource,
    /// `API_READ_TIMEOUT_SECS`: longest silence from a site's API, for a kind whose edge calls
    /// its sites' APIs directly (default 60).
    pub api_read_timeout_secs: u64,
    /// The address to listen on.
    pub listen: SocketAddr,
    /// `METRICS_ADDR`: where Prometheus metrics are served, apart from the public port.
    pub metrics_addr: SocketAddr,
}

/// Where the kind's edge key comes from.
enum SigningKeySource {
    /// `EDGE_KEY_FILE`: a file holding it.
    File(String),
    /// `EDGE_KEY`: the key itself.
    Inline(String),
}

/// The value of variable `name`.
fn var(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name).map_err(|_| ConfigError::Missing(name))
}

/// Variable `name` as a URL that `transport` allows.
fn url(name: &'static str, transport: Transport) -> Result<Url, ConfigError> {
    let url = Url::parse(&var(name)?).map_err(|_| ConfigError::Invalid(name))?;
    if !transport::allows(transport, &url) {
        return Err(ConfigError::Insecure(name));
    }
    Ok(url)
}

impl EdgeConfig {
    /// Reads and validates the settings; HTTP URLs only with `ALLOW_INSECURE_HTTP=true`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let transport = transport::from_env().ok_or(ConfigError::Invalid("ALLOW_INSECURE_HTTP"))?;
        let hub_url = url("HUB_URL", transport)?;
        let hub_internal_url = match std::env::var("HUB_INTERNAL_URL") {
            Ok(_) => url("HUB_INTERNAL_URL", transport)?,
            Err(_) => hub_url.clone(),
        };
        let signing_key = match std::env::var("EDGE_KEY_FILE") {
            Ok(path) => SigningKeySource::File(path),
            Err(_) => SigningKeySource::Inline(var("EDGE_KEY")?),
        };
        Ok(Self {
            app_id: var("APP_ID")?,
            registry_dir: var("REGISTRY_DIR")?,
            reload_interval: Duration::from_secs(
                std::env::var("REGISTRY_RELOAD_SECS")
                    .map_or(Ok(10), |value| value.parse())
                    .ok()
                    .filter(|secs| *secs > 0)
                    .ok_or(ConfigError::Invalid("REGISTRY_RELOAD_SECS"))?,
            ),
            registry_from_hub: std::env::var("REGISTRY_FROM_HUB")
                .is_ok_and(|value| value == "true"),
            sync_interval: Duration::from_millis(
                std::env::var("REGISTRY_SYNC_MILLIS")
                    .map_or(Ok(1_000), |value| value.parse())
                    .ok()
                    .filter(|millis| *millis > 0)
                    .ok_or(ConfigError::Invalid("REGISTRY_SYNC_MILLIS"))?,
            ),
            hub_internal_url: hub_internal_url.as_str().trim_end_matches('/').to_owned(),
            hub_url,
            signing_key,
            api_read_timeout_secs: std::env::var("API_READ_TIMEOUT_SECS")
                .map_or(Ok(60), |value| value.parse())
                .map_err(|_| ConfigError::Invalid("API_READ_TIMEOUT_SECS"))?,
            client_ip: ClientIpSource::from_settings(
                std::env::var("CLIENT_IP_HEADER").ok().as_deref(),
                std::env::var("TRUSTED_PROXIES").ok().as_deref(),
            )?,
            listen: std::env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:5200".into())
                .parse()
                .map_err(|_| ConfigError::Invalid("LISTEN_ADDR"))?,
            metrics_addr: std::env::var("METRICS_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:9100".into())
                .parse()
                .map_err(|_| ConfigError::Invalid("METRICS_ADDR"))?,
        })
    }
}

/// The kind's signer, with the key `config` names.
pub fn load_signer(config: &EdgeConfig) -> Result<EdgeSigner, ConfigError> {
    let text = match &config.signing_key {
        SigningKeySource::File(path) => std::fs::read_to_string(path)
            .map_err(|error| ConfigError::KeyFile(path.clone(), error))?,
        SigningKeySource::Inline(text) => text.clone(),
    };
    Ok(EdgeSigner::from_base64(&config.app_id, &text)?)
}
