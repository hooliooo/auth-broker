//! Whether plain-HTTP URLs are allowed: never in production, where anyone on the network path
//! could swap the provider's keys, read tokens or pose as the hub.

pub use oidc::Transport;

/// `ALLOW_INSECURE_HTTP`: `true` accepts `http://` URLs for the identity provider, the hub and
/// site origins, for a local stack; absent or `false` allows HTTPS only. `None` for any
/// other value.
pub fn from_env() -> Option<Transport> {
    match std::env::var("ALLOW_INSECURE_HTTP").as_deref() {
        Err(_) | Ok("false") => Some(Transport::HttpsOnly),
        Ok("true") => Some(Transport::AllowInsecureHttp),
        Ok(_) => None,
    }
}

/// Whether `url` may be used under `transport`: HTTPS, or HTTP when it is allowed.
pub fn allows(transport: Transport, url: &reqwest::Url) -> bool {
    url.scheme() == "https" || (url.scheme() == "http" && transport == Transport::AllowInsecureHttp)
}
