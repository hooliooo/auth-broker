//! Header names the edge and hub exchange, and header hygiene shared by both proxies.

use axum::http::{HeaderMap, HeaderName, header::CONNECTION};

/// The calling site's id, on edge-to-hub requests and on the hub's requests to the API.
pub const SITE_ID: &str = "x-site-id";
/// When the edge signed the request, in Unix seconds.
pub const SITE_TIMESTAMP: &str = "x-site-timestamp";
/// A random value the hub accepts only once per site.
pub const SITE_NONCE: &str = "x-site-nonce";
/// The edge's Ed25519 signature; see [`crate::signing`].
pub const SITE_SIGNATURE: &str = "x-site-signature";
/// The session handle from the site's cookie, covered by the signature.
pub const SESSION_HANDLE: &str = "x-session-handle";
/// The site's tenant, set by the hub from the registry.
pub const TENANT: &str = "x-tenant";
/// The site's app kind, set by the hub from the registry.
pub const APP_ID: &str = "x-app-id";

/// Headers only the broker itself may set; anything a browser sends with these names is dropped.
pub const BROKER_HEADERS: [&str; 7] = [
    SITE_ID,
    SITE_TIMESTAMP,
    SITE_NONCE,
    SITE_SIGNATURE,
    SESSION_HANDLE,
    TENANT,
    APP_ID,
];

/// Hop-by-hop headers (RFC 9110 §7.6.1); never forwarded in either direction.
const HOP_BY_HOP: [&str; 8] = [
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers in which a proxy reports who the client is and how it connected: its address
/// (`forwarded`, `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`, `true-client-ip`), the
/// host, port and path prefix it asked for, whether it used HTTPS, and which proxy answered
/// (`x-forwarded-server`, set by Traefik and Apache). A browser can send them too, so they are
/// removed and each hop sets its own `x-forwarded-for` (see [`crate::client::ip`]).
pub const FORWARDING: [&str; 10] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-forwarded-proto",
    "x-forwarded-server",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
];

/// Removes from `headers` the hop-by-hop headers (RFC 9110 §7.6.1) and any a sender declared
/// connection-only by listing them in `Connection`, then `Connection` itself.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    headers.remove(CONNECTION);
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Removes from `headers` every header only the broker may set ([`BROKER_HEADERS`]).
pub fn strip_broker_headers(headers: &mut HeaderMap) {
    for name in BROKER_HEADERS {
        headers.remove(name);
    }
}

/// Removes from `headers` every forwarding header ([`FORWARDING`]).
pub fn strip_forwarding(headers: &mut HeaderMap) {
    for name in FORWARDING {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::strip_forwarding;

    #[test]
    fn given_the_headers_an_ingress_adds_then_none_of_them_is_passed_on() {
        let mut headers = HeaderMap::new();
        for name in [
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-forwarded-proto",
            "x-forwarded-server",
            "x-real-ip",
        ] {
            headers.insert(name, HeaderValue::from_static("set-by-traefik"));
        }
        headers.insert("x-trace", HeaderValue::from_static("keep"));

        strip_forwarding(&mut headers);

        assert_eq!(headers.len(), 1, "{headers:?}");
        assert_eq!(headers["x-trace"], "keep");
    }
}
