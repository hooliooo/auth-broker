//! A native app's loopback redirect (RFC 8252 §7.3): after sign-in, the hub sends the browser to
//! `http://127.0.0.1:<port><path>` (or `[::1]`), where the desktop app listens for the moment of
//! sign-in. The app picks a free port each time, so any port is accepted; the path is the one its
//! kind registered.

use reqwest::Url;

/// `uri` as a native app's redirect for registered path `path`, if it is one: plain `http` to the
/// IPv4 or IPv6 loopback literal with an explicit port, exactly `path`, and no query, fragment or
/// credentials. `localhost` is refused, as RFC 8252 §8.3 advises: the name may resolve elsewhere,
/// and the app might not be the one listening on it.
pub fn redirect(uri: &str, path: &str) -> Option<Url> {
    let url = Url::parse(uri).ok()?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
    let plain = url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_some()
        && url.path() == path
        && url.query().is_none()
        && url.fragment().is_none();
    (loopback && plain).then_some(url)
}

#[cfg(test)]
mod tests {
    use super::redirect;

    #[test]
    fn given_a_loopback_address_on_any_port_then_it_is_accepted() {
        for uri in [
            "http://127.0.0.1:51004/callback",
            "http://127.0.0.1:1/callback",
            "http://[::1]:65535/callback",
        ] {
            assert!(redirect(uri, "/callback").is_some(), "{uri}");
        }
    }

    #[test]
    fn given_anything_else_then_it_is_refused() {
        for uri in [
            "http://localhost:51004/callback",
            "https://127.0.0.1:51004/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:51004/other",
            "http://127.0.0.1:51004/callback?next=x",
            "http://127.0.0.1:51004/callback#x",
            "http://user@127.0.0.1:51004/callback",
            "http://127.0.0.2:51004/callback",
            "http://10.0.0.1:51004/callback",
            "http://evil.example:51004/callback",
            "com.example.app:/callback",
            "not a url",
        ] {
            assert!(redirect(uri, "/callback").is_none(), "{uri}");
        }
    }
}
