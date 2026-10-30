//! Reading and writing cookies, at the hub and at every edge.

use axum::http::{
    HeaderMap, HeaderValue,
    header::{COOKIE, InvalidHeaderValue},
};

use crate::crypto::hash_key;

/// The login cookie of one sign-in, `<prefix>-<hash of state>`, so sign-ins started in two tabs
/// do not overwrite each other's cookie.
pub fn login_cookie(prefix: &str, state: &str) -> String {
    format!("{prefix}-{}", &hash_key(state)[..16])
}

/// The value of cookie `name` in the request's `headers`, if sent.
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

/// A `Set-Cookie` value for cookie `name` holding `value`, with `same_site` (`Strict` or
/// `Lax`) and a lifetime of `max_age` seconds. Always `HttpOnly`, `Secure` and `Path=/`, as
/// `__Host-` cookies must be; browsers enforce it.
pub fn set(
    name: &str,
    value: &str,
    same_site: &str,
    max_age: u64,
) -> Result<HeaderValue, InvalidHeaderValue> {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; Secure; SameSite={same_site}; Max-Age={max_age}"
    ))
}

/// A `Set-Cookie` value that deletes cookie `name`; `same_site` must match how it was set.
pub fn clear(name: &str, same_site: &str) -> Result<HeaderValue, InvalidHeaderValue> {
    set(name, "", same_site, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_two_states_then_their_login_cookies_differ_and_are_stable() {
        assert_ne!(
            login_cookie("__Host-x", "state-a"),
            login_cookie("__Host-x", "state-b")
        );
        assert_eq!(
            login_cookie("__Host-x", "state-a"),
            login_cookie("__Host-x", "state-a")
        );
        assert!(login_cookie("__Host-x", "state-a").starts_with("__Host-x-"));
    }
}
