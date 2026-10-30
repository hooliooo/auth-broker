//! Mapping a browser's `/api/*` path onto an API's base URL, without letting it escape that base.

use axum::http::Uri;
use reqwest::Url;

/// Whether `path` has a `.` or `..` segment, also percent-encoded or split by backslashes, as
/// lenient servers decode them: URL parsing or the API might resolve it outside the base.
pub fn has_dot_segment(path: &str) -> bool {
    path.to_ascii_lowercase()
        .replace("%2e", ".")
        .replace("%5c", "/")
        .replace('\\', "/")
        .split('/')
        .any(|segment| segment == "." || segment == "..")
}

/// The API URL for browser request `uri`: its path after `/api`, with its query, appended to
/// `api_base_url`. `None` if the path has dot segments ([`has_dot_segment`]) or the result is
/// not under the base.
pub fn api_url(api_base_url: &str, uri: &Uri) -> Option<Url> {
    let path = uri.path().strip_prefix("/api").unwrap_or(uri.path());
    if has_dot_segment(path) {
        return None;
    }
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let base = api_base_url.trim_end_matches('/');
    let url = Url::parse(&format!("{base}{path}{query}")).ok()?;
    url.as_str().starts_with(base).then_some(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A base URL with a path, so escaping it would be visible.
    const BASE: &str = "http://api.internal/v1";

    /// The API URL for `path_and_query`, as text.
    fn target(path_and_query: &str) -> Option<String> {
        api_url(BASE, &path_and_query.parse().unwrap()).map(String::from)
    }

    #[test]
    fn given_an_api_path_then_it_maps_under_the_base_with_its_query() {
        assert_eq!(
            target("/api/orders/7?page=2").as_deref(),
            Some("http://api.internal/v1/orders/7?page=2")
        );
    }

    #[test]
    fn given_dot_segments_then_the_path_is_refused() {
        for path in [
            "/api/../admin",
            "/api/%2e%2e/admin",
            "/api/%2E%2E/%2e%2e/metrics",
            "/api/orders/./7",
            "/api/orders/%2e/7",
            "/api/..%5Cadmin",
        ] {
            assert_eq!(target(path), None, "{path}");
        }
    }

    #[test]
    fn given_dots_inside_a_segment_then_the_path_is_kept() {
        assert_eq!(
            target("/api/files/report..final.pdf").as_deref(),
            Some("http://api.internal/v1/files/report..final.pdf")
        );
    }
}
