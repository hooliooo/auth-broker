//! Where the browser goes after sign-in: only ever a path on the site's own origin.

use reqwest::Url;

/// Resolves a browser-supplied return target against `base` and keeps it only if it stays on
/// that origin. Returns path + query + fragment, so the result can never name another host.
pub fn sanitize(raw: Option<&str>, base: &Url) -> String {
    let Some(raw) = raw else { return "/".into() };
    match base.join(raw) {
        Ok(resolved) if resolved.origin() == base.origin() => {
            let mut out = resolved.path().to_string();
            if let Some(q) = resolved.query() {
                out.push('?');
                out.push_str(q);
            }
            if let Some(f) = resolved.fragment() {
                out.push('#');
                out.push_str(f);
            }
            out
        }
        _ => "/".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://plant-a.example/").unwrap()
    }

    #[test]
    fn given_same_origin_paths_when_sanitizing_then_they_are_kept() {
        assert_eq!(sanitize(None, &base()), "/");
        assert_eq!(
            sanitize(Some("/orders/42?tab=1#x"), &base()),
            "/orders/42?tab=1#x"
        );
    }

    #[test]
    fn given_foreign_origin_targets_when_sanitizing_then_they_fall_back_to_root() {
        for raw in [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "/\t/evil.com",
            "javascript:alert(1)",
            "http://plant-a.example/",
        ] {
            assert_eq!(sanitize(Some(raw), &base()), "/", "accepted {raw:?}");
        }
    }
}
