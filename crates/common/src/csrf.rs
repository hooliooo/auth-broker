//! Cross-site request forgery protection: a custom header on every request the session cookie
//! authorizes (RFC 10017 §6.1.3.3.2), whatever its method.
//!
//! A kind's sites share the kind's domain, so they are the same site to a browser:
//! `SameSite=Strict` does not stop a script injected into one site from sending another site's
//! session cookie, and a `GET` needs no CORS preflight. The header closes that gap: no page of
//! another origin can add it without a preflight, which no edge grants.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Header the app must send with value `1` on every call to `/api/*` and `/auth/*`.
pub const CSRF_HEADER: &str = "x-csrf";
/// Routes under the protected prefixes that cannot carry the header: the browser navigates to
/// them, to start signing in and when the hub hands the sign-in back.
const EXEMPT_PATHS: &[&str] = &["/auth/login", "/auth/handoff"];

/// Whether a request for `path` must carry the header: the routes that act on the session.
/// Health checks and the app's own pages carry no session.
pub fn needs_header(path: &str) -> bool {
    (path.starts_with("/api/") || path.starts_with("/auth/")) && !EXEMPT_PATHS.contains(&path)
}

/// Middleware: refuses `request` with 403 if its route needs the CSRF header and it is missing,
/// otherwise passes it to `next`.
pub async fn require_header(request: Request, next: Next) -> Response {
    let present = request
        .headers()
        .get(CSRF_HEADER)
        .is_some_and(|v| v.as_bytes() == b"1");
    if needs_header(request.uri().path()) && !present {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::needs_header;

    #[test]
    fn given_a_session_route_then_it_needs_the_header_whatever_the_method() {
        for path in ["/api/orders", "/api/x/y", "/auth/session", "/auth/logout"] {
            assert!(needs_header(path), "{path}");
        }
    }

    #[test]
    fn given_navigations_and_checks_then_no_header_is_needed() {
        for path in [
            "/auth/login",
            "/auth/handoff",
            "/",
            "/health",
            "/health/ready",
        ] {
            assert!(!needs_header(path), "{path}");
        }
    }
}
