//! Gives every request an id: in the logs (a tracing span), on the response, and on the call
//! the edge makes to the hub and the hub to the API, so one user's problem can be followed
//! across services.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use tracing::{Instrument, info_span};

use crate::random::random_token;

/// Header carrying the request id.
pub const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Whether an incoming `id` looks like a request id and may be kept; anything else is
/// replaced, so a client cannot write arbitrary text into the logs.
fn acceptable(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Middleware: gives `request` an id, runs `next` inside a tracing span carrying it, and
/// returns the id on the response.
pub async fn assign(mut request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get(&REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|id| acceptable(id))
        .map(str::to_owned)
        .or_else(|| random_token().ok())
        .unwrap_or_else(|| "unavailable".to_owned());
    let value = HeaderValue::from_str(&id).unwrap_or(HeaderValue::from_static("unavailable"));
    request.headers_mut().insert(REQUEST_ID, value.clone());

    let span = info_span!(
        "request",
        id = %id,
        method = %request.method(),
        path = %request.uri().path(),
    );
    let mut response = next.run(request).instrument(span).await;
    response.headers_mut().insert(REQUEST_ID, value);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_an_id_like_value_then_it_is_kept() {
        assert!(acceptable("8f14e45f-ceea-467a"));
        assert!(acceptable("Ab_12345"));
    }

    #[test]
    fn given_text_that_is_not_an_id_then_it_is_replaced() {
        assert!(!acceptable("short"));
        assert!(!acceptable("has spaces in it"));
        assert!(!acceptable("line\nbreak-injection"));
        assert!(!acceptable(&"x".repeat(65)));
    }
}
