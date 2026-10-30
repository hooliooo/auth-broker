//! For a kind whose edge calls its sites' APIs directly: a site's `/api/*` goes straight to that
//! site's `api_url` with the provider's access token, fetched from the hub and cached briefly. The
//! hub keeps the refresh token; the edge only ever holds short-lived access tokens, in memory.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::Request,
    http::{
        HeaderName, HeaderValue, Method,
        header::{AUTHORIZATION, COOKIE, HOST, SET_COOKIE},
    },
    response::Response,
};
use common::{
    api_path::api_url,
    causes::with_causes,
    crypto::hash_key,
    csrf::CSRF_HEADER,
    headers::{strip_broker_headers, strip_forwarding, strip_hop_by_hop},
};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::debug;

use common::metrics;

use crate::{error::EdgeError, state::AppState};

/// The longest a cached token is used: sign-out and lost access take effect within this.
const CACHE_MAX_AGE: Duration = Duration::from_secs(60);
/// A cached token with less than this left is fetched again.
const MIN_TOKEN_LEFT: Duration = Duration::from_secs(30);
/// How long a request waits for a free slot in its site's bulkhead before getting a 503, as the
/// hub waits for its kinds' slots.
const QUEUE_WAIT: Duration = Duration::from_secs(2);

/// Bulkheads for direct API calls, one per site and edge instance, each with the kind's
/// `max_concurrency` slots: one site's slow API or traffic spike fills only its own slots, and an
/// overloaded edge answers 503 instead of queueing without bound (perf/REPORT.md).
#[derive(Default)]
pub struct Bulkheads {
    /// Each site's slots and the limit they were made for; replaced when the registry changes it.
    by_site: Mutex<HashMap<String, (usize, Arc<Semaphore>)>>,
}

impl Bulkheads {
    /// The slots of site `site_id`, sized `limit`.
    fn for_site(&self, site_id: &str, limit: usize) -> Arc<Semaphore> {
        let mut by_site = self.by_site.lock().unwrap_or_else(PoisonError::into_inner);
        match by_site.get(site_id) {
            Some((current, slots)) if *current == limit => slots.clone(),
            _ => {
                let slots = Arc::new(Semaphore::new(limit));
                by_site.insert(site_id.to_owned(), (limit, slots.clone()));
                slots
            }
        }
    }
}

/// One cached access token.
struct Cached {
    /// The token.
    token: String,
    /// When it was fetched from the hub.
    fetched: Instant,
    /// When it expires.
    expires: Instant,
}

/// Access tokens by site and hashed session handle, in this edge's memory only. The site is
/// part of the key, so a handle presented at another site's host never finds a token.
#[derive(Default)]
pub struct TokenCache {
    /// The entries; expired ones are dropped as new ones are added.
    entries: Mutex<HashMap<String, Cached>>,
}

impl TokenCache {
    /// The cached token of session `handle` at site `site_id`, if it is younger than
    /// [`CACHE_MAX_AGE`] and has [`MIN_TOKEN_LEFT`] left.
    fn get(&self, site_id: &str, handle: &str) -> Option<String> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        entries
            .get(&key(site_id, handle))
            .filter(|entry| {
                now.duration_since(entry.fetched) < CACHE_MAX_AGE
                    && entry.expires > now + MIN_TOKEN_LEFT
            })
            .map(|entry| entry.token.clone())
    }

    /// Caches `token` for session `handle` at site `site_id`, expiring in `expires_in`.
    fn put(&self, site_id: &str, handle: &str, token: String, expires_in: Duration) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        entries.retain(|_, entry| now.duration_since(entry.fetched) < CACHE_MAX_AGE);
        entries.insert(
            key(site_id, handle),
            Cached {
                token,
                fetched: now,
                expires: now + expires_in,
            },
        );
    }

    /// Forgets session `handle`'s token at site `site_id`, at sign-out.
    pub fn forget(&self, site_id: &str, handle: &str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key(site_id, handle));
    }
}

/// The cache key of session `handle` at site `site_id`; site ids never contain a newline.
fn key(site_id: &str, handle: &str) -> String {
    hash_key(&format!("{site_id}\n{handle}"))
}

/// Answer of the hub's `/broker/token`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    /// The access token.
    access_token: String,
    /// Seconds until it expires.
    expires_in: u64,
}

/// An access token for session `handle` at site `site_id`: cached, or fetched from `app`'s hub,
/// which refreshes it at the provider if needed. 401 once the hub no longer has the session.
async fn access_token(app: &AppState, site_id: &str, handle: &str) -> Result<String, EdgeError> {
    if let Some(token) = app.tokens.get(site_id, handle) {
        metrics::counter("edge_token_cache_total", &[("outcome", "hit")]);
        return Ok(token);
    }
    metrics::counter("edge_token_cache_total", &[("outcome", "miss")]);
    let response = app
        .hub
        .request(site_id, Method::POST, "/broker/token", Some(handle))?
        .send()
        .await?;
    if !response.status().is_success() {
        debug!(status = %response.status(), "hub has no token for this session");
        return Err(match response.status().as_u16() {
            401 | 403 | 404 => EdgeError::Unauthorized("no token for this session"),
            _ => EdgeError::Hub(format!("token request answered {}", response.status())),
        });
    }
    let token: TokenResponse = response.json().await?;
    app.tokens.put(
        site_id,
        handle,
        token.access_token.clone(),
        Duration::from_secs(token.expires_in),
    );
    Ok(token.access_token)
}

/// Forwards `request` for session `handle` at site `site_id` to that site's API at `upstream`
/// with the session's access token and the browser's address (from `peer` or a trusted proxy's
/// header) as `X-Forwarded-For`, and streams the answer back.
pub async fn api(
    app: &AppState,
    site_id: &str,
    upstream: &reqwest::Url,
    handle: &str,
    peer: SocketAddr,
    request: Request,
) -> Result<Response, EdgeError> {
    let url = api_url(upstream.as_str(), request.uri())
        .ok_or(EdgeError::BadRequest("API path not allowed"))?;
    let slots = app.bulkheads.for_site(site_id, app.sites.max_concurrency());
    let permit = tokio::time::timeout(QUEUE_WAIT, slots.acquire_owned())
        .await
        .map_err(|_| EdgeError::Busy(format!("site '{site_id}' is at its concurrency limit")))?
        .map_err(|_| EdgeError::Busy("bulkhead closed".into()))?;
    let token = access_token(app, site_id, handle).await?;

    let (parts, body) = request.into_parts();
    let mut forwarded = parts.headers;
    let client = app.config.client_ip.client_ip(&forwarded, peer);
    strip_hop_by_hop(&mut forwarded);
    strip_broker_headers(&mut forwarded);
    strip_forwarding(&mut forwarded);
    for name in [AUTHORIZATION, COOKIE, HOST] {
        forwarded.remove(name);
    }
    forwarded.remove(CSRF_HEADER);
    forwarded.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&client.to_string())?,
    );
    forwarded.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );

    let upstream = app
        .api
        .request(parts.method, url)
        .headers(forwarded)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
        .map_err(|e| EdgeError::Api(with_causes(&e)))?;
    let mut response = Response::builder().status(upstream.status());
    let mut returned = upstream.headers().clone();
    strip_hop_by_hop(&mut returned);
    // A cookie the API set would land on the site's origin, outside the edge's control.
    returned.remove(SET_COOKIE);
    if let Some(headers) = response.headers_mut() {
        headers.extend(returned);
    }
    // The slot is held until the response body has been fully streamed.
    let stream = futures_util::StreamExt::map(upstream.bytes_stream(), move |chunk| {
        let _held = &permit;
        chunk
    });
    Ok(response.body(Body::from_stream(stream))?)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::Bulkheads;

    #[test]
    fn given_two_sites_then_each_has_its_own_slots() {
        let bulkheads = Bulkheads::default();
        let plant_d = bulkheads.for_site("plant-d", 2);
        let _taken = (
            plant_d.try_acquire().unwrap(),
            plant_d.try_acquire().unwrap(),
        );

        assert!(plant_d.try_acquire().is_err(), "plant-d is full");
        assert!(
            bulkheads.for_site("plant-e", 2).try_acquire().is_ok(),
            "plant-e's calls are not held up by plant-d's"
        );
    }

    #[test]
    fn given_the_same_limit_then_the_slots_are_kept_and_a_new_limit_replaces_them() {
        let bulkheads = Bulkheads::default();
        let first = bulkheads.for_site("plant-d", 2);
        assert!(Arc::ptr_eq(&first, &bulkheads.for_site("plant-d", 2)));

        let resized = bulkheads.for_site("plant-d", 5);
        assert!(!Arc::ptr_eq(&first, &resized));
        assert_eq!(resized.available_permits(), 5);
    }
}
