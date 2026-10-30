//! `/api/*` from an edge to the site's app kind's API, with the session's access token and
//! the verified app, site and tenant.

use std::{net::IpAddr, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        HeaderName, HeaderValue,
        header::{AUTHORIZATION, COOKIE, HOST, SET_COOKIE},
    },
    response::Response,
    routing::any,
};
use common::{
    api_path::api_url,
    headers::{self, strip_broker_headers, strip_forwarding, strip_hop_by_hop},
};

use crate::{
    error::AppError,
    session::{self, fresh_access_token},
    signed::SignedEdge,
    state::AppState,
};

/// How long a request waits for a free slot in its kind's bulkhead before getting a 503.
const QUEUE_WAIT: Duration = Duration::from_secs(2);
/// The header the edge reports the browser's address in, and the API receives it in.
const FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// `/api/{*rest}`: every method, forwarded to the site's kind's API.
pub fn routes() -> Router<AppState> {
    Router::new().route("/api/{*rest}", any(api))
}

/// Forwards `request` from `edge` to its kind's API as `{api_upstream}/{rest}`, with the
/// session's access token (refreshed if needed) and the site's verified facts, and streams
/// the answer back.
async fn api(
    State(state): State<AppState>,
    edge: SignedEdge,
    request: Request,
) -> Result<Response, AppError> {
    let client = edge.client(&state)?;
    // A direct kind's edge calls its sites' APIs itself; the hub never carries its traffic.
    let upstream = client.app.api_upstream.as_ref().ok_or(AppError::NotFound)?;
    let url = api_url(upstream.as_str(), request.uri())
        .ok_or(AppError::BadRequest("API path not allowed"))?;
    // One kind's slow API or traffic spike fills only its own slots, never the others'.
    let permit = tokio::time::timeout(QUEUE_WAIT, client.in_flight.clone().acquire_owned())
        .await
        .map_err(|_| {
            AppError::NotReady(format!("app '{}' is at its concurrency limit", edge.app.id))
        })?
        .map_err(|_| AppError::NotReady("bulkhead closed".into()))?;

    let handle = edge.require_handle()?;
    let mut redis = state.redis.clone();
    let current = session::load_for_site(&mut redis, handle, &edge.site.id)
        .await?
        .ok_or(AppError::Unauthorized("no session for this site"))?;
    let token = fresh_access_token(&state, &client, handle, current)
        .await?
        .ok_or(AppError::Unauthorized(
            "session ended or cannot be refreshed",
        ))?;

    let (parts, body) = request.into_parts();
    let mut forwarded = parts.headers;
    // The browser's address as the edge determined it; trusted because the request is signed
    // and only the edge sets this header.
    let client_ip = forwarded
        .get(&FORWARDED_FOR)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<IpAddr>().ok());
    strip_hop_by_hop(&mut forwarded);
    strip_broker_headers(&mut forwarded);
    strip_forwarding(&mut forwarded);
    for name in [AUTHORIZATION, COOKIE, HOST] {
        forwarded.remove(name);
    }
    if let Some(ip) = client_ip {
        forwarded.insert(FORWARDED_FOR, HeaderValue::from_str(&ip.to_string())?);
    }
    forwarded.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    // Facts the API may trust, because only the hub can reach it and the hub verified them.
    forwarded.insert(headers::APP_ID, HeaderValue::from_str(&edge.app.id)?);
    forwarded.insert(headers::SITE_ID, HeaderValue::from_str(&edge.site.id)?);
    forwarded.insert(headers::TENANT, HeaderValue::from_str(&edge.site.tenant)?);

    let upstream = client
        .api
        .request(parts.method, url)
        .headers(forwarded)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await?;

    let mut response = Response::builder().status(upstream.status());
    let mut returned = upstream.headers().clone();
    strip_hop_by_hop(&mut returned);
    // A cookie the API set would land on the site's origin, outside the broker's control.
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
