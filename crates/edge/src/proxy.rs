//! `/api/*` from the browser to the hub, signed with the kind's edge key for the request's site;
//! or, for a kind whose edge calls its sites' APIs directly, to that site's API (see
//! [`crate::direct`]).

use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{
        HeaderName, HeaderValue,
        header::{AUTHORIZATION, COOKIE, HOST, SET_COOKIE},
    },
    response::Response,
    routing::any,
};
use common::{
    api_path::has_dot_segment,
    csrf::CSRF_HEADER,
    headers::{strip_broker_headers, strip_forwarding, strip_hop_by_hop},
};

use crate::{auth::session_handle, error::EdgeError, sites::CurrentSite, state::AppState};

/// `/api/{*rest}`: every method, forwarded to the hub.
pub fn routes() -> Router<AppState> {
    Router::new().route("/api/{*rest}", any(api))
}

/// Forwards `request` to the hub, signed for `site` (from the request's host) and its session,
/// with the browser's address (from `peer` or a trusted proxy's header) as `X-Forwarded-For`, and
/// streams the answer back.
async fn api(
    State(app): State<AppState>,
    CurrentSite(site): CurrentSite,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, EdgeError> {
    let handle =
        session_handle(request.headers()).ok_or(EdgeError::Unauthorized("no session cookie"))?;
    // Refused here already, so a path the API might resolve outside its base never travels.
    if has_dot_segment(request.uri().path()) {
        return Err(EdgeError::BadRequest("API path not allowed"));
    }
    if let Some(upstream) = site.api_url.clone() {
        return crate::direct::api(&app, &site.id, &upstream, &handle, peer, request).await;
    }
    let (parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();

    // Nothing the browser sends can speak for the site: its credentials, any broker headers
    // and any claim about its address are dropped; the edge's signature is added by the hub client.
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

    let hub_response = app
        .hub
        .request(&site.id, parts.method, &path_and_query, Some(&handle))?
        .headers(forwarded)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await?;

    let mut response = Response::builder().status(hub_response.status());
    let mut returned = hub_response.headers().clone();
    strip_hop_by_hop(&mut returned);
    returned.remove(SET_COOKIE);
    if let Some(headers) = response.headers_mut() {
        headers.extend(returned);
    }
    Ok(response.body(Body::from_stream(hub_response.bytes_stream()))?)
}
