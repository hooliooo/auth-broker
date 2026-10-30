//! Sign-in via the hub, and each site's session cookie, under that site's own origin.

use axum::{
    Json, Router,
    body::Body,
    extract::{Query, State},
    http::{
        HeaderMap, HeaderValue, Method,
        header::{CACHE_CONTROL, CONTENT_TYPE, REFERRER_POLICY, SET_COOKIE},
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{cookie, crypto::constant_time_eq, pkce, random::random_token, return_url, signing};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{error::EdgeError, sites::CurrentSite, state::AppState};

// `__Host-Http-` (RFC 6265bis, RFC 10017 §6.1.3.2): only this site's origin over HTTPS, never a
// subdomain (`__Host-`), and only from a `Set-Cookie` header, never from page JavaScript
// (`Http-`), so an injected script cannot plant a session. Browsers that know only `__Host-`
// still enforce that part.

/// Prefix of the per-sign-in login cookies; see [`cookie::login_cookie`].
pub const LOGIN_COOKIE: &str = "__Host-Http-login";
/// Name of the session cookie; its value is the hub's session handle.
pub const SESSION_COOKIE: &str = "__Host-Http-session";
/// How long a sign-in may take.
const LOGIN_TTL_SECS: u64 = 300;
/// Where a sign-in that could not be completed sends the browser, so the app can say so.
const LOGIN_FAILED_PATH: &str = "/?login_error=1";

/// The routes browsers call.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/auth/login", get(login))
        .route("/auth/handoff", get(handoff))
        .route("/auth/session", get(current))
        .route("/auth/logout", post(logout))
}

/// A demo page; a real site serves its SPA on this same origin instead.
async fn home() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// The session handle from the session cookie in `headers`, if it is well formed.
pub fn session_handle(headers: &HeaderMap) -> Option<String> {
    cookie::get(headers, SESSION_COOKIE).filter(|h| signing::is_nonce(h))
}

/// Marks `response` as never to be cached.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Query of `/auth/login`.
#[derive(Deserialize)]
struct LoginQuery {
    /// Where to go after sign-in; only a path on this site is kept.
    #[serde(rename = "returnUrl")]
    return_url: Option<String>,
}

/// The login cookie carries everything the edge needs at handoff time, so the edge stores
/// nothing: `state.verifier.base64url(return_to)`. It is HttpOnly, and the verifier is useless
/// without both the handoff code and the kind's edge key.
struct LoginCookie {
    /// The edge's state, sent to the hub and returned with the handoff code.
    state: String,
    /// The PKCE verifier for the challenge sent to the hub.
    verifier: String,
    /// Where to go after sign-in.
    return_to: String,
}

impl LoginCookie {
    /// The cookie's value.
    fn encode(&self) -> String {
        format!(
            "{}.{}.{}",
            self.state,
            self.verifier,
            URL_SAFE_NO_PAD.encode(self.return_to.as_bytes())
        )
    }

    /// The cookie read back from `value`; `None` if it is damaged.
    fn decode(value: &str) -> Option<Self> {
        let mut parts = value.splitn(3, '.');
        let state = parts.next()?.to_owned();
        let verifier = parts.next()?.to_owned();
        let return_to = String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
        Some(Self {
            state,
            verifier,
            return_to,
        })
    }
}

/// `GET /auth/login` with query `q`: starts sign-in at `site` (from the request's host) by
/// sending the browser to the hub.
async fn login(
    State(app): State<AppState>,
    CurrentSite(site): CurrentSite,
    Query(q): Query<LoginQuery>,
) -> Result<Response, EdgeError> {
    // Every site an edge serves has an origin: it was matched by its host.
    let origin = site.origin.as_ref().ok_or(EdgeError::UnknownSite)?;
    let login = LoginCookie {
        state: random_token()?,
        verifier: pkce::new_verifier()?,
        return_to: return_url::sanitize(q.return_url.as_deref(), origin),
    };
    let mut url = app
        .config
        .hub_url
        .join("/broker/login")
        .map_err(|_| EdgeError::BadRequest("HUB_URL cannot be joined"))?;
    url.query_pairs_mut()
        .append_pair("site", &site.id)
        .append_pair("state", &login.state)
        .append_pair("code_challenge", &pkce::challenge(&login.verifier))
        .append_pair("code_challenge_method", pkce::METHOD);

    let mut response = Redirect::to(url.as_str()).into_response();
    // Lax: it must arrive on the hub's cross-site redirect back to /auth/handoff. One
    // cookie per sign-in, so sign-ins started in two tabs both complete.
    response.headers_mut().append(
        SET_COOKIE,
        cookie::set(
            &cookie::login_cookie(LOGIN_COOKIE, &login.state),
            &login.encode(),
            "Lax",
            LOGIN_TTL_SECS,
        )?,
    );
    Ok(response)
}

/// Query of the hub's redirect to `/auth/handoff`.
#[derive(Deserialize)]
struct HandoffQuery {
    /// The one-time handoff code.
    code: Option<String>,
    /// The edge's state from the sign-in start.
    state: Option<String>,
}

/// Body of the hub's `/broker/redeem`.
#[derive(Serialize)]
struct RedeemRequest<'a> {
    /// The handoff code.
    code: &'a str,
    /// The PKCE verifier from the login cookie.
    code_verifier: &'a str,
}

/// Answer of the hub's `/broker/redeem`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RedeemResponse {
    /// The session handle.
    handle: String,
    /// The session cookie's lifetime.
    max_age: u64,
}

/// `GET /auth/handoff` with query `q`: the hub sends the browser back here with a one-time code.
/// On any failure the browser goes to the app with an error marker instead of a bare status
/// page; either way this sign-in's login cookie (from `headers`) is cleared.
async fn handoff(
    State(app): State<AppState>,
    CurrentSite(site): CurrentSite,
    headers: HeaderMap,
    Query(q): Query<HandoffQuery>,
) -> Response {
    let login_cookie = q
        .state
        .as_deref()
        .map(|state| cookie::login_cookie(LOGIN_COOKIE, state));
    let mut response =
        match complete_handoff(&app, &site.id, &headers, q, login_cookie.as_deref()).await {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, "sign-in could not be completed");
                Redirect::to(LOGIN_FAILED_PATH).into_response()
            }
        };
    if let Some(name) = login_cookie
        && let Ok(clear) = cookie::clear(&name, "Lax")
    {
        response.headers_mut().append(SET_COOKIE, clear);
    }
    no_store(response)
}

/// The work of [`handoff`]: checks query `q` against the browser's `login_cookie` in `headers`,
/// redeems the code at `app`'s hub for site `site_id`, and sets the session cookie.
async fn complete_handoff(
    app: &AppState,
    site_id: &str,
    headers: &HeaderMap,
    q: HandoffQuery,
    login_cookie: Option<&str>,
) -> Result<Response, EdgeError> {
    let (code, state) = q
        .code
        .zip(q.state)
        .ok_or(EdgeError::BadRequest("handoff without code and state"))?;
    // The sign-in must have started in this browser (blocks login CSRF on the site's
    // domain), checked before the code is redeemed, so a stranger cannot spend it.
    let login = login_cookie
        .and_then(|name| cookie::get(headers, name))
        .and_then(|value| LoginCookie::decode(&value))
        .ok_or(EdgeError::Unauthorized(
            "no sign-in in progress in this browser",
        ))?;
    if !constant_time_eq(&login.state, &state) {
        return Err(EdgeError::Unauthorized(
            "state does not match this browser's sign-in",
        ));
    }

    let response = app
        .hub
        .request(site_id, Method::POST, "/broker/redeem", None)?
        .json(&RedeemRequest {
            code: &code,
            code_verifier: &login.verifier,
        })
        .send()
        .await?;
    if !response.status().is_success() {
        warn!(status = %response.status(), "hub refused the handoff");
        return Err(EdgeError::Unauthorized("hub refused the handoff"));
    }
    let redeemed: RedeemResponse = response.json().await?;
    if !signing::is_nonce(&redeemed.handle) {
        return Err(EdgeError::Hub("hub returned a malformed handle".into()));
    }

    let mut response = Redirect::to(&login.return_to).into_response();
    let headers = response.headers_mut();
    headers.append(
        SET_COOKIE,
        cookie::set(SESSION_COOKIE, &redeemed.handle, "Strict", redeemed.max_age)?,
    );
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    Ok(response)
}

/// Relays a small hub `response` (status, JSON body) to the browser, uncached.
async fn relay(response: reqwest::Response) -> Result<Response, EdgeError> {
    let status = response.status();
    let body = response.bytes().await?;
    Ok(no_store(
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))?,
    ))
}

/// `GET /auth/session`: who is signed in at `site` (session cookie in `headers`); 401
/// means "show the sign-in button".
async fn current(
    State(app): State<AppState>,
    CurrentSite(site): CurrentSite,
    headers: HeaderMap,
) -> Result<Response, EdgeError> {
    let handle = session_handle(&headers).ok_or(EdgeError::Unauthorized("no session cookie"))?;
    let response = app
        .hub
        .request(&site.id, Method::GET, "/broker/session", Some(&handle))?
        .send()
        .await?;
    relay(response).await
}

/// Body of `/auth/logout`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogoutBody {
    /// Where the SPA navigates next; the site's start page unless the identity provider
    /// could not be told.
    logout_url: Option<String>,
}

/// `POST /auth/logout`: ends the session at `site` (cookie in `headers`) at the hub, which ends
/// it at the identity provider; the SPA then navigates to `logoutUrl`.
async fn logout(
    State(app): State<AppState>,
    CurrentSite(site): CurrentSite,
    headers: HeaderMap,
) -> Result<Response, EdgeError> {
    let handle = session_handle(&headers).ok_or(EdgeError::Unauthorized("no session cookie"))?;
    app.tokens.forget(&site.id, &handle);
    let response = app
        .hub
        .request(&site.id, Method::POST, "/broker/logout", Some(&handle))?
        .send()
        .await?;
    // The cookie goes either way: a session the hub no longer knows is gone too.
    let logout_url = if response.status().is_success() {
        response
            .json::<serde_json::Value>()
            .await?
            .get("logoutUrl")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    } else {
        None
    };
    let mut reply = Json(LogoutBody { logout_url }).into_response();
    reply
        .headers_mut()
        .append(SET_COOKIE, cookie::clear(SESSION_COOKIE, "Strict")?);
    Ok(no_store(reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_a_login_cookie_when_round_tripped_then_all_parts_survive() {
        let cookie = LoginCookie {
            state: random_token().unwrap(),
            verifier: pkce::new_verifier().unwrap(),
            return_to: "/orders?tab=open.items#top".into(),
        };
        let decoded = LoginCookie::decode(&cookie.encode()).unwrap();
        assert_eq!(decoded.state, cookie.state);
        assert_eq!(decoded.verifier, cookie.verifier);
        assert_eq!(decoded.return_to, cookie.return_to);
    }

    #[test]
    fn given_a_damaged_login_cookie_when_decoded_then_it_is_refused() {
        assert!(LoginCookie::decode("only-one-part").is_none());
        assert!(LoginCookie::decode("a.b.%%%").is_none());
    }

    #[test]
    fn given_cookie_headers_when_reading_the_handle_then_only_well_formed_handles_count() {
        let mut headers = HeaderMap::new();
        let handle = random_token().unwrap();
        headers.insert(
            "cookie",
            format!("other=1; {SESSION_COOKIE}={handle}")
                .parse()
                .unwrap(),
        );
        assert_eq!(session_handle(&headers), Some(handle));
        headers.insert(
            "cookie",
            format!("{SESSION_COOKIE}=bad value").parse().unwrap(),
        );
        assert_eq!(session_handle(&headers), None);
    }
}
