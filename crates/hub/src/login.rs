//! The browser-facing half of the hub: sign-in with the app kind's provider client, the handoff
//! back to the site, the post-logout bounce, and the provider's back-channel logout.

use std::net::SocketAddr;

use axum::{
    Form, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, REFERRER_POLICY, SET_COOKIE},
    },
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use common::{
    causes::with_causes,
    cookie,
    crypto::{constant_time_eq, hash_key},
    loopback, metrics, pkce,
    provider::IdentityProvider,
    random::random_token,
    registry::{App, Site},
    sealed::{self, Purpose},
    signing,
};
use oidc::oidc::{JwtVerificationError, JwtVerifier};
use redis::AsyncCommands;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info, warn};

use crate::{
    catalog::AppClient,
    error::AppError,
    ratelimit,
    session::{self, Session, lifetime_secs, now},
    state::AppState,
    tokens::{self, Refusal},
};

/// Prefix of the hub's per-sign-in login cookies; `__Host-Http-` as the edges' cookies.
const HUB_LOGIN_COOKIE: &str = "__Host-Http-hub-login";
/// How long a sign-in may take at the provider.
const LOGIN_TTL_SECS: u64 = 300;
/// A handoff code must be redeemed by the edge within this window.
pub const HANDOFF_TTL_SECS: u64 = 60;
/// Oldest back-channel logout token accepted, by its `iat`.
const LOGOUT_TOKEN_MAX_AGE_SECS: u64 = 120;
/// How long a used logout token's `jti` is remembered: until it could no longer pass the `iat`
/// check, leeway included.
const LOGOUT_JTI_TTL_SECS: u64 = LOGOUT_TOKEN_MAX_AGE_SECS + 2 * oidc::oidc::LEEWAY_SECS;

/// The routes browsers and the provider call.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/broker/login", get(broker_login))
        .route("/auth/callback", get(callback))
        .route("/broker/logged-out/{site}", get(logged_out))
        .route("/auth/backchannel-logout/{app}", post(backchannel_logout))
}

/// Query of `/broker/login`, set by the edge, or by a native installation's desktop app.
#[derive(Deserialize)]
struct BrokerLoginQuery {
    /// The site signing in.
    site: String,
    /// For a native installation only: the app's loopback address for this sign-in
    /// (RFC 8252 §7.3). An edge kind's destination comes from the registry, never the request.
    redirect_uri: Option<String>,
    /// The edge's own state; returned with the handoff code.
    state: String,
    /// The edge's PKCE challenge; the handoff code is useless without its verifier.
    code_challenge: String,
    /// Must be `S256`.
    code_challenge_method: String,
}

/// Sealed with the hub's own `state` while the user is at the provider.
#[derive(Serialize, Deserialize)]
struct PendingLogin {
    /// The site signing in.
    site_id: String,
    /// The edge's state, to return with the handoff code.
    edge_state: String,
    /// The edge's PKCE challenge, for the handoff.
    edge_challenge: String,
    /// For a native installation: where its app listens for the handoff.
    #[serde(default)]
    native_redirect: Option<String>,
    /// The hub's PKCE verifier for the provider.
    verifier: String,
    /// The ID token must carry this nonce.
    nonce: String,
}

/// Sealed with the handoff code; becomes a session when the site's edge redeems it.
#[derive(Serialize, Deserialize)]
pub struct Handoff {
    /// The edge's PKCE challenge; the redeemer must present its verifier.
    pub edge_challenge: String,
    /// The session-to-be.
    pub session: Session,
    /// How long the session lasts: the provider's `refresh_expires_in`.
    pub lifetime_secs: u64,
}

/// Redis key of the pending sign-in for hub `state`.
fn login_key(state: &str) -> String {
    format!("hub:login:{}", hash_key(state))
}

/// Redis key of the handoff for `code`.
pub fn handoff_key(code: &str) -> String {
    format!("hub:handoff:{}", hash_key(code))
}

/// `state`'s client for kind `app_id`, or 503 while it is still being built.
fn client_for(state: &AppState, app_id: &str) -> Result<std::sync::Arc<AppClient>, AppError> {
    state
        .runtime
        .client(app_id)
        .ok_or_else(|| AppError::NotReady(format!("client for app '{app_id}' not ready")))
}

/// The scopes a sign-in at `site` of `app` requests: the kind's, plus for a direct kind
/// the scope with which `provider` names the site in tokens.
fn scopes_for(provider: &dyn IdentityProvider, app: &App, site: &Site) -> String {
    match provider.site_scope(&site.id).filter(|_| app.direct()) {
        Some(scope) => format!("{} {scope}", app.scopes),
        None => app.scopes.clone(),
    }
}

/// Marks `response` as never to be cached.
pub fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /broker/login` with query `q`: an edge sent the browser here to sign in for its
/// site. `peer` and `headers` give the client address for the rate limit.
async fn broker_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<BrokerLoginQuery>,
) -> Result<Response, AppError> {
    let catalog = state.runtime.catalog();
    let (site, app) = catalog
        .registry
        .enabled(&q.site)
        .filter(|(site, _)| state.config.served_access.serves(site))
        .ok_or(AppError::BadRequest("unknown or disabled site"))?;
    if q.code_challenge_method != pkce::METHOD || !pkce::is_challenge(&q.code_challenge) {
        return Err(AppError::BadRequest("edge PKCE challenge must be S256"));
    }
    if !signing::is_nonce(&q.state) {
        return Err(AppError::BadRequest("edge state malformed"));
    }
    // A native installation's app listens on loopback for this sign-in only; a web-app
    // installation has its registered origin, and no request may move it. The installation
    // decides, not its kind: a kind may have both.
    let native = app.native.as_ref().filter(|_| site.is_native());
    let native_redirect = match (native, q.redirect_uri.as_deref()) {
        (Some(native), Some(uri)) => Some(
            loopback::redirect(uri, &native.redirect_path)
                .ok_or(AppError::BadRequest(
                    "redirect_uri must be http://127.0.0.1:<port> or http://[::1]:<port> with the kind's path",
                ))?
                .to_string(),
        ),
        (Some(_), None) => {
            return Err(AppError::BadRequest(
                "a native installation must name its loopback redirect_uri",
            ));
        }
        (None, Some(_)) => {
            return Err(AppError::BadRequest(
                "a web-app installation returns to its registered origin; redirect_uri is not accepted",
            ));
        }
        (None, None) => None,
    };

    // Unauthenticated and writes to Redis, so it is rate limited per client and per site.
    let mut redis = state.redis.clone();
    let ip = state.config.client_ip.client_ip(&headers, peer);
    if !ratelimit::allow(
        &mut redis,
        &format!("login-ip:{ip}"),
        state.config.login_per_minute_per_ip,
    )
    .await?
    {
        metrics::counter("hub_rate_limited_total", &[("scope", "client")]);
        return Err(AppError::TooManyRequests(
            "sign-in rate per client exceeded",
        ));
    }
    if !ratelimit::allow(
        &mut redis,
        &format!("login-site:{}", site.id),
        site.login_per_minute,
    )
    .await?
    {
        metrics::counter("hub_rate_limited_total", &[("scope", "site")]);
        return Err(AppError::TooManyRequests("sign-in rate per site exceeded"));
    }
    let client = client_for(&state, &app.id)?;

    let (hub_state, nonce, verifier) = (random_token()?, random_token()?, pkce::new_verifier()?);
    let pending = PendingLogin {
        site_id: site.id.clone(),
        edge_state: q.state,
        edge_challenge: q.code_challenge,
        native_redirect,
        verifier: verifier.clone(),
        nonce: nonce.clone(),
    };
    redis
        .set_ex::<_, _, ()>(
            login_key(&hub_state),
            sealed::seal(
                &hub_state,
                Purpose::PendingLogin,
                &serde_json::to_vec(&pending)?,
            )?,
            LOGIN_TTL_SECS,
        )
        .await?;

    let mut url = client.authorization_url.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &app.client_id)
        .append_pair("redirect_uri", state.config.callback_url.as_str())
        // The kind's registry entry decides the scopes; the browser has no say.
        .append_pair(
            "scope",
            &scopes_for(state.config.provider.as_ref(), app, site),
        )
        .append_pair("state", &hub_state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &pkce::challenge(&verifier))
        .append_pair("code_challenge_method", pkce::METHOD);

    let mut response = Redirect::to(url.as_str()).into_response();
    // Lax: it must ride along on the provider's cross-site redirect back to /auth/callback.
    response.headers_mut().append(
        SET_COOKIE,
        cookie::set(
            &cookie::login_cookie(HUB_LOGIN_COOKIE, &hub_state),
            &hub_state,
            "Lax",
            LOGIN_TTL_SECS,
        )?,
    );
    Ok(response)
}

/// Query of the provider's redirect to `/auth/callback`.
#[derive(Deserialize)]
struct CallbackQuery {
    /// The authorization code.
    code: Option<String>,
    /// The hub's state.
    state: Option<String>,
    /// The provider's error code, if sign-in failed there.
    error: Option<String>,
    /// The provider's description of `error`.
    error_description: Option<String>,
}

/// The provider's answer to the code exchange.
#[derive(Deserialize)]
struct TokenResponse {
    /// The access token.
    access_token: String,
    /// Seconds until it expires.
    expires_in: u64,
    /// The ID token.
    id_token: String,
    /// The refresh token.
    refresh_token: Option<String>,
}

/// The ID token claims the hub reads; signature, issuer, audience and expiry are already
/// checked by the verifier.
#[derive(Deserialize)]
struct IdTokenClaims {
    /// The user's id.
    sub: String,
    /// Must match the sign-in's nonce.
    nonce: Option<String>,
    /// The client the token was issued to, if named.
    azp: Option<String>,
    /// A single string or a list (OIDC Core §2).
    aud: Value,
    /// `sid`: the provider's session, for back-channel logout.
    #[serde(rename = "sid")]
    iam_sid: Option<String>,
    /// The user's name, with the `profile` scope.
    preferred_username: Option<String>,
    /// The user's display name, with the `profile` scope.
    name: Option<String>,
    /// The user's email, with the `email` scope.
    email: Option<String>,
}

/// The ID token checks OIDC Core §3.1.3.7 adds to signature, issuer, audience and expiry:
/// if `claims` name an authorized party, it must be `client_id`. Whether they are an ID token's
/// at all is the provider's to say ([`IdentityProvider::is_id_token`]).
fn check_id_token(claims: &IdTokenClaims, client_id: &str) -> Result<(), AppError> {
    let several_audiences = claims
        .aud
        .as_array()
        .is_some_and(|audiences| audiences.len() > 1);
    match claims.azp.as_deref() {
        Some(azp) if azp != client_id => {
            Err(AppError::Unauthorized("ID token issued to another client"))
        }
        None if several_audiences => Err(AppError::Unauthorized(
            "ID token with several audiences, no azp",
        )),
        _ => Ok(()),
    }
}

/// `GET /auth/callback` with query `q`: the provider's redirect back. Every app kind's client
/// registers this URL; the pending sign-in says which kind it was for. Whatever the outcome,
/// this sign-in's login cookie (from the request's `headers`) is cleared.
async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let login_cookie = q
        .state
        .as_deref()
        .map(|hub_state| cookie::login_cookie(HUB_LOGIN_COOKIE, hub_state));
    let (result, labels) = complete_sign_in(&state, &headers, q, login_cookie.as_deref()).await;
    let (kind, access) = labels.unwrap_or_else(|| ("unknown".into(), "unknown"));
    let outcome = if result.is_ok() {
        "completed"
    } else {
        "failed"
    };
    metrics::counter(
        "hub_sign_ins_total",
        &[("kind", &kind), ("access", access), ("outcome", outcome)],
    );
    let mut response = result.unwrap_or_else(IntoResponse::into_response);
    if let Some(name) = login_cookie
        && let Ok(clear) = cookie::clear(&name, "Lax")
    {
        response.headers_mut().append(SET_COOKIE, clear);
    }
    no_store(response)
}

/// The work of [`callback`]: checks query `q` against `state`'s pending sign-in and the browser's
/// `login_cookie` in `headers`, exchanges the code, checks the tokens, and redirects to the
/// site with a handoff code. Also returns the app kind and the installation's access type, once
/// known.
async fn complete_sign_in(
    state: &AppState,
    headers: &HeaderMap,
    q: CallbackQuery,
    login_cookie: Option<&str>,
) -> (Result<Response, AppError>, Option<(String, &'static str)>) {
    let mut labels = None;
    let result = async {
        if let Some(error) = q.error.as_deref() {
            warn!(error, description = ?q.error_description, "the provider rejected sign-in");
            // A user who may not use this site is refused by the provider with
            // invalid_scope: show the no-access page, not a bare error.
            if matches!(error, "invalid_scope" | "access_denied") {
                return Err(AppError::Forbidden("the provider refused the user for this site"));
            }
            return Err(AppError::Unauthorized("the provider rejected sign-in"));
        }
        let (code, hub_state) = q
            .code
            .zip(q.state)
            .ok_or(AppError::BadRequest("callback without code and state"))?;
        // Checked before Redis is touched: a stranger opening this URL cannot consume the
        // pending sign-in, so the real user can still finish it.
        let bound = login_cookie
            .and_then(|name| cookie::get(headers, name))
            .ok_or(AppError::Unauthorized("no sign-in in progress in this browser"))?;
        if !constant_time_eq(&bound, &hub_state) {
            return Err(AppError::Unauthorized("state does not match this browser's sign-in"));
        }

        let mut redis = state.redis.clone();
        let raw: Option<Vec<u8>> = redis::cmd("GETDEL")
            .arg(login_key(&hub_state))
            .query_async(&mut redis)
            .await?;
        let pending: PendingLogin = serde_json::from_slice(
            &raw.and_then(|r| sealed::open(&hub_state, Purpose::PendingLogin, &r))
                .ok_or(AppError::Unauthorized("sign-in expired or already used"))?,
        )?;
        // The site may have been disabled while the user was at the provider.
        let catalog = state.runtime.catalog();
        let (site, app) = catalog
            .registry
            .enabled(&pending.site_id)
            .ok_or(AppError::Unauthorized("site disabled during sign-in"))?;
        labels = Some((app.id.clone(), site.access_kind()));
        let client = client_for(state, &app.id)?;

        let provider = state.config.provider.as_ref();
        let (tokens, token_response) = exchange_code(state, &client, &code, &pending.verifier).await?;
        let id_claims = client
            .verifier
            .verify(&tokens.id_token)
            .await
            .map_err(|error| {
                verification_failed(error, AppError::Unauthorized("ID token failed verification"))
            })?;
        if !provider.is_id_token(&id_claims) {
            return Err(AppError::Unauthorized("not an ID token"));
        }
        let claims: IdTokenClaims = serde_json::from_value(id_claims)
            .map_err(|_| AppError::Unauthorized("ID token has unexpected claims"))?;
        check_id_token(&claims, &app.client_id)?;
        match claims.nonce.as_deref() {
            Some(nonce) if constant_time_eq(nonce, &pending.nonce) => {}
            _ => return Err(AppError::Unauthorized("nonce mismatch")),
        }
        match tokens::check(provider, app, &site.id, &tokens.access_token) {
            Ok(()) => {}
            Err(Refusal::MissingRole | Refusal::WrongSite) => {
                return Err(AppError::Forbidden("user lacks the app's role or the site's membership"));
            }
            Err(refusal) => {
                error!(app = %app.id, ?refusal, "the provider issued an access token the app's API would refuse");
                return Err(AppError::Upstream("access token not usable for this app".into()));
            }
        }

        let issued_at = now();
        let handoff = Handoff {
            edge_challenge: pending.edge_challenge,
            session: Session {
                app_id: app.id.clone(),
                site_id: site.id.clone(),
                tenant: site.tenant.clone(),
                sub: claims.sub,
                iam_sid: claims.iam_sid,
                preferred_username: claims.preferred_username,
                name: claims.name,
                email: claims.email,
                id_token: tokens.id_token,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_at: issued_at + tokens.expires_in,
                created_at: issued_at,
            },
            lifetime_secs: lifetime_secs(provider.session_lifetime_secs(&token_response)),
        };
        let handoff_code = random_token()?;
        redis
            .set_ex::<_, _, ()>(
                handoff_key(&handoff_code),
                sealed::seal(&handoff_code, Purpose::Handoff, &serde_json::to_vec(&handoff)?)?,
                HANDOFF_TTL_SECS,
            )
            .await?;

        // The destination comes from the registry, never from the request; for a native
        // installation, the loopback address checked when the sign-in started.
        let mut target = match pending.native_redirect.as_deref() {
            Some(uri) => Url::parse(uri)
                .map_err(|_| AppError::Unauthorized("native redirect unusable"))?,
            None => site
                .handoff_url()
                .ok_or(AppError::Unauthorized("site has no origin to return to"))?,
        };
        target
            .query_pairs_mut()
            .append_pair("code", &handoff_code)
            .append_pair("state", &pending.edge_state);
        let mut response = Redirect::to(target.as_str()).into_response();
        response
            .headers_mut()
            .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        Ok(response)
    }
    .await;
    (result, labels)
}

/// Exchanges authorization `code` and PKCE `verifier` for tokens at the provider, as `client`;
/// also returns the whole token response, for the provider's own fields.
async fn exchange_code(
    state: &AppState,
    client: &AppClient,
    code: &str,
    verifier: &str,
) -> Result<(TokenResponse, Value), AppError> {
    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("redirect_uri", state.config.callback_url.to_string()),
        ("code_verifier", verifier.to_owned()),
    ];
    form.extend(client.auth_fields(state)?);
    let response = state
        .idp
        .post(client.token_endpoint())
        .form(&form)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body: Value = response.json().await.unwrap_or_default();
        warn!(%status, app = %client.app.id, error = ?body["error"], description = ?body["error_description"], "authorization code exchange rejected");
        // A provider refusing a user for the site answers access_denied or invalid_scope
        // (Keycloak: it leaves a non-member's organization out and its membership extension
        // refuses).
        if body["error"] == "access_denied" || body["error"] == "invalid_scope" {
            return Err(AppError::Forbidden("user is not a member of the site"));
        }
        return Err(AppError::Unauthorized(
            "authorization code exchange rejected",
        ));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|e| AppError::Upstream(with_causes(&e)))?;
    Ok((serde_json::from_value(body.clone())?, body))
}

/// `GET /broker/logged-out/{site}`: the provider's post-logout redirect; bounces to the
/// site's home, or for a native installation, which has none, says so in the browser.
async fn logged_out(
    State(state): State<AppState>,
    Path(site): Path<String>,
) -> Result<Response, AppError> {
    let catalog = state.runtime.catalog();
    let site = catalog.registry.get(&site).ok_or(AppError::NotFound)?;
    Ok(match site.home_url() {
        Some(home) => Redirect::to(home.as_str()).into_response(),
        None => Html(SIGNED_OUT_PAGE).into_response(),
    })
}

/// What the browser shows after a native installation's sign-out: the app is elsewhere.
const SIGNED_OUT_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Signed out</title>\
    <p>You are signed out. You can close this window and return to the application.</p>";

/// Body of `/auth/backchannel-logout/{app}`.
#[derive(Deserialize)]
struct LogoutTokenForm {
    /// The provider's signed logout token.
    logout_token: String,
}

/// `POST /auth/backchannel-logout/{app}`: The provider, server to server, for kind `app_id`'s
/// client. Ends that kind's sessions of the provider's session named in `form`'s token, once per
/// token, and counts the outcome.
async fn backchannel_logout(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Form(form): Form<LogoutTokenForm>,
) -> Result<StatusCode, AppError> {
    let result = end_backchannel_sessions(&state, &app_id, &form.logout_token).await;
    let outcome = match &result {
        Ok(_) => "accepted",
        Err(AppError::Unauthorized("logout token replayed")) => "replayed",
        Err(AppError::ProviderUnavailable(_)) => "provider_unavailable",
        Err(_) => "invalid",
    };
    metrics::counter(
        "hub_backchannel_logouts_total",
        &[("kind", &app_id), ("outcome", outcome)],
    );
    result
}

/// What a token that failed verification with `error` answers: 503 if the provider's keys could
/// not be fetched, which is not the token's fault, otherwise `invalid`. The reason is logged
/// either way; the client never sees it.
fn verification_failed(error: JwtVerificationError, invalid: AppError) -> AppError {
    match error {
        JwtVerificationError::ProviderUnavailable(reason) => AppError::ProviderUnavailable(reason),
        other => {
            warn!(error = %other, "token failed verification");
            invalid
        }
    }
}

/// The work of [`backchannel_logout`]: verifies `logout_token` for kind `app_id` and ends its
/// sessions, using `state`'s Redis and verifier.
async fn end_backchannel_sessions(
    state: &AppState,
    app_id: &str,
    logout_token: &str,
) -> Result<StatusCode, AppError> {
    let client = client_for(state, app_id)?;
    let json = client
        .verifier
        .verify(logout_token)
        .await
        .map_err(|error| {
            verification_failed(
                error,
                AppError::BadRequest("logout token failed verification"),
            )
        })?;
    // The logout event, no nonce, a session or subject, a jti and a fresh iat (§2.6).
    let claims = oidc::logout::logout_claims(&json, now(), LOGOUT_TOKEN_MAX_AGE_SECS)
        .map_err(|_| AppError::BadRequest("not a valid back-channel logout token"))?;
    let iam_sid = claims
        .sid
        .ok_or(AppError::BadRequest("logout token without sid"))?;
    let mut redis = state.redis.clone();

    // Each logout token is accepted once. It is marked as used only after its sessions are gone,
    // so if deleting them fails, the provider's retry of the same token still goes through.
    let used_key = format!("hub:logout-jti:{}", hash_key(&claims.jti));
    if redis.exists::<_, bool>(&used_key).await? {
        return Err(AppError::Unauthorized("logout token replayed"));
    }
    let removed = session::delete_by_iam_sid(&mut redis, app_id, &iam_sid).await?;
    redis
        .set_ex::<_, _, ()>(&used_key, 1, LOGOUT_JTI_TTL_SECS)
        .await?;
    info!(app = %app_id, removed, "back-channel logout ended sessions");
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn given_the_providers_keys_unavailable_then_the_token_is_not_blamed() {
        let unavailable = verification_failed(
            JwtVerificationError::ProviderUnavailable("connection refused".into()),
            AppError::BadRequest("logout token failed verification"),
        );
        assert!(matches!(unavailable, AppError::ProviderUnavailable(_)));
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

        let invalid = verification_failed(
            JwtVerificationError::Invalid("bad signature".into()),
            AppError::BadRequest("logout token failed verification"),
        );
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    }

    /// Valid ID token claims for client `hub-a`, changed by `extra`; a `null` removes a claim.
    fn id_token(extra: Value) -> IdTokenClaims {
        let mut claims = json!({ "sub": "user", "typ": "ID", "aud": "hub-a", "azp": "hub-a" });
        for (key, value) in extra.as_object().unwrap() {
            if value.is_null() {
                claims.as_object_mut().unwrap().remove(key);
            } else {
                claims[key] = value.clone();
            }
        }
        serde_json::from_value(claims).unwrap()
    }

    #[test]
    fn given_an_id_token_for_this_client_then_it_is_accepted() {
        assert!(check_id_token(&id_token(json!({})), "hub-a").is_ok());
        assert!(check_id_token(&id_token(json!({ "azp": null })), "hub-a").is_ok());
    }

    #[test]
    fn given_another_client_then_it_is_refused() {
        assert!(check_id_token(&id_token(json!({ "azp": "hub-b" })), "hub-a").is_err());
        assert!(
            check_id_token(
                &id_token(json!({ "aud": ["hub-a", "x"], "azp": null })),
                "hub-a"
            )
            .is_err()
        );
    }
}
