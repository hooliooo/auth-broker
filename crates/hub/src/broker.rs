//! The edge-facing half of the hub. Every route here takes [`SignedEdge`], so only registered,
//! enabled sites can reach it.

use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use common::{
    metrics, pkce,
    provider::Logout,
    sealed::{self, Purpose},
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    catalog::AppClient,
    error::AppError,
    login::{Handoff, handoff_key, no_store},
    session::{self, SSO_MAX_SECS, fresh_access_token, now},
    signed::SignedEdge,
    state::AppState,
};

/// The routes edges call.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/broker/redeem", post(redeem))
        .route("/broker/session", get(current))
        .route("/broker/logout", post(logout))
        .route("/broker/token", post(token))
}

/// Body of `/broker/redeem`.
#[derive(Deserialize)]
struct RedeemRequest {
    /// The one-time handoff code.
    code: String,
    /// The edge's PKCE verifier for the challenge it sent at sign-in start.
    code_verifier: String,
}

/// Answer of `/broker/redeem`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RedeemResponse {
    /// The session handle, for the site's cookie.
    handle: String,
    /// How long the edge's session cookie lives: the hub's 24-hour cap, so the cookie outlives
    /// the session; the hub decides when the session ends.
    max_age: u64,
}

/// `POST /broker/redeem`: `edge` trades a one-time handoff code in `body` for a session handle.
async fn redeem(
    State(app): State<AppState>,
    edge: SignedEdge,
    Json(body): Json<RedeemRequest>,
) -> Result<Response, AppError> {
    let mut redis = app.redis.clone();
    let raw: Option<Vec<u8>> = redis::cmd("GETDEL")
        .arg(handoff_key(&body.code))
        .query_async(&mut redis)
        .await?;
    let handoff: Handoff = serde_json::from_slice(
        &raw.and_then(|r| sealed::open(&body.code, Purpose::Handoff, &r))
            .ok_or(AppError::Unauthorized(
                "handoff code unknown, expired or used",
            ))?,
    )?;
    if handoff.session.site_id != edge.site.id {
        warn!(code_site = %handoff.session.site_id, caller = %edge.site.id, "handoff redeemed by the wrong site");
        return Err(AppError::Unauthorized(
            "handoff code belongs to another site",
        ));
    }
    if !pkce::verify(&body.code_verifier, &handoff.edge_challenge) {
        return Err(AppError::Unauthorized("handoff PKCE verifier mismatch"));
    }
    let handle = session::create(&mut redis, &handoff.session, handoff.lifetime_secs).await?;
    Ok(no_store(
        Json(RedeemResponse {
            handle,
            max_age: SSO_MAX_SECS,
        })
        .into_response(),
    ))
}

/// Answer of `/broker/session`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionView {
    /// The app kind.
    app: String,
    /// The user's id.
    sub: String,
    /// The user's name, if requested.
    preferred_username: Option<String>,
    /// The user's display name, if requested.
    name: Option<String>,
    /// The user's email, if requested.
    email: Option<String>,
    /// The site.
    site: String,
    /// The site's tenant.
    tenant: String,
}

/// `GET /broker/session`: who is signed in at `edge`'s site, for the edge's
/// `/auth/session`.
async fn current(State(app): State<AppState>, edge: SignedEdge) -> Result<Response, AppError> {
    let mut redis = app.redis.clone();
    let s = session::load_for_site(&mut redis, edge.require_handle()?, &edge.site.id)
        .await?
        .ok_or(AppError::Unauthorized("no session for this site"))?;
    Ok(no_store(
        Json(SessionView {
            app: s.app_id,
            sub: s.sub,
            preferred_username: s.preferred_username,
            name: s.name,
            email: s.email,
            site: s.site_id,
            tenant: s.tenant,
        })
        .into_response(),
    ))
}

/// Answer of `/broker/token`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    /// The provider's access token for the session, naming the site's organization.
    access_token: String,
    /// Seconds until it expires.
    expires_in: u64,
}

/// `POST /broker/token`: the access token of `edge`'s session, for a direct kind whose edges
/// call their API themselves; refreshed at the provider first if under a minute is left, which also
/// re-checks the user's role and membership. The refresh token never leaves the hub.
async fn token(State(app): State<AppState>, edge: SignedEdge) -> Result<Response, AppError> {
    if !edge.app.direct() {
        // A proxied kind's tokens never leave the hub.
        return Err(AppError::NotFound);
    }
    let handle = edge.require_handle()?;
    let client = edge.client(&app)?;
    let mut redis = app.redis.clone();
    let current = session::load_for_site(&mut redis, handle, &edge.site.id)
        .await?
        .ok_or(AppError::Unauthorized("no session for this site"))?;
    let access_token = fresh_access_token(&app, &client, handle, current)
        .await?
        .ok_or(AppError::Unauthorized(
            "session ended or cannot be refreshed",
        ))?;
    let expires_at = session::load_for_site(&mut redis, handle, &edge.site.id)
        .await?
        .map_or(0, |s| s.expires_at);
    metrics::counter("hub_tokens_issued_total", &[("kind", &edge.app.id)]);
    Ok(no_store(
        Json(TokenResponse {
            access_token,
            expires_in: expires_at.saturating_sub(now()),
        })
        .into_response(),
    ))
}

/// Answer of `/broker/logout`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogoutResponse {
    /// Where the browser goes next: the site's start page, or the provider's logout page
    /// where the provider's own session must end in the browser.
    logout_url: String,
}

/// `POST /broker/logout`: ends `edge`'s session here and at the identity provider. With a
/// provider that ends sessions server to server, no token passes through the browser.
async fn logout(State(app): State<AppState>, edge: SignedEdge) -> Result<Response, AppError> {
    let handle = edge.require_handle()?;
    let client = edge.client(&app)?;
    let mut redis = app.redis.clone();
    let s = session::load_for_site(&mut redis, handle, &edge.site.id)
        .await?
        .ok_or(AppError::Unauthorized("no session for this site"))?;
    session::delete(&mut redis, handle, &s).await?;

    let ended = match (app.config.provider.logout(), s.refresh_token.as_deref()) {
        (Logout::RefreshTokenAtEndSession, Some(refresh_token)) => {
            post_with_client_auth(
                &app,
                &client,
                client.internal_end_session_endpoint(),
                &[("refresh_token", refresh_token)],
            )
            .await
        }
        (Logout::RevokeThenBrowser, Some(refresh_token)) => {
            // The refresh token dies here; the provider's own session still needs the browser.
            post_with_client_auth(
                &app,
                &client,
                client.revocation_endpoint(),
                &[
                    ("token", refresh_token),
                    ("token_type_hint", "refresh_token"),
                ],
            )
            .await;
            false
        }
        (_, None) => false,
    };
    let outcome = if ended { "ended" } else { "browser" };
    metrics::counter(
        "hub_logouts_total",
        &[("kind", &edge.app.id), ("provider", outcome)],
    );
    let logout_url = match client.end_session_url.clone() {
        // The provider's own page, where the user confirms; no token in the URL.
        Some(mut url) if !ended => {
            url.query_pairs_mut()
                .append_pair("client_id", &client.app.client_id)
                .append_pair(
                    "post_logout_redirect_uri",
                    app.config.logged_out_url(&edge.site.id).as_str(),
                );
            url
        }
        // Over everywhere already, or the provider has no page to finish it on.
        _ => edge.site.home_url(),
    };
    Ok(no_store(
        Json(LogoutResponse {
            logout_url: logout_url.to_string(),
        })
        .into_response(),
    ))
}

/// Posts `fields` plus `client`'s authentication to the provider's `endpoint`, server to server;
/// `true` if it answered with success. A failure is only logged: the hub's session is already
/// gone.
async fn post_with_client_auth(
    app: &AppState,
    client: &AppClient,
    endpoint: Option<&str>,
    fields: &[(&'static str, &str)],
) -> bool {
    let Some(endpoint) = endpoint else {
        warn!("the provider publishes no endpoint for this logout step");
        return false;
    };
    let mut form: Vec<(&'static str, String)> =
        fields.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
    match client.auth_fields(app) {
        Ok(auth) => form.extend(auth),
        Err(error) => {
            warn!(%error, "cannot authenticate the logout");
            return false;
        }
    }
    match app.idp.post(endpoint).form(&form).send().await {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            warn!(status = %response.status(), "the provider refused the logout");
            false
        }
        Err(error) => {
            warn!(%error, "the provider could not be reached for logout");
            false
        }
    }
}
