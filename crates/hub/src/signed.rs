//! Verifies that a request really comes from a kind's edge, for one of the kind's registered,
//! enabled web-app installations; or from a native installation itself, with one of its keys.

use std::sync::Arc;

use axum::{extract::FromRequestParts, http::request::Parts};
use common::{
    headers,
    registry::{App, Site},
    signing::{self, SignatureInput},
};

use crate::{catalog::AppClient, error::AppError, session::now, state::AppState};

/// A request proven to come from `app`'s edge, for `site`, or from native installation `site`
/// itself. Handlers that take this never see unsigned traffic.
pub struct SignedEdge {
    /// The site the request is for.
    pub site: Site,
    /// The site's app kind.
    pub app: App,
    /// The session handle the edge sent, if any; covered by the signature.
    pub handle: Option<String>,
}

impl SignedEdge {
    /// The session handle, or 401 without one.
    pub fn require_handle(&self) -> Result<&str, AppError> {
        self.handle
            .as_deref()
            .ok_or(AppError::Unauthorized("no session handle"))
    }

    /// The site's app kind client, or 503 while it is still being built.
    pub fn client(&self, state: &AppState) -> Result<Arc<AppClient>, AppError> {
        state.runtime.client(&self.app.id).ok_or_else(|| {
            AppError::NotReady(format!("client for app '{}' not ready", self.app.id))
        })
    }
}

/// Header `name` of `parts` as text.
fn header<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

impl FromRequestParts<AppState> for SignedEdge {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let (Some(site_id), Some(timestamp), Some(nonce), Some(signature)) = (
            header(parts, headers::SITE_ID),
            header(parts, headers::SITE_TIMESTAMP),
            header(parts, headers::SITE_NONCE),
            header(parts, headers::SITE_SIGNATURE),
        ) else {
            return Err(AppError::Unauthorized("signature headers missing"));
        };
        let catalog = state.runtime.catalog();
        let (site, app) = catalog
            .registry
            .enabled(site_id)
            .filter(|(site, _)| state.config.served_access.serves(site))
            .ok_or(AppError::Unauthorized(
                "signature from unknown or disabled site",
            ))?;
        // The kind's one edge key for a web-app installation, so only the edge of the site's own
        // kind can speak for it; the named key for a native installation, so only that
        // installation can. One lookup and one verification, however many keys it has.
        let key = site
            .verifying_key(app, header(parts, headers::SITE_KEY_ID))
            .ok_or(AppError::Unauthorized(
                "signature key unknown for this site",
            ))?;
        let timestamp: u64 = timestamp
            .parse()
            .map_err(|_| AppError::Unauthorized("signature timestamp malformed"))?;
        if now().abs_diff(timestamp) > state.config.max_clock_skew_secs {
            return Err(AppError::Unauthorized(
                "signature timestamp outside allowed skew",
            ));
        }
        if !signing::is_nonce(nonce) {
            return Err(AppError::Unauthorized("signature nonce malformed"));
        }
        let handle = header(parts, headers::SESSION_HANDLE).map(str::to_owned);
        let input = SignatureInput {
            site_id,
            method: parts.method.as_str(),
            path_and_query: parts.uri.path_and_query().map_or("/", |p| p.as_str()),
            timestamp,
            nonce,
            handle: handle.as_deref(),
        };
        if !signing::verify(key, &input, signature) {
            return Err(AppError::Unauthorized("signature invalid"));
        }

        // Only after the signature checks out, so strangers cannot fill the nonce store.
        let mut redis = state.redis.clone();
        let first_use: Option<String> = redis::cmd("SET")
            .arg(format!("hub:nonce:{site_id}:{nonce}"))
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(state.config.max_clock_skew_secs * 2 + 1)
            .query_async(&mut redis)
            .await?;
        if first_use.is_none() {
            return Err(AppError::Unauthorized("signature replayed"));
        }

        Ok(Self {
            site: site.clone(),
            app: app.clone(),
            handle,
        })
    }
}
