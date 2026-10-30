//! Signed requests from this edge to the hub.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderValue, Method};
use common::{headers, signing::EdgeSigner};
use reqwest::{Client, RequestBuilder};

use crate::error::EdgeError;

/// Makes signed requests to the hub.
pub struct HubClient {
    /// HTTP client without a total timeout.
    http: Client,
    /// The hub's base URL as this edge reaches it.
    base: String,
    /// The kind's signer.
    signer: EdgeSigner,
}

/// The current time in Unix seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl HubClient {
    /// Signs with `signer` and sends with `http` to the hub at `base`.
    pub fn new(http: Client, base: String, signer: EdgeSigner) -> Self {
        Self { http, base, signer }
    }

    /// A request to the hub for site `site_id`, signed for `method`, `path_and_query` and the
    /// session handle. The path must be sent exactly as signed.
    pub fn request(
        &self,
        site_id: &str,
        method: Method,
        path_and_query: &str,
        handle: Option<&str>,
    ) -> Result<RequestBuilder, EdgeError> {
        let signed = self
            .signer
            .sign(site_id, method.as_str(), path_and_query, handle, now())?;
        let mut headers = HeaderMap::new();
        signed.apply(&mut headers);
        if let Some(handle) = handle {
            headers.insert(headers::SESSION_HANDLE, HeaderValue::from_str(handle)?);
        }
        Ok(self
            .http
            .request(method, format!("{}{}", self.base, path_and_query))
            .headers(headers))
    }

    /// The hub's base URL as this edge reaches it.
    pub fn base(&self) -> &str {
        &self.base
    }
}
