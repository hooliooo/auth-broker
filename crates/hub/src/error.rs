//! Every failure maps to one status; reasons go to the log, never to the client.

use axum::{
    http::{StatusCode, header::InvalidHeaderValue},
    response::{IntoResponse, Response},
};
use common::{causes::with_causes, random::RandomUnavailable};
use redis::RedisError;
use thiserror::Error;
use tracing::{debug, error, warn};

/// Why a request failed.
#[derive(Debug, Error)]
pub enum AppError {
    /// The request itself is malformed (400).
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    /// No valid session, signature or sign-in (401).
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    /// Signed in, but not allowed to use this app kind (403).
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// No such site or route (404).
    #[error("not found")]
    NotFound,
    /// A sign-in rate limit was reached (429).
    #[error("too many requests: {0}")]
    TooManyRequests(&'static str),
    /// The app kind's client is not built yet, or its API is saturated on this instance (503).
    #[error("not ready: {0}")]
    NotReady(String),
    /// The provider's keys could not be fetched to check a token: not the token's fault (503).
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(String),
    /// The provider or an API could not be reached or answered unexpectedly (502).
    #[error("upstream failure: {0}")]
    Upstream(String),
    /// A client assertion could not be made (500).
    #[error(transparent)]
    ClientCredentials(#[from] common::client::credentials::ClientAssertionError),
    /// The random source failed (500).
    #[error(transparent)]
    Random(#[from] RandomUnavailable),
    /// Redis failed (503).
    #[error(transparent)]
    Redis(#[from] RedisError),
    /// A value could not be (de)serialized (500).
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A header value could not be built (500).
    #[error(transparent)]
    Header(#[from] InvalidHeaderValue),
    /// A response could not be built (500).
    #[error(transparent)]
    Response(#[from] axum::http::Error),
}

impl From<reqwest::Error> for AppError {
    fn from(value: reqwest::Error) -> Self {
        AppError::Upstream(with_causes(&value))
    }
}

impl AppError {
    /// The status this error answers with.
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::NotReady(_) | AppError::ProviderUnavailable(_) | AppError::Redis(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        match &self {
            // Signature failures mean a misconfigured or hostile caller: worth seeing.
            AppError::Unauthorized(reason) if reason.starts_with("signature") => {
                warn!(error = %self, "edge request refused")
            }
            AppError::TooManyRequests(_) | AppError::Forbidden(_) => {
                warn!(error = %self, "request refused")
            }
            _ if status.is_server_error() => error!(error = %self, "request failed"),
            _ => debug!(error = %self, "request rejected"),
        }
        let body = match status {
            StatusCode::FORBIDDEN => "You do not have access to this application.",
            StatusCode::TOO_MANY_REQUESTS => "Too many sign-in attempts; try again in a minute.",
            _ => "",
        };
        (status, body).into_response()
    }
}
