//! Every failure maps to one status.

use axum::{
    http::{StatusCode, header::InvalidHeaderValue},
    response::{IntoResponse, Response},
};
use common::{causes::with_causes, random::RandomUnavailable, signing::SigningError};
use thiserror::Error;
use tracing::{debug, error};

/// Why a request failed; reasons go to the log, never to the browser.
#[derive(Debug, Error)]
pub enum EdgeError {
    /// The request is malformed (400).
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    /// No valid session or sign-in (401).
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    /// The request's host is none of this edge's sites (404).
    #[error("no site of this edge has this host")]
    UnknownSite,
    /// The hub could not be reached or answered unexpectedly.
    #[error("hub failure: {0}")]
    Hub(String),
    /// A direct kind's API could not be reached (502).
    #[error("API failure: {0}")]
    Api(String),
    /// A site's direct API calls are at their limit on this edge (503).
    #[error("busy: {0}")]
    Busy(String),
    /// The random source failed (500).
    #[error(transparent)]
    Random(#[from] RandomUnavailable),
    /// A request could not be signed (500).
    #[error(transparent)]
    Signing(#[from] SigningError),
    /// A header value could not be built (500).
    #[error(transparent)]
    Header(#[from] InvalidHeaderValue),
    /// A response could not be built (500).
    #[error(transparent)]
    Response(#[from] axum::http::Error),
}

impl From<reqwest::Error> for EdgeError {
    fn from(value: reqwest::Error) -> Self {
        EdgeError::Hub(with_causes(&value))
    }
}

impl IntoResponse for EdgeError {
    fn into_response(self) -> Response {
        let status = match &self {
            EdgeError::BadRequest(_) => StatusCode::BAD_REQUEST,
            EdgeError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            EdgeError::UnknownSite => StatusCode::NOT_FOUND,
            EdgeError::Hub(_) | EdgeError::Api(_) => StatusCode::BAD_GATEWAY,
            EdgeError::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() {
            error!(error = %self, "request failed");
        } else {
            debug!(error = %self, "request rejected");
        }
        status.into_response()
    }
}
