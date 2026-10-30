//! The hub's shared state.

use std::sync::Arc;

use redis::aio::ConnectionManager;
use reqwest::Client;

use crate::{catalog::Runtime, config::HubConfig};

/// Everything a handler needs; cheap to clone.
#[derive(Clone)]
pub struct AppState {
    /// For the provider only: short total timeout, no redirects.
    pub idp: Client,
    /// Sessions, sign-ins, handoffs, nonces and rate counters.
    pub redis: ConnectionManager,
    /// The live registry and per-kind clients.
    pub runtime: Arc<Runtime>,
    /// The settings.
    pub config: Arc<HubConfig>,
}
