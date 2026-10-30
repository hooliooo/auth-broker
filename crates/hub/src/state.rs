//! The hub's shared state.

use std::sync::Arc;

use oidc::OidcJwtVerifier;
use redis::aio::ConnectionManager;
use registry_store::Store;
use reqwest::Client;
use tokio::sync::OnceCell;

use crate::{
    catalog::{RawPayload, Runtime},
    config::HubConfig,
};

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
    /// Where installations and their keys are kept, if not in the registry files.
    pub store: Option<Store>,
    /// Verifies provisioning clients' tokens for the admin API; built on first use, as the
    /// provider may start after the hub.
    pub admin_verifier: Arc<OnceCell<OidcJwtVerifier<RawPayload>>>,
}
