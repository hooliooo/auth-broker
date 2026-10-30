//! The edge's shared state.

use std::sync::Arc;

use crate::{
    config::EdgeConfig,
    direct::{Bulkheads, TokenCache},
    hub::HubClient,
    sites::Sites,
};

#[derive(Clone)]
/// Everything a handler needs; cheap to clone.
pub struct AppState {
    /// Signed requests to the hub.
    pub hub: Arc<HubClient>,
    /// The settings.
    pub config: Arc<EdgeConfig>,
    /// The kind's sites, from the registry.
    pub sites: Arc<Sites>,
    /// For a direct kind: calls the sites' APIs.
    pub api: reqwest::Client,
    /// For a direct kind: access tokens fetched from the hub, by session.
    pub tokens: Arc<TokenCache>,
    /// For a direct kind: the API calls each site may have in flight.
    pub bulkheads: Arc<Bulkheads>,
}
