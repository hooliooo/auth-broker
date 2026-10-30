//! Health and registry status, for orchestrators and operators.

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};
use tracing::warn;

use crate::state::AppState;

/// Liveness, readiness, and the registry this instance serves.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
        .route("/health/registry", get(registry))
}

/// Ready while Redis answers and every app kind has a working provider client.
async fn ready(State(state): State<AppState>) -> StatusCode {
    let mut redis = state.redis.clone();
    if let Err(error) = redis::cmd("PING").query_async::<String>(&mut redis).await {
        warn!(%error, "Redis is not reachable");
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    if state.runtime.missing_clients().is_empty() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// What this instance is serving: lets operators confirm every instance runs the same registry.
async fn registry(State(state): State<AppState>) -> Json<Value> {
    let catalog = state.runtime.catalog();
    let missing = state.runtime.missing_clients();
    let apps: Vec<Value> = catalog
        .registry
        .apps()
        .iter()
        .map(|app| {
            let sites: Vec<&str> = catalog
                .registry
                .sites()
                .iter()
                .filter(|s| s.app_id == app.id)
                .map(|s| s.id.as_str())
                .collect();
            json!({ "id": app.id, "client_ready": !missing.contains(&app.id), "sites": sites })
        })
        .collect();
    Json(json!({ "version": catalog.version, "apps": apps }))
}
