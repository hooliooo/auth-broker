//! Health, for orchestrators.

use axum::{Router, extract::State, http::StatusCode, routing::get};
use tracing::warn;

use crate::state::AppState;

/// Liveness and readiness.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(ready))
}

/// Ready only while the hub answers and the registry lists at least one enabled site of this
/// kind: without either, nobody can sign in or call an API.
async fn ready(State(app): State<AppState>) -> StatusCode {
    if app.sites.count() == 0 {
        warn!("no enabled site of this kind in the registry");
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let url = format!("{}/health", app.hub.base());
    match reqwest::get(&url).await {
        Ok(response) if response.status().is_success() => StatusCode::OK,
        Ok(response) => {
            warn!(status = %response.status(), "hub is not healthy");
            StatusCode::SERVICE_UNAVAILABLE
        }
        Err(error) => {
            warn!(%error, "hub is not reachable");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
