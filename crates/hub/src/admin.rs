//! The registry admin API: provisioning automation creates, changes and removes installations and
//! their keys in the store. Served on its own address (`ADMIN_ADDR`), apart from the public port,
//! and only to callers whose access token from the provider carries the admin audience and role
//! (`ADMIN_AUDIENCE`, `ADMIN_ROLE`), e.g. a Keycloak client with a service account.
//!
//! Every write is validated against its kind with the registry's own rules, and the store's
//! constraints keep ids, origins, hosts and keys unique. The hub, and every other hub instance,
//! picks the change up from the store within a second or so.

use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use common::registry::{
    InstallationRecord, key_id, parse_public_key, validate_installation, web_hosts,
};
use oidc::{
    OidcJwtVerifier,
    oidc::{JwtVerificationError, JwtVerifier},
};
use registry_store::{InstallationWrite, Store, StoreError};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::state::AppState;

/// The most keys in use one installation may hold.
pub const MAX_KEYS: i64 = 10_000;

/// The admin routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/installations/{id}",
            get(show).put(put).delete(remove),
        )
        .route("/admin/installations/{id}/keys", post(add_key))
        .route(
            "/admin/installations/{id}/keys/{key_id}",
            delete(revoke_key),
        )
}

/// Why an admin or key enrollment request failed. The body says why: the caller is automation
/// that must be able to fix its request.
#[derive(Debug)]
pub enum AdminError {
    /// No valid token (401).
    Unauthorized(&'static str),
    /// A valid token without the admin role (403).
    Forbidden,
    /// No such installation or key (404).
    NotFound,
    /// The request breaks the registry's rules (400).
    Invalid(String),
    /// The request conflicts with what the store holds (409).
    Conflict(String),
    /// The store or the provider cannot be reached (503).
    Unavailable(String),
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AdminError::Unauthorized(why) => (StatusCode::UNAUTHORIZED, why.to_owned()),
            AdminError::Forbidden => (
                StatusCode::FORBIDDEN,
                "the token lacks the admin role".into(),
            ),
            AdminError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            AdminError::Invalid(why) => (StatusCode::BAD_REQUEST, why),
            AdminError::Conflict(why) => (StatusCode::CONFLICT, why),
            AdminError::Unavailable(why) => {
                warn!(error = %why, "admin request could not be served");
                (StatusCode::SERVICE_UNAVAILABLE, "try again later".into())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<StoreError> for AdminError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => AdminError::NotFound,
            StoreError::Conflict(why) => AdminError::Conflict(why.to_owned()),
            StoreError::SignerRevoked => AdminError::Unauthorized("signature key revoked"),
            StoreError::Database(e) => AdminError::Unavailable(e.to_string()),
        }
    }
}

/// A caller whose token carries the admin audience and role.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = AdminError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AdminError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(AdminError::Unauthorized("bearer token missing"))?;
        let config = &state.config;
        let verifier = state
            .admin_verifier
            .get_or_try_init(|| {
                OidcJwtVerifier::with_discovery_url(
                    &config.issuer,
                    &config.discovery_url,
                    state.idp.clone(),
                    config.admin_audience.clone(),
                    config.transport,
                )
            })
            .await
            .map_err(|e| AdminError::Unavailable(format!("provider not reachable: {e}")))?;
        let claims: Value = verifier.verify(token).await.map_err(|error| match error {
            JwtVerificationError::ProviderUnavailable(why) => AdminError::Unavailable(why),
            other => {
                warn!(error = %other, "admin token refused");
                AdminError::Unauthorized("token invalid")
            }
        })?;
        let has_role = claims["realm_access"]["roles"]
            .as_array()
            .is_some_and(|roles| roles.iter().any(|role| role == config.admin_role.as_str()));
        if !has_role {
            return Err(AdminError::Forbidden);
        }
        Ok(Self)
    }
}

/// `state`'s store; every admin route needs one.
fn store(state: &AppState) -> Result<&Store, AdminError> {
    state.store.as_ref().ok_or(AdminError::NotFound)
}

/// Body of `PUT /admin/installations/{id}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InstallationBody {
    /// The app kind; never changes.
    kind: String,
    /// The tenant.
    tenant: String,
    /// A web-app installation's origin; absent for a native one. Which it is never changes.
    #[serde(default)]
    origin: Option<String>,
    /// Its API, for a kind whose edge calls each installation's API.
    #[serde(default)]
    api_url: Option<String>,
    /// Whether it may sign in; yes unless said otherwise.
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    /// Its own sign-in rate, if not its kind's.
    #[serde(default)]
    login_per_minute: Option<u64>,
}

/// Installations are enabled unless the request says otherwise.
fn enabled_by_default() -> bool {
    true
}

/// `PUT /admin/installations/{id}`: creates installation `id` or changes it. A native
/// installation starts without keys; add them with `POST …/keys`.
async fn put(
    State(state): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
    Json(body): Json<InstallationBody>,
) -> Result<Json<Value>, AdminError> {
    let store = store(&state)?;
    let record = InstallationRecord {
        id,
        kind: body.kind,
        origin: body.origin,
        keys: Vec::new(),
        api_url: body.api_url,
        tenant: body.tenant,
        enabled: body.enabled,
        login_per_minute: body.login_per_minute,
    };
    let catalog = state.runtime.catalog();
    let app = catalog
        .registry
        .app(&record.kind)
        .ok_or_else(|| AdminError::Invalid(format!("unknown app kind '{}'", record.kind)))?;
    let site =
        validate_installation(&record, app).map_err(|e| AdminError::Invalid(e.to_string()))?;
    let (host, bare_host) =
        web_hosts(&site).map_or((None, None), |(host, bare)| (Some(host), bare));
    let write = InstallationWrite {
        origin: site
            .origin()
            .map(|origin| origin.as_str().trim_end_matches('/').to_owned()),
        host,
        bare_host,
        login_per_minute: record
            .login_per_minute
            .map(|rate| i64::try_from(rate).unwrap_or(i64::MAX)),
        id: record.id,
        kind: record.kind,
        tenant: record.tenant,
        enabled: record.enabled,
        api_url: record.api_url,
    };
    let version = store.put_installation(&write).await?;
    info!(installation = %write.id, kind = %write.kind, version, "installation written");
    Ok(Json(json!({ "version": version })))
}

/// `GET /admin/installations/{id}`: the installation as stored, with every key it ever had.
async fn show(
    State(state): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
) -> Result<Json<Value>, AdminError> {
    let stored = store(&state)?.installation(&id).await?;
    Ok(Json(serde_json::to_value(stored).unwrap_or_default()))
}

/// `DELETE /admin/installations/{id}`: removes the installation for good.
async fn remove(
    State(state): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
) -> Result<Json<Value>, AdminError> {
    let version = store(&state)?.remove_installation(&id).await?;
    info!(installation = %id, version, "installation removed");
    Ok(Json(json!({ "version": version })))
}

/// Body of a key enrollment.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeyBody {
    /// The key, `ed25519:<base64url>`.
    pub public_key: String,
}

/// `POST /admin/installations/{id}/keys`: adds a key to native installation `id`.
async fn add_key(
    State(state): State<AppState>,
    _: Admin,
    Path(id): Path<String>,
    Json(body): Json<KeyBody>,
) -> Result<Json<Value>, AdminError> {
    enroll(&state, &id, &body.public_key, None).await.map(Json)
}

/// `DELETE /admin/installations/{id}/keys/{key_id}`: revokes one of installation `id`'s keys.
async fn revoke_key(
    State(state): State<AppState>,
    _: Admin,
    Path((id, key_id)): Path<(String, String)>,
) -> Result<Json<Value>, AdminError> {
    revoke(&state, &id, &key_id, None).await.map(Json)
}

/// Adds `public_key` to native installation `installation_id`; for provisioning, or for an
/// installation enrolling its own workstations with `signer`, the key id that signed, which the
/// store checks is still in use. Answers with the key's id and the new version.
pub async fn enroll(
    state: &AppState,
    installation_id: &str,
    public_key: &str,
    signer: Option<&str>,
) -> Result<Value, AdminError> {
    let store = store(state)?;
    let key = parse_public_key(public_key).ok_or_else(|| {
        AdminError::Invalid("publicKey must be 'ed25519:' followed by 32 bytes in base64url".into())
    })?;
    let catalog = state.runtime.catalog();
    if catalog
        .registry
        .apps()
        .iter()
        .any(|app| app.edge_public_key == Some(key))
    {
        return Err(AdminError::Conflict("this key is a kind's edge key".into()));
    }
    let key_id = key_id(&key);
    let version = store
        .add_key(installation_id, &key, &key_id, MAX_KEYS, signer)
        .await?;
    info!(installation = installation_id, %key_id, version, "installation key enrolled");
    Ok(json!({ "keyId": key_id, "version": version }))
}

/// Revokes key `key_id` of installation `installation_id`; with `signer`, the installation's own
/// key that signed, which the store checks is still in use. Answers with the new version.
pub async fn revoke(
    state: &AppState,
    installation_id: &str,
    key_id: &str,
    signer: Option<&str>,
) -> Result<Value, AdminError> {
    let version = store(state)?
        .revoke_key(installation_id, key_id, signer)
        .await?;
    info!(installation = installation_id, %key_id, version, "installation key revoked");
    Ok(json!({ "version": version }))
}
