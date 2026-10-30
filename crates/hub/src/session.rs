//! Sessions, keyed by an opaque handle the edge keeps in its cookie. Each session belongs to one
//! site and therefore one app kind; any other site presenting the handle gets
//! nothing.
//!
//! A session lasts exactly as long as the provider's session behind it: each sign-in and token
//! refresh sets its expiry from the provider's `refresh_expires_in`, so the provider's SSO idle and
//! maximum lifetimes apply without being configured twice. Reading a session does not extend
//! it; a refresh, like at the provider, does. The hub additionally ends every session 24 hours
//! after sign-in.
//!
//! Keys that one operation touches together share a Redis Cluster slot: the handle hash sits in
//! `{…}` in both the session and lock keys.

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::{
    causes::with_causes,
    crypto::hash_key,
    metrics,
    random::random_token,
    sealed::{self, Purpose},
};
use redis::{AsyncCommands, Script, aio::ConnectionManager};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::{
    catalog::AppClient,
    error::AppError,
    state::AppState,
    tokens::{self, Refusal},
};

/// How long a session lasts when the provider does not say (no `refresh_expires_in`).
const DEFAULT_LIFETIME_SECS: u64 = 3_600;
/// The hub's own cap: a session ends this long after sign-in, whatever the provider allows.
pub const SSO_MAX_SECS: u64 = 24 * 3_600;
/// Refresh the access token when it has less than this left.
const REFRESH_AHEAD_SECS: u64 = 60;
/// How long one instance may hold a session's refresh lock; longer than any refresh call.
const REFRESH_LOCK_MILLIS: u64 = 30_000;
/// How long a request waits for another instance's refresh before giving up.
const REFRESH_LOCK_WAIT: Duration = Duration::from_secs(12);
/// Total time allowed for one refresh call to the provider.
const REFRESH_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Writes the session only if this caller still holds the refresh lock and the session still
/// exists, so a refresh can neither race another instance nor bring back a logged-out session.
const WRITE_IF_LOCK_HELD: &str = "\
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end \
if redis.call('SET', KEYS[2], ARGV[2], 'XX', 'EX', ARGV[3]) then return 1 end \
return 0";

/// Deletes the lock only if it is still ours.
const RELEASE_LOCK: &str = "\
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end \
return 0";

/// How long to keep a session whose provider says it lasts `provider_secs` more seconds: that
/// long, as the provider's session ends then; [`DEFAULT_LIFETIME_SECS`] if it does not say.
pub fn lifetime_secs(provider_secs: Option<u64>) -> u64 {
    match provider_secs {
        Some(secs) if secs > 0 => secs,
        _ => DEFAULT_LIFETIME_SECS,
    }
}

/// What the hub keeps per signed-in browser at one site, sealed in Redis under the handle.
#[derive(Serialize, Deserialize)]
pub struct Session {
    /// The site's app kind.
    pub app_id: String,
    /// The site that redeemed the sign-in; only it may use the session.
    pub site_id: String,
    /// The site's tenant.
    pub tenant: String,
    /// The user's id.
    pub sub: String,
    /// The provider's SSO session id; only used to find sessions on back-channel logout.
    pub iam_sid: Option<String>,
    /// The user's name, with the `profile` scope.
    pub preferred_username: Option<String>,
    /// The user's display name, with the `profile` scope.
    pub name: Option<String>,
    /// The user's email, with the `email` scope.
    pub email: Option<String>,
    /// The ID token.
    pub id_token: String,
    /// The current access token.
    pub access_token: String,
    /// The current refresh token; the provider rotates it on every refresh.
    pub refresh_token: Option<String>,
    /// When the access token expires, in Unix seconds.
    pub expires_at: u64,
    /// When the user signed in, in Unix seconds.
    pub created_at: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("app_id", &self.app_id)
            .field("site_id", &self.site_id)
            .field("sub", &self.sub)
            .finish_non_exhaustive()
    }
}

/// The current time in Unix seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Redis key of the session whose handle hashes to `hashed`.
fn session_key(hashed: &str) -> String {
    format!("hub:session:{{{hashed}}}")
}

/// Redis key of the refresh lock of the session whose handle hashes to `hashed`.
fn lock_key(hashed: &str) -> String {
    format!("hub:lock:{{{hashed}}}")
}

/// Redis key of the set of `app_id`'s sessions tied to provider session `iam_sid`. Per app
/// kind: a provider logout for one kind's client must not end another kind's sessions.
fn iam_index_key(app_id: &str, iam_sid: &str) -> String {
    format!("hub:iam-sid:{app_id}:{iam_sid}")
}

/// `session` encrypted under `handle`.
fn seal(handle: &str, session: &Session) -> Result<Vec<u8>, AppError> {
    Ok(sealed::seal(
        handle,
        Purpose::Session,
        &serde_json::to_vec(session)?,
    )?)
}

/// The session under `handle` in `redis`; `None` if it is missing, does not open, or is past the
/// 24-hour cap (then it is deleted). Reading does not extend it.
pub async fn load(
    redis: &mut ConnectionManager,
    handle: &str,
) -> Result<Option<Session>, AppError> {
    let raw: Option<Vec<u8>> = redis.get(session_key(&hash_key(handle))).await?;
    let Some(plaintext) = raw.and_then(|r| sealed::open(handle, Purpose::Session, &r)) else {
        return Ok(None);
    };
    let session: Session = serde_json::from_slice(&plaintext)?;
    if now().saturating_sub(session.created_at) > SSO_MAX_SECS {
        delete(redis, handle, &session).await?;
        return Ok(None);
    }
    Ok(Some(session))
}

/// The session under `handle` in `redis`, only if it belongs to `site_id`.
pub async fn load_for_site(
    redis: &mut ConnectionManager,
    handle: &str,
    site_id: &str,
) -> Result<Option<Session>, AppError> {
    Ok(load(redis, handle)
        .await?
        .filter(|session| session.site_id == site_id))
}

/// Stores `session` in `redis` under a fresh handle for `lifetime_secs`, records it for
/// back-channel logout, and returns the handle. The index is a separate key in another slot, so
/// it is written separately; a crash in between only means back-channel logout misses a session
/// that still expires on its own.
pub async fn create(
    redis: &mut ConnectionManager,
    session: &Session,
    lifetime_secs: u64,
) -> Result<String, AppError> {
    let handle = random_token()?;
    let hashed = hash_key(&handle);
    redis
        .set_ex::<_, _, ()>(session_key(&hashed), seal(&handle, session)?, lifetime_secs)
        .await?;
    if let Some(iam_sid) = session.iam_sid.as_deref() {
        let index = iam_index_key(&session.app_id, iam_sid);
        redis::pipe()
            .sadd(&index, &hashed)
            .ignore()
            .expire(&index, SSO_MAX_SECS as i64)
            .ignore()
            .query_async::<()>(redis)
            .await?;
    }
    Ok(handle)
}

/// Deletes `session`, stored under `handle`, from `redis`, and from its back-channel index.
pub async fn delete(
    redis: &mut ConnectionManager,
    handle: &str,
    session: &Session,
) -> Result<(), AppError> {
    let hashed = hash_key(handle);
    redis.del::<_, ()>(session_key(&hashed)).await?;
    if let Some(iam_sid) = session.iam_sid.as_deref() {
        redis
            .srem::<_, _, ()>(iam_index_key(&session.app_id, iam_sid), &hashed)
            .await?;
    }
    Ok(())
}

/// Back-channel logout: deletes from `redis` every session of app kind `app_id` tied to the
/// provider session `iam_sid`; returns how many there were.
pub async fn delete_by_iam_sid(
    redis: &mut ConnectionManager,
    app_id: &str,
    iam_sid: &str,
) -> Result<usize, AppError> {
    let index = iam_index_key(app_id, iam_sid);
    let hashed: Vec<String> = redis.smembers(&index).await?;
    // One DEL per key: in a cluster each session lives in its own slot.
    for h in &hashed {
        redis.del::<_, ()>(session_key(h)).await?;
    }
    redis.del::<_, ()>(&index).await?;
    Ok(hashed.len())
}

/// The provider's answer to a refresh.
#[derive(Deserialize)]
struct RefreshResponse {
    /// The new access token.
    access_token: String,
    /// The rotated refresh token.
    refresh_token: Option<String>,
    /// A new ID token, if the provider issued one.
    id_token: Option<String>,
    /// Seconds until the access token expires.
    expires_in: u64,
}

/// An access token for `session` (stored under `handle`) valid for at least another minute,
/// refreshed with `client` if needed, using `app`'s Redis and provider client. `None`: the
/// session is gone, the provider refused the refresh, or the user lost access to the kind.
pub async fn fresh_access_token(
    app: &AppState,
    client: &AppClient,
    handle: &str,
    session: Session,
) -> Result<Option<String>, AppError> {
    if session.expires_at > now() + REFRESH_AHEAD_SECS {
        return Ok(Some(session.access_token));
    }
    let mut redis = app.redis.clone();
    let Some(lock) = RefreshLock::acquire(&mut redis, handle).await? else {
        warn!("token refresh still running elsewhere; giving up");
        return Ok(None);
    };
    let result = refresh_locked(app, client, &mut redis, handle, &lock).await;
    lock.release(&mut redis).await;
    result
}

/// The work of [`fresh_access_token`] while holding `lock`: re-reads the session under `handle`
/// from `redis`, refreshes it at the provider with `client` unless another request already did, and
/// writes it back while the lock is still held.
async fn refresh_locked(
    app: &AppState,
    client: &AppClient,
    redis: &mut ConnectionManager,
    handle: &str,
    lock: &RefreshLock,
) -> Result<Option<String>, AppError> {
    // Another request or hub instance may have refreshed while this one waited.
    let Some(mut session) = load(redis, handle).await? else {
        return Ok(None);
    };
    if session.expires_at > now() + REFRESH_AHEAD_SECS {
        return Ok(Some(session.access_token));
    }
    let Some(refresh_token) = session.refresh_token.clone() else {
        delete(redis, handle, &session).await?;
        return Ok(None);
    };
    let kind = client.app.id.as_str();

    let mut form = vec![
        ("grant_type", "refresh_token".to_owned()),
        ("refresh_token", refresh_token),
    ];
    form.extend(client.auth_fields(app)?);
    let response = app
        .idp
        .post(client.token_endpoint())
        .timeout(REFRESH_REQUEST_TIMEOUT)
        .form(&form)
        .send()
        .await
        .map_err(|error| {
            metrics::counter(
                "hub_token_refreshes_total",
                &[("kind", kind), ("outcome", "failed")],
            );
            AppError::Upstream(format!("token refresh failed: {error}"))
        })?;
    match response.status() {
        status if status.is_success() => {}
        // The refresh token is dead (expired, revoked, reused): so is the session.
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED => {
            metrics::counter(
                "hub_token_refreshes_total",
                &[("kind", kind), ("outcome", "rejected")],
            );
            warn!(status = %response.status(), "refresh token rejected; ending session");
            delete(redis, handle, &session).await?;
            return Ok(None);
        }
        // The provider is having trouble: keep the session, the next request tries again.
        status => {
            metrics::counter(
                "hub_token_refreshes_total",
                &[("kind", kind), ("outcome", "failed")],
            );
            return Err(AppError::Upstream(format!(
                "token endpoint returned {status}"
            )));
        }
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Upstream(with_causes(&e)))?;
    let provider = app.config.provider.as_ref();
    let lifetime = lifetime_secs(provider.session_lifetime_secs(&body));
    let refreshed: RefreshResponse = serde_json::from_value(body)?;
    // Roles are re-checked on every refresh: a user who lost access stops at the next one.
    if let Err(refusal) = tokens::check(
        provider,
        &client.app,
        &session.site_id,
        &refreshed.access_token,
    ) {
        if refusal == Refusal::MissingAudience {
            error!(app = %client.app.id, "the provider issued a token without the app's audience");
        }
        metrics::counter(
            "hub_token_refreshes_total",
            &[("kind", kind), ("outcome", "refused")],
        );
        delete(redis, handle, &session).await?;
        return Ok(None);
    }
    metrics::counter(
        "hub_token_refreshes_total",
        &[("kind", kind), ("outcome", "refreshed")],
    );
    session.access_token = refreshed.access_token;
    if let Some(rotated) = refreshed.refresh_token {
        session.refresh_token = Some(rotated);
    }
    if let Some(id_token) = refreshed.id_token {
        session.id_token = id_token;
    }
    session.expires_at = now() + refreshed.expires_in;

    let written: i64 = Script::new(WRITE_IF_LOCK_HELD)
        .key(&lock.key)
        .key(session_key(&hash_key(handle)))
        .arg(&lock.token)
        .arg(seal(handle, &session)?)
        .arg(lifetime)
        .invoke_async(redis)
        .await?;
    if written == 0 {
        // Lock lost to another hub instance, or the session ended meanwhile.
        return Ok(None);
    }
    Ok(Some(session.access_token))
}

/// A held refresh lock.
struct RefreshLock {
    /// The lock's Redis key.
    key: String,
    /// This holder's random token; only its holder may release the lock.
    token: String,
}

impl RefreshLock {
    /// Takes the refresh lock of the session under `handle` in `redis`, waiting up to
    /// [`REFRESH_LOCK_WAIT`]; `None` if it stayed busy.
    async fn acquire(
        redis: &mut ConnectionManager,
        handle: &str,
    ) -> Result<Option<Self>, AppError> {
        let lock = Self {
            key: lock_key(&hash_key(handle)),
            token: random_token()?,
        };
        let poll = Duration::from_millis(50);
        for _ in 0..REFRESH_LOCK_WAIT.as_millis() / poll.as_millis() {
            let acquired: Option<String> = redis::cmd("SET")
                .arg(&lock.key)
                .arg(&lock.token)
                .arg("NX")
                .arg("PX")
                .arg(REFRESH_LOCK_MILLIS)
                .query_async(redis)
                .await?;
            if acquired.is_some() {
                return Ok(Some(lock));
            }
            tokio::time::sleep(poll).await;
        }
        Ok(None)
    }

    /// Releases the lock in `redis` if it is still ours; if that fails, it expires.
    async fn release(self, redis: &mut ConnectionManager) {
        let result: Result<i64, _> = Script::new(RELEASE_LOCK)
            .key(&self.key)
            .arg(&self.token)
            .invoke_async(redis)
            .await;
        if let Err(error) = result {
            warn!(%error, "could not release refresh lock; it will expire");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_keycloaks_refresh_lifetime_then_the_session_lasts_as_long() {
        assert_eq!(lifetime_secs(Some(1_800)), 1_800);
    }

    #[test]
    fn given_no_or_an_unlimited_refresh_lifetime_then_the_default_applies() {
        assert_eq!(lifetime_secs(None), DEFAULT_LIFETIME_SECS);
        assert_eq!(lifetime_secs(Some(0)), DEFAULT_LIFETIME_SECS);
    }
}
