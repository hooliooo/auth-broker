//! A per-instance cache of the Identity and Access Management (IAM) provider's signing keys.
//!
//! The keys are loaded at startup and refreshed once they are older than the configured `ttl` but
//! refetched earlier when a token's header contains a key id unknown to the cache. The refetch
//! happens at most once within the `min_refresh_interval`, to prevent flooding and handle
//! concurrent requests. When a refresh fails, the previous keys are kept.

use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse},
};
use reqwest::Client;
use thiserror::Error;
use tokio::{sync::Mutex, time::Instant};

use crate::{causes::with_causes, oidc::JwtVerificationError};

/// Why the key set could not be fetched.
#[derive(Debug, Error)]
pub enum SourceError {
    /// The connection failed.
    #[error("Could not reach the JWKS endpoint: {0}")]
    Unreachable(String),
    /// The endpoint answered with an error status.
    #[error("The JWKS endpoint returned an error: {0}")]
    ErrorStatus(String),
    /// The body is not a key set.
    #[error("The JWKS endpoint did not return a key set: {0}")]
    Malformed(String),
}

/// Where the JSON Web Key Set (JWKS) comes from. A trait so the cache can be tested without
/// HTTP.
#[async_trait]
pub trait JwksSource: std::fmt::Debug + Send + Sync {
    /// The current key set.
    async fn fetch(&self) -> Result<JwkSet, SourceError>;
}

/// Fetches the JWKS from the provider's `jwks_uri`.
#[derive(Debug)]
pub struct HttpJwksSource {
    /// Client the key set is fetched with.
    client: reqwest::Client,
    /// The provider's `jwks_uri`.
    jwks_uri: String,
}

impl HttpJwksSource {
    /// Fetches from `jwks_uri` with `client`.
    pub fn new(client: Client, jwks_uri: String) -> Self {
        Self { client, jwks_uri }
    }
}

#[async_trait]
impl JwksSource for HttpJwksSource {
    async fn fetch(&self) -> Result<JwkSet, SourceError> {
        self.client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|err| SourceError::Unreachable(with_causes(&err)))?
            .error_for_status()
            .map_err(|err| SourceError::ErrorStatus(with_causes(&err)))?
            .json()
            .await
            .map_err(|err| SourceError::Malformed(with_causes(&err)))
    }
}

/// A key that can verify signatures, and the one algorithm it may be used with.
#[derive(Debug)]
pub struct SigningKey {
    /// The public key.
    pub key: DecodingKey,
    /// The only algorithm tokens signed with this key may use.
    pub algorithm: Algorithm,
}

/// One fetched key set, keyed by key id. Replaced as a whole on every refresh.
#[derive(Debug)]
struct Keys {
    /// Usable signing keys by key id.
    by_kid: HashMap<String, Arc<SigningKey>>,
    /// When the set was fetched; the TTL counts from here.
    fetched_at: Instant,
}

impl Keys {
    /// The usable signing keys of `set`, fetched at `fetched_at`. Other keys are skipped rather
    /// than failing the whole set: a JWKS may also list encryption keys or other algorithms.
    fn from_set(set: &JwkSet, fetched_at: Instant) -> Self {
        let by_kid = set
            .keys
            .iter()
            .filter(|jwk| !matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)))
            .filter_map(|jwk| {
                let kid = jwk.common.key_id.clone()?;
                let algorithm = signing_algorithm(jwk)?;
                let key = DecodingKey::from_jwk(jwk).ok()?;
                Some((kid, Arc::new(SigningKey { key, algorithm })))
            })
            .collect();
        Self { by_kid, fetched_at }
    }
}

/// The algorithm `jwk` signs with: its `alg` if set, otherwise its key type's usual one.
/// `None` for keys that cannot be used, including symmetric ones: a secret in a public key set
/// would let anyone who reads it sign tokens.
fn signing_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    let algorithm = match (jwk.common.key_algorithm, &jwk.algorithm) {
        (_, AlgorithmParameters::OctetKey(_)) => return None,
        (Some(key_algorithm), _) => Algorithm::try_from(key_algorithm).ok()?,
        (None, AlgorithmParameters::RSA(_)) => Algorithm::RS256,
        (None, AlgorithmParameters::EllipticCurve(params)) => match params.curve {
            EllipticCurve::P256 => Algorithm::ES256,
            EllipticCurve::P384 => Algorithm::ES384,
            _ => return None,
        },
        (None, AlgorithmParameters::OctetKeyPair(_)) => Algorithm::EdDSA,
        (None, _) => return None,
    };

    let symmetric = matches!(
        algorithm,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    );
    (!symmetric).then_some(algorithm)
}

/// The provider's signing keys, shared by every request of this instance.
#[derive(Debug)]
pub struct Cache {
    /// Where keys are fetched from.
    source: Box<dyn JwksSource>,
    /// Read on every request; the guard is only held to clone the `Arc`.
    keys: RwLock<Arc<Keys>>,
    /// Held across the fetch, so concurrent refreshes wait for one another. Guards the time of
    /// the last attempt, which the cooldown is measured from.
    last_refresh: Mutex<Instant>,
    /// When the last fetch finished, readable without waiting for [`Self::last_refresh`]: during
    /// a cooldown, lookups learn there is nothing to do without queueing on that lock.
    last_finished: RwLock<Instant>,
    /// How old the keys may get before a lookup refreshes them.
    ttl: Duration,
    /// The cooldown: the least time between two fetches, however many lookups ask for one.
    min_refresh_interval: Duration,
}

impl Cache {
    /// Loads the keys from `source`; they are refreshed once older than `ttl`, and fetched at
    /// most once per `min_refresh_interval`. Fails if `source` cannot be reached.
    pub async fn new(
        source: impl JwksSource + 'static,
        ttl: Duration,
        min_refresh_interval: Duration,
    ) -> Result<Self, SourceError> {
        let now = Instant::now();
        let keys = Keys::from_set(&source.fetch().await?, now);
        Ok(Self {
            source: Box::new(source),
            keys: RwLock::new(Arc::new(keys)),
            last_refresh: Mutex::new(now),
            last_finished: RwLock::new(now),
            ttl,
            min_refresh_interval,
        })
    }

    /// The key with id `kid`, refreshing the set first if `kid` is unknown or the keys are
    /// older than the TTL.
    pub async fn key(&self, kid: &str) -> Result<Arc<SigningKey>, JwtVerificationError> {
        let keys = self.snapshot();
        if keys.fetched_at.elapsed() < self.ttl
            && let Some(key) = keys.by_kid.get(kid)
        {
            return Ok(key.clone());
        }

        // Unknown key id, or keys past their ttl
        let (keys, failure) = self.refresh(&keys).await;
        match (keys.by_kid.get(kid), failure) {
            (Some(key), _) => Ok(key.clone()),
            // The provider may have rotated to this key, but could not be asked
            (None, Some(error)) => {
                Err(JwtVerificationError::ProviderUnavailable(error.to_string()))
            }
            (None, None) => Err(JwtVerificationError::Invalid(format!(
                "no signing key with id '{kid}'"
            ))),
        }
    }

    /// The current key set, without holding the lock.
    fn snapshot(&self) -> Arc<Keys> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Refetches the keys unless another request replaced `seen` meanwhile or the cooldown has
    /// not passed. Returns the keys to use (the previous ones if the fetch failed) and this
    /// call's fetch failure, if any.
    async fn refresh(&self, seen: &Arc<Keys>) -> (Arc<Keys>, Option<SourceError>) {
        // Fast path: a fetch finished within the cooldown and the keys are still the ones seen,
        // so there is nothing to do. Without it, every lookup during a provider outage would
        // queue on the lock only to learn that. A fetch still in flight has not finished, so
        // lookups then wait for its result instead, e.g. a key the provider just rotated in.
        let finished = *self
            .last_finished
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        if finished.elapsed() < self.min_refresh_interval && Arc::ptr_eq(&self.snapshot(), seen) {
            return (seen.clone(), None);
        }

        let mut last_refresh = self.last_refresh.lock().await;

        // Another request refreshed while this one waited for the lock
        let current = self.snapshot();
        if !Arc::ptr_eq(&current, seen) {
            return (current, None);
        }
        if last_refresh.elapsed() < self.min_refresh_interval {
            return (current, None);
        }

        *last_refresh = Instant::now();
        let fetched = self.source.fetch().await;
        *self
            .last_finished
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
        match fetched {
            Ok(set) => {
                let fresh = Arc::new(Keys::from_set(&set, Instant::now()));
                *self.keys.write().unwrap_or_else(PoisonError::into_inner) = fresh.clone();
                (fresh, None)
            }
            Err(error) => {
                tracing::warn!(%error, "Keeping the previous signing keys");
                (current, Some(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use jsonwebtoken::{Algorithm, jwk::JwkSet};
    use serde_json::{Value, json};

    use crate::{
        cache::{Cache, JwksSource, Keys, SourceError},
        oidc::JwtVerificationError,
    };

    /// Key TTL in the tests.
    const TTL: Duration = Duration::from_secs(600);
    /// Refresh cooldown in the tests.
    const COOLDOWN: Duration = Duration::from_secs(30);

    /// Placeholder key material: valid base64url, but no real key. `DecodingKey::from_jwk`
    /// only decodes it, and no signature is checked here.
    const MODULUS: &str =
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QA";

    /// A placeholder RSA signing key with id `kid`.
    fn rsa_key(kid: &str) -> Value {
        json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": MODULUS, "e": "AQAB" })
    }

    /// A key set of `keys`.
    fn set_of(keys: Vec<Value>) -> JwkSet {
        serde_json::from_value(json!({ "keys": keys })).unwrap()
    }

    /// A key set with one placeholder key per id in `kids`.
    fn key_set(kids: &[&str]) -> JwkSet {
        set_of(kids.iter().map(|kid| rsa_key(kid)).collect())
    }

    /// A key source the test controls, counting fetches.
    #[derive(Debug)]
    struct TestSource {
        /// What the next fetch returns; `None` fails it.
        response: Arc<Mutex<Option<JwkSet>>>,
        /// How many fetches happened.
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl JwksSource for TestSource {
        async fn fetch(&self) -> Result<JwkSet, SourceError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.response
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| SourceError::Unreachable("connection refused".into()))
        }
    }

    /// A cache over a [`TestSource`], with handles to control and observe it.
    struct CacheTestState {
        /// The cache under test.
        cache: Cache,
        /// What the source's next fetch returns.
        response: Arc<Mutex<Option<JwkSet>>>,
        /// How many fetches the source served.
        fetches: Arc<AtomicUsize>,
    }

    impl CacheTestState {
        /// A cache loaded with placeholder keys `kids`.
        async fn new(kids: &[&str]) -> Self {
            let response = Arc::new(Mutex::new(Some(key_set(kids))));
            let fetches = Arc::new(AtomicUsize::new(0));
            let source = TestSource {
                response: response.clone(),
                fetches: fetches.clone(),
            };
            let cache = Cache::new(source, TTL, COOLDOWN).await.unwrap();
            Self {
                cache,
                response,
                fetches,
            }
        }

        /// Makes the next fetches return `set`, or fail if `None`.
        fn serve(&self, set: Option<JwkSet>) {
            *self.response.lock().unwrap() = set
        }

        /// How many fetches happened so far.
        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_known_kid_when_queried_then_it_should_only_be_fetched_once() {
        let state = CacheTestState::new(&["a"]).await;
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 1);
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_rotated_key_when_queried_then_it_should_refetch_once() {
        let state = CacheTestState::new(&["a"]).await;
        assert_eq!(state.fetches(), 1);
        tokio::time::advance(COOLDOWN).await;
        state.serve(Some(key_set(&["a", "b"])));

        assert!(state.cache.key("b").await.is_ok());
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_unknown_kid_within_min_refresh_interval_when_queried_then_it_should_not_refetch()
     {
        let state = CacheTestState::new(&["a"]).await;
        let result = state.cache.key("not-a-key").await;

        assert!(matches!(result, Err(JwtVerificationError::Invalid(_))));
        assert_eq!(state.fetches(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn given_concurrent_unknown_kids_when_queried_then_it_should_refetch_only_once() {
        let state = CacheTestState::new(&["a"]).await;
        assert_eq!(state.fetches(), 1);
        tokio::time::advance(COOLDOWN).await;
        state.serve(Some(key_set(&["a", "b"])));
        let (first, second, third) = tokio::join!(
            state.cache.key("b"),
            state.cache.key("b"),
            state.cache.key("b"),
        );
        assert!(first.is_ok() && second.is_ok() && third.is_ok());
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_keys_older_than_ttl_when_queried_then_it_should_refresh() {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(TTL).await;
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_failed_refresh_when_a_known_kid_is_queried_then_it_should_return_the_old_key()
    {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(TTL).await;
        state.serve(None);

        assert!(state.cache.key("a").await.is_ok());
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_failed_refresh_when_an_unknown_kid_is_queried_then_it_should_return_an_error()
    {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(COOLDOWN).await;
        state.serve(None);

        let result = state.cache.key("b").await;
        assert!(matches!(
            result,
            Err(JwtVerificationError::ProviderUnavailable(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_failed_refresh_when_looked_up_during_the_cooldown_then_it_does_not_wait_for_the_lock()
     {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(TTL).await;
        state.serve(None);
        assert!(state.cache.key("a").await.is_ok(), "the old key is kept");

        // As if another lookup were stuck holding the refresh lock.
        let _held = state.cache.last_refresh.lock().await;
        let lookup = tokio::time::timeout(Duration::from_secs(1), state.cache.key("a")).await;

        assert!(lookup.is_ok(), "answered without queueing on the lock");
        assert_eq!(state.fetches(), 2, "and without another fetch");
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_fetch_in_flight_when_its_new_key_is_looked_up_then_it_waits_for_the_result() {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(COOLDOWN).await;
        state.serve(Some(key_set(&["a", "b"])));

        // Both ask for the rotated-in key at once; the second must not skip the in-flight fetch.
        let (first, second) = tokio::join!(state.cache.key("b"), state.cache.key("b"));

        assert!(first.is_ok() && second.is_ok());
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_unreachable_source_at_startup_when_created_then_it_should_return_an_error() {
        let source = TestSource {
            response: Arc::new(Mutex::new(None)),
            fetches: Arc::new(AtomicUsize::new(0)),
        };
        assert!(Cache::new(source, TTL, COOLDOWN).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_key_set_when_loaded_then_only_signing_keys_should_be_kept() {
        let kid = "ulvOORCVelRFp5JKoU9H21TJZBSqk2YY7N59oZpcgfs";
        let set = set_of(vec![
            rsa_key(kid),
            json!({ "kty": "RSA", "use": "enc", "kid": "encryption", "n": MODULUS, "e": "AQAB" }),
            json!({ "kty": "oct", "kid": "secret", "k": "c2VjcmV0" }),
            json!({ "kty": "RSA", "use": "sig", "n": MODULUS, "e": "AQAB" }),
        ]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert_eq!(keys.by_kid.len(), 1);
        assert!(keys.by_kid.contains_key(kid));
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_key_without_alg_when_loaded_it_should_use_its_key_types_default() {
        let set = set_of(vec![
            json!({"kty": "RSA", "kid": "no-alg", "n": MODULUS, "e": "AQAB"}),
        ]);

        let keys = Keys::from_set(&set, tokio::time::Instant::now());
        assert_eq!(keys.by_kid["no-alg"].algorithm, Algorithm::RS256);
    }
}
