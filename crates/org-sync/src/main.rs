//! The organization sync: one Keycloak organization per installation of every direct kind (a kind
//! whose edge calls its installations' APIs with tokens naming the installation), kept in step
//! with the registry store.
//!
//! It reads the store through a read-only account and the app kinds from the registry files, and
//! is the only component holding Keycloak admin credentials: a service account with the
//! `manage-organizations` role and nothing more. The hub never gets them.
//!
//! At start, and then every `ORG_SYNC_FULL_SECS`, it makes a full pass: creates missing
//! organizations, updates changed ones, disables those of removed or retired installations, and
//! reports drift (organizations it manages that the store does not hold). In between it follows
//! the store's changes every `ORG_SYNC_MILLIS`. An organization's alias is the installation id
//! and never changes; its `tenant` attribute is the installation's tenant.
//!
//!   org-sync           follow the store for the life of the process
//!   org-sync --once    one full pass, then exit

use std::{
    collections::{HashMap, HashSet},
    process::ExitCode,
    time::{Duration, Instant},
};

use common::registry::{Registry, read_documents};
use futures_util::{StreamExt, stream};
use registry_store::{InstallationState, Store};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Requests to Keycloak in flight at once during a full pass.
const IN_FLIGHT: usize = 16;
/// Organizations listed per page.
const PAGE: usize = 500;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// The settings, from the environment.
struct Config {
    /// `REGISTRY_DATABASE_URL`: the store, through a read-only account.
    database_url: String,
    /// `REGISTRY_DIR`: the app kinds' documents.
    registry_dir: String,
    /// `KEYCLOAK_URL`: Keycloak as this job reaches it.
    keycloak_url: String,
    /// `REALM`.
    realm: String,
    /// `ORG_SYNC_CLIENT_ID`, `ORG_SYNC_CLIENT_SECRET`: the service account.
    client_id: String,
    client_secret: String,
    /// `ORG_SYNC_MILLIS`: how often to follow the store.
    follow_every: Duration,
    /// `ORG_SYNC_FULL_SECS`: how often to make a full pass.
    full_every: Duration,
}

impl Config {
    fn from_env() -> Result<Self, Error> {
        let var = |name: &str| std::env::var(name).map_err(|_| format!("missing env var '{name}'"));
        let number = |name: &str, default: u64| -> Result<u64, Error> {
            std::env::var(name).map_or(Ok(default), |v| {
                v.parse()
                    .map_err(|_| format!("env var '{name}' is invalid").into())
            })
        };
        Ok(Self {
            database_url: var("REGISTRY_DATABASE_URL")?,
            registry_dir: var("REGISTRY_DIR")?,
            keycloak_url: var("KEYCLOAK_URL")?.trim_end_matches('/').to_owned(),
            realm: var("REALM")?,
            client_id: var("ORG_SYNC_CLIENT_ID")?,
            client_secret: var("ORG_SYNC_CLIENT_SECRET")?,
            follow_every: Duration::from_millis(number("ORG_SYNC_MILLIS", 2_000)?),
            full_every: Duration::from_secs(number("ORG_SYNC_FULL_SECS", 3_600)?),
        })
    }
}

/// What a pass did.
#[derive(Default)]
struct Tally {
    created: usize,
    updated: usize,
    unchanged: usize,
    failed: usize,
}

/// Keycloak's admin API for organizations, as the service account.
struct Keycloak {
    http: Client,
    config: Config,
    /// The service account's token, and when to fetch a new one.
    token: Mutex<Option<(String, Instant)>>,
}

impl Keycloak {
    /// A token for the service account, fetched again shortly before it expires.
    async fn token(&self) -> Result<String, Error> {
        let mut token = self.token.lock().await;
        if let Some((value, renew_at)) = token.as_ref()
            && Instant::now() < *renew_at
        {
            return Ok(value.clone());
        }
        let c = &self.config;
        let answer: Value = self
            .http
            .post(format!(
                "{}/realms/{}/protocol/openid-connect/token",
                c.keycloak_url, c.realm
            ))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", c.client_id.as_str()),
                ("client_secret", c.client_secret.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let value = answer["access_token"]
            .as_str()
            .ok_or("no access token")?
            .to_owned();
        let lifetime = answer["expires_in"].as_u64().unwrap_or(60);
        *token = Some((
            value.clone(),
            Instant::now() + Duration::from_secs(lifetime.saturating_sub(15)),
        ));
        Ok(value)
    }

    /// The realm's admin URL for `path`.
    fn url(&self, path: &str) -> String {
        format!(
            "{}/admin/realms/{}{path}",
            self.config.keycloak_url, self.config.realm
        )
    }

    /// The realm's admin URL for `path` with `query`.
    fn url_with(&self, path: &str, query: &[(&str, &str)]) -> Result<reqwest::Url, Error> {
        let mut url = reqwest::Url::parse(&self.url(path))?;
        url.query_pairs_mut().extend_pairs(query);
        Ok(url)
    }

    /// Every organization, with attributes.
    async fn organizations(&self) -> Result<Vec<Value>, Error> {
        let mut all = Vec::new();
        loop {
            let page: Vec<Value> = self
                .http
                .get(self.url_with(
                    "/organizations",
                    &[
                        ("first", &all.len().to_string()),
                        ("max", &PAGE.to_string()),
                        ("briefRepresentation", "false"),
                    ],
                )?)
                .bearer_auth(self.token().await?)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let done = page.len() < PAGE;
            all.extend(page);
            if done {
                return Ok(all);
            }
        }
    }

    /// The organization with alias `alias`, if any.
    async fn organization(&self, alias: &str) -> Result<Option<Value>, Error> {
        let found: Vec<Value> = self
            .http
            .get(self.url_with(
                "/organizations",
                &[
                    ("search", alias),
                    ("exact", "true"),
                    ("briefRepresentation", "false"),
                ],
            )?)
            .bearer_auth(self.token().await?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(found.into_iter().find(|org| org["alias"] == alias))
    }

    /// Makes `existing` (or a new organization) match `wanted`; what it did.
    async fn apply(&self, wanted: &Wanted, existing: Option<Value>) -> Result<Outcome, Error> {
        let Some(mut org) = existing else {
            if !wanted.enabled && wanted.removed {
                return Ok(Outcome::Unchanged);
            }
            let created = self
                .http
                .post(self.url("/organizations"))
                .bearer_auth(self.token().await?)
                .json(&json!({
                    "name": wanted.alias, "alias": wanted.alias, "enabled": wanted.enabled,
                    "attributes": { "tenant": [wanted.tenant], "managed-by": ["hub"] }
                }))
                .send()
                .await?;
            // Another pass may have created it in between.
            if created.status() == StatusCode::CONFLICT {
                return Ok(Outcome::Unchanged);
            }
            created.error_for_status()?;
            return Ok(Outcome::Created);
        };
        let up_to_date = org["enabled"] == wanted.enabled
            && org["attributes"]["tenant"] == json!([wanted.tenant])
            && org["attributes"]["managed-by"] == json!(["hub"]);
        if up_to_date {
            return Ok(Outcome::Unchanged);
        }
        org["enabled"] = json!(wanted.enabled);
        if !org["attributes"].is_object() {
            org["attributes"] = json!({});
        }
        org["attributes"]["tenant"] = json!([wanted.tenant]);
        org["attributes"]["managed-by"] = json!(["hub"]);
        let id = org["id"]
            .as_str()
            .ok_or("organization without id")?
            .to_owned();
        self.http
            .put(self.url(&format!("/organizations/{id}")))
            .bearer_auth(self.token().await?)
            .json(&org)
            .send()
            .await?
            .error_for_status()?;
        Ok(Outcome::Updated)
    }
}

/// What an installation's organization should be.
struct Wanted {
    alias: String,
    tenant: String,
    /// Enabled only while the installation is enabled and not removed.
    enabled: bool,
    removed: bool,
}

enum Outcome {
    Created,
    Updated,
    Unchanged,
}

/// The app kinds whose installations each need an organization: those without `api_upstream`.
fn direct_kinds(dir: &str) -> Result<HashSet<String>, Error> {
    let (documents, _) = read_documents(dir)?;
    let kinds =
        Registry::kinds_from_documents(documents.iter().map(|(n, t)| (n.as_str(), t.as_str())))?;
    Ok(kinds
        .apps()
        .iter()
        .filter(|app| app.direct())
        .map(|app| app.id.clone())
        .collect())
}

/// `state`'s organization as wanted, if its kind needs one.
fn wanted(state: InstallationState, direct: &HashSet<String>) -> Option<Wanted> {
    direct.contains(&state.kind).then_some(Wanted {
        enabled: state.enabled && !state.removed,
        removed: state.removed,
        alias: state.id,
        tenant: state.tenant,
    })
}

/// Every installation's organization made to match, and drift reported. Returns the store
/// version it covered.
async fn full_pass(keycloak: &Keycloak, store: &Store) -> Result<i64, Error> {
    let direct = direct_kinds(&keycloak.config.registry_dir)?;
    let (version, states) = store.installation_states().await?;
    let mut existing: HashMap<String, Value> = keycloak
        .organizations()
        .await?
        .into_iter()
        .filter_map(|org| Some((org["alias"].as_str()?.to_owned(), org)))
        .collect();
    let in_store: HashSet<String> = states.iter().map(|s| s.id.clone()).collect();
    let work: Vec<(Wanted, Option<Value>)> = states
        .into_iter()
        .filter_map(|state| wanted(state, &direct))
        .map(|wanted| {
            let org = existing.remove(&wanted.alias);
            (wanted, org)
        })
        .collect();
    let tally = apply_all(keycloak, work).await;
    for (alias, org) in existing {
        if org["attributes"]["managed-by"] == json!(["hub"]) && !in_store.contains(&alias) {
            warn!(
                "DRIFT: organization {alias} is managed by the hub but not in the registry store"
            );
        }
    }
    info!(
        version,
        created = tally.created,
        updated = tally.updated,
        unchanged = tally.unchanged,
        failed = tally.failed,
        "organizations: full pass done"
    );
    Ok(version)
}

/// `work` applied, `IN_FLIGHT` at a time; each change logged.
async fn apply_all(keycloak: &Keycloak, work: Vec<(Wanted, Option<Value>)>) -> Tally {
    let outcomes: Vec<(String, Result<Outcome, Error>)> = stream::iter(work)
        .map(|(wanted, org)| async move {
            let outcome = keycloak.apply(&wanted, org).await;
            (wanted.alias, outcome)
        })
        .buffer_unordered(IN_FLIGHT)
        .collect()
        .await;
    let mut tally = Tally::default();
    for (alias, outcome) in outcomes {
        match outcome {
            Ok(Outcome::Created) => {
                info!("organization {alias} created");
                tally.created += 1;
            }
            Ok(Outcome::Updated) => {
                info!("organization {alias} updated");
                tally.updated += 1;
            }
            Ok(Outcome::Unchanged) => tally.unchanged += 1,
            Err(error) => {
                warn!(%error, "organization {alias} not synced");
                tally.failed += 1;
            }
        }
    }
    tally
}

/// The organizations of installations changed after `since`; returns the version covered, or
/// `since` again if something failed, so the changes are tried again.
async fn follow(keycloak: &Keycloak, store: &Store, since: i64) -> Result<i64, Error> {
    let (version, states) = store.states_since(since).await?;
    if version <= since {
        return Ok(since);
    }
    let direct = direct_kinds(&keycloak.config.registry_dir)?;
    let mut work = Vec::new();
    for wanted in states
        .into_iter()
        .filter_map(|state| wanted(state, &direct))
    {
        let org = keycloak.organization(&wanted.alias).await?;
        work.push((wanted, org));
    }
    let tally = apply_all(keycloak, work).await;
    Ok(if tally.failed == 0 { version } else { since })
}

async fn run() -> Result<(), Error> {
    let once = std::env::args().nth(1).as_deref() == Some("--once");
    let config = Config::from_env()?;
    let store = Store::connect(&config.database_url).await?;
    let keycloak = Keycloak {
        http: Client::builder().timeout(Duration::from_secs(30)).build()?,
        config,
        token: Mutex::new(None),
    };
    let mut version = full_pass(&keycloak, &store).await?;
    if once {
        return Ok(());
    }
    let mut last_full = Instant::now();
    loop {
        tokio::time::sleep(keycloak.config.follow_every).await;
        let step = if last_full.elapsed() >= keycloak.config.full_every {
            last_full = Instant::now();
            full_pass(&keycloak, &store).await
        } else {
            follow(&keycloak, &store, version).await
        };
        match step {
            Ok(covered) => version = covered,
            Err(error) => warn!(%error, "organizations not synced; trying again"),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "organization sync failed");
            ExitCode::FAILURE
        }
    }
}
