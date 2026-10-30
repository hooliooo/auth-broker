//! The registry's installations and their keys in Postgres, for installations created by
//! provisioning automation and keys enrolled by the installations themselves.
//!
//! App kinds stay in reviewed files; this store holds what changes often. Every write takes the
//! next version from one row and stamps what it writes with it (see `schema.sql`), so a reader
//! catches up with [`Store::changes_since`] instead of reading everything again. The hub serves
//! from memory and only follows the store: no request waits on it.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::registry::{InstallationRecord, KEY_PREFIX};
use serde::Serialize;
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    postgres::{PgPoolOptions, PgRow},
};
use thiserror::Error;

/// The tables, created if missing; safe to run on every start.
pub const SCHEMA: &str = include_str!("schema.sql");

/// Why a store operation failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Postgres could not be reached or failed.
    #[error("registry store: {0}")]
    Database(#[from] sqlx::Error),
    /// No such installation or key.
    #[error("not found")]
    NotFound,
    /// The write would break a rule: what it conflicts with.
    #[error("{0}")]
    Conflict(&'static str),
    /// The key that signed a self-service change is no longer one of the installation's keys in
    /// use, though a hub may not have followed its revocation yet.
    #[error("the signing key is revoked")]
    SignerRevoked,
}

/// An installation as a writer submits it, already validated against its kind.
#[derive(Clone, Debug)]
pub struct InstallationWrite {
    /// The installation's id.
    pub id: String,
    /// Its app kind; never changes.
    pub kind: String,
    /// Its tenant.
    pub tenant: String,
    /// Whether it may sign in.
    pub enabled: bool,
    /// A web-app installation's origin; `None` for a native one. Which of the two it is never
    /// changes.
    pub origin: Option<String>,
    /// The origin's host with its port.
    pub host: Option<String>,
    /// The origin's host alone, when its port is the scheme's default.
    pub bare_host: Option<String>,
    /// Its API, for a kind whose edge calls each installation's API.
    pub api_url: Option<String>,
    /// Its own sign-in rate, if not its kind's.
    pub login_per_minute: Option<i64>,
}

/// One of an installation's keys as stored.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredKey {
    /// The id requests name it by.
    pub key_id: String,
    /// The key, `ed25519:<base64url>`.
    pub public_key: String,
    /// Whether it was revoked; revoked keys stay, so they are never reused.
    pub revoked: bool,
}

/// An installation as stored, with every key it ever had.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredInstallation {
    /// Its fields, with only the keys in use.
    pub installation: InstallationRecord,
    /// Whether it was removed.
    pub removed: bool,
    /// The version of its last change.
    pub version: i64,
    /// Every key, in use or revoked.
    pub keys: Vec<StoredKey>,
}

/// An installation to import, with its keys and their ids.
pub type Import = (InstallationWrite, Vec<([u8; 32], String)>);

/// Installations changed after a version, up to the version given first: each with its record,
/// or `None` if it was removed.
pub type Changes = (i64, Vec<(String, Option<InstallationRecord>)>);

/// A query for installations, each with its keys in use, as [`record`] reads them; `$where`
/// filters `i` (installations), and the text stays fixed at compile time.
macro_rules! records_where {
    ($where:literal) => {
        concat!(
            "select i.id, i.kind, i.tenant, i.enabled, i.origin, i.api_url, i.login_per_minute, ",
            "i.removed, i.version, coalesce(array_agg(k.public_key order by k.key_id) ",
            "filter (where k.key_id is not null), '{}') as keys ",
            "from installations i left join installation_keys k ",
            "on k.installation_id = i.id and not k.revoked where ",
            $where,
            " group by i.id"
        )
    };
}

/// The registry's installations in Postgres.
#[derive(Clone)]
pub struct Store {
    /// Connections, shared by the hub's sync and its writers.
    pool: PgPool,
}

impl Store {
    /// Connects to `url`, e.g. `postgres://hub@registry-db/registry`.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
        Ok(Self { pool })
    }

    /// Creates the tables if they are missing.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::raw_sql(SCHEMA).execute(&self.pool).await?;
        Ok(())
    }

    /// Every installation in use, with its keys in use, and the version they are as of.
    pub async fn load_all(&self) -> Result<(i64, Vec<InstallationRecord>), StoreError> {
        let mut tx = self.snapshot().await?;
        let version = head(&mut tx).await?;
        let rows = sqlx::query(records_where!("not i.removed"))
            .fetch_all(&mut *tx)
            .await?;
        let records = rows.iter().map(record).collect::<Result<_, _>>()?;
        tx.commit().await?;
        Ok((version, records))
    }

    /// Every installation that changed after version `since`, itself or through its keys.
    pub async fn changes_since(&self, since: i64) -> Result<Changes, StoreError> {
        let mut tx = self.snapshot().await?;
        let version = head(&mut tx).await?;
        if version <= since {
            return Ok((version, Vec::new()));
        }
        let ids: Vec<String> = sqlx::query_scalar(
            "select id from installations where version > $1 and version <= $2 \
             union select installation_id from installation_keys where version > $1 and version <= $2",
        )
        .bind(since)
        .bind(version)
        .fetch_all(&mut *tx)
        .await?;
        let rows = sqlx::query(records_where!("i.id = any($1)"))
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
        tx.commit().await?;
        changes(&rows, version)
    }

    /// Kind `kind`'s web-app installations, for its edge: those that changed after `since`,
    /// or every current one when `since` is 0. Keys do not matter to an edge.
    pub async fn web_installations(&self, kind: &str, since: i64) -> Result<Changes, StoreError> {
        let mut tx = self.snapshot().await?;
        let version = head(&mut tx).await?;
        let rows = sqlx::query(records_where!(
            "i.kind = $1 and i.origin is not null and i.version > $2 and i.version <= $3 \
             and ($2 > 0 or not i.removed)"
        ))
        .bind(kind)
        .bind(since)
        .bind(version)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        changes(&rows, version)
    }

    /// Installation `id` as stored, with every key it ever had.
    pub async fn installation(&self, id: &str) -> Result<StoredInstallation, StoreError> {
        let row = sqlx::query(records_where!("i.id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        let keys = sqlx::query(
            "select key_id, public_key, revoked from installation_keys \
             where installation_id = $1 order by key_id",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| {
            Ok(StoredKey {
                key_id: row.try_get("key_id")?,
                public_key: key_text(&row.try_get::<Vec<u8>, _>("public_key")?),
                revoked: row.try_get("revoked")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
        Ok(StoredInstallation {
            installation: record(&row)?,
            removed: row.try_get("removed")?,
            version: row.try_get("version")?,
            keys,
        })
    }

    /// Creates installation `write.id`, or updates it if its kind and access type are the same
    /// and it was not removed. Returns the new version.
    pub async fn put_installation(&self, write: &InstallationWrite) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let version = next_version(&mut tx).await?;
        if !upsert(&mut tx, write, version).await? {
            return Err(StoreError::Conflict(
                "the installation was removed, or its kind or access type would change",
            ));
        }
        tx.commit().await?;
        Ok(version)
    }

    /// Removes installation `id`; its id is never reused, its keys never accepted again.
    pub async fn remove_installation(&self, id: &str) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let version = next_version(&mut tx).await?;
        let removed = sqlx::query(
            "update installations set removed = true, version = $2 where id = $1 and not removed",
        )
        .bind(id)
        .bind(version)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if removed == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(version)
    }

    /// Adds `key`, with id `key_id`, to native installation `installation_id`, which may then
    /// hold at most `max_keys` keys in use. With `signer`, the installation's own key making the
    /// change, which must still be in use. Returns the new version.
    pub async fn add_key(
        &self,
        installation_id: &str,
        key: &[u8; 32],
        key_id: &str,
        max_keys: i64,
        signer: Option<&str>,
    ) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let version = next_version(&mut tx).await?;
        signer_in_use(&mut tx, installation_id, signer).await?;
        let native: Option<bool> = sqlx::query_scalar(
            "select origin is null from installations where id = $1 and not removed",
        )
        .bind(installation_id)
        .fetch_optional(&mut *tx)
        .await?;
        match native {
            None => return Err(StoreError::NotFound),
            Some(false) => {
                return Err(StoreError::Conflict(
                    "a web-app installation has no keys of its own",
                ));
            }
            Some(true) => {}
        }
        let in_use: i64 = sqlx::query_scalar(
            "select count(*) from installation_keys where installation_id = $1 and not revoked",
        )
        .bind(installation_id)
        .fetch_one(&mut *tx)
        .await?;
        if in_use >= max_keys {
            return Err(StoreError::Conflict("the installation holds its most keys"));
        }
        sqlx::query(
            "insert into installation_keys (key_id, public_key, installation_id, version) \
             values ($1, $2, $3, $4)",
        )
        .bind(key_id)
        .bind(key.as_slice())
        .bind(installation_id)
        .bind(version)
        .execute(&mut *tx)
        .await
        .map_err(conflict)?;
        tx.commit().await?;
        Ok(version)
    }

    /// Revokes key `key_id` of installation `installation_id`. With `signer`, the installation's
    /// own key making the change, which must still be in use. Returns the new version.
    pub async fn revoke_key(
        &self,
        installation_id: &str,
        key_id: &str,
        signer: Option<&str>,
    ) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let version = next_version(&mut tx).await?;
        signer_in_use(&mut tx, installation_id, signer).await?;
        let revoked = sqlx::query(
            "update installation_keys set revoked = true, version = $3 \
             where key_id = $1 and installation_id = $2 and not revoked",
        )
        .bind(key_id)
        .bind(installation_id)
        .bind(version)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if revoked == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(version)
    }

    /// Writes `installations`, each with its keys and their ids, in one transaction: creates or
    /// updates each, and adds keys it does not have. For seeding a store from registry files.
    pub async fn import(&self, installations: &[Import]) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let version = next_version(&mut tx).await?;
        for (write, keys) in installations {
            if !upsert(&mut tx, write, version).await? {
                return Err(StoreError::Conflict(
                    "an installation was removed, or its kind or access type would change",
                ));
            }
            for (key, key_id) in keys {
                sqlx::query(
                    "insert into installation_keys (key_id, public_key, installation_id, version) \
                     values ($1, $2, $3, $4) on conflict (key_id) do nothing",
                )
                .bind(key_id)
                .bind(key.as_slice())
                .bind(&write.id)
                .bind(version)
                .execute(&mut *tx)
                .await
                .map_err(conflict)?;
            }
        }
        tx.commit().await?;
        Ok(version)
    }

    /// A read-only transaction that sees one consistent snapshot.
    async fn snapshot(&self) -> Result<Transaction<'static, Postgres>, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("set transaction isolation level repeatable read, read only")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}

/// The latest version written, as seen by `tx`.
async fn head(tx: &mut Transaction<'static, Postgres>) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar("select version from registry_head")
        .fetch_one(&mut **tx)
        .await?)
}

/// Refuses unless `signer`, if any, is one of installation `installation_id`'s keys in use. Run
/// after [`next_version`], so no revocation can commit in between: a hub may still accept a
/// revoked key for a moment, the store never.
async fn signer_in_use(
    tx: &mut Transaction<'static, Postgres>,
    installation_id: &str,
    signer: Option<&str>,
) -> Result<(), StoreError> {
    let Some(signer) = signer else {
        return Ok(());
    };
    let in_use: bool = sqlx::query_scalar(
        "select exists (select 1 from installation_keys \
         where key_id = $1 and installation_id = $2 and not revoked)",
    )
    .bind(signer)
    .bind(installation_id)
    .fetch_one(&mut **tx)
    .await?;
    if in_use {
        Ok(())
    } else {
        Err(StoreError::SignerRevoked)
    }
}

/// Takes the next version for `tx`'s writes, holding the head row until `tx` ends, so writes
/// commit in version order.
async fn next_version(tx: &mut Transaction<'static, Postgres>) -> Result<i64, StoreError> {
    Ok(
        sqlx::query_scalar("update registry_head set version = version + 1 returning version")
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Inserts `write` at `version`, or updates the installation if its kind and access type are the
/// same and it was not removed; `false` if neither happened.
async fn upsert(
    tx: &mut Transaction<'static, Postgres>,
    write: &InstallationWrite,
    version: i64,
) -> Result<bool, StoreError> {
    let written = sqlx::query(
        "insert into installations \
             (id, kind, tenant, enabled, origin, host, bare_host, api_url, login_per_minute, version) \
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         on conflict (id) do update set \
             tenant = excluded.tenant, enabled = excluded.enabled, origin = excluded.origin, \
             host = excluded.host, bare_host = excluded.bare_host, api_url = excluded.api_url, \
             login_per_minute = excluded.login_per_minute, version = excluded.version \
         where installations.kind = excluded.kind and not installations.removed \
           and (installations.origin is null) = (excluded.origin is null)",
    )
    .bind(&write.id)
    .bind(&write.kind)
    .bind(&write.tenant)
    .bind(write.enabled)
    .bind(&write.origin)
    .bind(&write.host)
    .bind(&write.bare_host)
    .bind(&write.api_url)
    .bind(write.login_per_minute)
    .bind(version)
    .execute(&mut **tx)
    .await
    .map_err(conflict)?
    .rows_affected();
    Ok(written == 1)
}

/// A unique-index violation as the rule it breaks; any other error as it is.
fn conflict(error: sqlx::Error) -> StoreError {
    let constraint = match &error {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
            db.constraint().map(str::to_owned)
        }
        _ => return StoreError::Database(error),
    };
    StoreError::Conflict(match constraint.as_deref() {
        Some("installations_origin") => "another installation has this origin",
        Some("installations_host" | "installations_bare_host") => {
            "another installation of the kind answers to this host"
        }
        Some("installation_keys_pkey" | "installation_keys_public_key_key") => {
            "this key is, or was, another key in the registry"
        }
        _ => "the write conflicts with an existing entry",
    })
}

/// The installation in `row` ([`records_where`]) as a record with its keys in use.
fn record(row: &PgRow) -> Result<InstallationRecord, sqlx::Error> {
    let keys: Vec<Vec<u8>> = row.try_get("keys")?;
    Ok(InstallationRecord {
        id: row.try_get("id")?,
        kind: row.try_get("kind")?,
        origin: row.try_get("origin")?,
        keys: keys.iter().map(|key| key_text(key)).collect(),
        api_url: row.try_get("api_url")?,
        tenant: row.try_get("tenant")?,
        enabled: row.try_get("enabled")?,
        login_per_minute: row
            .try_get::<Option<i64>, _>("login_per_minute")?
            .and_then(|rate| u64::try_from(rate).ok()),
    })
}

/// `rows` as changes up to `version`: removed installations as `None`.
fn changes(rows: &[PgRow], version: i64) -> Result<Changes, StoreError> {
    let mut changes = Vec::with_capacity(rows.len());
    for row in rows {
        let installation = record(row)?;
        let removed: bool = row.try_get("removed")?;
        changes.push((installation.id.clone(), (!removed).then_some(installation)));
    }
    Ok((version, changes))
}

/// `key` as the registry writes keys, `ed25519:<base64url>`.
fn key_text(key: &[u8]) -> String {
    format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(key))
}
