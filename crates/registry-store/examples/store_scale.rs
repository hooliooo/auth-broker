//! Measures the registry store at scale: a hub's first load of a million installations (half
//! web-app, half native with two keys each) from Postgres, following when nothing changed,
//! writing and applying batches of changes, compacting, and an edge's full fetch. Fills the
//! database it is given, which must be empty:
//!
//! docker run -d --rm --name registry-scale -e POSTGRES_PASSWORD=test \
//!   -p 127.0.0.1:55433:5432 postgres:18-alpine
//! REGISTRY_SCALE_DATABASE_URL=postgres://postgres:test@127.0.0.1:55433/postgres \
//!   cargo run --release -p registry-store --example store_scale [-- <installations>]

use std::time::Instant;

use common::{alloc, registry::Registry};
use registry_store::Store;

#[global_allocator]
static ALLOCATOR: alloc::Counting = alloc::Counting;

fn mb(bytes: u64) -> String {
    format!("{:.0} MB", bytes as f64 / 1e6)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("REGISTRY_SCALE_DATABASE_URL")?;
    let n: i64 = std::env::args()
        .nth(1)
        .map_or(Ok(1_000_000), |a| a.parse())?;
    let half = n / 2;
    let store = Store::connect(&url).await?;
    store.migrate().await?;

    // Filled in Postgres itself; key ids as the registry derives them.
    let started = Instant::now();
    let pool = sqlx::PgPool::connect(&url).await?;
    for statement in [
        format!("insert into installations (id, kind, tenant, enabled, origin, host, bare_host, api_url, version)
         select 'web-' || i, 'inspection', 't', true, 'https://web-' || i || '.inspection.example',
                'web-' || i || '.inspection.example:443', 'web-' || i || '.inspection.example',
                'https://api.example', 1 from generate_series(0, {half} - 1) i"),
        format!("insert into installations (id, kind, tenant, enabled, api_url, version)
         select 'inst-' || i, 'planner', 't', true, 'https://api.example', 1
         from generate_series(0, {half} - 1) i"),
        format!("insert into installation_keys (key_id, public_key, installation_id, version)
         select substr(translate(encode(sha256(k), 'base64'), '+/', '-_'), 1, 16), k, id, 1
         from (select 'inst-' || i as id, sha256(('a' || i)::bytea) as k from generate_series(0, {half} - 1) i
               union all
               select 'inst-' || i, sha256(('b' || i)::bytea) from generate_series(0, {half} - 1) i) keys"),
        "update registry_head set version = 1".to_owned(),
        "analyze".to_owned(),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement)).execute(&pool).await?;
    }
    println!(
        "filled {n} installations and {} keys in {:?}",
        half * 2,
        started.elapsed()
    );

    let kinds = Registry::kinds_from_documents([
        (
            "inspection.json",
            r#"{ "app": { "id": "inspection", "client_id": "hub-inspection",
            "edge_public_key": "ed25519:CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk", "api_audience": "i" } }"#,
        ),
        (
            "planner.json",
            r#"{ "app": { "id": "planner", "client_id": "hub-planner", "native": {},
            "api_audience": "p" } }"#,
        ),
    ])?;

    // A hub's first load.
    let before = alloc::snapshot();
    let started = Instant::now();
    let (version, records) = store.load_all().await?;
    let fetched = started.elapsed();
    let (registry, rejected) = kinds.with_installations(records);
    let loaded = started.elapsed();
    let held = alloc::snapshot().live_bytes - before.live_bytes;
    let peak = alloc::snapshot().peak_live_bytes - before.live_bytes;
    assert!(
        rejected.is_empty(),
        "{:?}",
        &rejected[..rejected.len().min(3)]
    );
    println!(
        "first load: {} installations in {loaded:?} (query and transfer {fetched:?}), holding {}, peak {}",
        registry.site_count(),
        mb(held),
        mb(peak)
    );

    // Following when nothing changed.
    let started = Instant::now();
    for _ in 0..200 {
        store.changes_since(version).await?;
    }
    println!(
        "follow, nothing changed: {:?} per poll",
        started.elapsed() / 200
    );

    // Batches of key enrollments: written one transaction each, then followed and applied.
    let mut registry = registry;
    let mut since = version;
    let mut serial = 0u32;
    for batch in [1u32, 100, 10_000] {
        let started = Instant::now();
        for _ in 0..batch {
            let mut key = [7u8; 32];
            key[..4].copy_from_slice(&serial.to_be_bytes());
            let id = common::registry::key_id(&key);
            store
                .add_key(
                    &format!("inst-{}", serial % half as u32),
                    &key,
                    &id,
                    10_000,
                    None,
                )
                .await?;
            serial += 1;
        }
        let written = started.elapsed();
        let started = Instant::now();
        let (next, changes) = store.changes_since(since).await?;
        let followed = started.elapsed();
        let count = changes.len();
        let started = Instant::now();
        let (changed, rejected) = registry.with_changes(changes);
        let applied = started.elapsed();
        assert!(rejected.is_empty());
        registry = changed;
        since = next;
        println!(
            "{batch} changes: written in {written:?} ({:?} each), fetched in {followed:?}, applied in {applied:?} ({count} installations)",
            written / batch
        );
    }

    let started = Instant::now();
    let compacted = registry.compacted();
    println!(
        "compaction of {} installations: {:?}",
        compacted.site_count(),
        started.elapsed()
    );

    // An edge's full fetch of its kind, as the hub reads it for /broker/registry.
    let started = Instant::now();
    let (_, web) = store.web_installations("inspection", 0).await?;
    let fetched = started.elapsed();
    let json = serde_json::to_vec(&web)?.len() as u64;
    println!(
        "edge full fetch: {} web-app installations in {fetched:?}, {} as JSON",
        web.len(),
        mb(json)
    );
    let started = Instant::now();
    for _ in 0..200 {
        store.web_installations("inspection", since).await?;
    }
    println!(
        "edge follow, nothing changed: {:?} per poll",
        started.elapsed() / 200
    );
    Ok(())
}
