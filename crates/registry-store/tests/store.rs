//! The store against a real Postgres. Each test gets its own database.
//!
//! docker run -d --rm --name registry-store-test -e POSTGRES_PASSWORD=test \
//!   -p 127.0.0.1:55432:5432 postgres:18-alpine
//! REGISTRY_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432 \
//!   cargo test -p registry-store -- --ignored

use registry_store::{InstallationWrite, Store, StoreError};
use sqlx::Connection;

/// A store in a new, empty database named after `test`.
async fn store(test: &str) -> Store {
    let base = std::env::var("REGISTRY_TEST_DATABASE_URL")
        .expect("REGISTRY_TEST_DATABASE_URL names a Postgres server");
    let mut admin = sqlx::PgConnection::connect(&format!("{base}/postgres"))
        .await
        .unwrap();
    for statement in [
        format!("drop database if exists {test}"),
        format!("create database {test}"),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
            .execute(&mut admin)
            .await
            .unwrap();
    }
    let store = Store::connect(&format!("{base}/{test}")).await.unwrap();
    store.migrate().await.unwrap();
    store.migrate().await.expect("migrating twice is harmless");
    store
}

/// A web-app installation of `kind` at host `host`.
fn web(id: &str, kind: &str, host: &str) -> InstallationWrite {
    InstallationWrite {
        id: id.into(),
        kind: kind.into(),
        tenant: "t".into(),
        enabled: true,
        origin: Some(format!("https://{host}")),
        host: Some(format!("{host}:443")),
        bare_host: Some(host.into()),
        api_url: Some("https://api.example".into()),
        login_per_minute: None,
    }
}

/// A native installation of `kind`.
fn native(id: &str, kind: &str) -> InstallationWrite {
    InstallationWrite {
        origin: None,
        host: None,
        bare_host: None,
        ..web(id, kind, "unused")
    }
}

fn conflict(result: Result<i64, StoreError>) -> &'static str {
    match result {
        Err(StoreError::Conflict(why)) => why,
        other => panic!("expected a conflict, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs Postgres: REGISTRY_TEST_DATABASE_URL"]
async fn given_writes_then_versions_rise_and_readers_catch_up_with_only_the_changes() {
    let store = store("versions").await;
    assert_eq!(store.load_all().await.unwrap(), (0, vec![]));
    let v1 = store
        .put_installation(&web("plant-a", "inspection", "plant-a.example"))
        .await
        .unwrap();
    let v2 = store
        .put_installation(&native("plant-i", "inspection"))
        .await
        .unwrap();
    let v3 = store
        .add_key("plant-i", &[1; 32], "key-1", 10, None, "test")
        .await
        .unwrap();
    assert!(v1 < v2 && v2 < v3);

    let (version, all) = store.load_all().await.unwrap();
    assert_eq!(version, v3);
    assert_eq!(all.len(), 2);
    let plant_i = all.iter().find(|r| r.id == "plant-i").unwrap();
    assert_eq!(plant_i.keys.len(), 1);

    // A reader at v2 sees only plant-i, which changed through its key.
    let (version, changes) = store.changes_since(v2).await.unwrap();
    assert_eq!(version, v3);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].0, "plant-i");
    assert_eq!(
        store.changes_since(v3).await.unwrap(),
        (v3, vec![]),
        "nothing new"
    );

    // Revoking the key and removing plant-a reach readers as changes too.
    let v4 = store.revoke_key("plant-i", "key-1", None).await.unwrap();
    let v5 = store.remove_installation("plant-a").await.unwrap();
    let (version, changes) = store.changes_since(v3).await.unwrap();
    assert_eq!(version, v5);
    let plant_i = changes
        .iter()
        .find(|(id, _)| id == "plant-i")
        .unwrap()
        .1
        .as_ref()
        .unwrap();
    assert!(plant_i.keys.is_empty(), "revoked at {v4}");
    assert!(
        changes
            .iter()
            .any(|(id, record)| id == "plant-a" && record.is_none()),
        "removed"
    );
}

#[tokio::test]
#[ignore = "needs Postgres: REGISTRY_TEST_DATABASE_URL"]
async fn given_writes_that_break_the_rules_then_the_store_refuses_them() {
    let store = store("rules").await;
    store
        .put_installation(&web("plant-a", "inspection", "plant-a.example"))
        .await
        .unwrap();
    store
        .put_installation(&native("plant-i", "inspection"))
        .await
        .unwrap();
    store
        .put_installation(&native("plant-j", "inspection"))
        .await
        .unwrap();

    // Same origin; same host in the kind (another scheme); kind or access type changing.
    let mut same_host = web("plant-b", "inspection", "plant-a.example");
    same_host.origin = Some("http://plant-a.example:443".into());
    same_host.bare_host = None;
    assert_eq!(
        conflict(
            store
                .put_installation(&web("plant-b", "billing", "plant-a.example"))
                .await
        ),
        "another installation has this origin"
    );
    assert_eq!(
        conflict(store.put_installation(&same_host).await),
        "another installation of the kind answers to this host"
    );
    assert!(
        store
            .put_installation(&web("plant-b", "billing", "plant-b.example"))
            .await
            .is_ok(),
        "another kind, another host"
    );
    assert!(
        conflict(
            store
                .put_installation(&web("plant-a", "billing", "plant-a.example"))
                .await
        )
        .contains("kind or access type")
    );
    assert!(
        conflict(
            store
                .put_installation(&native("plant-a", "inspection"))
                .await
        )
        .contains("kind or access type")
    );

    // Keys: only for native installations, unique for ever, bounded per installation.
    assert_eq!(
        conflict(
            store
                .add_key("plant-a", &[1; 32], "k1", 10, None, "test")
                .await
        ),
        "a web-app installation has no keys of its own"
    );
    store
        .add_key("plant-i", &[1; 32], "k1", 10, None, "test")
        .await
        .unwrap();
    assert_eq!(
        conflict(
            store
                .add_key("plant-j", &[1; 32], "k1-again", 10, None, "test")
                .await
        ),
        "this key is, or was, another key in the registry"
    );
    store.revoke_key("plant-i", "k1", None).await.unwrap();
    assert!(
        store
            .add_key("plant-i", &[1; 32], "k1", 10, None, "test")
            .await
            .is_err(),
        "a revoked key never returns"
    );
    store
        .add_key("plant-i", &[2; 32], "k2", 1, None, "test")
        .await
        .unwrap();
    assert_eq!(
        conflict(
            store
                .add_key("plant-i", &[3; 32], "k3", 1, None, "test")
                .await
        ),
        "the installation holds its most keys"
    );
    assert!(matches!(
        store
            .add_key("plant-z", &[4; 32], "k4", 10, None, "test")
            .await,
        Err(StoreError::NotFound)
    ));

    // A removed installation's id is never reused; its origin may be.
    store.remove_installation("plant-a").await.unwrap();
    assert!(
        conflict(
            store
                .put_installation(&web("plant-a", "inspection", "plant-a.example"))
                .await
        )
        .contains("removed")
    );
    store
        .put_installation(&web("plant-a2", "inspection", "plant-a.example"))
        .await
        .unwrap();
    assert!(matches!(
        store.remove_installation("plant-a").await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
#[ignore = "needs Postgres: REGISTRY_TEST_DATABASE_URL"]
async fn given_an_edge_then_it_gets_only_its_kinds_web_installations() {
    let store = store("edges").await;
    let v1 = store
        .put_installation(&web("plant-a", "inspection", "plant-a.example"))
        .await
        .unwrap();
    store
        .put_installation(&web("plant-c", "billing", "plant-c.example"))
        .await
        .unwrap();
    store
        .put_installation(&native("plant-i", "inspection"))
        .await
        .unwrap();
    let (_, all) = store.web_installations("inspection", 0).await.unwrap();
    let ids: Vec<&str> = all.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["plant-a"]);

    let mut retired = web("plant-a", "inspection", "plant-a.example");
    retired.enabled = false;
    store.put_installation(&retired).await.unwrap();
    store
        .put_installation(&web("plant-b", "inspection", "plant-b.example"))
        .await
        .unwrap();
    let (_, changes) = store.web_installations("inspection", v1).await.unwrap();
    assert_eq!(changes.len(), 2);
    assert!(
        !changes
            .iter()
            .find(|(id, _)| id == "plant-a")
            .unwrap()
            .1
            .as_ref()
            .unwrap()
            .enabled
    );

    let (_, before_removal) = store.web_installations("inspection", 0).await.unwrap();
    let removed_at = store.remove_installation("plant-b").await.unwrap();
    let (version, after) = store
        .web_installations("inspection", removed_at - 1)
        .await
        .unwrap();
    assert_eq!(version, removed_at);
    assert_eq!(after, vec![("plant-b".to_owned(), None)]);
    let (_, full) = store.web_installations("inspection", 0).await.unwrap();
    assert_eq!(
        full.len(),
        before_removal.len() - 1,
        "a full read leaves removed ones out"
    );
}

#[tokio::test]
#[ignore = "needs Postgres: REGISTRY_TEST_DATABASE_URL"]
async fn given_a_revoked_signer_then_it_can_no_longer_change_the_installations_keys() {
    let store = store("signers").await;
    store
        .put_installation(&native("plant-i", "inspection"))
        .await
        .unwrap();
    store
        .add_key("plant-i", &[1; 32], "k1", 10, None, "test")
        .await
        .unwrap();
    store
        .add_key("plant-i", &[2; 32], "k2", 10, Some("k1"), "test")
        .await
        .unwrap();
    store.revoke_key("plant-i", "k1", Some("k2")).await.unwrap();
    assert!(matches!(
        store
            .add_key("plant-i", &[3; 32], "k3", 10, Some("k1"), "test")
            .await,
        Err(StoreError::SignerRevoked)
    ));
    assert!(matches!(
        store.revoke_key("plant-i", "k2", Some("k1")).await,
        Err(StoreError::SignerRevoked)
    ));
    assert!(
        matches!(
            store
                .add_key("plant-j", &[3; 32], "k3", 10, Some("k2"), "test")
                .await,
            Err(StoreError::SignerRevoked | StoreError::NotFound)
        ),
        "a key speaks only for its own installation"
    );
}

#[tokio::test]
#[ignore = "needs Postgres: REGISTRY_TEST_DATABASE_URL"]
async fn given_an_installation_then_its_stored_form_shows_every_key() {
    let store = store("stored").await;
    store
        .put_installation(&native("plant-i", "inspection"))
        .await
        .unwrap();
    store
        .add_key("plant-i", &[1; 32], "k1", 10, None, "test")
        .await
        .unwrap();
    store
        .add_key("plant-i", &[2; 32], "k2", 10, None, "test")
        .await
        .unwrap();
    store.revoke_key("plant-i", "k1", None).await.unwrap();
    let stored = store.installation("plant-i").await.unwrap();
    assert_eq!(stored.installation.keys.len(), 1, "in use");
    assert_eq!(stored.keys.len(), 2, "with the revoked one");
    assert!(stored.keys.iter().any(|k| k.key_id == "k1" && k.revoked));
    assert!(!stored.removed);
    assert!(matches!(
        store.installation("plant-z").await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
#[ignore = "needs Postgres: REGISTRY_TEST_DATABASE_URL"]
async fn given_concurrent_writers_then_a_follower_never_misses_one() {
    let store = store("ordering").await;
    let writers: Vec<_> = (0..40)
        .map(|n| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .put_installation(&native(&format!("plant-{n}"), "inspection"))
                    .await
            })
        })
        .collect();
    // A follower polling while the writers race sees each installation exactly when its version
    // is covered, never skipping one that commits late.
    let mut seen = std::collections::HashSet::new();
    let mut since = 0;
    for _ in 0..200 {
        let (version, changes) = store.changes_since(since).await.unwrap();
        seen.extend(changes.into_iter().map(|(id, _)| id));
        since = version;
        if seen.len() == 40 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    for writer in writers {
        writer.await.unwrap().unwrap();
    }
    let (version, changes) = store.changes_since(since).await.unwrap();
    seen.extend(changes.into_iter().map(|(id, _)| id));
    assert_eq!(version, 40);
    assert_eq!(seen.len(), 40);
}
