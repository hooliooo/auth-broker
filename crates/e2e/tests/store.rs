//! End-to-end tests for installations kept in the registry store: provisioning automation writing
//! them through the hub's admin API with a Keycloak service account's token, installations
//! enrolling and revoking their own keys, and the hub and the kind's edge following each change.
//! Against the local cluster.
//!
//! dev/k8s/up.sh
//! cargo test -p e2e --features e2e

#![cfg(feature = "e2e")]

mod support;

use common::signing::{EdgeSigner, generate_key};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use support::*;

/// The admin API's answer to `method` on `path` with `body`, as status and JSON.
async fn admin(
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = admin_request(method, path, token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// A new Ed25519 key, as a desktop app keeps it, and its public half for the registry.
fn new_key() -> (String, String) {
    let key = generate_key().unwrap();
    let public = EdgeSigner::from_base64("new", &key).unwrap().public_key();
    (key, public)
}

#[tokio::test]
async fn given_a_provisioned_web_installation_then_its_kinds_edge_and_the_hub_serve_it_until_it_is_retired_and_removed()
 {
    wait_for_stack().await;
    let token = provisioner_token().await;
    let id = unique_label("plant-z");
    let host = format!("{id}.inspection.broker.localhost");
    let browser = client_for_host(&host);
    let login = || async {
        browser
            .get(format!("https://{host}/auth/login"))
            .send()
            .await
            .unwrap()
            .status()
    };
    assert_eq!(
        login().await,
        StatusCode::NOT_FOUND,
        "not an installation yet"
    );

    let mut installation = json!({
        "kind": "inspection", "origin": format!("https://{host}"), "tenant": "customer-z",
        "apiUrl": "http://api-inspection:8081"
    });
    let path = format!("/admin/installations/{id}");
    assert_eq!(
        admin(&token, Method::PUT, &path, Some(installation.clone()))
            .await
            .0,
        StatusCode::OK
    );
    assert!(
        eventually(10, || async { login().await == StatusCode::SEE_OTHER }).await,
        "the kind's edge serves it, without a restart or a file change"
    );
    assert_eq!(
        hub_login_status(&id).await,
        StatusCode::SEE_OTHER,
        "and the hub signs it in"
    );

    installation["enabled"] = json!(false);
    assert_eq!(
        admin(&token, Method::PUT, &path, Some(installation.clone()))
            .await
            .0,
        StatusCode::OK
    );
    assert!(
        eventually(10, || async { login().await == StatusCode::NOT_FOUND }).await,
        "retired at the edge"
    );
    assert_eq!(
        hub_login_status(&id).await,
        StatusCode::BAD_REQUEST,
        "and at the hub"
    );

    assert_eq!(
        admin(&token, Method::DELETE, &path, None).await.0,
        StatusCode::OK
    );
    let (status, stored) = admin(&token, Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stored["removed"], true);
    installation["enabled"] = json!(true);
    assert_eq!(
        admin(&token, Method::PUT, &path, Some(installation))
            .await
            .0,
        StatusCode::CONFLICT,
        "a removed installation's id never returns"
    );
}

#[tokio::test]
async fn given_a_provisioned_native_installation_then_its_workstations_enroll_and_revoke_their_own_keys()
 {
    wait_for_stack().await;
    let token = provisioner_token().await;
    let id = unique_label("desk");
    let path = format!("/admin/installations/{id}");
    let installation =
        json!({ "kind": "planner", "tenant": "customer-x", "apiUrl": "http://localhost:8185" });
    assert_eq!(
        admin(&token, Method::PUT, &path, Some(installation))
            .await
            .0,
        StatusCode::OK
    );

    // Provisioning gives the installation its first key...
    let (first_key, first_public) = new_key();
    let (status, enrolled) = admin(
        &token,
        Method::POST,
        &format!("{path}/keys"),
        Some(json!({ "publicKey": first_public })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = installation_with(&id, &first_key);
    assert_eq!(enrolled["keyId"], first.key_id());

    // ...with which, once the hub has followed the store, a workstation enrolls a second itself...
    let (second_key, second_public) = new_key();
    let mut second_id = None;
    for _ in 0..20 {
        if let Ok(key_id) = first.enroll(&second_public).await {
            second_id = Some(key_id);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let second = installation_with(&id, &second_key);
    assert_eq!(second_id.as_deref(), Some(second.key_id().as_str()));

    // ...which signs for the installation in turn, and retires the first workstation.
    let (_, third_public) = new_key();
    assert!(
        eventually(10, || async { second.enroll(&third_public).await.is_ok() }).await,
        "the second key speaks for the installation"
    );
    second.revoke_key(&first.key_id()).await.unwrap();
    let (_, fourth_public) = new_key();
    assert!(
        eventually(10, || async {
            matches!(
                first.enroll(&fourth_public).await,
                Err(native_app::Error::Refused(StatusCode::UNAUTHORIZED))
            )
        })
        .await,
        "a revoked key is refused everywhere"
    );

    let (_, stored) = admin(&token, Method::GET, &path, None).await;
    let keys = stored["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
    assert_eq!(keys.iter().filter(|k| k["revoked"] == true).count(), 1);
    assert_eq!(
        stored["installation"]["keys"].as_array().unwrap().len(),
        2,
        "in use"
    );
}

#[tokio::test]
async fn given_admin_requests_without_a_valid_token_or_breaking_the_rules_then_the_hub_refuses_them()
 {
    wait_for_stack().await;
    let probe = format!("/admin/installations/{}", unique_label("probe"));
    let body = json!({ "kind": "planner", "tenant": "t", "apiUrl": "http://localhost:8185" });
    for token in ["", "not-a-token"] {
        assert_eq!(
            admin(token, Method::PUT, &probe, Some(body.clone()))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    let token = provisioner_token().await;
    let refusals = [
        (
            json!({ "kind": "unknown", "tenant": "t" }),
            StatusCode::BAD_REQUEST,
            "an unknown kind",
        ),
        (
            json!({ "kind": "billing", "tenant": "t" }),
            StatusCode::BAD_REQUEST,
            "native, in a kind without native settings",
        ),
        (
            json!({ "kind": "planner", "origin": "https://x.planner.example", "tenant": "t", "apiUrl": "http://localhost:8185" }),
            StatusCode::BAD_REQUEST,
            "web, in a kind without an edge",
        ),
        (
            json!({ "kind": "inspection", "origin": PLANT_A, "tenant": "t", "apiUrl": "http://api-inspection:8081" }),
            StatusCode::CONFLICT,
            "another installation's origin",
        ),
        (
            json!({ "kind": "planner", "tenant": "t", "extra": 1 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "an unknown field",
        ),
    ];
    for (body, status, why) in refusals {
        assert_eq!(
            admin(&token, Method::PUT, &probe, Some(body)).await.0,
            status,
            "{why}"
        );
    }
    assert_eq!(
        admin(&token, Method::PUT, "/admin/installations/plant-a", Some(json!({ "kind": "inspection", "tenant": "customer1", "apiUrl": "http://api-inspection:8081" })))
            .await
            .0,
        StatusCode::CONFLICT,
        "a web-app installation cannot turn native"
    );

    // Keys: well formed, never a kind's edge key, never for a web-app installation.
    assert_eq!(
        admin(&token, Method::PUT, &probe, Some(body)).await.0,
        StatusCode::OK
    );
    let keys = format!("{probe}/keys");
    let edge_key = edge_signer("inspection").public_key();
    for (public_key, status, why) in [
        (
            "ed25519:short".to_owned(),
            StatusCode::BAD_REQUEST,
            "malformed",
        ),
        (edge_key, StatusCode::CONFLICT, "a kind's edge key"),
    ] {
        assert_eq!(
            admin(
                &token,
                Method::POST,
                &keys,
                Some(json!({ "publicKey": public_key }))
            )
            .await
            .0,
            status,
            "{why}"
        );
    }
    let (_, public) = new_key();
    assert_eq!(
        admin(
            &token,
            Method::POST,
            "/admin/installations/plant-a/keys",
            Some(json!({ "publicKey": public }))
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "a web-app installation has no keys of its own"
    );
}
