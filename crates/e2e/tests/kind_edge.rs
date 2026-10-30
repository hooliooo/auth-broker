//! End-to-end tests for one edge per app kind: one edge serves every site of its kind, each
//! under its own host, and signs for each with the kind's one key. Against the local cluster.
//!
//! dev/k8s/up.sh
//! cargo test -p e2e --features e2e

#![cfg(feature = "e2e")]

mod support;

use reqwest::{Method, StatusCode, Url};
use serde_json::Value;
use support::*;

/// The response body as JSON.
async fn json(response: reqwest::Response) -> Value {
    response.json().await.unwrap()
}

/// Signs `user` in at `site` in `browser`; returns the session handle.
async fn sign_in_at(browser: &mut Browser, site: &str, user: &str) -> String {
    let handoff = sign_in(browser, site, user).await;
    assert_eq!(
        handoff.status(),
        StatusCode::SEE_OTHER,
        "edge finishes sign-in at {site}"
    );
    assert!(
        location(&handoff).query().is_none(),
        "no login error at {site}: {}",
        location(&handoff)
    );
    browser.cookie(site, SESSION).expect("session cookie set")
}

/// `GET /auth/session` at `site` with session `handle`, sent with that site's host.
async fn session_at(site: &str, handle: &str) -> reqwest::Response {
    client()
        .get(format!("{site}/auth/session"))
        .header("cookie", format!("{SESSION}={handle}"))
        .header(common::csrf::CSRF_HEADER, "1")
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn given_one_edge_for_two_sites_when_signing_in_at_each_then_each_has_its_own_session() {
    wait_for_stack().await;
    let mut browser = Browser::new();
    let user = fresh_user();
    let handle_a = sign_in_at(&mut browser, PLANT_A, &user).await;
    // The same browser, the same edge process: Keycloak's single sign-on takes it straight
    // through, but plant-b gets a session of its own under its own host.
    let handle_b = sign_in_at(&mut browser, PLANT_B, &user).await;
    assert_ne!(handle_a, handle_b);
    assert_eq!(
        browser.cookie(PLANT_A, SESSION).as_deref(),
        Some(handle_a.as_str()),
        "plant-b's sign-in left plant-a's cookie alone"
    );

    for (site, handle, id) in [
        (PLANT_A, &handle_a, "plant-a"),
        (PLANT_B, &handle_b, "plant-b"),
    ] {
        let response = browser.get(&format!("{site}/auth/session")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["site"], id, "the edge resolved {site} to {id}");
        assert_eq!(read_session(handle).await.unwrap()["site_id"], id);
    }
}

#[tokio::test]
async fn given_a_sessions_handle_when_presented_under_another_sites_host_then_it_is_refused() {
    wait_for_stack().await;
    let mut browser = Browser::new();
    let handle_a = sign_in_at(&mut browser, PLANT_A, &fresh_user()).await;

    assert_eq!(
        session_at(PLANT_A, &handle_a).await.status(),
        StatusCode::OK
    );
    // plant-b is served by the same edge with the same key; the hub still holds the session
    // for plant-a only.
    assert_eq!(
        session_at(PLANT_B, &handle_a).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn given_a_host_the_edge_does_not_serve_then_it_answers_not_found() {
    wait_for_stack().await;
    let http = client();
    for site in [PLANT_UNKNOWN, PLANT_RETIRED] {
        for path in ["/auth/login", "/auth/session", "/api/x"] {
            // With the header the app sends: the host decides, not the CSRF check.
            let status = http
                .get(format!("{site}{path}"))
                .header(common::csrf::CSRF_HEADER, "1")
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(status, StatusCode::NOT_FOUND, "{site}{path}");
        }
    }
    // Another kind's site sent to this kind's edge: the billing site's name under the inspection
    // kind's domain, which the ingress sends to the inspection edge.
    let status = http
        .get("https://plant-c.inspection.broker.localhost/auth/login")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn given_a_sign_in_at_one_of_the_edges_sites_then_the_hub_hands_off_to_that_sites_host() {
    wait_for_stack().await;
    let mut browser = Browser::new();
    let login = browser.get(&login_url(PLANT_B, "/orders")).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let to_hub = location(&login);
    assert_eq!(
        to_hub
            .query_pairs()
            .find(|(k, _)| k == "site")
            .map(|(_, v)| v.into_owned()),
        Some("plant-b".to_owned()),
        "the edge names the site the browser came to"
    );

    let mut browser = Browser::new();
    let handoff = sign_in_until_handoff(&mut browser, PLANT_B, &fresh_user()).await;
    assert_eq!(
        handoff.origin(),
        Url::parse(PLANT_B).unwrap().origin(),
        "back to plant-b, not to the edge's other sites"
    );
}

#[tokio::test]
async fn given_one_kinds_edge_key_when_signing_for_another_kinds_site_then_the_hub_refuses() {
    wait_for_stack().await;
    let mut browser = Browser::new();
    let handle_d = sign_in_at(&mut browser, PLANT_D, &fresh_member_of_both()).await;

    let as_own_kind = signer("plant-d")
        .sign("GET", "/broker/session", Some(&handle_d), now())
        .unwrap();
    let response = hub_request(
        Method::GET,
        "/broker/session",
        &as_own_kind,
        Some(&handle_d),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the maintenance edge's key works"
    );

    // The inspection edge's key, claiming to speak for a maintenance site.
    let forged = signer_as("inspection", "plant-d")
        .sign("GET", "/broker/session", Some(&handle_d), now())
        .unwrap();
    let response = hub_request(Method::GET, "/broker/session", &forged, Some(&handle_d))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let forged = signer_as("maintenance", "plant-a")
        .sign("POST", "/broker/redeem", None, now())
        .unwrap();
    let response = hub_request(Method::POST, "/broker/redeem", &forged, None)
        .json(&serde_json::json!({ "code": "x", "code_verifier": "y" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The installations `echo`'s token names.
fn named_sites(echo: &Value) -> Vec<String> {
    match &echo["bearer"]["claims"]["organization"] {
        Value::Object(by_alias) => by_alias.keys().cloned().collect(),
        Value::Array(aliases) => aliases
            .iter()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

#[tokio::test]
async fn given_a_kind_with_one_central_api_then_its_edge_sends_each_sites_calls_with_that_sites_token()
 {
    wait_for_stack().await;
    let user = fresh_user();
    let mut browser = Browser::new();
    sign_in_at(&mut browser, PLANT_A, &user).await;
    sign_in_at(&mut browser, PLANT_B, &user).await;

    // Both sites' api_url is the one inspection API; the token tells it which site is calling.
    for (site, id) in [(PLANT_A, "plant-a"), (PLANT_B, "plant-b")] {
        let response = browser.get(&format!("{site}/api/reports")).await;
        assert_eq!(response.status(), StatusCode::OK, "{site}");
        let echo = json(response).await;
        assert_eq!(echo["bearer"]["claims"]["azp"], "hub-inspection");
        assert_eq!(
            named_sites(&echo),
            [id],
            "{site}'s call carried a token for {id}"
        );
        assert!(
            echo["headers"].get("x-site-id").is_none(),
            "no hub headers: the hub was not in the path"
        );
    }
}

#[tokio::test]
async fn given_a_direct_kind_then_its_one_edge_calls_each_sites_own_api_with_that_sites_token() {
    wait_for_stack().await;
    let user = fresh_member_of_both();
    let mut browser = Browser::new();
    sign_in_at(&mut browser, PLANT_D, &user).await;
    sign_in_at(&mut browser, PLANT_E, &user).await;

    for (site, id) in [(PLANT_D, "plant-d"), (PLANT_E, "plant-e")] {
        let response = browser.get(&format!("{site}/api/orders")).await;
        assert_eq!(response.status(), StatusCode::OK, "{site}");
        let echo = json(response).await;
        // Each API accepts only tokens naming its own site, so a 200 already proves the routing;
        // the claims show it.
        assert_eq!(
            named_sites(&echo),
            [id],
            "{site}'s API got a token for {id}"
        );
    }
}
