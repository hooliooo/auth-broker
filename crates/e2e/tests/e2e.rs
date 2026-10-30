//! End-to-end tests for the auth broker against the local cluster.
//!
//! dev/k8s/up.sh
//! cargo test -p e2e --features e2e

#![cfg(feature = "e2e")]

mod support;

use std::time::Duration;

use reqwest::{Method, StatusCode, Url};
use serde_json::Value;
use support::*;

async fn json(response: reqwest::Response) -> Value {
    response.json().await.unwrap()
}

fn audiences(echo: &Value) -> Vec<String> {
    match &echo["bearer"]["claims"]["aud"] {
        Value::String(aud) => vec![aud.clone()],
        Value::Array(auds) => auds
            .iter()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

/// Signs in a fresh user at `site`; returns the browser, the session handle and the user.
async fn signed_in(site: &str) -> (Browser, String, String) {
    let user = fresh_user();
    let mut browser = Browser::new();
    let handoff = sign_in(&mut browser, site, &user).await;
    assert_eq!(
        handoff.status(),
        StatusCode::SEE_OTHER,
        "edge finishes sign-in"
    );
    let handle = browser.cookie(site, SESSION).expect("session cookie set");
    (browser, handle, user)
}

#[tokio::test]
async fn given_the_stack_when_probed_then_the_hub_and_every_edge_are_ready() {
    wait_for_stack().await;
    let http = client();
    for base in [HUB, PLANT_A, PLANT_B, PLANT_C] {
        assert_eq!(
            http.get(format!("{base}/health"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            http.get(format!("{base}/health/ready"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn given_a_login_at_a_site_when_started_then_the_edge_hands_off_to_the_hub_and_the_hub_to_keycloak()
 {
    wait_for_stack().await;
    let mut browser = Browser::new();

    let login = browser.get(&login_url(PLANT_A, "/orders")).await;

    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let broker = location(&login);
    assert_eq!(broker.origin().ascii_serialization(), HUB);
    assert_eq!(broker.path(), "/broker/login");
    assert_eq!(query_param(&broker, "site").as_deref(), Some("plant-a"));
    assert_eq!(
        query_param(&broker, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(
        query_param(&broker, "code_challenge").map(|c| c.len()),
        Some(43)
    );
    let cookie = set_cookie_with_prefix(&login, LOGIN)
        .expect("edge login cookie")
        .to_ascii_lowercase();
    for attribute in [
        "httponly",
        "secure",
        "samesite=lax",
        "max-age=300",
        "path=/",
    ] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
    let (state, _verifier, return_to) =
        login_cookie_parts(&browser.cookie_with_prefix(PLANT_A, LOGIN).unwrap());
    assert_eq!(query_param(&broker, "state"), Some(state));
    assert_eq!(return_to, "/orders");

    let to_keycloak = browser.get(broker.as_str()).await;
    assert_eq!(to_keycloak.status(), StatusCode::SEE_OTHER);
    let authorize = location(&to_keycloak);
    assert!(
        authorize.path().ends_with("/protocol/openid-connect/auth"),
        "{authorize}"
    );
    assert_eq!(
        query_param(&authorize, "client_id").as_deref(),
        Some("hub-inspection"),
        "the site's kind's client"
    );
    assert_eq!(
        query_param(&authorize, "redirect_uri").as_deref(),
        Some(format!("{HUB}/auth/callback").as_str()),
        "one callback for every site"
    );
    assert_eq!(
        query_param(&authorize, "code_challenge_method").as_deref(),
        Some("S256")
    );
}

#[tokio::test]
async fn given_unknown_disabled_or_malformed_requests_when_starting_at_the_hub_then_they_are_refused()
 {
    wait_for_stack().await;
    let http = client();
    let challenge = common::pkce::challenge("x".repeat(43).as_str());
    let state = "s".repeat(43);
    for (site, method, challenge) in [
        ("nope", "S256", challenge.as_str()),
        ("plant-retired", "S256", challenge.as_str()),
        ("plant-a", "plain", challenge.as_str()),
        ("plant-a", "S256", "too-short"),
    ] {
        let mut url = Url::parse(&format!("{HUB}/broker/login")).unwrap();
        url.query_pairs_mut()
            .append_pair("site", site)
            .append_pair("state", &state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", method);
        let status = http.get(url).send().await.unwrap().status();
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{site} {method} {challenge}"
        );
    }
}

#[tokio::test]
async fn given_valid_credentials_when_signing_in_then_the_site_gets_its_own_session() {
    wait_for_stack().await;
    let user = fresh_user();
    let mut browser = Browser::new();

    let handoff = sign_in(&mut browser, PLANT_A, &user).await;

    assert_eq!(handoff.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&handoff).as_str(), format!("{PLANT_A}/orders"));
    let session_cookie = set_cookie(&handoff, SESSION).unwrap().to_ascii_lowercase();
    assert!(
        session_cookie.contains("samesite=strict"),
        "{session_cookie}"
    );
    assert!(
        browser.cookie_with_prefix(PLANT_A, LOGIN).is_none(),
        "login cookie cleared"
    );
    assert!(
        browser.cookie_with_prefix(HUB, HUB_LOGIN).is_none(),
        "hub login cookie cleared"
    );

    let me = browser.get(&format!("{PLANT_A}/auth/session")).await;
    assert_eq!(me.status(), StatusCode::OK);
    let me = json(me).await;
    assert_eq!(me["site"], "plant-a");
    assert_eq!(me["tenant"], "customer1");
    assert_eq!(me["preferredUsername"], user.as_str());
}

#[tokio::test]
async fn given_a_session_when_calling_the_api_then_only_the_bearer_and_verified_site_facts_arrive()
{
    wait_for_stack().await;
    // Billing keeps the hub forwarding its API calls: the hub adds the site's verified facts.
    let (mut browser, _, user) = signed_in(PLANT_C).await;

    // The browser tries to impersonate another site and tenant; the edge drops it.
    let forged = [
        ("x-site-id", "plant-b"),
        ("x-tenant", "evil"),
        ("authorization", "Bearer forged"),
    ];
    let response = browser
        .send(
            Method::GET,
            &format!("{PLANT_C}/api/things?x=1"),
            &forged,
            None,
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let echo = json(response).await;
    assert_eq!(echo["path"], "/things", "/api is stripped");
    assert_eq!(echo["query"], "x=1");
    assert_eq!(
        echo["bearer"]["claims"]["azp"], "hub-billing",
        "issued to this kind's client"
    );
    assert!(
        audiences(&echo).contains(&"billing-api".to_owned()),
        "for this kind's API"
    );
    assert_eq!(
        echo["bearer"]["claims"]["preferred_username"],
        user.as_str()
    );
    let headers = &echo["headers"];
    assert_eq!(headers["x-app-id"], "billing");
    assert_eq!(headers["x-site-id"], "plant-c");
    assert_eq!(headers["x-tenant"], "customer1");
    for leaked in [
        "cookie",
        "x-csrf",
        "x-session-handle",
        "x-site-signature",
        "x-site-nonce",
    ] {
        assert!(headers.get(leaked).is_none(), "{leaked} reached the API");
    }

    // Inspection's edge calls its central API itself: no hub headers at all, forged ones
    // dropped, and the site and tenant come from the token, which names plant-a.
    let (mut browser, _, _) = signed_in(PLANT_A).await;
    let response = browser
        .send(
            Method::GET,
            &format!("{PLANT_A}/api/things?x=1"),
            &forged,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let echo = json(response).await;
    assert_eq!(echo["path"], "/things", "/api is stripped");
    let claims = &echo["bearer"]["claims"];
    assert_eq!(claims["azp"], "hub-inspection");
    assert_eq!(
        claims["organization"]["plant-a"]["tenant"],
        serde_json::json!(["customer1"]),
        "the token names the site and its tenant"
    );
    for header in [
        "x-app-id",
        "x-site-id",
        "x-tenant",
        "cookie",
        "x-session-handle",
    ] {
        assert!(
            echo["headers"].get(header).is_none(),
            "{header} reached the API"
        );
    }
}

#[tokio::test]
async fn given_an_api_call_without_the_csrf_header_then_it_is_forbidden_even_a_read() {
    wait_for_stack().await;
    let (mut browser, _, _) = signed_in(PLANT_A).await;
    let url = format!("{PLANT_A}/api/orders");

    // A script on another site of the kind's domain would send the Strict cookie (same site),
    // but could not add the header: reads are refused too (RFC 10017 §6.1.3.3.2).
    for (method, path, body) in [
        (Method::POST, "/api/orders", Some("{}".to_owned())),
        (Method::GET, "/api/orders", None),
        (Method::GET, "/auth/session", None),
    ] {
        let without = browser
            .send_without_csrf(method.clone(), &format!("{PLANT_A}{path}"), &[], body)
            .await;
        assert_eq!(without.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }

    let with = browser
        .send(
            Method::POST,
            &url,
            &[("x-csrf", "1"), ("content-type", "application/json")],
            Some(r#"{"qty":2}"#.into()),
        )
        .await;
    assert_eq!(with.status(), StatusCode::OK);
    let echo = json(with).await;
    assert_eq!(echo["method"], "POST");
    assert_eq!(echo["body_bytes"], 9, "body streamed through both hops");
}

#[tokio::test]
async fn given_a_handle_from_site_a_when_presented_at_site_b_then_it_is_worthless() {
    wait_for_stack().await;
    let (_, handle, _) = signed_in(PLANT_A).await;
    let mut thief = Browser::new();
    thief.set_cookie(PLANT_B, SESSION, &handle);

    assert_eq!(
        thief.get(&format!("{PLANT_B}/auth/session")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        thief.get(&format!("{PLANT_B}/api/things")).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn given_unsigned_or_forged_requests_when_sent_to_the_hub_then_they_are_refused() {
    wait_for_stack().await;
    let (_, handle, _) = signed_in(PLANT_A).await;
    let http = client();

    let unsigned = http
        .get(format!("{HUB}/broker/session"))
        .header("x-session-handle", &handle)
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);

    // Site B's key, claiming to be site A.
    let mut forged = signer("plant-b")
        .sign("GET", "/broker/session", Some(&handle), now())
        .unwrap();
    forged.site_id = "plant-a".into();
    let response = hub_request(Method::GET, "/broker/session", &forged, Some(&handle))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Correct key, but five minutes old.
    let stale = signer("plant-a")
        .sign("GET", "/broker/session", Some(&handle), now() - 300)
        .unwrap();
    let response = hub_request(Method::GET, "/broker/session", &stale, Some(&handle))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A retired site with a perfectly valid signature.
    let retired = signer("plant-retired")
        .sign("GET", "/broker/session", Some(&handle), now())
        .unwrap();
    let response = hub_request(Method::GET, "/broker/session", &retired, Some(&handle))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Signed for a different path than the one requested.
    let other_path = signer("plant-a")
        .sign("GET", "/broker/other", Some(&handle), now())
        .unwrap();
    let response = hub_request(Method::GET, "/broker/session", &other_path, Some(&handle))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_a_valid_signed_request_when_replayed_then_the_second_copy_is_refused() {
    wait_for_stack().await;
    let (_, handle, _) = signed_in(PLANT_A).await;
    let signed = signer("plant-a")
        .sign("GET", "/broker/session", Some(&handle), now())
        .unwrap();

    let first = hub_request(Method::GET, "/broker/session", &signed, Some(&handle))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(json(first).await["site"], "plant-a");

    let replay = hub_request(Method::GET, "/broker/session", &signed, Some(&handle))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_a_handoff_code_when_redeemed_by_another_site_then_it_is_refused() {
    wait_for_stack().await;
    let mut browser = Browser::new();
    let handoff = sign_in_until_handoff(&mut browser, PLANT_A, &fresh_user()).await;
    let code = query_param(&handoff, "code").unwrap();
    let (_, verifier, _) = login_cookie_parts(&browser.cookie_with_prefix(PLANT_A, LOGIN).unwrap());

    let as_plant_b = signer("plant-b")
        .sign("POST", "/broker/redeem", None, now())
        .unwrap();
    let response = hub_request(Method::POST, "/broker/redeem", &as_plant_b, None)
        .json(&serde_json::json!({ "code": code, "code_verifier": verifier }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_a_handoff_code_when_the_verifier_is_wrong_or_it_is_reused_then_it_is_refused() {
    wait_for_stack().await;

    // Wrong PKCE verifier, right site.
    let mut browser = Browser::new();
    let handoff = sign_in_until_handoff(&mut browser, PLANT_A, &fresh_user()).await;
    let code = query_param(&handoff, "code").unwrap();
    let as_plant_a = signer("plant-a")
        .sign("POST", "/broker/redeem", None, now())
        .unwrap();
    let response = hub_request(Method::POST, "/broker/redeem", &as_plant_a, None)
        .json(&serde_json::json!({ "code": code, "code_verifier": "w".repeat(43) }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A completed handoff cannot be replayed: not through the edge, not at the hub.
    let mut browser = Browser::new();
    let handoff = sign_in_until_handoff(&mut browser, PLANT_A, &fresh_user()).await;
    let code = query_param(&handoff, "code").unwrap();
    let (_, verifier, _) = login_cookie_parts(&browser.cookie_with_prefix(PLANT_A, LOGIN).unwrap());
    assert_eq!(
        browser.get(handoff.as_str()).await.status(),
        StatusCode::SEE_OTHER
    );
    let replayed = browser.get(handoff.as_str()).await;
    assert_eq!(location(&replayed).path(), "/", "back to the app");
    assert_eq!(
        query_param(&location(&replayed), "login_error").as_deref(),
        Some("1")
    );
    assert!(
        set_cookie(&replayed, SESSION).is_none(),
        "no session from a replayed handoff"
    );
    let again = signer("plant-a")
        .sign("POST", "/broker/redeem", None, now())
        .unwrap();
    let response = hub_request(Method::POST, "/broker/redeem", &again, None)
        .json(&serde_json::json!({ "code": code, "code_verifier": verifier }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_a_handoff_url_when_opened_in_another_browser_then_the_edge_refuses_it() {
    wait_for_stack().await;
    let mut victim = Browser::new();
    let handoff = sign_in_until_handoff(&mut victim, PLANT_A, &fresh_user()).await;

    let mut other = Browser::new();
    let refused = other.get(handoff.as_str()).await;
    assert_eq!(
        query_param(&location(&refused), "login_error").as_deref(),
        Some("1")
    );
    assert!(other.cookie(PLANT_A, SESSION).is_none());
    // Refused before redeeming, so the real browser still finishes.
    let finished = victim.get(handoff.as_str()).await;
    assert_eq!(location(&finished).as_str(), format!("{PLANT_A}/orders"));
    assert!(victim.cookie(PLANT_A, SESSION).is_some());
}

#[tokio::test]
async fn given_foreign_origin_return_urls_when_starting_sign_in_then_they_become_root() {
    wait_for_stack().await;
    for raw in [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "/\t/evil.com",
    ] {
        let mut browser = Browser::new();
        browser.get(&login_url(PLANT_A, raw)).await;
        let (_, _, return_to) =
            login_cookie_parts(&browser.cookie_with_prefix(PLANT_A, LOGIN).unwrap());
        assert_eq!(return_to, "/", "accepted {raw:?}");
    }
}

#[tokio::test]
async fn given_a_session_when_logging_out_then_it_ends_here_and_at_keycloak_without_the_browser() {
    wait_for_stack().await;
    let (mut browser, handle, user) = signed_in(PLANT_A).await;
    let refresh_token = read_session(&handle).await.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let logout = format!("{PLANT_A}/auth/logout");

    assert_eq!(
        browser
            .send_without_csrf(Method::POST, &logout, &[], None)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "CSRF header required"
    );

    let response = browser.post(&logout, &[("x-csrf", "1")]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        set_cookie(&response, SESSION)
            .unwrap()
            .to_ascii_lowercase()
            .contains("max-age=0")
    );
    // The hub ended Keycloak's session itself, so the browser just goes home: no token in a URL.
    assert_eq!(json(response).await["logoutUrl"], format!("{PLANT_A}/"));

    let mut stale = Browser::new();
    stale.set_cookie(PLANT_A, SESSION, &handle);
    assert_eq!(
        stale.get(&format!("{PLANT_A}/auth/session")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        keycloak_refresh_status("hub-inspection", &refresh_token).await,
        StatusCode::BAD_REQUEST,
        "Keycloak's session is over"
    );
    // Signing in again needs the password: the browser's Keycloak session is gone.
    let login = browser.get(&login_url(PLANT_A, "/")).await;
    let broker = browser.get(location(&login).as_str()).await;
    let page = browser.get(location(&broker).as_str()).await;
    assert_eq!(
        page.status(),
        StatusCode::OK,
        "Keycloak asks {user} for the password again"
    );
}

#[tokio::test]
async fn given_keycloak_fails_during_logout_then_the_browser_gets_keycloaks_logout_page_without_a_token()
 {
    wait_for_stack().await;
    let (mut browser, handle, _) = signed_in(PLANT_A).await;
    let refresh_token = read_session(&handle).await.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    arm_keycloak_fault(&refresh_token, 503).await;

    let response = browser
        .post(&format!("{PLANT_A}/auth/logout"), &[("x-csrf", "1")])
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    let logout_url = Url::parse(json(response).await["logoutUrl"].as_str().unwrap()).unwrap();
    assert!(
        logout_url
            .path()
            .ends_with("/protocol/openid-connect/logout"),
        "{logout_url}"
    );
    assert_eq!(
        query_param(&logout_url, "client_id").as_deref(),
        Some("hub-inspection")
    );
    assert_eq!(
        query_param(&logout_url, "post_logout_redirect_uri").as_deref(),
        Some(format!("{HUB}/broker/logged-out/plant-a").as_str())
    );
    assert!(
        query_param(&logout_url, "id_token_hint").is_none(),
        "no token in the URL"
    );
    assert!(
        read_session(&handle).await.is_none(),
        "the hub's session is gone anyway"
    );

    let bounce = client()
        .get(format!("{HUB}/broker/logged-out/plant-a"))
        .send()
        .await
        .unwrap();
    assert_eq!(bounce.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&bounce).as_str(), format!("{PLANT_A}/"));
}

#[tokio::test]
async fn given_one_browser_when_signing_in_at_two_sites_then_keycloak_sso_gives_two_separate_sessions()
 {
    wait_for_stack().await;
    let user = fresh_user();
    let mut browser = Browser::new();
    assert_eq!(
        sign_in(&mut browser, PLANT_A, &user).await.status(),
        StatusCode::SEE_OTHER
    );
    // Second site: Keycloak recognises the user, no password this time.
    assert_eq!(
        sign_in(&mut browser, PLANT_B, &user).await.status(),
        StatusCode::SEE_OTHER
    );

    let handle_a = browser.cookie(PLANT_A, SESSION).unwrap();
    let handle_b = browser.cookie(PLANT_B, SESSION).unwrap();
    assert_ne!(handle_a, handle_b);
    let a = json(browser.get(&format!("{PLANT_A}/auth/session")).await).await;
    let b = json(browser.get(&format!("{PLANT_B}/auth/session")).await).await;
    assert_eq!(
        (a["site"].as_str(), a["tenant"].as_str()),
        (Some("plant-a"), Some("customer1"))
    );
    assert_eq!(
        (b["site"].as_str(), b["tenant"].as_str()),
        (Some("plant-b"), Some("customer2"))
    );
    let api_b = json(browser.get(&format!("{PLANT_B}/api/x")).await).await;
    assert_eq!(
        api_b["bearer"]["claims"]["organization"]["plant-b"]["tenant"],
        serde_json::json!(["customer2"]),
        "plant-b's token names plant-b and its tenant"
    );
}

#[tokio::test]
async fn given_keycloak_ends_a_users_sessions_when_back_channel_logout_arrives_then_every_site_is_signed_out()
 {
    wait_for_stack().await;
    let user = fresh_user();
    let mut browser = Browser::new();
    assert_eq!(
        sign_in(&mut browser, PLANT_A, &user).await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        sign_in(&mut browser, PLANT_B, &user).await.status(),
        StatusCode::SEE_OTHER
    );
    for site in [PLANT_A, PLANT_B] {
        assert_eq!(
            browser.get(&format!("{site}/auth/session")).await.status(),
            StatusCode::OK
        );
    }

    keycloak_logout_user(&user).await;

    for site in [PLANT_A, PLANT_B] {
        let mut ended = false;
        for _ in 0..20 {
            if browser.get(&format!("{site}/auth/session")).await.status()
                == StatusCode::UNAUTHORIZED
            {
                ended = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(ended, "{site} session survived back-channel logout");
    }
}

#[tokio::test]
async fn given_a_short_lived_access_token_when_it_nears_expiry_then_the_hub_refreshes_it_transparently()
 {
    wait_for_stack().await;
    // Through the hub, so every call reaches the hub's refresh; a direct kind's edge caches
    // tokens for up to a minute (see auth_hub.rs for its refresh).
    let (mut browser, _, user) = signed_in(PLANT_C).await;
    let first = json(browser.get(&format!("{PLANT_C}/api/token")).await).await;

    // The test realm issues 70 s tokens; the hub refreshes once fewer than 60 s remain.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let second = json(browser.get(&format!("{PLANT_C}/api/token")).await).await;

    assert_ne!(
        first["bearer"]["fingerprint"], second["bearer"]["fingerprint"],
        "a new token"
    );
    let (exp1, exp2) = (
        first["bearer"]["claims"]["exp"].as_u64().unwrap(),
        second["bearer"]["claims"]["exp"].as_u64().unwrap(),
    );
    assert!(
        exp2 > exp1,
        "refreshed token expires later ({exp1} -> {exp2})"
    );
    assert_eq!(
        second["bearer"]["claims"]["preferred_username"],
        user.as_str(),
        "same user"
    );
}

#[tokio::test]
async fn given_a_site_of_the_second_kind_when_calling_its_api_then_tokens_belong_to_that_kind() {
    wait_for_stack().await;
    let (mut browser, _, user) = signed_in(PLANT_C).await;

    let me = json(browser.get(&format!("{PLANT_C}/auth/session")).await).await;
    assert_eq!(
        (me["app"].as_str(), me["site"].as_str()),
        (Some("billing"), Some("plant-c"))
    );

    let echo = json(browser.get(&format!("{PLANT_C}/api/invoices")).await).await;
    assert_eq!(echo["bearer"]["claims"]["azp"], "hub-billing");
    assert!(audiences(&echo).contains(&"billing-api".to_owned()));
    assert!(!audiences(&echo).contains(&"inspection-api".to_owned()));
    assert_eq!(
        echo["bearer"]["claims"]["preferred_username"],
        user.as_str()
    );
    assert_eq!(echo["headers"]["x-app-id"], "billing");
    assert_eq!(echo["headers"]["x-tenant"], "customer1");
}

#[tokio::test]
async fn given_a_token_of_one_kind_when_presented_to_another_kinds_api_then_that_api_refuses_it() {
    wait_for_stack().await;
    let (mut inspection, _, _) = signed_in(PLANT_A).await;
    let (mut billing, _, _) = signed_in(PLANT_C).await;
    let inspection_token = json(inspection.get(&format!("{PLANT_A}/api/x")).await).await["bearer"]
        ["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let billing_token =
        json(billing.get(&format!("{PLANT_C}/api/x")).await).await["bearer"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
    let http = client();
    let call = |api: &'static str, token: String| {
        let http = http.clone();
        async move {
            http.get(format!("{api}/x"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    assert_eq!(
        call(ECHO_INSPECTION, inspection_token.clone()).await,
        StatusCode::OK
    );
    assert_eq!(
        call(ECHO_BILLING, inspection_token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(ECHO_BILLING, billing_token.clone()).await,
        StatusCode::OK
    );
    assert_eq!(
        call(ECHO_INSPECTION, billing_token).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn given_one_browser_when_signing_in_to_two_kinds_then_sso_gives_separate_sessions_per_kind()
{
    wait_for_stack().await;
    let user = fresh_user();
    let mut browser = Browser::new();
    assert_eq!(
        sign_in(&mut browser, PLANT_A, &user).await.status(),
        StatusCode::SEE_OTHER
    );
    // Another kind: Keycloak recognises the user, no password this time.
    assert_eq!(
        sign_in(&mut browser, PLANT_C, &user).await.status(),
        StatusCode::SEE_OTHER
    );

    let a = json(browser.get(&format!("{PLANT_A}/auth/session")).await).await;
    let c = json(browser.get(&format!("{PLANT_C}/auth/session")).await).await;
    assert_eq!(a["app"], "inspection");
    assert_eq!(c["app"], "billing");

    let mut thief = Browser::new();
    thief.set_cookie(PLANT_C, SESSION, &browser.cookie(PLANT_A, SESSION).unwrap());
    assert_eq!(
        thief.get(&format!("{PLANT_C}/api/x")).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn given_a_user_without_the_kinds_role_when_signing_in_then_the_hub_refuses_access() {
    wait_for_stack().await;
    let mut browser = Browser::new();

    let callback = sign_in_to_hub_callback(&mut browser, PLANT_A, USER_WITHOUT_ROLES).await;

    assert_eq!(callback.status(), StatusCode::FORBIDDEN);
    assert!(
        callback
            .text()
            .await
            .unwrap()
            .contains("do not have access")
    );
    assert!(
        browser.cookie(PLANT_A, SESSION).is_none(),
        "no session was created"
    );
}

#[tokio::test]
async fn given_a_slow_streaming_response_when_proxied_then_it_is_not_cut_off() {
    wait_for_stack().await;
    let (mut browser, _, _) = signed_in(PLANT_A).await;
    let started = std::time::Instant::now();

    // 14 seconds: longer than the old 10-second total timeout that used to cut it off.
    let response = browser.get(&format!("{PLANT_A}/api/slow?seconds=14")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();

    assert_eq!(body.lines().count(), 14, "every chunk arrived");
    assert!(body.ends_with("chunk 14\n"));
    assert!(started.elapsed() >= Duration::from_secs(13));
}

#[tokio::test]
async fn given_a_flood_of_sign_in_starts_when_they_exceed_the_sites_limit_then_the_hub_answers_429()
{
    wait_for_stack().await;
    // plant-limited allows 3 per minute; 7 starts cannot all fit, even across a minute boundary.
    let mut statuses = Vec::new();
    for _ in 0..7 {
        statuses.push(hub_login_status("plant-limited").await);
    }
    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .all(|s| *s == StatusCode::SEE_OTHER || *s == StatusCode::TOO_MANY_REQUESTS)
    );
    assert_eq!(
        hub_login_status("plant-a").await,
        StatusCode::SEE_OTHER,
        "other sites unaffected"
    );
}

#[tokio::test]
async fn given_registry_changes_when_files_change_then_the_hub_reloads_valid_ones_and_ignores_broken_ones()
 {
    wait_for_stack().await;
    let before = hub_registry().await["version"].clone();

    // A broken file is refused as a whole: the hub keeps serving the previous registry.
    {
        let _broken = TempRegistryFile::write("zz-broken.json", "{ this is not json");
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(
            hub_registry().await["version"],
            before,
            "broken change ignored"
        );
        assert_eq!(
            hub_login_status("plant-a").await,
            StatusCode::SEE_OTHER,
            "still serving"
        );
    }

    // A new app kind with a site appears without a restart...
    let key = common::signing::EdgeSigner::from_base64(
        "reload-probe",
        &common::signing::generate_key().unwrap(),
    )
    .unwrap()
    .public_key();
    let probe = serde_json::json!({
        "app": {
            "id": "reload-probe", "client_id": "hub-reload-probe", "edge_public_key": key,
            "api_upstream": "http://api-inspection:8081", "api_audience": "reload-probe-api"
        },
        "sites": [{ "id": "reload-probe-plant", "origin": "http://reload-probe.localhost:5298",
                    "tenant": "probe" }]
    });
    let file = TempRegistryFile::write("zz-reload-probe.json", &probe.to_string());
    assert!(
        eventually(20, || async {
            hub_login_status("reload-probe-plant").await == StatusCode::SEE_OTHER
        })
        .await,
        "new site served after reload"
    );
    let registry = hub_registry().await;
    assert_ne!(registry["version"], before);
    assert!(
        registry["apps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == "reload-probe")
    );

    // ...and disappears again when its file is removed.
    drop(file);
    assert!(
        eventually(20, || async {
            hub_login_status("reload-probe-plant").await == StatusCode::BAD_REQUEST
        })
        .await,
        "removed site refused after reload"
    );
}

// ---- Hardening carried over from the Rust BFF ----

#[tokio::test]
async fn given_private_key_jwt_then_the_hub_publishes_only_its_public_key() {
    wait_for_stack().await;
    let jwks: Value = client()
        .get(format!("{HUB}/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["alg"], "ES256");
    assert!(key["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
    assert!(key.get("d").is_none(), "no private key material");
}

#[tokio::test]
async fn given_a_client_assertion_then_keycloak_accepts_it_once_and_never_after_it_expires() {
    wait_for_stack().await;
    let kid = hub_client_key_id().await;
    let request = |assertion: String| async move {
        token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "not-a-refresh-token"),
            ("client_id", "hub-billing"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", &assertion),
        ])
        .await
    };
    let assertion = client_assertion(&hub_client_key(), &kid, "hub-billing", 60);

    // Accepted as the client: the failure is the made-up refresh token, not the assertion.
    let (_, first) = request(assertion.clone()).await;
    assert_eq!(
        first.as_deref(),
        Some("invalid_grant"),
        "the client is authenticated"
    );
    let (status, replayed) = request(assertion).await;
    assert_eq!(
        (status, replayed.as_deref()),
        (StatusCode::BAD_REQUEST, Some("invalid_client")),
        "once only"
    );
    let (_, expired) = request(client_assertion(
        &hub_client_key(),
        &kid,
        "hub-billing",
        -120,
    ))
    .await;
    assert_eq!(
        expired.as_deref(),
        Some("invalid_client"),
        "an expired assertion is refused"
    );
}

#[tokio::test]
async fn given_a_client_assertion_signed_with_another_key_or_a_secret_then_keycloak_refuses_it() {
    wait_for_stack().await;
    let kid = hub_client_key_id().await;
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let forged_key = jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref());
    let (_, forged) = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "x"),
        ("client_id", "hub-inspection"),
        ("client_assertion_type", JWT_BEARER),
        (
            "client_assertion",
            &client_assertion(&forged_key, &kid, "hub-inspection", 60),
        ),
    ])
    .await;
    assert_eq!(forged.as_deref(), Some("invalid_client"));

    // The prototype's secret: the kinds' clients no longer have one.
    let (_, secret) = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", "x"),
        ("client_id", "hub-inspection"),
        ("client_secret", "hub-inspection.secret"),
    ])
    .await;
    assert_eq!(secret.as_deref(), Some("invalid_client"));
}

#[tokio::test]
async fn given_a_sign_in_then_the_session_lasts_as_long_as_keycloaks() {
    wait_for_stack().await;
    let (_, handle, _) = signed_in(PLANT_A).await;
    // The realm's SSO idle timeout is 30 minutes; the session's expiry follows it.
    let ttl = session_ttl(&handle).await;
    assert!((1_700..=1_800).contains(&ttl), "session TTL {ttl}");
}

#[tokio::test]
async fn given_a_request_without_a_refresh_then_the_session_is_not_extended() {
    wait_for_stack().await;
    let (mut browser, handle, _) = signed_in(PLANT_A).await;
    redis::cmd("EXPIRE")
        .arg(format!(
            "hub:session:{{{}}}",
            common::crypto::hash_key(&handle)
        ))
        .arg(500)
        .query_async::<()>(&mut redis().await)
        .await
        .unwrap();

    assert_eq!(
        browser
            .get(&format!("{PLANT_A}/auth/session"))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        browser.get(&format!("{PLANT_A}/api/x")).await.status(),
        StatusCode::OK
    );

    assert!(
        session_ttl(&handle).await <= 500,
        "reading did not extend the session"
    );
}

#[tokio::test]
async fn given_a_token_refresh_then_the_session_is_extended_with_keycloaks() {
    wait_for_stack().await;
    let (mut browser, handle, _) = signed_in(PLANT_A).await;
    let mut session = read_session(&handle).await.unwrap();
    session["expires_at"] = 0.into();
    write_session(&handle, &session).await;
    redis::cmd("EXPIRE")
        .arg(format!(
            "hub:session:{{{}}}",
            common::crypto::hash_key(&handle)
        ))
        .arg(500)
        .query_async::<()>(&mut redis().await)
        .await
        .unwrap();

    assert_eq!(
        browser.get(&format!("{PLANT_A}/api/x")).await.status(),
        StatusCode::OK
    );

    assert!(
        session_ttl(&handle).await > 1_700,
        "the refresh set Keycloak's lifetime again"
    );
}

#[tokio::test]
async fn given_single_use_refresh_tokens_then_each_refresh_keeps_the_rotated_token() {
    wait_for_stack().await;
    // Through the hub, so every call reaches the hub's refresh; a direct kind's edge caches
    // tokens for up to a minute (see auth_hub.rs for its refresh).
    let (mut browser, handle, _) = signed_in(PLANT_C).await;
    let mut used = Vec::new();
    for _ in 0..2 {
        // Keycloak dates tokens and sessions in whole seconds and only spots a used token that
        // is older than the session's last refresh, so the steps must be a second apart.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let mut session = read_session(&handle).await.unwrap();
        used.push(session["refresh_token"].as_str().unwrap().to_owned());
        session["expires_at"] = 0.into();
        write_session(&handle, &session).await;
        assert_eq!(
            browser.get(&format!("{PLANT_C}/api/x")).await.status(),
            StatusCode::OK,
            "refreshed"
        );
    }
    let current = read_session(&handle).await.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !used.contains(&current),
        "every refresh stored a new refresh token"
    );
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    for old in &used {
        assert_eq!(
            keycloak_refresh_status("hub-billing", old).await,
            StatusCode::BAD_REQUEST,
            "spent"
        );
    }
}

#[tokio::test]
async fn given_parallel_requests_with_an_expired_token_then_one_refresh_serves_them_all() {
    wait_for_stack().await;
    let (browser, handle, _) = signed_in(PLANT_A).await;
    let mut session = read_session(&handle).await.unwrap();
    let before = session["refresh_token"].as_str().unwrap().to_owned();
    session["expires_at"] = 0.into();
    write_session(&handle, &session).await;
    drop(browser);

    // With single-use refresh tokens, two refreshes of the same token would end the session.
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let request = client()
            .get(format!("{PLANT_A}/api/x"))
            .header("cookie", format!("{SESSION}={handle}"))
            .header(common::csrf::CSRF_HEADER, "1");
        calls.spawn(async move { request.send().await.unwrap().status() });
    }
    let statuses = calls.join_all().await;
    assert!(
        statuses.iter().all(|status| *status == StatusCode::OK),
        "{statuses:?}"
    );
    let after = read_session(&handle).await.expect("the session survived");
    assert_ne!(after["refresh_token"], before.as_str(), "it was refreshed");
}

#[tokio::test]
async fn given_keycloak_fails_during_a_refresh_then_the_session_survives_and_recovers() {
    wait_for_stack().await;
    let (mut browser, handle, _) = signed_in(PLANT_A).await;
    let mut session = read_session(&handle).await.unwrap();
    let refresh_token = session["refresh_token"].as_str().unwrap().to_owned();
    session["expires_at"] = 0.into();
    write_session(&handle, &session).await;
    arm_keycloak_fault(&refresh_token, 503).await;

    assert_eq!(
        browser.get(&format!("{PLANT_A}/api/x")).await.status(),
        StatusCode::BAD_GATEWAY
    );
    assert!(
        read_session(&handle).await.is_some(),
        "a Keycloak outage signs nobody out"
    );

    assert_eq!(
        browser.get(&format!("{PLANT_A}/api/x")).await.status(),
        StatusCode::OK,
        "recovered"
    );
}

#[tokio::test]
async fn given_a_refresh_token_keycloak_rejects_then_the_session_ends() {
    wait_for_stack().await;
    let (mut browser, handle, _) = signed_in(PLANT_A).await;
    let mut session = read_session(&handle).await.unwrap();
    session["expires_at"] = 0.into();
    session["refresh_token"] = "not-a-refresh-token".into();
    write_session(&handle, &session).await;

    assert_eq!(
        browser.get(&format!("{PLANT_A}/api/x")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(read_session(&handle).await.is_none());
}

#[tokio::test]
async fn given_a_logout_token_when_it_is_replayed_then_it_is_refused() {
    wait_for_stack().await;
    let (mut browser, _, user) = signed_in(PLANT_A).await;
    let recorded_before = recorded_logout_tokens().await.len();
    keycloak_logout_user(&user).await;
    assert!(
        eventually(10, || async {
            recorded_logout_tokens().await.len() > recorded_before
        })
        .await,
        "Keycloak sent a logout token"
    );
    assert_eq!(
        browser
            .get(&format!("{PLANT_A}/auth/session"))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let token = recorded_logout_tokens().await.last().unwrap().clone();
    let replay = client()
        .post(format!("{HUB}/auth/backchannel-logout/inspection"))
        .form(&[("logout_token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::UNAUTHORIZED,
        "each logout token works once"
    );

    let forged = client()
        .post(format!("{HUB}/auth/backchannel-logout/inspection"))
        .form(&[("logout_token", "e30.e30.c2ln")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn given_forged_forwarding_headers_when_calling_the_api_then_only_the_edges_address_arrives()
{
    wait_for_stack().await;
    let (mut browser, _, _) = signed_in(PLANT_A).await;
    let response = browser
        .send(
            Method::GET,
            &format!("{PLANT_A}/api/x"),
            &[
                // As a trusted proxy in front of the edge would report the browser.
                ("cf-connecting-ip", "198.51.100.7"),
                ("x-forwarded-for", "10.0.0.1"),
                ("forwarded", "for=10.0.0.1"),
                ("x-real-ip", "10.0.0.1"),
                ("true-client-ip", "10.0.0.1"),
                ("x-forwarded-host", "evil.example"),
            ],
            None,
        )
        .await;
    let headers = &json(response).await["headers"];
    assert_eq!(
        headers["x-forwarded-for"], "198.51.100.7",
        "the address the edge determined"
    );
    for forged in [
        "forwarded",
        "x-real-ip",
        "true-client-ip",
        "x-forwarded-host",
        "cf-connecting-ip",
    ] {
        assert!(headers.get(forged).is_none(), "{forged} reached the API");
    }
}

#[tokio::test]
async fn given_dot_segments_in_an_api_path_then_they_are_refused() {
    wait_for_stack().await;
    let (mut browser, handle, _) = signed_in(PLANT_A).await;
    // Either layer may refuse. The ingress resolves `%2e%2e` itself, so those arrive outside
    // /api: the edge serves no such path (404), and the hub finds the signature, made for the path
    // as sent, no longer matches (401). What the ingress passes on unchanged, `..%5C`, the edge
    // and the hub refuse themselves (400).
    for path in [
        "/api/%2e%2e/admin",
        "/api/x/%2E%2E/%2e%2e/y",
        "/api/..%5Cadmin",
    ] {
        let edge_headers = [
            format!("Cookie: {SESSION}={handle}"),
            format!("{}: 1", common::csrf::CSRF_HEADER),
        ];
        let at_edge = raw_get_status(PLANT_A, path, &edge_headers).await;
        assert!(at_edge == 400 || at_edge == 404, "edge: {path}: {at_edge}");
        if path.contains("%5C") {
            assert_eq!(at_edge, 400, "edge: {path}");
        }
        // Straight to the hub's API route (billing's, which forwards), signed: refused there too.
        let signed = signer("plant-c")
            .sign("GET", path, Some(&handle), now())
            .unwrap();
        let headers = vec![
            format!("x-site-id: {}", signed.site_id),
            format!("x-site-timestamp: {}", signed.timestamp),
            format!("x-site-nonce: {}", signed.nonce),
            format!("x-site-signature: {}", signed.signature),
            format!("x-session-handle: {handle}"),
        ];
        let at_hub = raw_get_status(HUB, path, &headers).await;
        assert!(matches!(at_hub, 400 | 401 | 404), "hub: {path}: {at_hub}");
        if path.contains("%5C") {
            assert_eq!(at_hub, 400, "hub: {path}");
        }
    }
    let _ = &mut browser;
}

#[tokio::test]
async fn given_any_request_then_it_carries_a_request_id_through_to_the_api() {
    wait_for_stack().await;
    let (mut browser, _, _) = signed_in(PLANT_A).await;
    let response = browser
        .send(
            Method::GET,
            &format!("{PLANT_A}/api/x"),
            &[("x-request-id", "trace-0123456789")],
            None,
        )
        .await;
    assert_eq!(response.headers()["x-request-id"], "trace-0123456789");
    assert_eq!(
        json(response).await["headers"]["x-request-id"],
        "trace-0123456789",
        "kept to the API"
    );

    let invented = browser
        .send(
            Method::GET,
            &format!("{PLANT_A}/api/x"),
            &[("x-request-id", "bad id")],
            None,
        )
        .await;
    let id = invented.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_ne!(id, "bad id");
    assert_eq!(json(invented).await["headers"]["x-request-id"], id.as_str());
}

#[tokio::test]
async fn given_a_sign_in_asking_for_other_scopes_then_the_hub_requests_only_the_kinds_own() {
    wait_for_stack().await;
    let mut browser = Browser::new();
    let login = browser.get(&login_url(PLANT_A, "/")).await;
    let to_keycloak = browser
        .get(&format!(
            "{}&scope=openid%20offline_access",
            location(&login)
        ))
        .await;
    assert_eq!(
        query_param(&location(&to_keycloak), "scope").as_deref(),
        Some("openid profile email organization:plant-a"),
        "the registry decides, plus the site's organization for a direct kind; not the browser"
    );
}

#[tokio::test]
async fn given_two_sign_ins_started_in_one_browser_then_both_complete() {
    wait_for_stack().await;
    let user = fresh_user();
    let mut browser = Browser::new();
    // Two tabs: the second starts before the first finishes.
    let first = browser.get(&login_url(PLANT_A, "/first")).await;
    let second = browser.get(&login_url(PLANT_A, "/second")).await;
    assert_ne!(
        set_cookie_with_prefix(&first, LOGIN),
        set_cookie_with_prefix(&second, LOGIN)
    );

    let (first_broker, second_broker) = (location(&first), location(&second));
    assert_eq!(
        finish_sign_in(&mut browser, second_broker, &user)
            .await
            .path(),
        "/second"
    );
    assert_eq!(
        finish_sign_in(&mut browser, first_broker, &user)
            .await
            .path(),
        "/first"
    );
}

/// Finishes a sign-in in `browser` from the hub's `broker` URL as `user`; returns where the edge
/// sends the browser at the end.
async fn finish_sign_in(browser: &mut Browser, broker: Url, user: &str) -> Url {
    let to_keycloak = browser.get(broker.as_str()).await;
    let page = browser.get(location(&to_keycloak).as_str()).await;
    let callback = if page.status() == StatusCode::FOUND {
        location(&page)
    } else {
        location(&submit_credentials(browser, page, user).await)
    };
    let hub = browser.get(callback.as_str()).await;
    location(&browser.get(location(&hub).as_str()).await)
}

#[tokio::test]
async fn given_an_id_token_instead_of_an_access_token_then_the_api_refuses_it() {
    wait_for_stack().await;
    let (_, handle, _) = signed_in(PLANT_A).await;
    let id_token = read_session(&handle).await.unwrap()["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let status = client()
        .get(format!("{ECHO_INSPECTION}/x"))
        .bearer_auth(id_token)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_the_metrics_page_then_it_is_served_only_on_its_own_address() {
    wait_for_stack().await;
    let page = client().get(HUB_METRICS).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(
        page.text()
            .await
            .unwrap()
            .contains("# TYPE hub_http_requests_total counter")
    );
    assert_eq!(
        client()
            .get(format!("{HUB}/metrics"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn given_sign_ins_and_refreshes_then_they_are_counted() {
    wait_for_stack().await;
    let sign_ins = hub_metric(
        "hub_sign_ins_total",
        r#"kind="billing",outcome="completed""#,
    )
    .await;
    let refreshes = hub_metric(
        "hub_token_refreshes_total",
        r#"kind="billing",outcome="refreshed""#,
    )
    .await;

    let (mut browser, handle, _) = signed_in(PLANT_C).await;
    let mut session = read_session(&handle).await.unwrap();
    session["expires_at"] = 0.into();
    write_session(&handle, &session).await;
    assert_eq!(
        browser.get(&format!("{PLANT_C}/api/x")).await.status(),
        StatusCode::OK
    );

    assert!(
        hub_metric(
            "hub_sign_ins_total",
            r#"kind="billing",outcome="completed""#
        )
        .await
            > sign_ins
    );
    assert!(
        hub_metric(
            "hub_token_refreshes_total",
            r#"kind="billing",outcome="refreshed""#
        )
        .await
            > refreshes
    );
}
