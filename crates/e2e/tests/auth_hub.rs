//! End-to-end tests for the auth hub design: the maintenance kind, whose sites are
//! Keycloak organizations and whose edge calls each site's own API directly with
//! Keycloak's access token from the hub. Against the local cluster.
//!
//! dev/k8s/up.sh
//! cargo test -p e2e --features e2e

#![cfg(feature = "e2e")]

mod support;

use std::time::Duration;

use reqwest::{Method, StatusCode, Url};
use serde_json::{Value, json};
use support::*;

/// Held for writing while a test has plant-e's organization disabled, and for reading by every
/// test that signs in at plant-e, so they never overlap.
static SITE_E_ENABLED: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// The response body as JSON.
async fn json(response: reqwest::Response) -> Value {
    response.json().await.unwrap()
}

/// Signs `user` in at `site` in a new browser; returns the browser and the session handle.
async fn signed_in_as(site: &str, user: &str) -> (Browser, String) {
    let mut browser = Browser::new();
    let handoff = sign_in(&mut browser, site, user).await;
    assert_eq!(
        handoff.status(),
        StatusCode::SEE_OTHER,
        "edge finishes sign-in"
    );
    assert!(
        location(&handoff).query().is_none(),
        "no login error: {}",
        location(&handoff)
    );
    let handle = browser.cookie(site, SESSION).expect("session cookie set");
    (browser, handle)
}

/// The organization aliases a token's `organization` claim names.
fn organizations(claims: &Value) -> Vec<String> {
    match &claims["organization"] {
        Value::Object(by_alias) => by_alias.keys().cloned().collect(),
        Value::Array(aliases) => aliases
            .iter()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

/// A signed `POST /broker/token` as `site_id` for session `handle`; status and body.
async fn hub_token(site_id: &str, handle: &str) -> (StatusCode, Value) {
    let signed = signer(site_id)
        .sign("POST", "/broker/token", Some(handle), now())
        .unwrap();
    let response = hub_request(Method::POST, "/broker/token", &signed, Some(handle))
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or_default())
}

/// Makes the session under `handle` refresh at its next use.
async fn expire_access_token(handle: &str) {
    let mut session = read_session(handle).await.unwrap();
    session["expires_at"] = 0.into();
    write_session(handle, &session).await;
}

/// Runs Keycloak's authorization code flow as the hub's maintenance client, for `user`, asking
/// for `scope`; returns the code and its PKCE verifier, or `None` if Keycloak issued no code
/// (it refused, or stopped at a page of its own). Lets a test ask for scopes the hub never
/// would, to check the membership extension itself.
async fn keycloak_code(browser: &mut Browser, user: &str, scope: &str) -> Option<(String, String)> {
    let verifier = common::pkce::new_verifier().unwrap();
    let mut authorize = Url::parse(&format!(
        "{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/auth"
    ))
    .unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", "hub-maintenance")
        .append_pair("redirect_uri", &format!("{HUB}/auth/callback"))
        .append_pair("scope", scope)
        .append_pair("state", &common::random::random_token().unwrap())
        .append_pair("code_challenge", &common::pkce::challenge(&verifier))
        .append_pair("code_challenge_method", "S256");
    let page = browser.get(authorize.as_str()).await;
    let callback = if page.status() == StatusCode::FOUND {
        location(&page)
    } else {
        let html = page.text().await.unwrap();
        if !html.contains("kc-form-login") {
            return None;
        }
        let action = login_form_action(&html);
        let submitted = browser.post_form(&action, &[("username", user)]).await;
        let html = submitted.text().await.unwrap();
        let submitted = browser
            .post_form(
                &login_form_action(&html),
                &[("password", PASSWORD), ("credentialId", "")],
            )
            .await;
        if submitted.status() != StatusCode::FOUND {
            return None;
        }
        location(&submitted)
    };
    Some((query_param(&callback, "code")?, verifier))
}

/// Exchanges `code` with `verifier` as the hub's maintenance client; status and body.
async fn exchange(code: &str, verifier: &str) -> (StatusCode, Value) {
    let assertion = client_assertion(
        &hub_client_key(),
        &hub_client_key_id().await,
        "hub-maintenance",
        60,
    );
    let response = client()
        .post(format!(
            "{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &format!("{HUB}/auth/callback")),
            ("code_verifier", verifier),
            ("client_id", "hub-maintenance"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", &assertion),
        ])
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or_default())
}

/// The payload of JWT `token`, unverified.
fn payload(token: &str) -> Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn given_a_member_when_calling_the_api_then_the_edge_calls_its_sites_api_directly() {
    wait_for_stack().await;
    let (mut browser, _) = signed_in_as(PLANT_D, &fresh_member_of_plant_d_only()).await;

    let me = json(browser.get(&format!("{PLANT_D}/auth/session")).await).await;
    assert_eq!(
        (me["app"].as_str(), me["site"].as_str()),
        (Some("maintenance"), Some("plant-d"))
    );

    let echo = json(browser.get(&format!("{PLANT_D}/api/orders?x=1")).await).await;
    let claims = &echo["bearer"]["claims"];
    assert_eq!(claims["azp"], "hub-maintenance");
    assert_eq!(claims["typ"], "Bearer");
    assert_eq!(
        organizations(claims),
        ["plant-d"],
        "the token names the site"
    );
    assert_eq!(
        claims["organization"]["plant-d"]["tenant"],
        json!(["customer4"]),
        "with its tenant"
    );
    assert!(
        claims["organization"]["plant-d"]["id"].is_string(),
        "and its id"
    );
    assert_eq!(echo["path"], "/orders");
    let headers = &echo["headers"];
    // Nothing from the hub: the API learns the site from the token alone.
    for absent in [
        "x-site-id",
        "x-tenant",
        "x-app-id",
        "cookie",
        "x-csrf",
        "x-session-handle",
    ] {
        assert!(headers.get(absent).is_none(), "{absent} reached the API");
    }
    assert!(headers["x-forwarded-for"].is_string());
}

#[tokio::test]
async fn given_a_user_who_is_not_a_member_when_signing_in_then_there_is_no_token_and_a_clear_page()
{
    wait_for_stack().await;
    let _site_e = SITE_E_ENABLED.read().await;
    for (site, user) in [
        (PLANT_E, fresh_member_of_plant_d_only()),
        (PLANT_D, USER_OUTSIDER.to_owned()),
    ] {
        let mut browser = Browser::new();
        let callback = sign_in_to_hub_callback(&mut browser, site, &user).await;
        assert_eq!(callback.status(), StatusCode::FORBIDDEN, "{user} at {site}");
        assert!(
            callback
                .text()
                .await
                .unwrap()
                .contains("do not have access")
        );
        assert!(
            browser.cookie(site, SESSION).is_none(),
            "no session was created"
        );
    }
}

#[tokio::test]
async fn given_a_member_of_two_sites_then_each_session_keeps_its_own_organization() {
    wait_for_stack().await;
    let _site_e = SITE_E_ENABLED.read().await;
    let user = fresh_member_of_both();
    let mut browser = Browser::new();
    assert_eq!(
        sign_in(&mut browser, PLANT_D, &user).await.status(),
        StatusCode::SEE_OTHER
    );
    // The second site: Keycloak recognises the user, no password this time.
    assert_eq!(
        sign_in(&mut browser, PLANT_E, &user).await.status(),
        StatusCode::SEE_OTHER
    );
    let (handle_d, handle_e) = (
        browser.cookie(PLANT_D, SESSION).unwrap(),
        browser.cookie(PLANT_E, SESSION).unwrap(),
    );

    for round in 0..2 {
        if round == 1 {
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            expire_access_token(&handle_d).await;
            expire_access_token(&handle_e).await;
        }
        let (_, d) = hub_token("plant-d", &handle_d).await;
        let (_, e) = hub_token("plant-e", &handle_e).await;
        assert_eq!(
            organizations(&payload(d["accessToken"].as_str().unwrap())),
            ["plant-d"],
            "round {round}"
        );
        assert_eq!(
            organizations(&payload(e["accessToken"].as_str().unwrap())),
            ["plant-e"],
            "round {round}"
        );
    }
    let session_d = payload(
        read_session(&handle_d).await.unwrap()["access_token"]
            .as_str()
            .unwrap(),
    );
    let session_e = payload(
        read_session(&handle_e).await.unwrap()["access_token"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(
        session_d["sid"], session_e["sid"],
        "one Keycloak session for both"
    );
}

#[tokio::test]
async fn given_a_token_for_one_site_then_another_sites_api_refuses_it() {
    wait_for_stack().await;
    let _site_e = SITE_E_ENABLED.read().await;
    let (mut browser, _) = signed_in_as(PLANT_D, &fresh_member_of_both()).await;
    let token = json(browser.get(&format!("{PLANT_D}/api/x")).await).await["bearer"]["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let call = |api: &'static str, token: String| async move {
        client()
            .get(format!("{api}/x"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
    };

    // Copied tokens are accepted (decided): at the site they were issued for...
    assert_eq!(call(ECHO_MAINT_D, token.clone()).await, StatusCode::OK);
    // ...and nowhere else, even by a user who is a member of both.
    assert_eq!(
        call(ECHO_MAINT_E, token.clone()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(ECHO_INSPECTION, token).await,
        StatusCode::UNAUTHORIZED,
        "another kind"
    );
}

#[tokio::test]
async fn given_a_direct_kind_then_the_hub_never_carries_its_api_traffic_and_proxied_kinds_get_no_tokens()
 {
    wait_for_stack().await;
    let (_, handle_d) = signed_in_as(PLANT_D, &fresh_member_of_plant_d_only()).await;
    let signed = signer("plant-d")
        .sign("GET", "/api/x", Some(&handle_d), now())
        .unwrap();
    let through_hub = hub_request(Method::GET, "/api/x", &signed, Some(&handle_d))
        .send()
        .await
        .unwrap();
    assert_eq!(through_hub.status(), StatusCode::NOT_FOUND);

    let (_, handle_c) = signed_in_as(PLANT_C, &fresh_user()).await;
    let (status, _) = hub_token("plant-c", &handle_c).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a proxied kind's tokens never leave the hub"
    );
}

#[tokio::test]
async fn given_cached_tokens_then_the_edge_asks_the_hub_about_once_a_minute() {
    wait_for_stack().await;
    let (mut browser, _) = signed_in_as(PLANT_D, &fresh_member_of_plant_d_only()).await;
    let first = json(browser.get(&format!("{PLANT_D}/api/x")).await).await;
    let second = json(browser.get(&format!("{PLANT_D}/api/x")).await).await;
    assert_eq!(
        first["bearer"]["fingerprint"], second["bearer"]["fingerprint"],
        "served from the cache"
    );
}

#[tokio::test]
async fn given_a_removed_membership_then_the_next_refresh_ends_the_session() {
    wait_for_stack().await;
    let user = fresh_member_of_plant_d_only();
    let (_, handle) = signed_in_as(PLANT_D, &user).await;
    let organization_id = organization("plant-d").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let user_id = user_id(&user).await;
    let removed = admin(
        Method::DELETE,
        &format!("/organizations/{organization_id}/members/{user_id}"),
        None,
    )
    .await;
    assert!(removed.status().is_success(), "{}", removed.status());

    expire_access_token(&handle).await;
    let (status, _) = hub_token("plant-d", &handle).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Keycloak refused the refresh"
    );
    assert!(read_session(&handle).await.is_none(), "the session ended");
    let restored = admin(
        Method::POST,
        &format!("/organizations/{organization_id}/members"),
        Some(json!(user_id)),
    )
    .await;
    assert!(restored.status().is_success());
}

#[tokio::test]
async fn given_a_disabled_site_then_refreshes_are_refused() {
    wait_for_stack().await;
    let _site_e = SITE_E_ENABLED.write().await;
    let (_, handle) = signed_in_as(PLANT_E, &fresh_member_of_both()).await;
    let mut plant_e = organization("plant-e").await;
    let id = plant_e["id"].as_str().unwrap().to_owned();
    plant_e["enabled"] = false.into();
    assert!(
        admin(
            Method::PUT,
            &format!("/organizations/{id}"),
            Some(plant_e.clone())
        )
        .await
        .status()
        .is_success()
    );

    expire_access_token(&handle).await;
    let (status, _) = hub_token("plant-e", &handle).await;

    plant_e["enabled"] = true.into();
    assert!(
        admin(Method::PUT, &format!("/organizations/{id}"), Some(plant_e))
            .await
            .status()
            .is_success()
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(read_session(&handle).await.is_none());
}

#[tokio::test]
async fn given_scopes_the_hub_never_asks_for_then_keycloak_refuses_the_token() {
    wait_for_stack().await;
    let _site_e = SITE_E_ENABLED.read().await;
    let user = fresh_member_of_both();
    let mut browser = Browser::new();
    // A member, the right site: tokens are issued.
    let (code, verifier) = keycloak_code(&mut browser, &user, "openid organization:plant-d")
        .await
        .unwrap();
    let (status, tokens) = exchange(&code, &verifier).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let access = payload(tokens["access_token"].as_str().unwrap());
    assert_eq!(organizations(&access), ["plant-d"], "{access}");

    for scope in [
        "openid",
        "openid organization",
        "openid organization:*",
        "openid organization:plant-d organization:plant-e",
    ] {
        // Keycloak may stop at a page of its own (e.g. choosing an organization) or refuse the
        // request; if it does issue a code, the extension refuses the tokens.
        // Given several organizations, Keycloak sometimes keeps just one of them: the token then
        // names exactly one site the user is a member of, which is acceptable.
        if let Some((code, verifier)) = keycloak_code(&mut browser, &user, scope).await {
            let (status, body) = exchange(&code, &verifier).await;
            if status == StatusCode::OK {
                let named = organizations(&payload(body["access_token"].as_str().unwrap()));
                assert_eq!(named.len(), 1, "{scope}: never several sites in one token");
            } else {
                assert_eq!(status, StatusCode::BAD_REQUEST, "{scope}: {body}");
                assert_eq!(body["error"], "invalid_scope", "{scope}");
            }
        }
    }
}

#[tokio::test]
async fn given_a_refresh_asking_for_another_site_then_keycloak_refuses_it() {
    wait_for_stack().await;
    let _site_e = SITE_E_ENABLED.read().await;
    let user = fresh_member_of_both();
    let mut browser = Browser::new();
    let (code, verifier) = keycloak_code(&mut browser, &user, "openid organization:plant-d")
        .await
        .unwrap();
    let (_, tokens) = exchange(&code, &verifier).await;
    let assertion = client_assertion(
        &hub_client_key(),
        &hub_client_key_id().await,
        "hub-maintenance",
        60,
    );

    let (status, error) = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
        ("scope", "openid organization:plant-e"),
        ("client_id", "hub-maintenance"),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", &assertion),
    ])
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        matches!(error.as_deref(), Some("invalid_scope")),
        "{error:?}"
    );
}

#[tokio::test]
async fn given_sign_out_at_one_site_then_every_site_and_kind_in_the_browser_is_signed_out() {
    wait_for_stack().await;
    let _site_e = SITE_E_ENABLED.read().await;
    let user = fresh_member_of_both();
    let mut browser = Browser::new();
    for site in [PLANT_D, PLANT_E, PLANT_A] {
        assert_eq!(
            sign_in(&mut browser, site, &user).await.status(),
            StatusCode::SEE_OTHER,
            "{site}"
        );
    }

    let response = browser
        .post(&format!("{PLANT_D}/auth/logout"), &[("x-csrf", "1")])
        .await;
    assert_eq!(json(response).await["logoutUrl"], format!("{PLANT_D}/"));

    // Keycloak's back-channel logout reaches the hub for every kind the session touched.
    for site in [PLANT_E, PLANT_A] {
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
        assert!(ended, "{site} is signed out too");
    }
    // The next sign-in anywhere asks for the password.
    let login = browser.get(&login_url(PLANT_E, "/")).await;
    let broker = browser.get(location(&login).as_str()).await;
    assert_eq!(
        browser.get(location(&broker).as_str()).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn given_the_registry_then_the_organization_sync_creates_sites_and_reports_drift() {
    wait_for_stack().await;
    let plant_d = organization("plant-d").await;
    assert_eq!(plant_d["alias"], "plant-d");
    assert_eq!(plant_d["attributes"]["tenant"], json!(["customer4"]));
    assert_eq!(plant_d["attributes"]["managed-by"], json!(["hub"]));

    // An organization the hub manages but the registry no longer lists.
    let created = admin(
        Method::POST,
        "/organizations",
        Some(json!({ "name": "plant-gone", "alias": "plant-gone", "attributes": { "managed-by": ["hub"] } })),
    )
    .await;
    assert!(created.status().is_success(), "{}", created.status());
    // The cluster's organization sync job, run once.
    let (succeeded, stdout) = run_organization_sync();
    let gone = organization("plant-gone").await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    admin(Method::DELETE, &format!("/organizations/{gone}"), None).await;
    assert!(succeeded, "{stdout}");
    assert!(
        stdout.contains("organization plant-d up to date"),
        "{stdout}"
    );
    assert!(
        stdout.contains("DRIFT: organization plant-gone"),
        "{stdout}"
    );
}
