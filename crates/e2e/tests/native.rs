//! End-to-end tests for native installations (RFC 8252): desktop apps that sign in through the
//! system browser with a loopback redirect, and sign their requests to the hub with their own
//! installation's key. They drive `native-app`, the same library a desktop app uses. Against
//! the local cluster.
//!
//! dev/k8s/up.sh
//! cargo test -p e2e --features e2e

#![cfg(feature = "e2e")]

mod support;

use std::time::Duration;

use reqwest::{StatusCode, Url};
use serde_json::Value;
use support::*;

/// The hub's `/broker/login` URL for native installation `site` with `redirect_uri`, as a
/// desktop app would build it, with a valid state and challenge.
fn login_with_redirect(site: &str, redirect_uri: &str) -> Url {
    let verifier = common::pkce::new_verifier().unwrap();
    let mut url = Url::parse(&format!("{HUB}/broker/login")).unwrap();
    url.query_pairs_mut()
        .append_pair("site", site)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", &common::random::random_token().unwrap())
        .append_pair("code_challenge", &common::pkce::challenge(&verifier))
        .append_pair("code_challenge_method", "S256");
    url
}

/// The status of a GET to `url` without following redirects.
async fn status_of(url: &Url) -> StatusCode {
    client().get(url.clone()).send().await.unwrap().status()
}

#[tokio::test]
async fn given_a_native_installation_when_signing_in_through_the_system_browser_then_its_app_gets_a_session_naming_it()
 {
    wait_for_stack().await;
    let app = installation("plant-f");
    let session = native_sign_in(&app, &fresh_user()).await;

    let who = app.whoami(&session).await.unwrap();
    assert_eq!(who["app"], "planner");
    assert_eq!(who["site"], "plant-f");
    assert_eq!(who["tenant"], "customer6");
}

#[tokio::test]
async fn given_a_signed_in_installation_then_its_api_accepts_the_tokens_it_fetches_and_they_name_it()
 {
    wait_for_stack().await;
    let app = installation("plant-g");
    let session = native_sign_in(&app, &fresh_user()).await;

    let token = app.access_token(&session).await.unwrap();
    assert!(token.expires_in > 0);
    let response = client()
        .get(format!("{ECHO_PLANNER}/reports"))
        .bearer_auth(&token.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the kind's API accepts it"
    );
    let echo: Value = response.json().await.unwrap();
    let claims = &echo["bearer"]["claims"];
    assert_eq!(
        claims["azp"], "hub-planner",
        "the hub's client for the kind, not one per installation"
    );
    assert!(
        claims["organization"].get("plant-g").is_some(),
        "the token names exactly this installation: {}",
        claims["organization"]
    );
}

#[tokio::test]
async fn given_a_second_workstation_key_of_the_installation_then_it_signs_for_the_installation_too()
{
    wait_for_stack().await;
    let desk_2 = installation_with("plant-f", &installation_key("plant-f-desk-2"));
    let session = native_sign_in(&desk_2, &fresh_user()).await;
    assert_eq!(desk_2.whoami(&session).await.unwrap()["site"], "plant-f");
}

#[tokio::test]
async fn given_a_redirect_that_is_not_the_apps_loopback_address_then_the_hub_refuses_the_sign_in() {
    wait_for_stack().await;
    for redirect_uri in [
        "http://evil.example:51004/callback",
        "http://localhost:51004/callback",
        "https://127.0.0.1:51004/callback",
        "http://127.0.0.1/callback",
        "http://127.0.0.1:51004/elsewhere",
        "http://127.0.0.1:51004/callback?next=https://evil.example",
    ] {
        assert_eq!(
            status_of(&login_with_redirect("plant-f", redirect_uri)).await,
            StatusCode::BAD_REQUEST,
            "{redirect_uri}"
        );
    }
    assert_eq!(
        status_of(&login_with_redirect(
            "plant-f",
            "http://[::1]:51004/callback"
        ))
        .await,
        StatusCode::SEE_OTHER,
        "IPv6 loopback, any port"
    );
}

#[tokio::test]
async fn given_a_native_installation_without_a_redirect_or_an_edge_site_with_one_then_the_hub_refuses()
 {
    wait_for_stack().await;
    let mut without = login_with_redirect("plant-f", "http://127.0.0.1:51004/callback");
    let kept: Vec<(String, String)> = without
        .query_pairs()
        .filter(|(key, _)| key != "redirect_uri")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    without.query_pairs_mut().clear().extend_pairs(kept);
    assert_eq!(
        status_of(&without).await,
        StatusCode::BAD_REQUEST,
        "a native app must name it"
    );

    // An edge's site returns to its registered origin only.
    assert_eq!(
        status_of(&login_with_redirect(
            "plant-a",
            "http://127.0.0.1:51004/callback"
        ))
        .await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn given_a_retired_installation_then_it_cannot_start_a_sign_in() {
    wait_for_stack().await;
    let app = installation("plant-h");
    let sign_in = app.begin_sign_in("/callback").await.unwrap();
    assert_eq!(status_of(sign_in.url()).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn given_a_user_who_is_not_a_member_of_the_installation_then_the_hub_refuses_the_sign_in() {
    wait_for_stack().await;
    let app = installation("plant-f");
    let sign_in = app.begin_sign_in("/callback").await.unwrap();
    let at_hub = sign_in_in_system_browser(sign_in.url(), USER_OUTSIDER).await;
    assert_eq!(
        at_hub.status(),
        StatusCode::FORBIDDEN,
        "no code goes back to the app"
    );
}

#[tokio::test]
async fn given_another_installations_key_when_redeeming_the_code_then_the_hub_refuses_it() {
    wait_for_stack().await;
    let plant_f = installation("plant-f");
    let sign_in = plant_f.begin_sign_in("/callback").await.unwrap();
    let (url, user) = (sign_in.url().clone(), fresh_user());
    let (code, _) = tokio::join!(
        sign_in.wait_for_code(Duration::from_secs(30)),
        sign_in_in_system_browser(&url, &user)
    );
    let code = code.unwrap();

    let plant_g = installation("plant-g");
    assert!(
        matches!(
            plant_g.redeem(&code, sign_in.verifier()).await,
            Err(native_app::Error::Refused(StatusCode::UNAUTHORIZED))
        ),
        "plant-g's key cannot speak for plant-f"
    );
    assert!(
        plant_f.redeem(&code, sign_in.verifier()).await.is_err(),
        "a code is tried once: the failed attempt used it up"
    );
}

#[tokio::test]
async fn given_a_code_when_redeemed_without_its_verifier_or_twice_then_the_hub_refuses_it() {
    wait_for_stack().await;
    let app = installation("plant-f");
    for wrong_verifier in [true, false] {
        let sign_in = app.begin_sign_in("/callback").await.unwrap();
        let (url, user) = (sign_in.url().clone(), fresh_user());
        let (code, _) = tokio::join!(
            sign_in.wait_for_code(Duration::from_secs(30)),
            sign_in_in_system_browser(&url, &user)
        );
        let code = code.unwrap();
        if wrong_verifier {
            let other = common::pkce::new_verifier().unwrap();
            assert!(
                app.redeem(&code, &other).await.is_err(),
                "PKCE: only this app instance's verifier"
            );
        } else {
            assert!(app.redeem(&code, sign_in.verifier()).await.is_ok());
            assert!(
                app.redeem(&code, sign_in.verifier()).await.is_err(),
                "a code works once"
            );
        }
    }
}

#[tokio::test]
async fn given_a_key_the_registry_does_not_list_then_the_hub_refuses_the_installations_requests() {
    wait_for_stack().await;
    let impostor = installation_with("plant-f", &common::signing::generate_key().unwrap());
    let session = native_app::Session {
        handle: "not-a-handle".into(),
    };
    assert!(matches!(
        impostor.whoami(&session).await,
        Err(native_app::Error::Refused(StatusCode::UNAUTHORIZED))
    ));
}

#[tokio::test]
async fn given_one_installations_session_then_another_installation_cannot_use_it() {
    wait_for_stack().await;
    let plant_f = installation("plant-f");
    let session = native_sign_in(&plant_f, &fresh_user()).await;
    let plant_g = installation("plant-g");
    assert!(matches!(
        plant_g.whoami(&session).await,
        Err(native_app::Error::Refused(StatusCode::UNAUTHORIZED))
    ));
    assert!(plant_g.access_token(&session).await.is_err());
}

#[tokio::test]
async fn given_a_signed_in_installation_when_signing_out_then_its_session_and_tokens_end() {
    wait_for_stack().await;
    let app = installation("plant-g");
    let session = native_sign_in(&app, &fresh_user()).await;
    let ended = app.sign_out(&session).await.unwrap();
    // Keycloak ends its session server to server: nothing left for the browser to do but read
    // the hub's signed-out page, as a native installation has no start page.
    let logout_url = ended["logoutUrl"].as_str().unwrap();
    assert!(
        logout_url.ends_with("/broker/logged-out/plant-g"),
        "{logout_url}"
    );
    let page = client().get(logout_url).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.text().await.unwrap().contains("signed out"));

    assert!(app.whoami(&session).await.is_err());
    assert!(app.access_token(&session).await.is_err());
}

// A mixed kind: inspection serves web-app installations through its edge, and native
// installation plant-i signs for itself, under the same Keycloak client.

#[tokio::test]
async fn given_a_native_installation_of_a_mixed_kind_then_its_tokens_come_from_the_kinds_client_and_name_it()
 {
    wait_for_stack().await;
    let app = installation("plant-i");
    let session = native_sign_in(&app, &fresh_user()).await;
    let who = app.whoami(&session).await.unwrap();
    assert_eq!(who["app"], "inspection");
    assert_eq!(who["tenant"], "customer10");

    let token = app.access_token(&session).await.unwrap();
    let response = client()
        .get(format!("{ECHO_INSPECTION}/reports"))
        .bearer_auth(&token.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the kind's API accepts it"
    );
    let echo: Value = response.json().await.unwrap();
    let claims = &echo["bearer"]["claims"];
    assert_eq!(
        claims["azp"], "hub-inspection",
        "the same client as the kind's web-app installations"
    );
    assert!(
        claims["organization"].get("plant-i").is_some(),
        "{}",
        claims["organization"]
    );
}

#[tokio::test]
async fn given_a_mixed_kind_then_its_edge_cannot_speak_for_its_native_installation_nor_the_installation_for_a_web_one()
 {
    wait_for_stack().await;
    let session = native_app::Session {
        handle: "not-a-handle".into(),
    };
    let edge_as_plant_i = installation_with("plant-i", &edge_key("inspection"));
    assert!(matches!(
        edge_as_plant_i.whoami(&session).await,
        Err(native_app::Error::Refused(StatusCode::UNAUTHORIZED))
    ));
    let plant_i_as_plant_a = installation_with("plant-a", &installation_key("plant-i"));
    assert!(matches!(
        plant_i_as_plant_a.whoami(&session).await,
        Err(native_app::Error::Refused(StatusCode::UNAUTHORIZED))
    ));
}

#[tokio::test]
async fn given_a_request_naming_a_wrong_key_or_none_then_the_hub_refuses_it() {
    wait_for_stack().await;
    let app = installation("plant-f");
    let session = native_sign_in(&app, &fresh_user()).await;
    let signer =
        common::signing::EdgeSigner::from_base64("plant-f", &installation_key("plant-f")).unwrap();
    let desk_2 =
        common::signing::EdgeSigner::from_base64("plant-f", &installation_key("plant-f-desk-2"))
            .unwrap();
    let send = |key_id: Option<String>| {
        let signed = signer
            .sign(
                "plant-f",
                "GET",
                "/broker/session",
                Some(&session.handle),
                now(),
            )
            .unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        signed.apply(&mut headers);
        match key_id {
            Some(id) => headers.insert(common::headers::SITE_KEY_ID, id.parse().unwrap()),
            None => headers.remove(common::headers::SITE_KEY_ID),
        };
        client()
            .get(format!("{HUB}/broker/session"))
            .headers(headers)
            .header(common::headers::SESSION_HANDLE, &session.handle)
            .send()
    };
    assert_eq!(
        send(Some(signer.key_id())).await.unwrap().status(),
        StatusCode::OK,
        "its own key id"
    );
    for (key_id, why) in [
        (None, "no key id"),
        (Some("not-a-key-id".to_owned()), "an unknown key id"),
        (Some(desk_2.key_id()), "another of the installation's keys"),
    ] {
        assert_eq!(
            send(key_id).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{why}"
        );
    }
}
