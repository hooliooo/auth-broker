//! A small browser for driving edges, the hub and Keycloak's login form, plus helpers that act
//! as a kind's edge (signing with its key for one site) or as a Keycloak admin.
//!
//! The e2e tests drive the local cluster (`dev/k8s/up.sh`): every public name is under
//! `broker.localhost`, over HTTPS through the ingress, and the tests resolve those names to it
//! themselves (`E2E_INGRESS_ADDR`). The load tests (`--features load`) drive the docker compose
//! measurement stack instead, at its `localhost` ports.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::signing::{EdgeSigner, SignedHeaders, SigningError};
use regex::Regex;
use reqwest::{
    Client, Method, RequestBuilder, Response, StatusCode, Url,
    header::{COOKIE, LOCATION, SET_COOKIE},
    redirect,
};

pub use stack::*;

/// Where the e2e tests find each part: the local cluster, through its ingress.
#[cfg(not(feature = "load"))]
mod stack {
    pub const HUB: &str = "https://hub.broker.localhost";
    pub const KEYCLOAK: &str = "https://keycloak.broker.localhost";
    /// Sites of the inspection kind, both served by the inspection edge.
    pub const PLANT_A: &str = "https://plant-a.inspection.broker.localhost";
    pub const PLANT_B: &str = "https://plant-b.inspection.broker.localhost";
    /// A site of the second app kind (billing), served by the billing edge.
    pub const PLANT_C: &str = "https://plant-c.billing.broker.localhost";
    /// Sites of the direct kind (maintenance), served by the maintenance edge, which calls each
    /// site's own API.
    pub const PLANT_D: &str = "https://plant-d.maintenance.broker.localhost";
    pub const PLANT_E: &str = "https://plant-e.maintenance.broker.localhost";
    /// A retired inspection site: in the registry, but disabled.
    pub const PLANT_RETIRED: &str = "https://plant-retired.inspection.broker.localhost";
    /// A host the inspection edge receives but no registry entry names.
    pub const PLANT_UNKNOWN: &str = "https://plant-unknown.inspection.broker.localhost";
    /// The names the tests send to the ingress themselves.
    pub(super) const PUBLIC_NAMES: &[&str] = &[
        "hub.broker.localhost",
        "keycloak.broker.localhost",
        "plant-a.inspection.broker.localhost",
        "plant-b.inspection.broker.localhost",
        "plant-c.billing.broker.localhost",
        "plant-c.inspection.broker.localhost",
        "plant-d.maintenance.broker.localhost",
        "plant-e.maintenance.broker.localhost",
        "plant-retired.inspection.broker.localhost",
        "plant-unknown.inspection.broker.localhost",
    ];
}

/// Where the load tests find each part: the docker compose measurement stack.
#[cfg(feature = "load")]
mod stack {
    pub const HUB: &str = "http://localhost:8090";
    pub const KEYCLOAK: &str = "http://localhost:8280";
    pub const PLANT_A: &str = "http://plant-a.localhost:5201";
    pub const PLANT_B: &str = "http://plant-b.localhost:5201";
    pub const PLANT_C: &str = "http://plant-c.localhost:5202";
    pub const PLANT_D: &str = "http://plant-d.localhost:5203";
    pub const PLANT_E: &str = "http://plant-e.localhost:5203";
    pub const PLANT_RETIRED: &str = "http://plant-retired.localhost:5201";
    pub const PLANT_UNKNOWN: &str = "http://plant-unknown.localhost:5201";
    /// `*.localhost` always means this machine, whatever the OS resolver thinks.
    pub(super) const PUBLIC_NAMES: &[&str] = &[
        "plant-a.localhost",
        "plant-b.localhost",
        "plant-c.localhost",
        "plant-d.localhost",
        "plant-e.localhost",
        "plant-retired.localhost",
        "plant-unknown.localhost",
    ];
}

/// The test realm.
pub const REALM: &str = "broker";
/// The test helpers: Keycloak fault proxy and back-channel logout recorder.
pub const HELPERS: &str = "http://localhost:5290";
/// The hub's metrics page, on its own port.
pub const HUB_METRICS: &str = "http://localhost:8091/metrics";
/// Prefix of the edges' per-sign-in login cookies.
pub const LOGIN: &str = "__Host-Http-login";
/// Prefix of the hub's per-sign-in login cookies.
pub const HUB_LOGIN: &str = "__Host-Http-hub-login";
/// The edges' session cookie.
pub const SESSION: &str = "__Host-Http-session";
/// Each maintenance site's own API.
pub const ECHO_MAINT_D: &str = "http://localhost:8183";
pub const ECHO_MAINT_E: &str = "http://localhost:8184";
/// Has every kind's role but is a member of no site.
pub const USER_OUTSIDER: &str = "test-user-outsider";
/// The planner kind's API, which its desktop installations call from this machine.
pub const ECHO_PLANNER: &str = "http://localhost:8185";
/// The stand-in APIs, reachable directly only so tests can present a token to the wrong kind.
pub const ECHO_INSPECTION: &str = "http://localhost:8181";
pub const ECHO_BILLING: &str = "http://localhost:8182";
pub const USER_WITHOUT_ROLES: &str = "test-user-norole";
pub const PASSWORD: &str = "test";

/// The realm's brute-force protection locks a user after a few sign-ins within a second, so
/// every password sign-in takes its own user from the pool the setup script creates.
static NEXT_USER: AtomicUsize = AtomicUsize::new(1);
const USER_POOL: usize = 160;

pub fn fresh_user() -> String {
    let n = NEXT_USER.fetch_add(1, Ordering::Relaxed);
    assert!(
        n <= USER_POOL,
        "test user pool exhausted; raise it in setup_realm.sh"
    );
    format!("test-user-{n}")
}

/// An unused pool user who is a member of both plant-d and plant-e (the even ones).
pub fn fresh_member_of_both() -> String {
    loop {
        let user = fresh_user();
        if user
            .trim_start_matches("test-user-")
            .parse::<usize>()
            .unwrap()
            % 2
            == 0
        {
            return user;
        }
    }
}

/// An unused pool user who is a member of plant-d only (the odd ones).
pub fn fresh_member_of_plant_d_only() -> String {
    loop {
        let user = fresh_user();
        if user
            .trim_start_matches("test-user-")
            .parse::<usize>()
            .unwrap()
            % 2
            == 1
        {
            return user;
        }
    }
}

/// Where the public names lead: the cluster's ingress (`E2E_INGRESS_ADDR`, default
/// `127.0.0.1:443`); for the compose stack, this machine at each URL's own port.
fn ingress() -> SocketAddr {
    if cfg!(feature = "load") {
        return "127.0.0.1:0".parse().unwrap();
    }
    std::env::var("E2E_INGRESS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:443".into())
        .parse()
        .expect("E2E_INGRESS_ADDR is an address and port")
}

/// A client that sends every public name to the stack itself, whatever the OS resolver thinks,
/// and follows no redirects. TLS is checked as usual: the local CA is trusted on this machine
/// (`mkcert -install`).
pub fn client() -> Client {
    PUBLIC_NAMES
        .iter()
        .fold(Client::builder(), |builder, name| {
            builder.resolve(name, ingress())
        })
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Cookies are kept per host, like a browser: plant-a, plant-b, and `localhost` (hub and
/// Keycloak, which share it because browsers ignore ports for cookies).
pub struct Browser {
    http: Client,
    jars: HashMap<String, HashMap<String, String>>,
}

impl Browser {
    pub fn new() -> Self {
        Self {
            http: client(),
            jars: HashMap::new(),
        }
    }

    pub async fn get(&mut self, url: &str) -> Response {
        self.send(Method::GET, url, &[], None).await
    }

    pub async fn post(&mut self, url: &str, headers: &[(&str, &str)]) -> Response {
        self.send(Method::POST, url, headers, None).await
    }

    pub async fn post_form(&mut self, url: &str, form: &[(&str, &str)]) -> Response {
        let body = serde_urlencoded(form);
        self.send(
            Method::POST,
            url,
            &[("content-type", "application/x-www-form-urlencoded")],
            Some(body),
        )
        .await
    }

    /// `method` on `url` with extra `headers` and an optional `body`, as the app sends it: with
    /// the CSRF header wherever the edge requires it, as the app's `fetch()` adds it to every
    /// call to the session's routes.
    pub async fn send(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<String>,
    ) -> Response {
        let path = Url::parse(url).unwrap().path().to_owned();
        let mut with_csrf = headers.to_vec();
        if common::csrf::needs_header(&path)
            && !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(common::csrf::CSRF_HEADER))
        {
            with_csrf.push((common::csrf::CSRF_HEADER, "1"));
        }
        self.send_without_csrf(method, url, &with_csrf, body).await
    }

    /// [`Self::send`] without adding the CSRF header: what a page of another origin could send.
    pub async fn send_without_csrf(
        &mut self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<String>,
    ) -> Response {
        let parsed = Url::parse(url).unwrap();
        let host = parsed.host_str().unwrap().to_owned();
        let mut request = self.http.request(method, url);
        if let Some(jar) = self.jars.get(&host).filter(|jar| !jar.is_empty()) {
            let cookie = jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header(COOKIE, cookie);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await.expect("request reaches the server");
        let jar = self.jars.entry(host).or_default();
        for raw in set_cookies(&response) {
            let (pair, attributes) = raw.split_once(';').unwrap_or((raw.as_str(), ""));
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if attributes.to_ascii_lowercase().contains("max-age=0") {
                jar.remove(name);
            } else {
                jar.insert(name.to_owned(), value.to_owned());
            }
        }
        response
    }

    /// The value of the only cookie for `url` whose name starts with `prefix`, e.g. a login
    /// cookie, which is named after its sign-in.
    pub fn cookie_with_prefix(&self, url: &str, prefix: &str) -> Option<String> {
        let host = Url::parse(url).unwrap().host_str().unwrap().to_owned();
        let matching: Vec<&String> = self
            .jars
            .get(&host)?
            .iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .map(|(_, value)| value)
            .collect();
        assert!(matching.len() <= 1, "several {prefix} cookies");
        matching.first().map(|value| (*value).clone())
    }

    pub fn cookie(&self, url: &str, name: &str) -> Option<String> {
        let host = Url::parse(url).unwrap().host_str().unwrap().to_owned();
        self.jars.get(&host)?.get(name).cloned()
    }

    pub fn set_cookie(&mut self, url: &str, name: &str, value: &str) {
        let host = Url::parse(url).unwrap().host_str().unwrap().to_owned();
        self.jars
            .entry(host)
            .or_default()
            .insert(name.to_owned(), value.to_owned());
    }
}

fn serde_urlencoded(form: &[(&str, &str)]) -> String {
    let mut url = Url::parse("http://x/").unwrap();
    url.query_pairs_mut().extend_pairs(form);
    url.query().unwrap_or_default().to_owned()
}

pub fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect()
}

pub fn set_cookie(response: &Response, name: &str) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
}

/// The `Set-Cookie` of `response` for a cookie whose name starts with `prefix`.
pub fn set_cookie_with_prefix(response: &Response, prefix: &str) -> Option<String> {
    set_cookies(response)
        .into_iter()
        .find(|c| c.starts_with(prefix))
}

/// The redirect target, resolved against the URL that was requested.
pub fn location(response: &Response) -> Url {
    let raw = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| {
            panic!(
                "{} from {} has no Location",
                response.status(),
                response.url()
            )
        });
    response.url().join(raw).unwrap()
}

pub fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

pub fn login_url(site: &str, return_url: &str) -> String {
    let mut url = Url::parse(site).unwrap().join("/auth/login").unwrap();
    url.query_pairs_mut().append_pair("returnUrl", return_url);
    url.to_string()
}

/// Runs a sign-in at `site` through Keycloak and returns the hub's answer to Keycloak's
/// redirect: normally a 303 to the site's handoff URL.
pub async fn sign_in_to_hub_callback(browser: &mut Browser, site: &str, user: &str) -> Response {
    let login = browser.get(&login_url(site, "/orders")).await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER, "edge starts sign-in");
    let broker = browser.get(location(&login).as_str()).await;
    assert_eq!(
        broker.status(),
        StatusCode::SEE_OTHER,
        "hub accepts the site"
    );
    let page = browser.get(location(&broker).as_str()).await;

    let callback = if page.status() == StatusCode::FOUND {
        // Already signed in at Keycloak (single sign-on): straight back to the hub.
        location(&page)
    } else {
        assert_eq!(
            page.status(),
            StatusCode::OK,
            "Keycloak shows its login page"
        );
        let submitted = submit_credentials(browser, page, user).await;
        if submitted.status() != StatusCode::FOUND {
            let status = submitted.status();
            let text = submitted.text().await.unwrap_or_default();
            let message = Regex::new(
                r#"(?s)id="input-error[^"]*"[^>]*>(.*?)<|class="[^"]*alert[^"]*"[^>]*>(.*?)</"#,
            )
            .unwrap()
            .captures(&text)
            .map(|c| {
                c.get(1)
                    .or(c.get(2))
                    .map_or("", |m| m.as_str())
                    .trim()
                    .to_owned()
            })
            .unwrap_or_else(|| text.chars().take(400).collect());
            panic!("Keycloak did not accept the credentials ({status}): {message}");
        }
        location(&submitted)
    };
    browser.get(callback.as_str()).await
}

/// Runs a sign-in at `site` up to the moment the hub sends the browser back to the edge.
/// Returns the handoff URL (not yet followed).
pub async fn sign_in_until_handoff(browser: &mut Browser, site: &str, user: &str) -> Url {
    let hub_callback = sign_in_to_hub_callback(browser, site, user).await;
    assert_eq!(
        hub_callback.status(),
        StatusCode::SEE_OTHER,
        "hub finishes sign-in"
    );
    location(&hub_callback)
}

/// A complete sign-in at `site`; returns the edge's handoff response.
pub async fn sign_in(browser: &mut Browser, site: &str, user: &str) -> Response {
    let handoff = sign_in_until_handoff(browser, site, user).await;
    browser.get(handoff.as_str()).await
}

/// Fills in Keycloak's login `page` for `user` and returns Keycloak's answer. With the
/// organization scope Keycloak asks for the username first (identity-first), then the password.
pub async fn submit_credentials(browser: &mut Browser, page: Response, user: &str) -> Response {
    let html = page.text().await.unwrap();
    let action = login_form_action(&html);
    if html.contains("name=\"password\"") {
        return browser
            .post_form(
                &action,
                &[
                    ("username", user),
                    ("password", PASSWORD),
                    ("credentialId", ""),
                ],
            )
            .await;
    }
    let password_page = browser.post_form(&action, &[("username", user)]).await;
    assert_eq!(
        password_page.status(),
        StatusCode::OK,
        "Keycloak asks for the password"
    );
    let html = password_page.text().await.unwrap();
    browser
        .post_form(
            &login_form_action(&html),
            &[("password", PASSWORD), ("credentialId", "")],
        )
        .await
}

/// The action URL of Keycloak's login form in `html`.
pub fn login_form_action(html: &str) -> String {
    let form = Regex::new(r#"(?s)<form\b[^>]*\bid="kc-form-login"[^>]*>"#)
        .unwrap()
        .find(html)
        .expect("page contains Keycloak's login form")
        .as_str();
    Regex::new(r#"\baction="([^"]+)""#)
        .unwrap()
        .captures(form)
        .expect("form has an action")[1]
        .replace("&amp;", "&")
}

/// The edge's login cookie is `state.verifier.base64url(return_to)`.
pub fn login_cookie_parts(value: &str) -> (String, String, String) {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut parts = value.splitn(3, '.');
    let state = parts.next().unwrap().to_owned();
    let verifier = parts.next().unwrap().to_owned();
    let return_to =
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap()).unwrap();
    (state, verifier, return_to)
}

/// The app kind of test site `site_id`, as the registry templates assign them.
pub fn kind_of(site_id: &str) -> &'static str {
    match site_id {
        "plant-c" => "billing",
        "plant-d" | "plant-e" => "maintenance",
        _ => "inspection",
    }
}

/// Kind `app_id`'s edge key, from `dev/keys`.
pub fn edge_key(app_id: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../dev/keys/edge-{app_id}.key",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Kind `app_id`'s edge signer.
pub fn edge_signer(app_id: &str) -> EdgeSigner {
    EdgeSigner::from_base64(app_id, &edge_key(app_id)).unwrap()
}

/// Signs as the edge of one kind, for one site.
pub struct SiteSigning {
    /// The site the requests are for.
    site_id: String,
    /// The signing edge.
    edge: EdgeSigner,
}

impl SiteSigning {
    /// Signs `method`, `path_and_query` and `handle` at `now` for this site.
    pub fn sign(
        &self,
        method: &str,
        path_and_query: &str,
        handle: Option<&str>,
        now: u64,
    ) -> Result<SignedHeaders, SigningError> {
        self.edge
            .sign(&self.site_id, method, path_and_query, handle, now)
    }
}

/// Signs for site `site_id` as its own kind's edge would.
pub fn signer(site_id: &str) -> SiteSigning {
    signer_as(kind_of(site_id), site_id)
}

/// Signs for site `site_id` as kind `app_id`'s edge, which may not be the site's own kind.
pub fn signer_as(app_id: &str, site_id: &str) -> SiteSigning {
    SiteSigning {
        site_id: site_id.to_owned(),
        edge: edge_signer(app_id),
    }
}

/// A request straight to the hub, carrying the given signed headers.
pub fn hub_request(
    method: Method,
    path: &str,
    signed: &SignedHeaders,
    handle: Option<&str>,
) -> RequestBuilder {
    let mut headers = reqwest::header::HeaderMap::new();
    signed.apply(&mut headers);
    let mut request = client()
        .request(method, format!("{HUB}{path}"))
        .headers(headers);
    if let Some(handle) = handle {
        request = request.header("x-session-handle", handle);
    }
    request
}

/// Waits until the hub and every kind's edge report ready.
pub async fn wait_for_stack() {
    let http = client();
    for _ in 0..90 {
        let mut ready = true;
        for base in [HUB, PLANT_A, PLANT_B, PLANT_C, PLANT_D, PLANT_E] {
            let ok = http
                .get(format!("{base}/health/ready"))
                .send()
                .await
                .is_ok_and(|r| r.status() == StatusCode::OK);
            ready &= ok;
        }
        if ready {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("stack not ready; is the cluster up (dev/k8s/up.sh)?");
}

/// Ends every Keycloak session of `username` through the admin API; Keycloak then sends
/// back-channel logout tokens to the hub.
pub async fn keycloak_logout_user(username: &str) {
    let http = client();
    let token: serde_json::Value = http
        .post(format!(
            "{KEYCLOAK}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "admin"),
            ("password", admin_password()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bearer = token["access_token"].as_str().unwrap().to_owned();
    let users: serde_json::Value = http
        .get(format!(
            "{KEYCLOAK}/admin/realms/{REALM}/users?username={username}&exact=true"
        ))
        .bearer_auth(&bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = users[0]["id"].as_str().expect("user exists").to_owned();
    let status = http
        .post(format!("{KEYCLOAK}/admin/realms/{REALM}/users/{id}/logout"))
        .bearer_auth(&bearer)
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success(), "admin logout returned {status}");
}

/// The hub's view of its registry: version, app kinds, their sites and client readiness.
pub async fn hub_registry() -> serde_json::Value {
    client()
        .get(format!("{HUB}/health/registry"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// GET /broker/login for `site` with a well-formed edge state and challenge; returns the
/// status.
pub async fn hub_login_status(site: &str) -> StatusCode {
    let state = common::random::random_token().unwrap();
    let challenge = common::pkce::challenge(&common::pkce::new_verifier().unwrap());
    let mut url = Url::parse(&format!("{HUB}/broker/login")).unwrap();
    url.query_pairs_mut()
        .append_pair("site", site)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    client().get(url).send().await.unwrap().status()
}

/// A registry document written next to the teams' files for the length of a test.
pub struct TempRegistryFile(std::path::PathBuf);

impl TempRegistryFile {
    pub fn write(name: &str, contents: &str) -> Self {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../dev/registry")
            .join(name);
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }
}

impl Drop for TempRegistryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Polls `check` every 500 ms for up to `seconds`.
pub async fn eventually<F, Fut>(seconds: u64, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..seconds * 2 {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

/// Makes the Keycloak proxy answer `status` once, to the first request from the hub whose body
/// contains `matches`.
pub async fn arm_keycloak_fault(matches: &str, status: u16) {
    let response = client()
        .post(format!("{HELPERS}/faults"))
        .json(&serde_json::json!({ "matches": matches, "status": status }))
        .send()
        .await
        .expect("the test helpers are reachable");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// The back-channel logout tokens the recorder has passed on to the hub (inspection kind).
pub async fn recorded_logout_tokens() -> Vec<String> {
    client()
        .get(format!("{HELPERS}/relay/logout-tokens"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// The `client_assertion_type` of a signed JWT client assertion.
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A request to the test realm's token endpoint with `form`; its status and its `error`, if any.
pub async fn token_request(form: &[(&str, &str)]) -> (StatusCode, Option<String>) {
    let response = client()
        .post(format!(
            "{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token"
        ))
        .form(form)
        .send()
        .await
        .expect("Keycloak is reachable");
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    (status, body["error"].as_str().map(str::to_owned))
}

/// The local stack's hub client key (`dev/keys/hub-client-key.pem`), which the running hub signs
/// its client assertions with.
pub fn hub_client_key() -> jsonwebtoken::EncodingKey {
    let pem = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../dev/keys/hub-client-key.pem"
    ))
    .expect("the local hub key exists; run dev/generate-dev-keys.sh");
    jsonwebtoken::EncodingKey::from_ec_pem(&pem).expect("an EC P-256 key")
}

/// The key id the hub publishes for its client key.
pub async fn hub_client_key_id() -> String {
    let jwks: serde_json::Value = client()
        .get(format!("{HUB}/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    jwks["keys"][0]["kid"]
        .as_str()
        .expect("the hub publishes its key")
        .to_owned()
}

/// A client assertion for client `client_id`, signed with `key` under key id `kid`, expiring
/// `expires_in` seconds from now (negative for one already expired).
pub fn client_assertion(
    key: &jsonwebtoken::EncodingKey,
    kid: &str,
    client_id: &str,
    expires_in: i64,
) -> String {
    let now = now() as i64;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid.to_owned());
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": format!("{KEYCLOAK}/realms/{REALM}"),
        "jti": common::random::random_token().unwrap(),
        "iat": now,
        "exp": now + expires_in,
    });
    jsonwebtoken::encode(&header, &claims, key).expect("signing works")
}

/// Keycloak's status for exchanging `refresh_token` as the hub would for `client_id`: 200 if
/// it is still valid.
pub async fn keycloak_refresh_status(client_id: &str, refresh_token: &str) -> StatusCode {
    let assertion = client_assertion(&hub_client_key(), &hub_client_key_id().await, client_id, 60);
    token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", &assertion),
    ])
    .await
    .0
}

/// The hub's Redis, as the tests reach it.
pub async fn redis() -> redis::aio::MultiplexedConnection {
    redis::Client::open("redis://localhost:6380")
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .expect("the stack's Redis is reachable")
}

/// The session under `handle`, opened as the hub would.
pub async fn read_session(handle: &str) -> Option<serde_json::Value> {
    use redis::AsyncCommands;
    let key = format!("hub:session:{{{}}}", common::crypto::hash_key(handle));
    let raw: Option<Vec<u8>> = redis().await.get(&key).await.unwrap();
    let plain = common::sealed::open(handle, common::sealed::Purpose::Session, &raw?)?;
    Some(serde_json::from_slice(&plain).unwrap())
}

/// Stores `session` under `handle` as the hub would, keeping its expiry.
pub async fn write_session(handle: &str, session: &serde_json::Value) {
    let key = format!("hub:session:{{{}}}", common::crypto::hash_key(handle));
    let sealed = common::sealed::seal(
        handle,
        common::sealed::Purpose::Session,
        &serde_json::to_vec(session).unwrap(),
    )
    .unwrap();
    redis::cmd("SET")
        .arg(&key)
        .arg(sealed)
        .arg("KEEPTTL")
        .query_async::<()>(&mut redis().await)
        .await
        .unwrap();
}

/// Seconds until the session under `handle` expires in Redis.
pub async fn session_ttl(handle: &str) -> i64 {
    use redis::AsyncCommands;
    let key = format!("hub:session:{{{}}}", common::crypto::hash_key(handle));
    redis().await.ttl(&key).await.unwrap()
}

/// The value of counter `name` with exactly `labels` on the hub's metrics page, 0 if absent.
pub async fn hub_metric(name: &str, labels: &str) -> u64 {
    let page = client()
        .get(HUB_METRICS)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let series = format!("{name}{{{labels}}} ");
    page.lines()
        .find_map(|line| line.strip_prefix(&series))
        .map_or(0, |value| value.trim().parse().unwrap())
}

/// The status of `GET {path}` sent byte for byte to `base` with extra `headers` (`Name: value`
/// lines), bypassing the URL normalisation an HTTP client would apply to `%2e` and friends;
/// over TLS with the ingress for an `https` base.
pub async fn raw_get_status(base: &str, path: &str, headers: &[String]) -> u16 {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// Sends `request` on `stream` and reads all of the answer.
    async fn exchange(mut stream: impl AsyncRead + AsyncWrite + Unpin, request: &str) -> Vec<u8> {
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        // The ingress may close without TLS's close_notify; what arrived is enough.
        let _ = stream.read_to_end(&mut response).await;
        response
    }

    let base = Url::parse(base).unwrap();
    let name = base.host_str().unwrap().to_owned();
    // As HTTP clients send it: with the port unless it is the scheme's default. Per-kind edges
    // tell sites apart by it.
    let host = match base.port() {
        Some(port) => format!("{name}:{port}"),
        None => name.clone(),
    };
    let extra: String = headers.iter().map(|h| format!("{h}\r\n")).collect();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n");
    let response = if base.scheme() == "https" {
        use rustls_platform_verifier::ConfigVerifierExt;
        let config = rustls::ClientConfig::with_platform_verifier().expect("the platform's roots");
        let tcp = tokio::net::TcpStream::connect(ingress()).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
            .connect(rustls::pki_types::ServerName::try_from(name).unwrap(), tcp)
            .await
            .expect("TLS with the ingress");
        exchange(tls, &request).await
    } else {
        let tcp =
            tokio::net::TcpStream::connect(("127.0.0.1", base.port_or_known_default().unwrap()))
                .await
                .unwrap();
        exchange(tcp, &request).await
    };
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("an HTTP status line")
}

/// The Keycloak admin's password: `E2E_KEYCLOAK_ADMIN_PASSWORD`, or else the one the cluster
/// generated, read with kubectl from the cluster's own context; `test` in the compose stack.
pub fn admin_password() -> &'static str {
    static PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PASSWORD.get_or_init(|| {
        if cfg!(feature = "load") {
            return "test".to_owned();
        }
        if let Ok(password) = std::env::var("E2E_KEYCLOAK_ADMIN_PASSWORD") {
            return password;
        }
        let password = kubectl(&[
            "get",
            "secret",
            "keycloak-admin",
            "-o",
            "jsonpath={.data.password}",
        ]);
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(password.trim())
            .expect("base64");
        String::from_utf8(decoded).expect("the password is text")
    })
}

/// The output of `kubectl` with `args`, in the cluster's own context and namespace; panics with
/// its error output if it fails.
pub fn kubectl(args: &[&str]) -> String {
    let output = std::process::Command::new("kubectl")
        .args(["--context", "kind-auth-broker", "-n", "auth-broker"])
        .args(args)
        .output()
        .expect("kubectl runs");
    assert!(
        output.status.success(),
        "kubectl {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Runs the organization sync once, as the cluster's suspended CronJob would; whether it
/// succeeded, and its output.
pub fn run_organization_sync() -> (bool, String) {
    let job = format!("sync-{}", now());
    kubectl(&["create", "job", &job, "--from=cronjob/organization-sync"]);
    let finished = std::process::Command::new("kubectl")
        .args(["--context", "kind-auth-broker", "-n", "auth-broker", "wait"])
        .args([
            &format!("job/{job}"),
            "--for=condition=Complete",
            "--timeout=120s",
        ])
        .output()
        .expect("kubectl runs")
        .status
        .success();
    let output = kubectl(&["logs", &format!("job/{job}")]);
    kubectl(&["delete", "job", &job, "--wait=false"]);
    (finished, output)
}

/// A Keycloak admin access token.
pub async fn admin_token() -> String {
    let token: serde_json::Value = client()
        .post(format!(
            "{KEYCLOAK}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "admin"),
            ("password", admin_password()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    token["access_token"].as_str().unwrap().to_owned()
}

/// `method` on admin path `path` of the test realm with optional JSON `body`; the response.
pub async fn admin(method: Method, path: &str, body: Option<serde_json::Value>) -> Response {
    let mut request = client()
        .request(method, format!("{KEYCLOAK}/admin/realms/{REALM}{path}"))
        .bearer_auth(admin_token().await);
    if let Some(body) = body {
        request = request.json(&body);
    }
    request.send().await.unwrap()
}

/// The id of user `username`.
pub async fn user_id(username: &str) -> String {
    let users: serde_json::Value = admin(
        Method::GET,
        &format!("/users?username={username}&exact=true"),
        None,
    )
    .await
    .json()
    .await
    .unwrap();
    users[0]["id"].as_str().expect("user exists").to_owned()
}

/// The organization of site `alias`, in full.
pub async fn organization(alias: &str) -> serde_json::Value {
    let found: serde_json::Value = admin(
        Method::GET,
        &format!("/organizations?search={alias}&exact=true"),
        None,
    )
    .await
    .json()
    .await
    .unwrap();
    let id = found[0]["id"]
        .as_str()
        .expect("organization exists")
        .to_owned();
    admin(Method::GET, &format!("/organizations/{id}"), None)
        .await
        .json()
        .await
        .unwrap()
}

/// Native installation key `name` (`dev/keys/installation-<name>.key`), as its desktop app holds it.
pub fn installation_key(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../dev/keys/installation-{name}.key",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the installation's key exists; dev/k8s/up.sh creates it")
}

/// Native installation `site_id`'s desktop app, signing with `key` (see [`installation_key`]).
pub fn installation_with(site_id: &str, key: &str) -> native_app::Installation {
    native_app::Installation::new(Url::parse(HUB).unwrap(), site_id, key, client()).unwrap()
}

/// Native installation `site_id`'s desktop app, with its own key.
pub fn installation(site_id: &str) -> native_app::Installation {
    installation_with(site_id, &installation_key(site_id))
}

/// Plays the system browser for a native app's sign-in at hub URL `url` as `user`: through the
/// hub and Keycloak's login form, and back to the app's loopback address, where the app takes
/// the code. Returns the hub's answer to the provider's redirect, for tests that expect the hub
/// to refuse.
pub async fn sign_in_in_system_browser(url: &Url, user: &str) -> Response {
    let mut browser = Browser::new();
    let started = browser.get(url.as_str()).await;
    assert_eq!(
        started.status(),
        StatusCode::SEE_OTHER,
        "the hub starts the sign-in"
    );
    let page = browser.get(location(&started).as_str()).await;
    assert_eq!(
        page.status(),
        StatusCode::OK,
        "Keycloak shows its login page"
    );
    let submitted = submit_credentials(&mut browser, page, user).await;
    assert_eq!(
        submitted.status(),
        StatusCode::FOUND,
        "Keycloak accepts the credentials"
    );
    let at_hub = browser.get(location(&submitted).as_str()).await;
    if at_hub.status() == StatusCode::SEE_OTHER {
        // Back to the app's loopback address, as the system browser would follow it.
        let back = location(&at_hub);
        assert_eq!(
            back.host_str(),
            Some("127.0.0.1"),
            "only to the loopback address"
        );
        let _ = browser.get(back.as_str()).await;
    }
    at_hub
}

/// Signs `user` in at native installation `app`, as its desktop app does with the system browser.
pub async fn native_sign_in(app: &native_app::Installation, user: &str) -> native_app::Session {
    let sign_in = app.begin_sign_in("/callback").await.unwrap();
    let url = sign_in.url().clone();
    let (session, _) = tokio::join!(
        app.finish_sign_in(sign_in, Duration::from_secs(30)),
        sign_in_in_system_browser(&url, user)
    );
    session.expect("the app redeems the code")
}
