//! The desktop side of a native installation (RFC 8252, OAuth 2.0 for Native Apps).
//!
//! A desktop app at an installation signs its users in through the hub, never through an
//! identity-provider client of its own:
//!
//! 1. [`Installation::begin_sign_in`] listens on the loopback interface at a free port and
//!    makes a `state` and a PKCE verifier; the app opens [`SignIn::url`] in the system browser
//!    (never an embedded web view, RFC 8252 §8.12).
//! 2. The hub signs the user in at the provider with the kind's client and the installation's
//!    scope, keeps the refresh token, and sends the browser back to the loopback address with a
//!    one-time code.
//! 3. [`Installation::finish_sign_in`] takes the code from the loopback request, checks the
//!    `state`, and redeems the code with the PKCE verifier in a request signed with the
//!    installation's key: only this installation can, and only this app instance holds the
//!    verifier. The answer is a session handle, not a token.
//! 4. [`Installation::access_token`] fetches short-lived access tokens naming the installation,
//!    for its API; [`Installation::sign_out`] ends the session.
//!
//! Every request to the hub is signed with the installation's Ed25519 key, the same way an edge
//! signs, so the hub knows exactly which installation is calling.

use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::{
    crypto::constant_time_eq,
    headers, pkce,
    random::{RandomUnavailable, random_token},
    signing::{EdgeSigner, SigningError},
};
use reqwest::{
    Client, Method, RequestBuilder, Url,
    header::{HeaderMap, HeaderValue},
};
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// How long the app waits for the browser to come back from signing in.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

/// Why signing in or talking to the hub failed.
#[derive(Debug, Error)]
pub enum Error {
    /// The installation's key is unusable.
    #[error(transparent)]
    Key(#[from] SigningError),
    /// The random source failed.
    #[error(transparent)]
    Random(#[from] RandomUnavailable),
    /// The loopback listener failed.
    #[error("loopback listener: {0}")]
    Io(#[from] std::io::Error),
    /// The hub could not be reached.
    #[error("hub unreachable: {0}")]
    Http(#[from] reqwest::Error),
    /// The hub refused a request: its status.
    #[error("the hub answered {0}")]
    Refused(reqwest::StatusCode),
    /// The browser came back with another sign-in's `state`.
    #[error("the browser came back with another sign-in's state")]
    StateMismatch,
    /// The browser came back with an error instead of a code.
    #[error("sign-in failed: {0}")]
    SignInFailed(String),
    /// The browser did not come back in time.
    #[error("the browser did not come back within {0:?}")]
    Timeout(Duration),
}

/// One native installation, as its desktop app knows it: its id, its key, and the hub.
pub struct Installation {
    /// The hub's public address, e.g. `https://hub.broker.localhost`.
    hub: Url,
    /// The installation's id in the registry.
    site_id: String,
    /// Signs every request with the installation's key.
    signer: EdgeSigner,
    /// Calls the hub.
    http: Client,
}

/// A signed-in session: the hub's handle for it. Not a token; worthless without the
/// installation's key.
#[derive(Clone, Debug)]
pub struct Session {
    /// The session handle.
    pub handle: String,
}

/// A sign-in in progress: the browser is, or is about to be, at [`Self::url`].
pub struct SignIn {
    /// Where to send the system browser.
    url: Url,
    /// The loopback listener the browser comes back to.
    listener: TcpListener,
    /// The path the browser comes back to, e.g. `/callback`.
    redirect_path: String,
    /// Must come back with the code.
    state: String,
    /// Redeems the code; never leaves this process before then.
    verifier: String,
}

impl SignIn {
    /// Where the app sends the system browser.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Waits up to `timeout` for the browser at the loopback address; the one-time code it
    /// brings, once its `state` is this sign-in's.
    pub async fn wait_for_code(&self, timeout: Duration) -> Result<String, Error> {
        tokio::time::timeout(timeout, wait_for_code(self))
            .await
            .map_err(|_| Error::Timeout(timeout))?
    }

    /// The PKCE verifier that redeems the code.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }
}

/// Answer of the hub's `/broker/redeem`.
#[derive(Deserialize)]
struct Redeemed {
    /// The session handle.
    handle: String,
}

/// Answer of the hub's `/broker/token`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessToken {
    /// The provider's access token, naming the installation.
    pub access_token: String,
    /// Seconds until it expires.
    pub expires_in: u64,
}

/// The current time in Unix seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Installation {
    /// Installation `site_id` with its key `key` (base64url PKCS#8, as `native-app keygen`
    /// writes it), calling the hub at `hub` with `http`.
    pub fn new(hub: Url, site_id: &str, key: &str, http: Client) -> Result<Self, Error> {
        Ok(Self {
            hub,
            site_id: site_id.to_owned(),
            signer: EdgeSigner::from_base64(site_id, key)?,
            http,
        })
    }

    /// The installation's `keys` entry for the registry.
    pub fn public_key(&self) -> String {
        self.signer.public_key()
    }

    /// Starts a sign-in: listens on `127.0.0.1` at a free port for the browser's return to
    /// `redirect_path` (the kind's registered path), and builds the hub URL to open in the
    /// system browser.
    pub async fn begin_sign_in(&self, redirect_path: &str) -> Result<SignIn, Error> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let (state, verifier) = (random_token()?, pkce::new_verifier()?);
        let mut url = self.hub.join("/broker/login").expect("a fixed path joins");
        url.query_pairs_mut()
            .append_pair("site", &self.site_id)
            .append_pair(
                "redirect_uri",
                &format!("http://127.0.0.1:{port}{redirect_path}"),
            )
            .append_pair("state", &state)
            .append_pair("code_challenge", &pkce::challenge(&verifier))
            .append_pair("code_challenge_method", pkce::METHOD);
        Ok(SignIn {
            url,
            listener,
            redirect_path: redirect_path.to_owned(),
            state,
            verifier,
        })
    }

    /// Finishes `sign_in`: waits up to `timeout` for the browser at the loopback address,
    /// checks its `state`, and redeems the code at the hub.
    pub async fn finish_sign_in(
        &self,
        sign_in: SignIn,
        timeout: Duration,
    ) -> Result<Session, Error> {
        let code = sign_in.wait_for_code(timeout).await?;
        self.redeem(&code, &sign_in.verifier).await
    }

    /// Trades one-time `code` and PKCE `verifier` for a session, in a signed request.
    pub async fn redeem(&self, code: &str, verifier: &str) -> Result<Session, Error> {
        let response = self
            .signed(Method::POST, "/broker/redeem", None)?
            .json(&json!({ "code": code, "code_verifier": verifier }))
            .send()
            .await?;
        let redeemed: Redeemed = accepted(response)?.json().await?;
        Ok(Session {
            handle: redeemed.handle,
        })
    }

    /// Who is signed in, as the hub sees `session`: the user, the installation and its tenant.
    pub async fn whoami(&self, session: &Session) -> Result<Value, Error> {
        let response = self
            .signed(Method::GET, "/broker/session", Some(&session.handle))?
            .send()
            .await?;
        Ok(accepted(response)?.json().await?)
    }

    /// A short-lived access token for `session`, naming this installation, for its API. The
    /// hub refreshes it at the provider when needed; the refresh token never leaves the hub.
    pub async fn access_token(&self, session: &Session) -> Result<AccessToken, Error> {
        let response = self
            .signed(Method::POST, "/broker/token", Some(&session.handle))?
            .send()
            .await?;
        Ok(accepted(response)?.json().await?)
    }

    /// Ends `session` at the hub and the provider; returns where the browser may finish
    /// signing out, if the provider needs it.
    pub async fn sign_out(&self, session: &Session) -> Result<Value, Error> {
        let response = self
            .signed(Method::POST, "/broker/logout", Some(&session.handle))?
            .send()
            .await?;
        Ok(accepted(response)?.json().await?)
    }

    /// A request to the hub, signed with the installation's key for `method`, `path` and the
    /// session `handle`.
    fn signed(
        &self,
        method: Method,
        path: &str,
        handle: Option<&str>,
    ) -> Result<RequestBuilder, Error> {
        let signed = self
            .signer
            .sign(&self.site_id, method.as_str(), path, handle, now())?;
        let mut headers = HeaderMap::new();
        signed.apply(&mut headers);
        if let Some(handle) = handle {
            headers.insert(
                headers::SESSION_HANDLE,
                HeaderValue::from_str(handle)
                    .map_err(|_| Error::Refused(reqwest::StatusCode::BAD_REQUEST))?,
            );
        }
        let url = self.hub.join(path).expect("a fixed path joins");
        Ok(self.http.request(method, url).headers(headers))
    }
}

/// `response` if the hub accepted the request.
fn accepted(response: reqwest::Response) -> Result<reqwest::Response, Error> {
    match response.status() {
        status if status.is_success() => Ok(response),
        status => Err(Error::Refused(status)),
    }
}

/// What the browser shows once it is back at the app.
const DONE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>Signed in</title>\
    <p>You are signed in. You can close this window and return to the application.</p>";

/// Serves the loopback listener of `sign_in` until the browser arrives at its redirect path
/// with a code and the right `state`; other requests (a favicon, say) get a 404.
async fn wait_for_code(sign_in: &SignIn) -> Result<String, Error> {
    loop {
        let (mut stream, _) = sign_in.listener.accept().await?;
        let mut request = Vec::new();
        let mut buffer = [0u8; 2048];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 16 * 1024 {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let head = String::from_utf8_lossy(&request);
        let target = head.split_whitespace().nth(1).unwrap_or("/");
        let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
            continue;
        };
        if url.path() != sign_in.redirect_path {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            continue;
        }
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        let body = DONE_PAGE;
        let _ = stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        if let Some(error) = param("error") {
            return Err(Error::SignInFailed(error));
        }
        // Only this sign-in's state proves the browser was sent by this app.
        match (param("code"), param("state")) {
            (Some(code), Some(state)) if constant_time_eq(&state, &sign_in.state) => {
                return Ok(code);
            }
            _ => return Err(Error::StateMismatch),
        }
    }
}
