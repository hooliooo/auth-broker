//! `native-app`: a stand-in desktop app for one native installation.
//!
//! ```text
//! native-app keygen <site id> <key file>   make the installation's key; prints its registry entry
//! native-app sign-in                       sign in through the system browser
//! native-app whoami                        who is signed in, as the hub sees it
//! native-app token                         a fresh access token naming the installation
//! native-app call <url>                    GET <url> with that access token, e.g. the API
//! native-app sign-out                      end the session
//! ```
//!
//! Settings, from the environment: `NATIVE_HUB_URL` (the hub), `NATIVE_SITE_ID` (the
//! installation), `NATIVE_KEY_FILE` (its key), `NATIVE_REDIRECT_PATH` (the kind's, default
//! `/callback`), `NATIVE_SESSION_FILE` (where the session handle is kept, default
//! `.native-session`), and `NATIVE_HUB_ADDR` to send the hub's name to a fixed address, e.g.
//! `127.0.0.1:443` for the local cluster.

use std::{io::Write, net::SocketAddr, process::ExitCode};

use native_app::{Installation, SIGN_IN_TIMEOUT, Session};
use reqwest::{Client, Url};

/// Runs the command; a failure is printed with its message and exits with 1.
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Setting `name`, required.
fn setting(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

/// The installation the settings describe.
fn installation() -> Result<Installation, Box<dyn std::error::Error>> {
    let hub = Url::parse(&setting("NATIVE_HUB_URL")?)?;
    let mut http = Client::builder();
    if let (Ok(addr), Some(host)) = (std::env::var("NATIVE_HUB_ADDR"), hub.host_str()) {
        http = http.resolve(host, addr.parse::<SocketAddr>()?);
    }
    let key = std::fs::read_to_string(setting("NATIVE_KEY_FILE")?)?;
    Ok(Installation::new(
        hub,
        &setting("NATIVE_SITE_ID")?,
        &key,
        http.build()?,
    )?)
}

/// Where the session handle is kept.
fn session_file() -> String {
    std::env::var("NATIVE_SESSION_FILE").unwrap_or_else(|_| ".native-session".into())
}

/// The saved session, if signed in.
fn session() -> Result<Session, Box<dyn std::error::Error>> {
    let handle = std::fs::read_to_string(session_file())
        .map_err(|_| "not signed in; run native-app sign-in")?;
    Ok(Session {
        handle: handle.trim().to_owned(),
    })
}

/// Writes `contents` to a new file at `path`, readable only by its owner.
fn write_private(path: &str, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents.as_bytes())
}

/// Opens `url` in the system browser, never an embedded one (RFC 8252 §8.12).
fn open_in_browser(url: &Url) {
    let opened = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
            .arg(url.as_str())
            .status()
    } else if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url.as_str()])
            .status()
    } else {
        std::process::Command::new("xdg-open")
            .arg(url.as_str())
            .status()
    };
    if !opened.is_ok_and(|status| status.success()) {
        println!("Open this address in your browser to sign in:");
    }
    println!("{url}");
}

/// Runs the command line.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", site, key_file] => {
            let key = common::signing::generate_key()?;
            let public = common::signing::EdgeSigner::from_base64(site, &key)?.public_key();
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(key_file)?.write_all(key.as_bytes())?;
            println!("{}", serde_json::json!({ "id": site, "keys": [public] }));
        }
        ["sign-in"] => {
            let installation = installation()?;
            let redirect_path =
                std::env::var("NATIVE_REDIRECT_PATH").unwrap_or_else(|_| "/callback".into());
            let sign_in = installation.begin_sign_in(&redirect_path).await?;
            open_in_browser(sign_in.url());
            let session = installation.finish_sign_in(sign_in, SIGN_IN_TIMEOUT).await?;
            write_private(&session_file(), &session.handle)?;
            println!("{}", installation.whoami(&session).await?);
        }
        ["whoami"] => println!("{}", installation()?.whoami(&session()?).await?),
        ["token"] => println!("{}", installation()?.access_token(&session()?).await?.access_token),
        ["call", url] => {
            let token = installation()?.access_token(&session()?).await?;
            let response = Client::new().get(*url).bearer_auth(&token.access_token).send().await?;
            println!("{}\n{}", response.status(), response.text().await?);
        }
        ["sign-out"] => {
            println!("{}", installation()?.sign_out(&session()?).await?);
            let _ = std::fs::remove_file(session_file());
        }
        _ => return Err("usage: native-app keygen <site> <key file> | sign-in | whoami | token | call <url> | sign-out".into()),
    }
    Ok(())
}
