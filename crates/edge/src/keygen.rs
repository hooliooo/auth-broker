//! `edge keygen <app-id> <key-file>`: a new key for an app kind's edge.
//!
//! Writes the kind's private edge key to `<key-file>` (readable only by its owner) and prints
//! the `edge_public_key` line for the kind's registry file. Adding a site needs no key: one entry
//! in the registry's `sites` list, served by the kind's existing edge.

use std::{fs::OpenOptions, io::Write};

use common::signing::{EdgeSigner, generate_key};

/// Runs `keygen` with `args`: the app kind and the key file.
pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [app_id, key_file] = args else {
        return Err("usage: edge keygen <app-id> <key-file>".into());
    };
    let key = generate_key()?;
    let signer = EdgeSigner::from_base64(app_id, &key)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(key_file)?.write_all(key.as_bytes())?;

    eprintln!(
        "Private key written to {key_file}; mount it as EDGE_KEY_FILE for the '{app_id}' edge."
    );
    eprintln!("Set this in the \"app\" object of the kind's registry file:");
    println!(
        "{}",
        serde_json::json!({ "edge_public_key": signer.public_key() })
    );
    Ok(())
}
