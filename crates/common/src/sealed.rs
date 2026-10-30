//! Encrypts values stored in Redis with a key derived from a secret the client holds (a session
//! handle, a login `state`, a handoff code). Redis only ever sees a hash of that secret, so a
//! Redis dump is unreadable, and a value cannot be moved to another key or purpose.

use std::sync::LazyLock;

use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hkdf::{HKDF_SHA256, Salt},
};

use crate::random::{RandomUnavailable, random_bytes};

/// What a sealed value is; part of its key and authenticated, so one kind of value can never
/// be opened as another.
#[derive(Clone, Copy)]
pub enum Purpose {
    /// A sign-in waiting for the provider's callback, sealed under the hub's `state`.
    PendingLogin,
    /// A finished sign-in waiting for its edge, sealed under the handoff code.
    Handoff,
    /// A session, sealed under its handle.
    Session,
}

impl Purpose {
    /// The purpose's fixed label: HKDF info and AEAD associated data.
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::PendingLogin => b"hub:pending-login:v1",
            Purpose::Handoff => b"hub:handoff:v1",
            Purpose::Session => b"hub:session:v1",
        }
    }
}

/// Fixed per application; built once because constructing a `Salt` precomputes an HMAC key.
static SALT: LazyLock<Salt> = LazyLock::new(|| Salt::new(HKDF_SHA256, b"hub-sealed-v1"));

/// The ChaCha20-Poly1305 key for values of `purpose` sealed under `secret`: HKDF-SHA256 with the
/// fixed salt and the purpose's label.
fn key_for(secret: &str, purpose: Purpose) -> LessSafeKey {
    let prk = SALT.extract(secret.as_bytes());
    let info = [purpose.label()];
    let okm = prk
        .expand(&info, &CHACHA20_POLY1305)
        .expect("ChaCha20-Poly1305 key length is valid for HKDF-SHA256");
    LessSafeKey::new(UnboundKey::from(okm))
}

/// `plaintext` encrypted for `purpose` under a key derived from `secret`, as
/// `nonce || ciphertext || tag`.
pub fn seal(
    secret: &str,
    purpose: Purpose,
    plaintext: &[u8],
) -> Result<Vec<u8>, RandomUnavailable> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let mut buffer = plaintext.to_vec();
    key_for(secret, purpose)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(purpose.label()),
            &mut buffer,
        )
        .map_err(|_| RandomUnavailable)?;
    let mut sealed = nonce.to_vec();
    sealed.extend(buffer);
    Ok(sealed)
}

/// The plaintext of `sealed`; `None` for anything not sealed with `secret` and `purpose`.
pub fn open(secret: &str, purpose: Purpose, sealed: &[u8]) -> Option<Vec<u8>> {
    let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
    let mut buffer = ciphertext.to_vec();
    let plaintext = key_for(secret, purpose)
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::from(purpose.label()),
            &mut buffer,
        )
        .ok()?;
    Some(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_a_sealed_value_when_opened_with_the_same_secret_and_purpose_then_it_round_trips() {
        let sealed = seal("handle", Purpose::Session, b"payload").unwrap();
        assert_eq!(
            open("handle", Purpose::Session, &sealed).as_deref(),
            Some(&b"payload"[..])
        );
    }

    #[test]
    fn given_any_single_bit_flip_or_wrong_context_when_opening_then_it_fails() {
        let sealed = seal("handle", Purpose::Session, b"payload").unwrap();
        assert!(open("other", Purpose::Session, &sealed).is_none());
        assert!(open("handle", Purpose::Handoff, &sealed).is_none());
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(
                open("handle", Purpose::Session, &tampered).is_none(),
                "byte {i}"
            );
        }
        assert!(open("handle", Purpose::Session, &sealed[..5]).is_none());
    }
}
