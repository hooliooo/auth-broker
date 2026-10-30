//! Random values from the operating system.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

/// The operating system's random source failed.
#[derive(Debug, Error)]
#[error("OS random source unavailable")]
pub struct RandomUnavailable;

/// `N` random bytes.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], RandomUnavailable> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| RandomUnavailable)?;
    Ok(bytes)
}

/// 256 random bits, base64url without padding (43 characters).
pub fn random_token() -> Result<String, RandomUnavailable> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}
