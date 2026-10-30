//! Hashing and comparison helpers for secrets.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};
use subtle::ConstantTimeEq;

/// SHA-256 of `value`, base64url-encoded: Redis keys never contain secret values.
pub fn hash_key(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, value.as_bytes()).as_ref())
}

/// Whether `a` equals `b`, in time independent of where they differ.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
