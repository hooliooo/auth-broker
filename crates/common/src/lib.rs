//! Shared building blocks for the auth broker.
//!
//! The hub and every edge link this crate, so both sides agree byte for byte on how requests
//! are signed, how sites are registered, and how cookies, CSRF and proxied headers are
//! handled. Several modules are the Rust BFF's (`auth-api`'s `crates/bff`), shared here by both
//! binaries.
#![warn(missing_docs)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

#[cfg(feature = "alloc-stats")]
pub mod alloc;
pub mod api_path;
pub mod causes;
pub mod client;
pub mod cookie;
pub mod crypto;
pub mod csrf;
pub mod headers;
pub mod metrics;
pub mod pkce;
pub mod provider;
pub mod random;
pub mod registry;
pub mod request_id;
pub mod return_url;
pub mod sealed;
pub mod shutdown;
pub mod signing;
pub mod transport;
