//! Verifies tokens from an OpenID Connect provider.
//!
//! - [`oidc`]: discovery, signature checks against the provider's published keys, and the
//!   standard claim validations. Providers differ only in how claims are read
//!   ([`ProviderClaims`]).
//! - [`logout`]: the extra checks for back-channel logout tokens.
#![warn(missing_docs)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

mod cache;
mod causes;
pub mod logout;
pub mod oidc;

pub use oidc::{
    OidcJwtVerifier, OidcSetupError, ProviderClaims, Transport, WellKnownEndpoint,
    WellKnownEndpointError,
};
