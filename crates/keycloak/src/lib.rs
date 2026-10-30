//! Keycloak as the auth broker's identity provider.
//!
//! - Sites are Keycloak organizations, requested with the dynamic scope
//!   `organization:<alias>`; with the mapper's id and attribute options, the `organization`
//!   claim is an object keyed by alias, otherwise a list of aliases. The membership extension in
//!   `providers/keycloak/extension` makes sure a token names exactly one the user belongs to.
//! - Roles are realm roles, in `realm_access.roles`.
//! - Tokens carry `typ`: `ID` for ID tokens, `Bearer` for access tokens.
//! - Token responses carry `refresh_expires_in`: the time left in Keycloak's session.
//! - The end-session endpoint accepts a refresh token server to server.
#![warn(missing_docs)]

use common::provider::{IdentityProvider, Logout, string_list};
use serde_json::Value;

/// Keycloak's specifics.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keycloak;

impl IdentityProvider for Keycloak {
    fn name(&self) -> &'static str {
        "keycloak"
    }

    fn site_scope(&self, site_id: &str) -> Option<String> {
        Some(format!("organization:{site_id}"))
    }

    fn sites(&self, claims: &Value) -> Vec<String> {
        match &claims["organization"] {
            Value::Object(by_alias) => by_alias.keys().cloned().collect(),
            claim => string_list(claim),
        }
    }

    fn roles(&self, claims: &Value) -> Vec<String> {
        string_list(&claims["realm_access"]["roles"])
    }

    fn is_id_token(&self, claims: &Value) -> bool {
        claims["typ"] == "ID"
    }

    fn is_access_token(&self, claims: &Value) -> bool {
        claims["typ"] == "Bearer"
    }

    fn session_lifetime_secs(&self, token_response: &Value) -> Option<u64> {
        // 0 marks tokens that never expire on their own (offline tokens): no lifetime to follow.
        token_response["refresh_expires_in"]
            .as_u64()
            .filter(|secs| *secs > 0)
    }

    fn logout(&self) -> Logout {
        Logout::RefreshTokenAtEndSession
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn given_either_organization_claim_shape_then_the_aliases_are_read() {
        assert_eq!(
            Keycloak.sites(&json!({ "organization": ["plant-d"] })),
            ["plant-d"]
        );
        assert_eq!(
            Keycloak.sites(&json!({ "organization": { "plant-d": { "id": "1" } } })),
            ["plant-d"]
        );
        assert!(Keycloak.sites(&json!({})).is_empty());
        assert_eq!(
            Keycloak.site_scope("plant-d").as_deref(),
            Some("organization:plant-d")
        );
    }

    #[test]
    fn given_keycloak_claims_then_roles_types_and_lifetimes_are_read() {
        let claims = json!({ "typ": "Bearer", "realm_access": { "roles": ["maintenance-user"] } });
        assert_eq!(Keycloak.roles(&claims), ["maintenance-user"]);
        assert!(Keycloak.is_access_token(&claims));
        assert!(!Keycloak.is_id_token(&claims));
        assert_eq!(
            Keycloak.session_lifetime_secs(&json!({ "refresh_expires_in": 1800 })),
            Some(1800)
        );
        assert_eq!(
            Keycloak.session_lifetime_secs(&json!({ "refresh_expires_in": 0 })),
            None
        );
        assert_eq!(Keycloak.logout(), Logout::RefreshTokenAtEndSession);
    }
}
