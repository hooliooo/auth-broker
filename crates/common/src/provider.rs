//! What the hub needs to know about its identity provider beyond standard OpenID Connect: how to
//! ask for one site, where sites and roles are in a token, how token types and
//! session lifetimes are marked, and how a session is ended. The hub and the test API depend
//! only on [`IdentityProvider`]; each provider is one implementation of it ([`StandardOidc`]
//! here, Keycloak in its own crate).

use serde_json::Value;

/// How the hub ends a session at the provider when the user signs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Logout {
    /// Server to server: the session's refresh token, with client authentication, to the
    /// end-session endpoint (Keycloak). The browser then goes straight to the site.
    RefreshTokenAtEndSession,
    /// Revoke the refresh token (RFC 7009), then send the browser to the provider's end-session
    /// page (OpenID Connect RP-Initiated Logout), where the provider's own session ends.
    RevokeThenBrowser,
}

/// An identity provider's specifics.
pub trait IdentityProvider: Send + Sync {
    /// The provider's name, for logs and settings.
    fn name(&self) -> &'static str;

    /// The scope a sign-in at site `site_id` adds, for a kind whose tokens must
    /// name the site; `None` if the provider cannot name sites in tokens.
    fn site_scope(&self, site_id: &str) -> Option<String>;

    /// The sites access-token `claims` name.
    fn sites(&self, claims: &Value) -> Vec<String>;

    /// The roles access-token `claims` carry.
    fn roles(&self, claims: &Value) -> Vec<String>;

    /// Whether verified `claims` can be an ID token's; `false` only when the provider marks
    /// token types and these are marked otherwise.
    fn is_id_token(&self, claims: &Value) -> bool;

    /// Whether verified `claims` can be an access token's, by the same rule.
    fn is_access_token(&self, claims: &Value) -> bool;

    /// How long the session behind `token_response` lasts, in seconds, if the provider says.
    fn session_lifetime_secs(&self, token_response: &Value) -> Option<u64>;

    /// How the hub ends a session here.
    fn logout(&self) -> Logout;
}

/// Any OpenID Connect provider, with only standard claims: roles in a top-level `roles` claim,
/// no site claims, no token-type marks in the payload, no session lifetime in token
/// responses, and logout by revocation plus the browser. Kinds whose tokens must name their
/// site need a provider that can ([`IdentityProvider::site_scope`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct StandardOidc;

impl IdentityProvider for StandardOidc {
    fn name(&self) -> &'static str {
        "oidc"
    }

    fn site_scope(&self, _site_id: &str) -> Option<String> {
        None
    }

    fn sites(&self, _claims: &Value) -> Vec<String> {
        Vec::new()
    }

    fn roles(&self, claims: &Value) -> Vec<String> {
        string_list(&claims["roles"])
    }

    fn is_id_token(&self, _claims: &Value) -> bool {
        true
    }

    fn is_access_token(&self, _claims: &Value) -> bool {
        true
    }

    fn session_lifetime_secs(&self, _token_response: &Value) -> Option<u64> {
        None
    }

    fn logout(&self) -> Logout {
        Logout::RevokeThenBrowser
    }
}

/// The strings in JSON array `value`; empty for anything else.
pub fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn given_standard_claims_then_roles_come_from_the_roles_claim_and_no_site_is_named() {
        let claims = json!({ "roles": ["inspection-user", 7], "organization": ["plant-a"] });
        assert_eq!(StandardOidc.roles(&claims), ["inspection-user"]);
        assert!(StandardOidc.sites(&claims).is_empty());
        assert_eq!(StandardOidc.site_scope("plant-a"), None);
        assert_eq!(StandardOidc.logout(), Logout::RevokeThenBrowser);
    }
}
