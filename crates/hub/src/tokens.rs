//! Checks on access tokens the hub received directly from the identity provider's token
//! endpoint.
//!
//! These tokens arrive over the hub's own TLS connection to the provider, so their claims are
//! read without re-verifying the signature; the API verifies the signature on every request.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{provider::IdentityProvider, registry::App};
use serde_json::Value;

/// Why an access token may not be used for a kind.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The provider issued a token without this kind's audience: a provider misconfiguration.
    MissingAudience,
    /// The user lacks the role this kind requires.
    MissingRole,
    /// A direct kind's token does not name exactly the site.
    WrongSite,
    /// The token is not marked as an access token.
    NotAnAccessToken,
    /// The token is not a readable JWT.
    Unreadable,
}

/// The payload of JWT `token`, unverified.
fn claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// Whether `access_token`, read the way `provider` writes tokens, carries realm role `role`.
pub fn has_role(provider: &dyn IdentityProvider, access_token: &str, role: &str) -> bool {
    claims(access_token).is_some_and(|claims| provider.roles(&claims).iter().any(|r| r == role))
}

/// Whether `access_token` may be used for `app` at site `site_id`, read the way
/// `provider` writes tokens: an access token, the right audience, the required role if any, and
/// for a direct kind exactly the site.
pub fn check(
    provider: &dyn IdentityProvider,
    app: &App,
    site_id: &str,
    access_token: &str,
) -> Result<(), Refusal> {
    let claims = claims(access_token).ok_or(Refusal::Unreadable)?;
    if !provider.is_access_token(&claims) {
        return Err(Refusal::NotAnAccessToken);
    }
    let audience_ok = match &claims["aud"] {
        Value::String(aud) => aud == &app.api_audience,
        Value::Array(auds) => auds
            .iter()
            .any(|a| a.as_str() == Some(app.api_audience.as_str())),
        _ => false,
    };
    if !audience_ok {
        return Err(Refusal::MissingAudience);
    }
    if let Some(role) = &app.required_role
        && !provider.roles(&claims).contains(role)
    {
        return Err(Refusal::MissingRole);
    }
    if app.direct() && provider.sites(&claims) != [site_id] {
        return Err(Refusal::WrongSite);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use common::registry::Registry;
    use keycloak::Keycloak;
    use serde_json::json;

    use super::*;

    /// The kind `inspection`, through the hub, requiring `required_role` if given.
    fn app(required_role: Option<&str>) -> App {
        let role = required_role.map_or(String::new(), |r| format!(r#", "required_role": "{r}""#));
        let doc = format!(
            r#"{{ "app": {{ "id": "inspection", "client_id": "hub-inspection", "edge_public_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "api_upstream": "http://api", "api_audience": "inspection-api"{role} }} }}"#
        );
        Registry::from_documents([("a.json", doc.as_str())])
            .unwrap()
            .apps()[0]
            .clone()
    }

    /// An unsigned JWT with `claims`.
    fn token(claims: Value) -> String {
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    #[test]
    fn given_a_direct_kind_then_exactly_the_site_is_required() {
        let direct = Registry::from_documents([(
            "a.json",
            r#"{ "app": { "id": "maintenance", "client_id": "hub-m", "edge_public_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "api_audience": "m-api" } }"#,
        )])
        .unwrap()
        .apps()[0]
            .clone();
        let with = |organization: Value| {
            token(json!({ "typ": "Bearer", "aud": "m-api", "organization": organization }))
        };
        assert_eq!(
            check(&Keycloak, &direct, "plant-d", &with(json!(["plant-d"]))),
            Ok(())
        );
        assert_eq!(
            check(
                &Keycloak,
                &direct,
                "plant-d",
                &with(json!({ "plant-d": { "id": "1" } }))
            ),
            Ok(())
        );
        for wrong in [json!(["plant-e"]), json!(["plant-d", "plant-e"]), json!([])] {
            assert_eq!(
                check(&Keycloak, &direct, "plant-d", &with(wrong)),
                Err(Refusal::WrongSite)
            );
        }
    }

    #[test]
    fn given_tokens_when_checked_against_an_app_then_type_audience_and_role_decide() {
        let roles = |r: &str| json!({ "roles": [r] });
        let with_role = token(
            json!({ "typ": "Bearer", "aud": ["inspection-api", "account"], "realm_access": roles("inspection-user") }),
        );
        assert_eq!(
            check(
                &Keycloak,
                &app(Some("inspection-user")),
                "plant-a",
                &with_role
            ),
            Ok(())
        );
        let other_kind = token(
            json!({ "typ": "Bearer", "aud": ["billing-api"], "realm_access": roles("inspection-user") }),
        );
        assert_eq!(
            check(
                &Keycloak,
                &app(Some("inspection-user")),
                "plant-a",
                &other_kind
            ),
            Err(Refusal::MissingAudience)
        );
        let no_role = token(
            json!({ "typ": "Bearer", "aud": "inspection-api", "realm_access": roles("billing-user") }),
        );
        assert_eq!(
            check(
                &Keycloak,
                &app(Some("inspection-user")),
                "plant-a",
                &no_role
            ),
            Err(Refusal::MissingRole)
        );
        let id_token = token(json!({ "typ": "ID", "aud": "inspection-api" }));
        assert_eq!(
            check(&Keycloak, &app(None), "plant-a", &id_token),
            Err(Refusal::NotAnAccessToken)
        );
        assert_eq!(
            check(&Keycloak, &app(None), "plant-a", "not-a-jwt"),
            Err(Refusal::Unreadable)
        );
    }

    #[test]
    fn given_a_standard_provider_then_roles_come_from_its_roles_claim() {
        let with_role = token(json!({ "aud": "inspection-api", "roles": ["inspection-user"] }));
        assert_eq!(
            check(
                &common::provider::StandardOidc,
                &app(Some("inspection-user")),
                "plant-a",
                &with_role
            ),
            Ok(())
        );
    }
}
