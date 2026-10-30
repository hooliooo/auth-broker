//! The checks OpenID Connect Back-Channel Logout 1.0 (§2.6) adds on top of an ordinary token
//! verification: the logout event, no nonce, a subject or session, and a fresh, unique token.

use serde_json::Value;

use crate::oidc::{JwtVerificationError, LEEWAY_SECS};

/// The `events` member that marks a token as a back-channel logout token.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// What a verified logout token asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogoutClaims {
    /// Unique per logout token; a token seen before must be refused (replay).
    pub jti: String,
    /// The provider session to end, if the provider names one.
    pub sid: Option<String>,
    /// The user whose sessions to end, if the provider names one.
    pub sub: Option<String>,
    /// When the token expires; how long its `jti` has to be remembered.
    pub exp: u64,
}

/// Checks the `payload` of an already verified token as a logout token at time `now` (Unix
/// seconds). `max_age_secs` bounds how old its `iat` may be, so a captured token cannot be
/// replayed later even before it expires.
pub fn logout_claims(
    payload: &Value,
    now: u64,
    max_age_secs: u64,
) -> Result<LogoutClaims, JwtVerificationError> {
    let invalid = |reason: &str| JwtVerificationError::Invalid(format!("logout token: {reason}"));

    let has_event = payload
        .get("events")
        .and_then(Value::as_object)
        .is_some_and(|events| {
            events
                .get(BACKCHANNEL_LOGOUT_EVENT)
                .is_some_and(Value::is_object)
        });
    if !has_event {
        return Err(invalid("no back-channel logout event"));
    }
    // A nonce would mean an ID token is being passed off as a logout token.
    if payload.get("nonce").is_some() {
        return Err(invalid("carries a nonce"));
    }

    let text = |claim: &str| {
        payload
            .get(claim)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let (sid, sub) = (text("sid"), text("sub"));
    if sid.is_none() && sub.is_none() {
        return Err(invalid("names neither a session nor a subject"));
    }
    let jti = text("jti").ok_or(JwtVerificationError::MissingClaim("jti"))?;

    let iat = payload
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(JwtVerificationError::MissingClaim("iat"))?;
    if iat > now + LEEWAY_SECS {
        return Err(invalid("issued in the future"));
    }
    if now.saturating_sub(iat) > max_age_secs + LEEWAY_SECS {
        return Err(invalid("too old"));
    }
    let exp = payload
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(JwtVerificationError::MissingClaim("exp"))?;

    Ok(LogoutClaims { jti, sid, sub, exp })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// The tests' current time.
    const NOW: u64 = 1_800_000_000;
    /// The tests' maximum logout token age.
    const MAX_AGE: u64 = 120;

    /// A valid logout token payload.
    fn token() -> Value {
        json!({
            "iss": "https://idp.example/realms/test",
            "aud": "bff",
            "iat": NOW,
            "exp": NOW + 120,
            "jti": "logout-1",
            "sid": "session-1",
            "sub": "user-1",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        })
    }

    /// [`token`] without `claim`.
    fn without(claim: &str) -> Value {
        let mut payload = token();
        payload.as_object_mut().unwrap().remove(claim);
        payload
    }

    /// [`token`] with `claim` set to `value`.
    fn with(claim: &str, value: Value) -> Value {
        let mut payload = token();
        payload[claim] = value;
        payload
    }

    #[test]
    fn given_a_valid_logout_token_then_its_claims_are_returned() {
        let claims = logout_claims(&token(), NOW, MAX_AGE).unwrap();
        assert_eq!(
            claims,
            LogoutClaims {
                jti: "logout-1".into(),
                sid: Some("session-1".into()),
                sub: Some("user-1".into()),
                exp: NOW + 120,
            }
        );
    }

    #[test]
    fn given_only_a_session_or_only_a_subject_then_it_is_accepted() {
        assert!(logout_claims(&without("sub"), NOW, MAX_AGE).is_ok());
        assert!(logout_claims(&without("sid"), NOW, MAX_AGE).is_ok());
    }

    #[test]
    fn given_neither_a_session_nor_a_subject_then_it_is_refused() {
        let mut payload = without("sid");
        payload.as_object_mut().unwrap().remove("sub");
        assert!(logout_claims(&payload, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn given_no_logout_event_then_it_is_refused() {
        assert!(logout_claims(&without("events"), NOW, MAX_AGE).is_err());
        let other_event = with("events", json!({ "https://example/other": {} }));
        assert!(logout_claims(&other_event, NOW, MAX_AGE).is_err());
        let not_an_object = with("events", json!({ BACKCHANNEL_LOGOUT_EVENT: "yes" }));
        assert!(logout_claims(&not_an_object, NOW, MAX_AGE).is_err());
    }

    #[test]
    fn given_a_nonce_then_it_is_refused() {
        assert!(logout_claims(&with("nonce", json!("n")), NOW, MAX_AGE).is_err());
    }

    #[test]
    fn given_no_jti_then_it_is_refused() {
        assert!(matches!(
            logout_claims(&without("jti"), NOW, MAX_AGE),
            Err(JwtVerificationError::MissingClaim("jti"))
        ));
    }

    #[test]
    fn given_an_old_or_future_iat_then_it_is_refused() {
        let old = with("iat", json!(NOW - MAX_AGE - LEEWAY_SECS - 1));
        assert!(logout_claims(&old, NOW, MAX_AGE).is_err());
        let future = with("iat", json!(NOW + LEEWAY_SECS + 1));
        assert!(logout_claims(&future, NOW, MAX_AGE).is_err());
        let within_leeway = with("iat", json!(NOW - MAX_AGE - LEEWAY_SECS));
        assert!(logout_claims(&within_leeway, NOW, MAX_AGE).is_ok());
    }
}
