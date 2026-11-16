//! What the endpoints outside the spec, `POST /email` and `/acme`, share.
//! Each is a resource that takes a bearer token (RFC 6750), not an OAuth
//! endpoint, and answers as one: the token is an OIDC token from a provider
//! the policy names, verified as an exchange's subject token is, and must be
//! allowed the one profile the request names.

use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use super::config::{Config, ProfileConfig, ProviderConfig, Refusal};
use crate::oidc::{self, Jwt};

/// Why a request was refused: the status, and the error (RFC 6750 §3.1, or
/// RFC 6749 §4.1.2.1's `temporarily_unavailable` and `server_error`) with
/// its description.
pub struct Refused {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
}

impl Refused {
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn invalid_token(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_token", description)
    }

    pub fn insufficient_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "insufficient_scope", description)
    }

    pub fn unavailable(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            description,
        )
    }

    pub fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            error,
            description: description.into(),
        }
    }
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        let body = json!({ "error": self.error, "error_description": self.description });
        let mut response = (self.status, Json(body)).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            let challenge = format!("Bearer error=\"{}\"", self.error);
            if let Ok(value) = HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}

/// Who called, and the profile they're allowed.
pub struct Caller<'a> {
    pub provider: &'a ProviderConfig,
    pub jwt: Jwt,
    pub profile: ProfileConfig,
}

/// The caller whose bearer token is in `headers`, as for an exchange: its
/// provider must admit it, and it must be allowed `profile`.
pub async fn authorize<'a>(
    config: &'a Config,
    headers: &HeaderMap,
    profile: &str,
) -> Result<Caller<'a>, Refused> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| Refused::invalid_token("a bearer token is required"))?;

    let policy = config.policy();
    let (provider, jwt) = policy
        .providers
        .verify(token)
        .await
        .map_err(|err| match err {
            oidc::Error::TemporarilyUnavailable(why) => Refused::unavailable(why),
            err => Refused::invalid_token(err.to_string()),
        })?;
    if !policy.admit(&provider.name, &jwt.claims).allowed {
        return Err(Refused::insufficient_scope(format!(
            "the policy doesn't admit the token to provider {}",
            provider.name
        )));
    }
    let (profile, _) = policy
        .profiles_for(&provider.name, &jwt.claims, &[profile])
        .map_err(|refusal| match refusal {
            Refusal::Scope(why) | Refusal::Request(why) => Refused::insufficient_scope(why),
        })?;
    Ok(Caller {
        provider,
        jwt,
        profile,
    })
}
