//! `POST /email`: a message sent as an email profile's caller, through the
//! Worker's `send_email` binding, so a service sends email without an API
//! token of its own.
//!
//! Not in the API's spec, as the health endpoints aren't: its body is a raw
//! message (RFC 5322) up to Cloudflare's 25 MiB, which the generated router,
//! with its form bodies and 16 KiB limit, doesn't take. It's a resource that
//! takes a bearer token (RFC 6750), not an OAuth endpoint, and answers as one:
//!
//! - `Authorization: Bearer <token>`, an OIDC token from a provider the policy
//!   names, verified as an exchange's subject token is;
//! - `profile`, `from` and `to` (once per recipient) in the query: the email
//!   profile the token must be allowed, the envelope sender, which the
//!   message's `From` must be, and the envelope recipients, as an SMTP relay
//!   has them, so a `Bcc` is sent too;
//! - the message as the body.
//!
//! It answers `200` with the message's ID for each recipient; `400`
//! `invalid_request` for a request that isn't one; `401` `invalid_token` for a
//! token that isn't valid; `403` `insufficient_scope` for one that isn't
//! allowed the profile, or a sender or recipient the profile doesn't list;
//! and `503` `temporarily_unavailable` when the issuer's keys or the binding
//! fail. A relay can retry a `503`, and give up on anything else.

use std::sync::Arc;

use axum::{
    Json,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use tracing::{error, info, warn};
use worker::{EmailMessage, send::SendFuture};

use super::config::{Config, EmailConfig, Refusal, check_address};
use crate::oidc;

/// Where it's served.
pub const EMAIL_PATH: &str = "/email";

/// The largest message Cloudflare sends.
const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;

/// The most recipients Cloudflare sends one message to.
const MAX_RECIPIENTS: usize = 50;

/// Why a message wasn't sent: the status, and the error (RFC 6750 §3.1, or
/// RFC 6749 §4.1.2.1's `temporarily_unavailable` and `server_error`) with
/// its description.
struct Refused {
    status: StatusCode,
    error: &'static str,
    description: String,
}

impl Refused {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    fn invalid_token(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_token", description)
    }

    fn insufficient_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "insufficient_scope", description)
    }

    fn unavailable(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            description,
        )
    }

    fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
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

/// The handler: sends the message, or says why not. Every refusal is logged
/// as `email.deny`, with its full description, which the caller gets too
/// unless it's the broker's fault.
pub async fn send(State(config): State<Arc<Config>>, req: Request) -> Response {
    // Verifying and sending hold JavaScript values, which aren't `Send`; a
    // Worker is single-threaded, so it runs in a `SendFuture`.
    match SendFuture::new(send_as_caller(&config, req)).await {
        Ok(message_ids) => Json(json!({ "message_ids": message_ids })).into_response(),
        Err(refused) => {
            warn!(
                event = "email.deny",
                error = refused.error,
                message = %refused.description,
            );
            refused.into_response()
        }
    }
}

/// What the query says to send.
struct Envelope {
    profile: String,
    from: String,
    to: Vec<String>,
}

impl Envelope {
    /// The query's `profile`, `from` and each `to`.
    fn parse(query: Option<&str>) -> Result<Self, Refused> {
        let fields: Vec<(String, String)> =
            serde_urlencoded::from_str(query.unwrap_or_default())
                .map_err(|_| Refused::invalid_request("the query isn't form-encoded"))?;
        let one = |name: &str| {
            let mut values = fields.iter().filter(|(field, _)| field == name);
            match (values.next(), values.next()) {
                (Some((_, value)), None) if !value.is_empty() => Ok(value.clone()),
                _ => Err(Refused::invalid_request(format!(
                    "{name} must be given once"
                ))),
            }
        };
        let (profile, from) = (one("profile")?, one("from")?);
        let to: Vec<String> = fields
            .iter()
            .filter(|(field, _)| field == "to")
            .map(|(_, value)| value.clone())
            .collect();
        if to.is_empty() || to.len() > MAX_RECIPIENTS {
            return Err(Refused::invalid_request(format!(
                "to must be given 1 to {MAX_RECIPIENTS} times"
            )));
        }
        for address in std::iter::once(&from).chain(&to) {
            check_address(address)
                .map_err(|why| Refused::invalid_request(format!("{address} {why}")))?;
        }
        Ok(Self { profile, from, to })
    }
}

/// Sends the request's message as its caller, once per recipient, and
/// returns the message IDs.
async fn send_as_caller(config: &Config, req: Request) -> Result<Vec<String>, Refused> {
    let envelope = Envelope::parse(req.uri().query())?;
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(String::from)
        .ok_or_else(|| Refused::invalid_token("a bearer token is required"))?;

    // Who the caller is, as for an exchange: its provider, which must admit it.
    let policy = config.policy();
    let (provider, jwt) = policy
        .providers
        .verify(&token)
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

    // The profile it names, which it must be allowed, and which must be for
    // email; then the envelope, against it.
    let (profile, _) = policy
        .profiles_for(&provider.name, &jwt.claims, &[envelope.profile.as_str()])
        .map_err(|refusal| match refusal {
            Refusal::Scope(why) | Refusal::Request(why) => Refused::insufficient_scope(why),
        })?;
    let Some(email) = &profile.email else {
        return Err(Refused::insufficient_scope(format!(
            "profile {} isn't for email",
            profile.name
        )));
    };
    check_envelope(email, &envelope)?;

    // The message is read only for a caller the profile lets send: up to
    // 25 MiB is never buffered for anyone else.
    let raw = to_bytes(req.into_body(), MAX_MESSAGE_BYTES)
        .await
        .map_err(|_| Refused::invalid_request("the message is over 25 MiB"))?;
    let raw = String::from_utf8(raw.to_vec())
        .map_err(|_| Refused::invalid_request("the message isn't UTF-8"))?;
    let header_from = header_from(&raw).ok_or_else(|| {
        Refused::invalid_request("the message must have one From with one address")
    })?;
    if !header_from.eq_ignore_ascii_case(&envelope.from) {
        return Err(Refused::invalid_request(format!(
            "the message's From is {header_from}, not {}",
            envelope.from
        )));
    }

    let Some(binding) = config.email() else {
        error!(
            event = "email.misconfigured",
            message = "no send_email binding"
        );
        return Err(Refused::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the broker can't send email",
        ));
    };
    let claims = Value::Object(profile.forwarded_claims(&jwt.claims));
    let mut message_ids = Vec::with_capacity(envelope.to.len());
    for to in &envelope.to {
        let sent = async {
            let message = EmailMessage::new(&envelope.from, to, &raw)?;
            binding.send(&message).await
        };
        match sent.await {
            Ok(result) => message_ids.push(result.message_id()),
            Err(err) => {
                let why = String::from(err.message());
                // Some recipients may have been sent to already: a retry
                // sends to them again.
                return Err(Refused::unavailable(format!(
                    "Cloudflare: send_email to {to}: {why} (sent to {} of {})",
                    message_ids.len(),
                    envelope.to.len()
                )));
            }
        }
    }
    info!(
        event = "email.send",
        provider = %provider.name,
        profile = %profile.name,
        sub = jwt.claims.sub(),
        claims = %claims,
        from = %envelope.from,
        to = ?envelope.to,
        message_ids = ?message_ids,
    );
    Ok(message_ids)
}

/// Whether the profile lets its caller send as the envelope's sender, to each
/// of its recipients.
fn check_envelope(email: &EmailConfig, envelope: &Envelope) -> Result<(), Refused> {
    if !email.sends_as(&envelope.from) {
        return Err(Refused::insufficient_scope(format!(
            "the profile doesn't send as {}",
            envelope.from
        )));
    }
    if let Some(to) = envelope.to.iter().find(|to| !email.sends_to(to)) {
        return Err(Refused::insufficient_scope(format!(
            "the profile doesn't send to {to}"
        )));
    }
    Ok(())
}

/// The address in the message's one `From` header, if it has exactly one
/// with one mailbox: `Name <local@domain>` or `local@domain`.
fn header_from(raw: &str) -> Option<String> {
    let headers = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .map_or(raw, |(headers, _)| headers);

    // Unfolded (RFC 5322 §2.2.3): a line that starts with whitespace
    // continues the one before.
    let mut fields: Vec<String> = Vec::new();
    for line in headers.lines() {
        match fields.last_mut() {
            Some(field) if line.starts_with([' ', '\t']) => field.push_str(line),
            _ => fields.push(line.to_string()),
        }
    }
    let mut from = fields.iter().filter_map(|field| {
        let (name, value) = field.split_once(':')?;
        name.trim().eq_ignore_ascii_case("from").then_some(value)
    });
    let (Some(value), None) = (from.next(), from.next()) else {
        return None;
    };

    // One mailbox only: outside a quoted display name, a `,` separates
    // mailboxes and a `;` ends a group (RFC 5322 §3.4), so a list can't pass
    // for its last address.
    let bare = unquoted(value)?;
    if bare.contains([',', ';']) || bare.matches('<').count() > 1 {
        return None;
    }
    let address = match bare.rsplit_once('<') {
        Some((_, rest)) => rest.split_once('>')?.0,
        None => value,
    }
    .trim();
    check_address(address).ok()?;
    Some(address.to_string())
}

/// `value` without its quoted strings (RFC 5322 §3.2.4), which a display name
/// may be, and which may hold anything. `None` when a quote is left open.
fn unquoted(value: &str) -> Option<String> {
    let mut bare = String::new();
    let mut quoted = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            // A quoted pair: the next character is taken as it is.
            '\\' if quoted => {
                chars.next();
            }
            _ if !quoted => bare.push(c),
            _ => {}
        }
    }
    (!quoted).then_some(bare)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_one_from_address() {
        for (raw, expected) in [
            (
                "From: noreply@example.com\r\nTo: a@example.com\r\n\r\nbody",
                Some("noreply@example.com"),
            ),
            (
                "from: Gatus <noreply@example.com>\n\nbody",
                Some("noreply@example.com"),
            ),
            (
                "Subject: x\r\nFrom: \"Gatus, alerts\"\r\n <noreply@example.com>\r\n\r\n",
                Some("noreply@example.com"),
            ),
            // A From in the body isn't a header.
            ("Subject: x\r\n\r\nFrom: noreply@example.com", None),
            ("From: a@example.com\r\nFrom: b@example.com\r\n\r\n", None),
            ("From: a@example.com, b@example.com\r\n\r\n", None),
            // A list doesn't pass for its last mailbox.
            (
                "From: CEO <ceo@bank.example>, x <noreply@example.com>\r\n\r\n",
                None,
            ),
            (
                "From: <ceo@bank.example> <noreply@example.com>\r\n\r\n",
                None,
            ),
            (
                "From: Team: CEO <ceo@bank.example>;, <noreply@example.com>\r\n\r\n",
                None,
            ),
            // A quoted display name may hold anything.
            (
                "From: \"Alerts <ops>, \\\"prod\\\"\" <noreply@example.com>\r\n\r\n",
                Some("noreply@example.com"),
            ),
            ("From: \"Gatus <noreply@example.com>\r\n\r\n", None),
            ("From: Gatus\r\n\r\n", None),
            ("To: a@example.com\r\n\r\n", None),
        ] {
            assert_eq!(header_from(raw).as_deref(), expected, "{raw:?}");
        }
    }

    #[test]
    fn parses_the_envelope_from_the_query() {
        let envelope = Envelope::parse(Some(
            "profile=email.app&from=noreply%40example.com&to=a%40example.com&to=b%40example.com",
        ))
        .ok()
        .unwrap();
        assert_eq!(envelope.profile, "email.app");
        assert_eq!(envelope.from, "noreply@example.com");
        assert_eq!(envelope.to, ["a@example.com", "b@example.com"]);

        for (query, why) in [
            (None, "profile must be given once"),
            (
                Some("profile=p&from=a%40example.com"),
                "to must be given 1 to 50 times",
            ),
            (
                Some("profile=p&profile=q&from=a%40example.com&to=b%40example.com"),
                "profile must be given once",
            ),
            (
                Some("profile=p&from=Gatus%20%3Ca%40example.com%3E&to=b%40example.com"),
                "isn't a bare address",
            ),
        ] {
            let err = Envelope::parse(query).err().unwrap();
            assert!(
                err.description.contains(why),
                "{query:?}: {}",
                err.description
            );
        }
    }

    #[test]
    fn holds_the_envelope_to_the_profile() {
        let email = EmailConfig {
            from: vec!["noreply@example.com".into()],
            to: Some(vec!["alerts@example.com".into()]),
        };
        let envelope = |from: &str, to: &str| Envelope {
            profile: "email.app".into(),
            from: from.into(),
            to: vec![to.into()],
        };
        assert!(
            check_envelope(
                &email,
                &envelope("NoReply@Example.com", "alerts@example.com")
            )
            .is_ok()
        );
        let refused = |from, to| {
            check_envelope(&email, &envelope(from, to))
                .err()
                .unwrap()
                .description
        };
        assert_eq!(
            refused("admin@example.com", "alerts@example.com"),
            "the profile doesn't send as admin@example.com"
        );
        assert_eq!(
            refused("noreply@example.com", "boss@example.com"),
            "the profile doesn't send to boss@example.com"
        );

        let anyone = EmailConfig { to: None, ..email };
        assert!(
            check_envelope(
                &anyone,
                &envelope("noreply@example.com", "boss@example.com")
            )
            .is_ok()
        );
    }
}
