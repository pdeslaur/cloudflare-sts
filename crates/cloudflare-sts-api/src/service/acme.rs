//! `PUT` and `DELETE /acme`: an ACME DNS-01 challenge answered as an acme
//! profile's caller, so a service gets certificates without a DNS token of
//! its own. The broker writes the TXT record with the Cloudflare token, only
//! at the challenge record of a name the profile lists.
//!
//! Not in the API's spec, as `POST /email` isn't. It takes a bearer token, as
//! [`super::bearer`] has it:
//!
//! - `Authorization: Bearer <token>`;
//! - a JSON body, `{"profile", "name", "value"}`: the acme profile the token
//!   must be allowed, the record's full name, `_acme-challenge.<domain>`, and
//!   the challenge's digest, 43 characters of base64url (RFC 8555 §8.4).
//!
//! `PUT` adds the TXT record, unless it's there already; `DELETE` removes it,
//! if it's there. Either answers `204`; `400` `invalid_request` for a request
//! that isn't one; `401` `invalid_token` for a token that isn't valid; `403`
//! `insufficient_scope` for one that isn't allowed the profile, or a name
//! the profile doesn't list; and `503` `temporarily_unavailable` when the
//! issuer's keys or Cloudflare fail. A client can retry a `503`, and give up
//! on anything else.
//!
//! The records it adds carry [`RECORD_COMMENT`], and it removes only those:
//! the hourly cron sweeps the ones a client left behind.

use std::sync::Arc;

use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{info, warn};
use worker::send::SendFuture;

use super::{
    access::{Failure, failure},
    bearer::{Caller, Refused, authorize},
    config::{AcmeConfig, CloudflareConfig, Config},
};

/// Where it's served.
pub const ACME_PATH: &str = "/acme";

/// What the records the broker adds say about themselves, which is how it
/// tells them from anyone else's.
pub const RECORD_COMMENT: &str = "cloudflare-sts:acme";

/// The TTL of the records it adds, Cloudflare's least.
const RECORD_TTL: u32 = 60;

/// How long a record may stay before the cron removes it: well past any
/// challenge.
const RECORD_LIFETIME_SECS: i64 = 60 * 60;

/// The largest body it reads.
const MAX_BODY_BYTES: usize = 4 * 1024;

/// Records listed per page.
const PAGE_SIZE: usize = 100;

/// The handler: adds or removes the challenge's record, or says why not.
/// Every refusal is logged as `acme.deny`, with its full description, which
/// the caller gets too.
pub async fn answer(State(config): State<Arc<Config>>, req: Request) -> Response {
    // Verifying and calling Cloudflare hold JavaScript values, which aren't
    // `Send`; a Worker is single-threaded, so it runs in a `SendFuture`.
    match SendFuture::new(answer_as_caller(&config, req)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(refused) => {
            warn!(
                event = "acme.deny",
                error = refused.error,
                message = %refused.description,
            );
            refused.into_response()
        }
    }
}

/// What the body says to answer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    profile: String,
    name: String,
    value: String,
}

impl Challenge {
    fn parse(body: &[u8]) -> Result<Self, Refused> {
        let challenge: Self = serde_json::from_slice(body).map_err(|_| {
            Refused::invalid_request("the body must be JSON with profile, name and value")
        })?;
        if !is_digest(&challenge.value) {
            return Err(Refused::invalid_request(
                "value isn't a challenge's digest, 43 characters of base64url",
            ));
        }
        Ok(challenge)
    }
}

/// Whether `value` is a DNS-01 challenge's digest: a SHA-256, base64url
/// without padding. Nothing else is written, so the profile can't put
/// arbitrary text in the zone.
fn is_digest(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Adds or removes the request's record as its caller.
async fn answer_as_caller(config: &Config, req: Request) -> Result<(), Refused> {
    // Routed for PUT and DELETE only.
    let present = req.method() == Method::PUT;
    let headers = req.headers().clone();
    let body = to_bytes(req.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| Refused::invalid_request("the body is over 4 KiB"))?;
    let challenge = Challenge::parse(&body)?;

    let Caller {
        provider,
        jwt,
        profile,
    } = authorize(config, &headers, &challenge.profile).await?;
    let Some(zones) = &profile.acme else {
        return Err(Refused::insufficient_scope(format!(
            "profile {} isn't for ACME challenges",
            profile.name
        )));
    };
    // The zone whose names include the one asked for.
    let Some(acme) = zones.iter().find(|acme| acme.answers_at(&challenge.name)) else {
        return Err(Refused::insufficient_scope(format!(
            "the profile doesn't answer challenges at {}",
            challenge.name
        )));
    };
    let name = challenge
        .name
        .strip_suffix('.')
        .unwrap_or(&challenge.name)
        .to_ascii_lowercase();

    let cloudflare = config.cloudflare();
    let (event, done) = if present {
        (
            "acme.present",
            cloudflare
                .add_challenge(acme, &name, &challenge.value)
                .await,
        )
    } else {
        (
            "acme.cleanup",
            cloudflare
                .remove_challenge(acme, &name, &challenge.value)
                .await,
        )
    };
    done.map_err(|why| Refused::unavailable(format!("Cloudflare: {why}")))?;

    let claims = Value::Object(profile.forwarded_claims(&jwt.claims));
    info!(
        event,
        provider = %provider.name,
        profile = %profile.name,
        sub = jwt.claims.sub(),
        claims = %claims,
        zone = %acme.zone,
        name = %name,
    );
    Ok(())
}

/// Removes the challenge records clients left behind in every zone an acme
/// profile answers in, for the hourly cron. Returns how many.
///
/// # Errors
///
/// What Cloudflare answered, or that it didn't.
pub async fn sweep(config: &Config, now_secs: i64) -> Result<usize, Failure> {
    let mut swept = 0;
    for zone in config.policy().acme_zones() {
        swept += config.cloudflare().sweep_challenges(zone, now_secs).await?;
    }
    Ok(swept)
}

/// A TXT record, as Cloudflare lists it.
#[derive(Debug, Deserialize)]
struct Record {
    id: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    created_on: Option<chrono::DateTime<chrono::Utc>>,
}

impl Record {
    /// Whether the broker added it.
    fn is_ours(&self) -> bool {
        self.comment.as_deref() == Some(RECORD_COMMENT)
    }

    /// Whether it holds `value`. Cloudflare may quote a TXT record's content.
    fn holds(&self, value: &str) -> bool {
        self.content.trim_matches('"') == value
    }
}

impl CloudflareConfig {
    /// Adds a TXT record holding `value` at `name`, in the profile's zone,
    /// unless the broker already has.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn add_challenge(
        &self,
        acme: &AcmeConfig,
        name: &str,
        value: &str,
    ) -> Result<(), Failure> {
        let existing = self.challenge_records(&acme.zone, Some(name), 1).await?;
        if existing.iter().any(|r| r.is_ours() && r.holds(value)) {
            return Ok(());
        }
        let path = format!("/zones/{}/dns_records", acme.zone);
        let body = json!({
            "type": "TXT",
            "name": name,
            "content": format!("\"{value}\""),
            "ttl": RECORD_TTL,
            "comment": RECORD_COMMENT,
        });
        let (status, body) = self
            .call(worker::Method::Post, &path, Some(&body))
            .await
            .map_err(|err| err.to_string())?;
        if !(200..300).contains(&status) || body["success"] != true {
            return Err(format!("dnsRecords.create: {}", failure(status, &body)));
        }
        Ok(())
    }

    /// Removes the broker's TXT records holding `value` at `name`, in the
    /// profile's zone, if there are any.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn remove_challenge(
        &self,
        acme: &AcmeConfig,
        name: &str,
        value: &str,
    ) -> Result<(), Failure> {
        let records = self.challenge_records(&acme.zone, Some(name), 1).await?;
        for record in records.iter().filter(|r| r.is_ours() && r.holds(value)) {
            self.delete_record(&acme.zone, &record.id).await?;
        }
        Ok(())
    }

    /// Removes the broker's challenge records in `zone` older than an hour,
    /// which a client didn't, for the hourly cron. Returns how many.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn sweep_challenges(&self, zone: &str, now_secs: i64) -> Result<usize, Failure> {
        // Collect first: deleting while paginating would shift later pages
        // and skip records.
        let mut stale = Vec::new();
        for page in 1.. {
            let records = self.challenge_records(zone, None, page).await?;
            let count = records.len();
            stale.extend(records.into_iter().filter(|r| {
                r.is_ours()
                    && r.created_on
                        .is_some_and(|at| now_secs - at.timestamp() >= RECORD_LIFETIME_SECS)
            }));
            if count < PAGE_SIZE {
                break;
            }
        }
        for record in &stale {
            self.delete_record(zone, &record.id).await?;
            info!(event = "acme.sweep", zone = %zone, record_id = %record.id);
        }
        Ok(stale.len())
    }

    /// A page of the zone's TXT records the broker added, at `name` if it's
    /// given.
    async fn challenge_records(
        &self,
        zone: &str,
        name: Option<&str>,
        page: usize,
    ) -> Result<Vec<Record>, Failure> {
        let mut query = vec![
            ("type", "TXT".to_string()),
            ("comment.exact", RECORD_COMMENT.to_string()),
            ("per_page", PAGE_SIZE.to_string()),
            ("page", page.to_string()),
        ];
        if let Some(name) = name {
            query.push(("name.exact", name.to_string()));
        }
        let query = serde_urlencoded::to_string(&query).map_err(|err| err.to_string())?;
        let path = format!("/zones/{zone}/dns_records?{query}");
        let (status, body) = self
            .call(worker::Method::Get, &path, None)
            .await
            .map_err(|err| err.to_string())?;
        if !(200..300).contains(&status) || body["success"] != true {
            return Err(format!("dnsRecords.list: {}", failure(status, &body)));
        }
        serde_json::from_value(body["result"].clone())
            .map_err(|err| format!("dnsRecords.list: {err}"))
    }

    /// Deletes the record `id` in `zone`. One that's gone already is fine.
    async fn delete_record(&self, zone: &str, id: &str) -> Result<(), Failure> {
        let path = format!("/zones/{zone}/dns_records/{id}");
        let (status, body) = self
            .call(worker::Method::Delete, &path, None)
            .await
            .map_err(|err| err.to_string())?;
        if status == 404 || ((200..300).contains(&status) && body["success"] == true) {
            return Ok(());
        }
        Err(format!("dnsRecords.delete: {}", failure(status, &body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_only_a_challenges_digest() {
        let digest = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
        assert!(is_digest(digest));
        for value in [
            "",
            &digest[1..],
            &format!("{digest}A"),
            "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEu+0",
            "v=spf1 include:_spf.example.com ~all______",
        ] {
            assert!(!is_digest(value), "{value:?}");
        }
    }

    #[test]
    fn parses_the_challenge_from_the_body() {
        let body = br#"{"profile":"acme.app","name":"_acme-challenge.app.example.com","value":"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"}"#;
        let challenge = Challenge::parse(body).ok().unwrap();
        assert_eq!(challenge.profile, "acme.app");
        assert_eq!(challenge.name, "_acme-challenge.app.example.com");

        for (body, why) in [
            (&b"profile=acme.app"[..], "must be JSON"),
            (br#"{"profile":"acme.app","name":"x"}"#, "must be JSON"),
            (
                br#"{"profile":"acme.app","name":"x","value":"hello"}"#,
                "isn't a challenge's digest",
            ),
            (
                br#"{"profile":"a","name":"x","value":"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0","type":"CNAME"}"#,
                "must be JSON",
            ),
        ] {
            let err = Challenge::parse(body).err().unwrap();
            assert!(err.description.contains(why), "{}", err.description);
        }
    }

    #[test]
    fn tells_its_records_from_others() {
        let record: Record = serde_json::from_value(json!({
            "id": "rec-1",
            "content": "\"LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0\"",
            "comment": RECORD_COMMENT,
        }))
        .unwrap();
        assert!(record.is_ours());
        assert!(record.holds("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"));
        assert!(!record.holds("other"));

        let theirs: Record =
            serde_json::from_value(json!({ "id": "rec-2", "content": "x", "comment": null }))
                .unwrap();
        assert!(!theirs.is_ours());
    }
}
