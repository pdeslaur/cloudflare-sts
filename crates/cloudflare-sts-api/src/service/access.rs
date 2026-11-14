//! Cloudflare Access service tokens: the four calls the broker makes.
//!
//! By hand, over `fetch`, rather than the generated client: its create
//! request has no `tags`, which are how an Access policy tells one
//! application's tokens from another's, and the client's Access product is
//! hundreds of operations the Worker would carry for four.

//!
//! Cloudflare won't say a service token's secret is right, so revoking one
//! takes a [`handle`]: its ID with the broker's MAC of it. Only an exchange
//! gives one out, so an ID read from a log or a dashboard revokes nothing,
//! and a made-up one is refused before Cloudflare is asked about it.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use worker::Method;

use super::config::CloudflareConfig;

/// What a handle's MAC covers before the ID, so the key signs nothing that
/// could pass for anything else.
const HANDLE_CONTEXT: &str = "cloudflare-sts:access-service-token:";

/// The MAC of the service token `id` under `key`, not yet finalized.
fn handle_mac(key: &[u8], id: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(HANDLE_CONTEXT.as_bytes());
    mac.update(id.as_bytes());
    mac
}

/// The handle for the service token `id`: `<id>.<mac>`, the MAC
/// (HMAC-SHA-256, base64url) under `key`.
pub(super) fn handle(key: &[u8], id: &str) -> String {
    let mac = handle_mac(key, id).finalize().into_bytes();
    format!("{id}.{}", URL_SAFE_NO_PAD.encode(mac))
}

/// The ID in `handle`, if its MAC is `key`'s of that ID. Compared in constant
/// time.
pub(super) fn handle_id<'a>(key: &[u8], handle: &'a str) -> Option<&'a str> {
    let (id, mac) = handle.rsplit_once('.')?;
    let mac = URL_SAFE_NO_PAD.decode(mac).ok()?;
    handle_mac(key, id).verify_slice(&mac).ok()?;
    Some(id)
}

/// The shortest lifetime Cloudflare gives a service token: it refuses less
/// than 10 minutes.
pub const MIN_DURATION_SECS: u64 = 600;

/// A service token as it's created: the only time its secret is shown.
#[derive(Debug)]
pub struct Created {
    pub id: String,
    pub client_id: String,
    pub client_secret: String,
    pub expires_at: DateTime<Utc>,
}

/// A service token as it's listed or fetched.
#[derive(Debug, Deserialize)]
pub struct Listed {
    pub id: String,
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// What Cloudflare answered, when it wasn't what was asked: `returned 403`,
/// or what its errors said.
pub type Failure = String;

#[derive(Debug, Deserialize)]
struct CreatedResult {
    id: String,
    client_id: String,
    client_secret: String,
    expires_at: Option<DateTime<Utc>>,
}

pub(super) fn failure(status: u16, body: &Value) -> Failure {
    let said = body
        .pointer("/errors/0/message")
        .and_then(Value::as_str)
        .map(|message| format!(": {message}"))
        .unwrap_or_default();
    format!("returned {status}{said}")
}

impl CloudflareConfig {
    fn tokens_path(&self) -> String {
        format!("/accounts/{}/access/service_tokens", self.account_id())
    }

    /// Creates a service token named `name`, valid for `seconds` (at least
    /// [`MIN_DURATION_SECS`]), with `tags`.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn create_service_token(
        &self,
        name: &str,
        seconds: u64,
        tags: &Value,
    ) -> Result<Created, Failure> {
        let seconds = seconds.max(MIN_DURATION_SECS);
        let body = json!({ "name": name, "duration": format!("{seconds}s"), "tags": tags });
        let (status, body) = self
            .call(Method::Post, &self.tokens_path(), Some(&body))
            .await
            .map_err(|err| err.to_string())?;
        if !(200..300).contains(&status) || body["success"] != true {
            return Err(failure(status, &body));
        }
        let result: CreatedResult = serde_json::from_value(body["result"].clone())
            .map_err(|_| "returned no token".to_string())?;
        Ok(Created {
            id: result.id,
            client_id: result.client_id,
            client_secret: result.client_secret,
            // Cloudflare says when; the duration is the fallback.
            expires_at: result.expires_at.unwrap_or_else(|| {
                DateTime::from_timestamp(
                    (worker::Date::now().as_millis() / 1000 + seconds) as i64,
                    0,
                )
                .unwrap_or_default()
            }),
        })
    }

    /// One page of the account's service tokens, from 1.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn list_service_tokens(
        &self,
        page: usize,
        per_page: usize,
    ) -> Result<Vec<Listed>, Failure> {
        let path = format!("{}?page={page}&per_page={per_page}", self.tokens_path());
        let (status, body) = self
            .call(Method::Get, &path, None)
            .await
            .map_err(|err| err.to_string())?;
        if !(200..300).contains(&status) || body["success"] != true {
            return Err(failure(status, &body));
        }
        Ok(serde_json::from_value(body["result"].clone()).unwrap_or_default())
    }

    /// The service token `id`, or `None` if there isn't one.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn get_service_token(&self, id: &str) -> Result<Option<Listed>, Failure> {
        let path = format!("{}/{id}", self.tokens_path());
        let (status, body) = self
            .call(Method::Get, &path, None)
            .await
            .map_err(|err| err.to_string())?;
        match status {
            404 => Ok(None),
            200..=299 if body["success"] == true => {
                Ok(serde_json::from_value(body["result"].clone()).ok())
            }
            _ => Err(failure(status, &body)),
        }
    }

    /// Deletes the service token `id`. Whether it was there is `false`.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn delete_service_token(&self, id: &str) -> Result<bool, Failure> {
        let path = format!("{}/{id}", self.tokens_path());
        let (status, body) = self
            .call(Method::Delete, &path, None)
            .await
            .map_err(|err| err.to_string())?;
        match status {
            404 => Ok(false),
            200..=299 if body["success"] == true => Ok(true),
            _ => Err(failure(status, &body)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-cloudflare-token";
    const ID: &str = "f174e90a-fafe-4643-bbbc-4a0ed4fc8415";

    #[test]
    fn a_handle_gives_back_its_id() {
        let handle = handle(KEY, ID);
        assert!(handle.starts_with(&format!("{ID}.")), "{handle}");
        assert_eq!(handle_id(KEY, &handle), Some(ID));
    }

    #[test]
    fn refuses_anything_the_key_didnt_sign() {
        let signed = handle(KEY, ID);
        let (_, mac) = signed.rsplit_once('.').unwrap();
        let other = "0b0c4f2e-7d2c-4c0e-9a51-6f3be0d1c2a4";
        for forged in [
            // The ID alone, as a log or a dashboard shows it.
            ID.to_string(),
            format!("{ID}."),
            format!("{ID}.{}", URL_SAFE_NO_PAD.encode([0u8; 32])),
            format!("{ID}.not base64"),
            // Another token's ID under this one's MAC.
            format!("{other}.{mac}"),
            // A MAC cut short.
            signed[..signed.len() - 4].to_string(),
            String::new(),
        ] {
            assert_eq!(handle_id(KEY, &forged), None, "{forged}");
        }
        assert_eq!(
            handle_id(b"another-cloudflare-token", &signed),
            None,
            "a rotated Cloudflare token signs anew"
        );
    }
}
