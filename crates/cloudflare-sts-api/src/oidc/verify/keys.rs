//! An issuer's keys: its JWK Set (RFC 7517), the RSA (RFC 7518 §6.3) and
//! P-256 (§6.2) public keys in it that verify RS256 and ES256 signatures,
//! fetching it, and caching it per isolate.

use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use worker::{AbortSignal, Fetch, Method, Request};

use super::metadata;
use crate::oidc::{Algorithm, Error, crypto, error::invalid};

/// How long a fetched JWK Set is trusted before it's fetched again.
const JWKS_TTL_MS: u64 = 10 * 60 * 1000;

/// An unknown `kid` refetches an issuer's JWK Set at most this often, so
/// tokens with made-up key IDs can't make the Worker hammer the issuer.
const JWKS_MIN_REFETCH_MS: u64 = 30 * 1000;

thread_local! {
    /// Each issuer's keys, by issuer.
    static KEYS: RefCell<HashMap<String, KeySet>> = RefCell::new(HashMap::new());
}

/// `issuer`'s key for `alg` that `kid` names, or its only one for `alg` when
/// there's no `kid`:
/// cached, or fetched from `jwks_uri`, or the `jwks_uri` in its metadata.
pub(super) async fn find(
    issuer: &str,
    jwks_uri: Option<&str>,
    kid: Option<&str>,
    alg: Algorithm,
    now_ms: u64,
) -> Result<Key, Error> {
    let unknown = || invalid("unknown signing key");
    match KEYS.with_borrow(|sets| KeySet::lookup(sets.get(issuer), kid, alg, now_ms)) {
        Lookup::Hit(key) => return Ok(key),
        Lookup::Unknown => return Err(unknown()),
        Lookup::Fetch => {}
    }

    let jwks_uri = match jwks_uri {
        Some(jwks_uri) => jwks_uri.to_string(),
        None => metadata::jwks_uri(issuer).await?,
    };
    let jwks: JwkSet = fetch_json(&jwks_uri).await?;
    let set = KeySet {
        keys: jwks.signing_keys(),
        fetched_at: now_ms,
    };
    let key = set.find(kid, alg).cloned();
    KEYS.with_borrow_mut(|sets| sets.insert(issuer.to_string(), set));
    key.ok_or_else(unknown)
}

/// How long an issuer has to answer.
const FETCH_TIMEOUT_MS: u32 = 10 * 1000;

/// Whether `url` is somewhere keys may be fetched from: HTTPS, or plain HTTP
/// on a loopback address, for a local issuer in development. For checking
/// other URLs in a configuration the same way;
/// [`Providers::check`](crate::oidc::Providers::check) checks providers'.
///
/// # Errors
///
/// Why it isn't.
pub fn check_url(url: &str) -> Result<(), &'static str> {
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            url.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    let https = url
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
    if url.contains(char::is_whitespace) || !(https || loopback) {
        return Err("must be an https:// URL");
    }
    Ok(())
}

/// The JSON at `url`. A URL [`check_url`] refuses is never fetched, whoever
/// configured it.
pub(super) async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let unavailable =
        |err: worker::Error| Error::TemporarilyUnavailable(format!("fetching {url}: {err}"));
    check_url(url).map_err(|why| Error::TemporarilyUnavailable(format!("{url} {why}")))?;

    // `Request::new` hands the URL to the runtime; `Url::parse` would pull the
    // `url` crate and its IDNA tables into the bundle.
    let req = Request::new(url, Method::Get).map_err(unavailable)?;
    let signal = AbortSignal::from(web_sys::AbortSignal::timeout_with_u32(FETCH_TIMEOUT_MS));
    let mut resp = Fetch::Request(req)
        .send_with_signal(&signal)
        .await
        .map_err(unavailable)?;
    if resp.status_code() != 200 {
        return Err(Error::TemporarilyUnavailable(format!(
            "fetching {url} returned {}",
            resp.status_code()
        )));
    }
    resp.json().await.map_err(unavailable)
}

/// A JWK Set (RFC 7517 §5).
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// A JWK (RFC 7517 §4), with the members an RSA public key (RFC 7518 §6.3.1)
/// or an elliptic curve public key (§6.2.1) is read by.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    key_ops: Option<Vec<String>>,
    alg: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

impl Jwk {
    /// Whether it may verify signatures: if it says what it's for, it says
    /// signatures (RFC 7517 §4.2, §4.3). A SPIFFE bundle (SPIFFE Trust Domain
    /// and Bundle §4.2.2) says `jwt-svid` for the keys that sign JWT-SVIDs,
    /// and `x509-svid` for X.509 authorities, which never sign tokens.
    fn verifies(&self) -> bool {
        self.use_
            .as_deref()
            .is_none_or(|use_| use_ == "sig" || use_ == "jwt-svid")
            && (self.key_ops.as_ref()).is_none_or(|ops| ops.iter().any(|op| op == "verify"))
    }

    /// The algorithm it verifies, from its type and curve: RS256 for an RSA
    /// key, ES256 for a P-256 one. One whose `alg` names another algorithm
    /// (RFC 7517 §4.4; RFC 8725 §3.1) verifies none.
    fn algorithm(&self) -> Option<Algorithm> {
        let alg = match (self.kty.as_str(), self.crv.as_deref()) {
            ("RSA", _) => Algorithm::Rs256,
            ("EC", Some("P-256")) => Algorithm::Es256,
            _ => return None,
        };
        self.alg
            .as_deref()
            .is_none_or(|named| named == alg.name())
            .then_some(alg)
    }

    /// It as a [`Key`], if it's one that verifies signatures and has the
    /// members its type needs.
    fn key(self) -> Option<Key> {
        if !self.verifies() {
            return None;
        }
        let alg = self.algorithm()?;
        let jwk = match alg {
            Algorithm::Rs256 => json!({ "kty": "RSA", "n": self.n?, "e": self.e? }),
            Algorithm::Es256 => {
                json!({ "kty": "EC", "crv": "P-256", "x": self.x?, "y": self.y? })
            }
        };
        Some(Key {
            kid: self.kid,
            alg,
            jwk,
        })
    }
}

/// An issuer's public key, and the one algorithm it verifies.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Key {
    kid: Option<String>,
    alg: Algorithm,
    /// The JWK WebCrypto imports: only the public members its type needs.
    jwk: Value,
}

impl Key {
    /// Its `kid`, if it has one.
    pub(crate) fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Whether `signature` is its signature of `signing_input`, with its
    /// algorithm, checked with WebCrypto.
    pub(crate) async fn verify(
        &self,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        crypto::verify(self.alg, &self.jwk, signing_input, signature)
            .await
            .map_err(|err| Error::TemporarilyUnavailable(err.to_string()))
    }
}

impl JwkSet {
    /// The keys in it that verify RS256 or ES256 signatures. Any others are
    /// skipped, as RFC 7517 §5 says keys that aren't understood are.
    fn signing_keys(self) -> Vec<Key> {
        self.keys.into_iter().filter_map(Jwk::key).collect()
    }
}

/// An issuer's keys, cached per isolate.
struct KeySet {
    keys: Vec<Key>,
    fetched_at: u64,
}

#[derive(Debug, PartialEq)]
enum Lookup {
    Hit(Key),
    Fetch,
    /// Unknown `kid`, and the JWK Set was fetched too recently to try again.
    Unknown,
}

impl KeySet {
    /// The key for `alg` with this `kid`; without one, the only key for `alg`
    /// there is. A key never verifies another algorithm's signatures.
    fn find(&self, kid: Option<&str>, alg: Algorithm) -> Option<&Key> {
        let mut keys = self.keys.iter().filter(|key| key.alg == alg);
        match kid {
            Some(kid) => keys.find(|key| key.kid() == Some(kid)),
            None => match (keys.next(), keys.next()) {
                (Some(only), None) => Some(only),
                _ => None,
            },
        }
    }

    fn lookup(set: Option<&KeySet>, kid: Option<&str>, alg: Algorithm, now_ms: u64) -> Lookup {
        let Some(set) = set else {
            return Lookup::Fetch;
        };
        let age = now_ms.saturating_sub(set.fetched_at);
        match set.find(kid, alg) {
            Some(key) if age < JWKS_TTL_MS => Lookup::Hit(key.clone()),
            Some(_) => Lookup::Fetch,
            None if age < JWKS_MIN_REFETCH_MS => Lookup::Unknown,
            None => Lookup::Fetch,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const RS256: Algorithm = Algorithm::Rs256;
    const ES256: Algorithm = Algorithm::Es256;

    fn kids(jwks: Value) -> Vec<(String, Algorithm)> {
        let jwks: JwkSet = serde_json::from_value(jwks).unwrap();
        jwks.signing_keys()
            .into_iter()
            .map(|key| (key.kid.unwrap(), key.alg))
            .collect()
    }

    #[test]
    fn keeps_only_keys_that_verify_rs256_or_es256() {
        let ec = |kid: &str, extra: Value| {
            let mut key = json!({ "kty": "EC", "crv": "P-256", "kid": kid, "x": "AA", "y": "AA" });
            key.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            key
        };
        let kept = kids(json!({ "keys": [
            { "kty": "RSA", "kid": "plain", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "sig", "use": "sig", "alg": "RS256", "key_ops": ["verify"], "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "rs512", "alg": "RS512", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "rsa-es256", "alg": "ES256", "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "encrypt", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB" },
            { "kty": "RSA", "kid": "no-modulus", "e": "AQAB" },
            ec("ec", json!({})),
            ec("ec-sig", json!({ "use": "sig", "alg": "ES256" })),
            ec("ec-rs256", json!({ "alg": "RS256" })),
            ec("ec-es384", json!({ "alg": "ES384" })),
            ec("p384", json!({ "crv": "P-384" })),
            ec("no-y", json!({ "y": null })),
            { "kty": "EC", "kid": "no-curve", "x": "AA", "y": "AA" },
            { "kty": "OKP", "kid": "ed25519", "crv": "Ed25519", "x": "AA" },
        ]}));
        let kept: Vec<_> = kept.iter().map(|(kid, _)| kid.as_str()).collect();
        assert_eq!(kept, ["plain", "sig", "ec", "ec-sig"]);
    }

    #[test]
    fn keeps_a_spiffe_bundles_jwt_svid_keys_only() {
        let key = |kid: &str, use_: &str| json!({ "kty": "EC", "crv": "P-256", "kid": kid, "use": use_, "x": "AA", "y": "AA" });
        let kept = kids(json!({ "keys": [
            key("authority", "x509-svid"),
            key("jwt", "jwt-svid"),
            { "kty": "RSA", "kid": "rsa-jwt", "use": "jwt-svid", "n": "AQAB", "e": "AQAB" },
        ]}));
        assert_eq!(
            kept,
            [("jwt".to_string(), ES256), ("rsa-jwt".to_string(), RS256)]
        );
    }

    #[test]
    fn imports_only_the_public_members() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "EC", "crv": "P-256", "kid": "ec", "x": "AA", "y": "BB", "d": "secret", "use": "jwt-svid" },
        ]}))
        .unwrap();
        let keys = jwks.signing_keys();
        assert_eq!(
            keys[0].jwk,
            json!({ "kty": "EC", "crv": "P-256", "x": "AA", "y": "BB" })
        );
    }

    #[test]
    fn finds_a_key_only_for_its_own_algorithm() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB" },
            { "kty": "EC", "crv": "P-256", "kid": "ec", "x": "AA", "y": "AA" },
        ]}))
        .unwrap();
        let set = KeySet {
            keys: jwks.signing_keys(),
            fetched_at: 0,
        };
        let found = |kid, alg| set.find(kid, alg).and_then(Key::kid);
        assert_eq!(found(Some("rsa"), RS256), Some("rsa"));
        assert_eq!(found(Some("ec"), ES256), Some("ec"));
        assert_eq!(found(Some("rsa"), ES256), None);
        assert_eq!(found(Some("ec"), RS256), None);
        // Without a kid, the only key for the algorithm, though there are two.
        assert_eq!(found(None, RS256), Some("rsa"));
        assert_eq!(found(None, ES256), Some("ec"));
    }

    #[test]
    fn allows_http_only_on_loopback() {
        for url in [
            "https://issuer.example.com",
            "http://127.0.0.1:8788",
            "http://localhost",
            "http://[::1]:9000/oidc",
        ] {
            assert_eq!(check_url(url), Ok(()), "{url}");
        }
        for url in [
            "http://issuer.example.com",
            "https://",
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
            "https://issuer.example.com/a b",
        ] {
            assert!(check_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn refetches_sparingly() {
        let jwks: JwkSet = serde_json::from_value(json!({ "keys": [
            { "kty": "RSA", "kid": "key-1", "n": "AQAB", "e": "AQAB" },
        ]}))
        .unwrap();
        let set = KeySet {
            keys: jwks.signing_keys(),
            fetched_at: 0,
        };

        assert_eq!(KeySet::lookup(None, Some("key-1"), RS256, 0), Lookup::Fetch);
        assert!(matches!(
            KeySet::lookup(Some(&set), Some("key-1"), RS256, 1),
            Lookup::Hit(_)
        ));
        // Without a kid, the only key.
        assert!(matches!(
            KeySet::lookup(Some(&set), None, RS256, 1),
            Lookup::Hit(_)
        ));
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-1"), RS256, JWKS_TTL_MS),
            Lookup::Fetch
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), RS256, 1),
            Lookup::Unknown
        );
        assert_eq!(
            KeySet::lookup(Some(&set), Some("key-2"), RS256, JWKS_MIN_REFETCH_MS),
            Lookup::Fetch
        );
    }
}
