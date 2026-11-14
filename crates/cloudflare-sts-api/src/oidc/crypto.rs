//! RS256 (RSASSA-PKCS1-v1_5 with SHA-256) and ES256 (ECDSA on P-256 with
//! SHA-256) through the runtime's WebCrypto, for verifying and signing alike:
//! no RSA or ECDSA crate ends up in the wasm, and a signing key never leaves
//! WebCrypto.

use web_sys::{CryptoKey, SubtleCrypto, WorkerGlobalScope};
use worker::{
    js_sys::{self, Uint8Array},
    wasm_bindgen::{JsCast, JsValue},
    wasm_bindgen_futures::JsFuture,
};

use crate::oidc::{Algorithm, KeyError};

/// Whether `signature` is the `alg` signature of `signing_input` by the public
/// key `jwk`, a JWK of the type `alg` takes. A signature WebCrypto refuses to
/// check, such as one of the wrong length, isn't.
pub(crate) async fn verify(
    alg: Algorithm,
    jwk: &serde_json::Value,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<bool, KeyError> {
    let subtle = subtle()?;
    let jwk: js_sys::Object = js_sys::JSON::parse(&jwk.to_string())
        .map(JsCast::unchecked_into)
        .map_err(error)?;
    let usages = js_sys::Array::of1(&JsValue::from_str("verify"));
    let key: CryptoKey =
        promised(subtle.import_key_with_object("jwk", &jwk, &import_params(alg)?, false, &usages))
            .await?
            .unchecked_into();

    let verified = subtle.verify_with_object_and_buffer_source_and_buffer_source(
        &verify_params(alg)?,
        &key,
        &Uint8Array::from(signature),
        &Uint8Array::from(signing_input),
    );
    match verified {
        Ok(promise) => {
            Ok(JsFuture::from(promise).await.ok().and_then(|v| v.as_bool()) == Some(true))
        }
        Err(_) => Ok(false),
    }
}

/// What WebCrypto threw, as a [`KeyError`].
pub(crate) fn error(err: JsValue) -> KeyError {
    let why = err
        .dyn_ref::<js_sys::Error>()
        .map(|err| String::from(err.message()))
        .unwrap_or_else(|| format!("{err:?}"));
    KeyError(format!("WebCrypto: {why}"))
}

/// The runtime's `crypto.subtle`.
pub(crate) fn subtle() -> Result<SubtleCrypto, KeyError> {
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    Ok(scope.crypto().map_err(error)?.subtle())
}

/// What a WebCrypto call's promise resolves to.
pub(crate) async fn promised(
    promise: Result<js_sys::Promise, JsValue>,
) -> Result<JsValue, KeyError> {
    JsFuture::from(promise.map_err(error)?).await.map_err(error)
}

/// `alg`'s WebCrypto algorithm for importing a key.
pub(crate) fn import_params(alg: Algorithm) -> Result<js_sys::Object, KeyError> {
    params(match alg {
        Algorithm::Rs256 => r#"{"name":"RSASSA-PKCS1-v1_5","hash":"SHA-256"}"#,
        Algorithm::Es256 => r#"{"name":"ECDSA","namedCurve":"P-256"}"#,
    })
}

/// `alg`'s WebCrypto algorithm for signing and verifying. JWS's ES256
/// signatures are `r || s` (RFC 7518 §3.4), as WebCrypto's ECDSA takes them.
pub(crate) fn verify_params(alg: Algorithm) -> Result<js_sys::Object, KeyError> {
    params(match alg {
        Algorithm::Rs256 => r#"{"name":"RSASSA-PKCS1-v1_5","hash":"SHA-256"}"#,
        Algorithm::Es256 => r#"{"name":"ECDSA","hash":"SHA-256"}"#,
    })
}

fn params(json: &str) -> Result<js_sys::Object, KeyError> {
    js_sys::JSON::parse(json)
        .map(JsCast::unchecked_into)
        .map_err(error)
}
