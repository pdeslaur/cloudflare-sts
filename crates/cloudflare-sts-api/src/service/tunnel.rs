//! Cloudflare Tunnels: setting a locally-managed tunnel's secret, the one call
//! the broker makes for them.
//!
//! By hand, over `fetch`, as for Access: the generated client has no tunnels.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use web_sys::WorkerGlobalScope;
use worker::{Method, js_sys, wasm_bindgen::JsCast};

use super::{
    access::{Failure, failure},
    config::{CloudflareConfig, TunnelConfig},
};

/// How long a tunnel's secret is: Cloudflare takes no less, and cloudflared
/// makes its own this long.
const SECRET_BYTES: usize = 32;

impl CloudflareConfig {
    /// Sets a new random secret on `tunnel`, and returns it, base64. The
    /// previous one no longer registers connections.
    ///
    /// # Errors
    ///
    /// What Cloudflare answered, or that it didn't.
    pub async fn rotate_tunnel_secret(&self, tunnel: &TunnelConfig) -> Result<String, Failure> {
        let secret = STANDARD.encode(random_bytes()?);
        let path = format!("/accounts/{}/cfd_tunnel/{}", self.account_id(), tunnel.id);
        let body = json!({ "tunnel_secret": secret });
        let (status, body) = self
            .call(Method::Patch, &path, Some(&body))
            .await
            .map_err(|err| err.to_string())?;
        if !(200..300).contains(&status) || body["success"] != true {
            return Err(failure(status, &body));
        }
        Ok(secret)
    }
}

/// [`SECRET_BYTES`] from the runtime's cryptographically secure generator.
fn random_bytes() -> Result<[u8; SECRET_BYTES], Failure> {
    let mut bytes = [0u8; SECRET_BYTES];
    let scope = js_sys::global().unchecked_into::<WorkerGlobalScope>();
    scope
        .crypto()
        .and_then(|crypto| crypto.get_random_values_with_u8_array(&mut bytes))
        .map_err(|_| "WebCrypto gave no random bytes".to_string())?;
    Ok(bytes)
}
