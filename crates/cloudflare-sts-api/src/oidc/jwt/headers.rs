//! The JOSE Header (RFC 7515 §4): the parameters a JWT is verified by, and the
//! values the crate gives them.

use serde::Deserialize;

/// The algorithms (RFC 7518 §3.1) tokens are verified with: RS256, which OIDC
/// verifiers support by default, and ES256, which SPIFFE issuers sign with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// ECDSA on P-256 with SHA-256.
    Es256,
}

impl Algorithm {
    /// The one an `alg` names, if it's one of them.
    pub fn from_name(alg: &str) -> Option<Self> {
        match alg {
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// Its `alg`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

/// The JOSE Header parameters (RFC 7515 §4.1) a JWT is verified by.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Header {
    /// `alg`: an [`Algorithm`]'s name.
    pub alg: String,
    /// `kid`: which of its issuer's keys signed it.
    #[serde(default)]
    pub kid: Option<String>,
    /// `typ`: what kind of JWT it is (RFC 8725 §3.11), such as `JWT` or
    /// `at+jwt`.
    #[serde(default)]
    pub typ: Option<String>,
}

impl Header {
    /// Whether its `typ` is `expected`. Media types compare without case, and
    /// with or without their `application/` prefix (RFC 7515 §4.1.9).
    pub fn typ_is(&self, expected: &str) -> bool {
        let media_type = |typ: &str| {
            let typ = typ.to_ascii_lowercase();
            match typ.strip_prefix("application/") {
                Some(subtype) => subtype.to_string(),
                None => typ,
            }
        };
        self.typ
            .as_deref()
            .is_some_and(|typ| media_type(typ) == media_type(expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typ_compares_as_a_media_type() {
        let header = |typ: &str| Header {
            alg: "RS256".into(),
            kid: None,
            typ: Some(typ.into()),
        };
        assert!(header("at+jwt").typ_is("at+jwt"));
        assert!(header("application/AT+JWT").typ_is("at+jwt"));
        assert!(header("JWT").typ_is("application/jwt"));
        assert!(!header("JWT").typ_is("at+jwt"));
        assert!(!Header::default().typ_is("JWT"));
    }
}
