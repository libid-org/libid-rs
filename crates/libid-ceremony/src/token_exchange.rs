//! The GitHub Token-Exchange Service contract of platform-ceremonies section 6.3.
//!
//! GitHub uses a confidential client, so the exchange cannot run in the
//! browser: the client secret would have to go there. The deployment runs it
//! instead, inside a notarized TLS session, and returns the attestation. The
//! secret stays behind a range commitment and never reaches the browser.
//!
//! The service is stateless by requirement, not by preference. It holds
//! ceremony credentials, so retention would create a compromise target with no
//! protocol purpose (REQ-PLAT-42).

/// Fixed route on the redirect origin.
pub const ROUTE: &str = "/oauth/github/token-exchange";

pub const MAX_CODE_BYTES: usize = 1024;
pub const CODE_VERIFIER_LEN: usize = 43;
pub const MAX_ACCESS_TOKEN_BYTES: usize = 4096;
pub const MAX_BEARER_OPENING_BYTES: usize = 256;
pub const MAX_TOKEN_ATTESTATION_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenExchangeError {
    #[error("code is empty")]
    EmptyCode,
    #[error("code is {0} bytes, over the {MAX_CODE_BYTES}-byte bound")]
    CodeTooLong(usize),
    #[error("code carries a byte outside printable ASCII at index {0}")]
    CodeNotPrintable(usize),
    #[error("codeVerifier must match [A-Za-z0-9_-]{{43}}")]
    MalformedCodeVerifier,
    #[error("accessToken is {0} bytes, over the {MAX_ACCESS_TOKEN_BYTES}-byte bound")]
    AccessTokenTooLong(usize),
    #[error(
        "bearerOpening is {0} bytes, over the {MAX_BEARER_OPENING_BYTES}-byte bound"
    )]
    BearerOpeningTooLong(usize),
    #[error("tokenAttestation is {0} bytes, over the {MAX_TOKEN_ATTESTATION_BYTES}-byte bound")]
    AttestationTooLong(usize),
}

/// What the Canonical Runtime sends. Nothing else: the service uses only its
/// compiled client identifier, secret, redirect URI, token endpoint and notary
/// configuration, and accepts no caller-selected action, client, redirect,
/// endpoint or return URL (REQ-PLAT-41).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenExchangeRequestV1 {
    pub code: String,
    pub code_verifier: String,
}

/// What comes back. `access_token` and `bearer_opening` both stay inside the
/// browser: the opening is private witness material for the Proving Circuit,
/// and publishing it beside the commitment would publish the credential the
/// commitment exists to hide (REQ-PLAT-55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenExchangeResponseV1 {
    pub access_token: String,
    /// The attested data of the notarized exchange, as bytes.
    pub token_attestation: Vec<u8>,
    /// The blinder that opens the committed bearer range of that attestation.
    ///
    /// Without it the browser holds the attestation and the bearer but cannot
    /// build the proof: the blinder is prover-private material generated inside
    /// a session only this service ran (REQ-PLAT-54).
    pub bearer_opening: Vec<u8>,
}

impl TokenExchangeRequestV1 {
    /// Bounded parsing, per REQ-PLAT-37 and REQ-PLAT-38.
    pub fn validate(&self) -> Result<(), TokenExchangeError> {
        if self.code.is_empty() {
            return Err(TokenExchangeError::EmptyCode);
        }
        if self.code.len() > MAX_CODE_BYTES {
            return Err(TokenExchangeError::CodeTooLong(self.code.len()));
        }
        // Printable ASCII excludes whitespace and control characters, which is
        // what REQ-PLAT-37 asks for in one test.
        if let Some(i) = self.code.bytes().position(|b| !(0x21..=0x7e).contains(&b)) {
            return Err(TokenExchangeError::CodeNotPrintable(i));
        }
        if self.code_verifier.len() != CODE_VERIFIER_LEN
            || !self
                .code_verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(TokenExchangeError::MalformedCodeVerifier);
        }
        Ok(())
    }
}

impl TokenExchangeResponseV1 {
    /// Bounded parsing, per REQ-PLAT-39.
    pub fn validate(&self) -> Result<(), TokenExchangeError> {
        if self.access_token.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(TokenExchangeError::AccessTokenTooLong(
                self.access_token.len(),
            ));
        }
        if self.bearer_opening.len() > MAX_BEARER_OPENING_BYTES {
            return Err(TokenExchangeError::BearerOpeningTooLong(
                self.bearer_opening.len(),
            ));
        }
        if self.token_attestation.len() > MAX_TOKEN_ATTESTATION_BYTES {
            return Err(TokenExchangeError::AttestationTooLong(
                self.token_attestation.len(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> TokenExchangeRequestV1 {
        TokenExchangeRequestV1 {
            code: "abc123".into(),
            code_verifier: "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I".into(),
        }
    }

    #[test]
    fn accepts_a_well_formed_request() {
        request().validate().unwrap();
    }

    #[test]
    fn the_published_verifier_is_the_right_shape() {
        // The section 7 conformance vector must satisfy REQ-PLAT-38, or the
        // service would refuse a verifier the specification itself produces.
        assert_eq!(request().code_verifier.len(), CODE_VERIFIER_LEN);
        request().validate().unwrap();
    }

    #[test]
    fn refuses_an_empty_or_over_long_code() {
        let mut r = request();
        r.code = String::new();
        assert_eq!(r.validate(), Err(TokenExchangeError::EmptyCode));
        r.code = "a".repeat(MAX_CODE_BYTES + 1);
        assert_eq!(
            r.validate(),
            Err(TokenExchangeError::CodeTooLong(MAX_CODE_BYTES + 1))
        );
    }

    #[test]
    fn refuses_whitespace_and_control_bytes_in_a_code() {
        for bad in ["ab cd", "ab\tcd", "ab\ncd", "ab\0cd"] {
            let r = TokenExchangeRequestV1 {
                code: bad.into(),
                ..request()
            };
            assert!(
                matches!(r.validate(), Err(TokenExchangeError::CodeNotPrintable(_))),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn refuses_a_verifier_of_the_wrong_length_or_charset() {
        for bad in [
            "short",
            "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5", // 42
            "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5II", // 44
            "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1+gIZs5I", // base64, not base64url
            "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1/gIZs5I",
        ] {
            let r = TokenExchangeRequestV1 {
                code_verifier: bad.into(),
                ..request()
            };
            assert_eq!(
                r.validate(),
                Err(TokenExchangeError::MalformedCodeVerifier),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn refuses_an_over_long_response_field() {
        let ok = TokenExchangeResponseV1 {
            access_token: "t".into(),
            token_attestation: vec![0; 10],
            bearer_opening: vec![0; 16],
        };
        ok.validate().unwrap();

        let mut r = ok.clone();
        r.bearer_opening = vec![0; MAX_BEARER_OPENING_BYTES + 1];
        assert!(matches!(
            r.validate(),
            Err(TokenExchangeError::BearerOpeningTooLong(_))
        ));

        let mut r = ok.clone();
        r.access_token = "t".repeat(MAX_ACCESS_TOKEN_BYTES + 1);
        assert!(matches!(
            r.validate(),
            Err(TokenExchangeError::AccessTokenTooLong(_))
        ));
    }
}
