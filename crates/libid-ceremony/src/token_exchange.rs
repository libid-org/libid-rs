//! The GitHub Token Service contract of platform-ceremonies section 6.3.
//!
//! GitHub uses a confidential client, so the exchange cannot run in the
//! browser: the client secret would have to go there. The deployment runs it
//! instead, inside a notarized TLS session, and returns the attestation. The
//! secret stays behind a range commitment and never reaches the browser.
//!
//! The service is stateless by requirement, not by preference. It holds
//! ceremony credentials, so retention would create a compromise target with no
//! protocol purpose (REQ-PLAT-42).
//!
//! # What this module is, and is not
//!
//! Section 6.3 names protocol values, not serialized field names: "the browser
//! and deployment specifications own endpoint naming, transport framing,
//! serialization, parsing bounds, caller authentication, and cache policy".
//! So the route does not live here -- the deployment picks it, and the
//! implementation that serves it states it.
//!
//! What lives here is the record pair and the bounds a served request and
//! response must satisfy before the service acts on either. The semantics come
//! from REQ-PLAT-37, -38, -41, -54 and -55; the byte bounds come from the
//! GitHub token endpoint of the ceremony server contract, which is the
//! deployment specification that owns them.

pub const MAX_CODE_BYTES: usize = 1024;
pub const CODE_VERIFIER_LEN: usize = 43;
pub const MAX_ACCESS_TOKEN_BYTES: usize = 4096;
/// The bearer commitment's blinder is fixed-width prover material, not a
/// bounded string: the circuit opens exactly this many bytes.
pub const BEARER_OPENING_LEN: usize = 16;
pub const MAX_ATTESTED_DATA_BYTES: usize = 2 * 1024 * 1024;
/// A recoverable secp256k1 signature: `r || s || v`.
pub const SIGNATURE_LEN: usize = 65;
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
    #[error("accessToken is empty")]
    EmptyAccessToken,
    #[error("accessToken is {0} bytes, over the {MAX_ACCESS_TOKEN_BYTES}-byte bound")]
    AccessTokenTooLong(usize),
    #[error("accessToken carries a byte outside printable ASCII at index {0}")]
    AccessTokenNotPrintable(usize),
    #[error("attestedData is empty")]
    EmptyAttestedData,
    #[error(
        "the attestation is {0} bytes, over the {MAX_ATTESTED_DATA_BYTES}-byte bound"
    )]
    AttestedDataTooLong(usize),
    #[error(
        "the attestation is {0} bytes, too short to carry a {SIGNATURE_LEN}-byte \
         signature and any data"
    )]
    AttestationTooShort(usize),
    #[error("signature is {0} bytes, not the {SIGNATURE_LEN} a notary signature is")]
    SignatureWrongLength(usize),
    #[error(
        "bearerOpening is {0} bytes, not the {BEARER_OPENING_LEN} the circuit opens"
    )]
    BearerOpeningWrongLength(usize),
}

/// The index of the first byte outside printable ASCII, which excludes
/// whitespace and control characters. Both credentials carried here are held to
/// it: the code because it is echoed into a platform request, the bearer
/// because it is echoed into an `Authorization` header.
fn first_unprintable(s: &str) -> Option<usize> {
    s.bytes().position(|b| !(0x21..=0x7e).contains(&b))
}

/// What the Canonical Runtime sends. Nothing else: the service uses only its
/// compiled client identifier, secret, redirect URI, token endpoint and notary
/// configuration, and accepts no caller-selected action, client, redirect,
/// endpoint or return URL (REQ-PLAT-41).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRequest {
    pub code: String,
    pub code_verifier: String,
}

/// The signed attestation of the notarized exchange.
///
/// The bytes alone are not the attestation. REQ-PLAT-38 has the service return
/// the attestation, and an attestation is a byte string together with the
/// notary signature over it -- a record carrying only the bytes leaves the
/// browser holding something no verifier can check, and no field to put the
/// signature in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenAttestation {
    /// The byte-exact attested data of the notarized exchange, preserved as
    /// the notary produced it.
    pub attested_data: Vec<u8>,
    /// The notary signature authenticating those exact bytes.
    pub signature: Vec<u8>,
}

impl TokenAttestation {
    /// The single byte string the wire carries: the attested data, then the
    /// signature.
    ///
    /// One string rather than two fields because that is the room the response
    /// interface gives it -- `tokenAttestation` is one canonical unpadded
    /// base64url value. A notary signature is a fixed [`SIGNATURE_LEN`] bytes,
    /// so it is the tail, and the split needs no length prefix and no framing.
    ///
    /// THE LAYOUT IS NOT IN THE SPECIFICATION. REQ-PLAT-45 requires the
    /// returned attestation to carry the notary's signature and the response
    /// interface gives it one string to travel in, but how the two sit inside
    /// that string is left to the components sharing it. Every one of them
    /// reads this function, so they agree; an implementation written from the
    /// specification alone would have to guess, which is worth a sentence
    /// there.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.attested_data.len() + self.signature.len());
        out.extend_from_slice(&self.attested_data);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Split one wire string back into the pair.
    ///
    /// A string too short to hold a signature is refused rather than read as
    /// an empty-data attestation: the two would be indistinguishable, and the
    /// second is a record no verifier can check.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenExchangeError> {
        let split = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .filter(|n| *n > 0)
            .ok_or(TokenExchangeError::AttestationTooShort(bytes.len()))?;
        Ok(Self {
            attested_data: bytes[..split].to_vec(),
            signature: bytes[split..].to_vec(),
        })
    }
}

/// What comes back. `access_token` and `bearer_opening` both stay inside the
/// browser: the opening is private witness material for the Proving Circuit,
/// and publishing it beside the commitment would publish the credential the
/// commitment exists to hide (REQ-PLAT-55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_attestation: TokenAttestation,
    /// The blinder that opens the committed bearer range of that attestation.
    ///
    /// Without it the browser holds the attestation and the bearer but cannot
    /// build the proof: the blinder is prover-private material generated inside
    /// a session only this service ran (REQ-PLAT-54).
    pub bearer_opening: Vec<u8>,
}

impl TokenRequest {
    /// Bounded parsing, per REQ-PLAT-37 and the request bounds of the server
    /// contract.
    pub fn validate(&self) -> Result<(), TokenExchangeError> {
        if self.code.is_empty() {
            return Err(TokenExchangeError::EmptyCode);
        }
        if self.code.len() > MAX_CODE_BYTES {
            return Err(TokenExchangeError::CodeTooLong(self.code.len()));
        }
        if let Some(i) = first_unprintable(&self.code) {
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

impl TokenResponse {
    /// Bounded parsing, per REQ-PLAT-38 and the response bounds of the server
    /// contract.
    ///
    /// The three values are one result and the bounds say so: a bearer the
    /// header cannot carry, an opening the circuit cannot use, or a signature
    /// no recovery accepts each make the other two worthless, so each is exact
    /// rather than merely capped.
    pub fn validate(&self) -> Result<(), TokenExchangeError> {
        if self.access_token.is_empty() {
            return Err(TokenExchangeError::EmptyAccessToken);
        }
        if self.access_token.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(TokenExchangeError::AccessTokenTooLong(
                self.access_token.len(),
            ));
        }
        if let Some(i) = first_unprintable(&self.access_token) {
            return Err(TokenExchangeError::AccessTokenNotPrintable(i));
        }
        if self.token_attestation.attested_data.is_empty() {
            return Err(TokenExchangeError::EmptyAttestedData);
        }
        // REQ-PLAT-39 bounds the DECODED `tokenAttestation`, and that is this
        // pair together -- so the bound belongs on what `encode` produces.
        // Measured on the data alone it would admit a response a signature
        // over, which the browser then refuses for a reason nothing here said.
        let attestation_len = self.token_attestation.attested_data.len() + SIGNATURE_LEN;
        if attestation_len > MAX_ATTESTED_DATA_BYTES {
            return Err(TokenExchangeError::AttestedDataTooLong(attestation_len));
        }
        if self.token_attestation.signature.len() != SIGNATURE_LEN {
            return Err(TokenExchangeError::SignatureWrongLength(
                self.token_attestation.signature.len(),
            ));
        }
        if self.bearer_opening.len() != BEARER_OPENING_LEN {
            return Err(TokenExchangeError::BearerOpeningWrongLength(
                self.bearer_opening.len(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire carries one string, and the pair has to survive the trip:
    /// everything downstream reads the attested data by offset and recovers a
    /// key from the signature, so a byte moved between them derives a key
    /// nobody trusts.
    #[test]
    fn an_attestation_survives_the_one_string_it_travels_in() {
        let attestation = TokenAttestation {
            attested_data: (0u8..=200).collect(),
            signature: vec![0xab; SIGNATURE_LEN],
        };
        let encoded = attestation.encode();
        assert_eq!(encoded.len(), 201 + SIGNATURE_LEN);
        assert_eq!(TokenAttestation::decode(&encoded).unwrap(), attestation);
    }

    /// A string with room for a signature and nothing else decodes to empty
    /// attested data, which is a record no verifier can check. Refused here,
    /// where the reason is still legible.
    #[test]
    fn a_string_too_short_to_hold_both_is_refused() {
        for len in [0, 1, SIGNATURE_LEN - 1, SIGNATURE_LEN] {
            assert!(
                matches!(
                    TokenAttestation::decode(&vec![0u8; len]),
                    Err(TokenExchangeError::AttestationTooShort(_))
                ),
                "{len} bytes must not decode"
            );
        }
        assert!(TokenAttestation::decode(&[0u8; SIGNATURE_LEN + 1]).is_ok());
    }

    /// The bound is on what travels, not on half of it. Attested data that
    /// exactly fills the bound leaves no room for the signature beside it.
    #[test]
    fn the_bound_covers_the_signature_travelling_with_the_data() {
        let mut response = response();
        response.token_attestation.attested_data =
            vec![0u8; MAX_ATTESTED_DATA_BYTES - SIGNATURE_LEN];
        assert!(response.validate().is_ok());

        response.token_attestation.attested_data =
            vec![0u8; MAX_ATTESTED_DATA_BYTES - SIGNATURE_LEN + 1];
        assert!(matches!(
            response.validate(),
            Err(TokenExchangeError::AttestedDataTooLong(_))
        ));
    }

    fn request() -> TokenRequest {
        TokenRequest {
            code: "abc123".into(),
            code_verifier: "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I".into(),
        }
    }

    fn response() -> TokenResponse {
        TokenResponse {
            access_token: "gho_abc123".into(),
            token_attestation: TokenAttestation {
                attested_data: vec![0; 10],
                signature: vec![0; SIGNATURE_LEN],
            },
            bearer_opening: vec![0; BEARER_OPENING_LEN],
        }
    }

    #[test]
    fn accepts_a_well_formed_request() {
        request().validate().unwrap();
    }

    #[test]
    fn accepts_a_well_formed_response() {
        response().validate().unwrap();
    }

    #[test]
    fn the_published_verifier_is_the_right_shape() {
        // The section 7 conformance vector must satisfy the request bounds, or
        // the service would refuse a verifier the specification itself
        // produces.
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
            let r = TokenRequest {
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
            let r = TokenRequest {
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
    fn refuses_an_empty_or_over_long_access_token() {
        let mut r = response();
        r.access_token = String::new();
        assert_eq!(r.validate(), Err(TokenExchangeError::EmptyAccessToken));
        r.access_token = "t".repeat(MAX_ACCESS_TOKEN_BYTES + 1);
        assert_eq!(
            r.validate(),
            Err(TokenExchangeError::AccessTokenTooLong(
                MAX_ACCESS_TOKEN_BYTES + 1
            ))
        );
    }

    #[test]
    fn refuses_whitespace_and_control_bytes_in_an_access_token() {
        // The bearer is echoed into an `Authorization` header; a control byte
        // there is a header the platform never sees as one.
        for bad in ["gho_ab cd", "gho_ab\tcd", "gho_ab\r\ncd", "gho_ab\0cd"] {
            let r = TokenResponse {
                access_token: bad.into(),
                ..response()
            };
            assert!(
                matches!(
                    r.validate(),
                    Err(TokenExchangeError::AccessTokenNotPrintable(_))
                ),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn refuses_an_empty_or_over_long_attested_data() {
        let mut r = response();
        r.token_attestation.attested_data = Vec::new();
        assert_eq!(r.validate(), Err(TokenExchangeError::EmptyAttestedData));

        let mut r = response();
        r.token_attestation.attested_data = vec![0; MAX_ATTESTED_DATA_BYTES + 1];
        assert!(matches!(
            r.validate(),
            Err(TokenExchangeError::AttestedDataTooLong(_))
        ));
    }

    #[test]
    fn refuses_a_signature_that_is_not_exactly_recoverable_length() {
        for len in [0, SIGNATURE_LEN - 1, SIGNATURE_LEN + 1] {
            let mut r = response();
            r.token_attestation.signature = vec![0; len];
            assert_eq!(
                r.validate(),
                Err(TokenExchangeError::SignatureWrongLength(len)),
                "accepted a {len}-byte signature"
            );
        }
    }

    #[test]
    fn refuses_an_opening_that_is_not_exactly_what_the_circuit_opens() {
        // A near miss is the dangerous one: a bounded check accepted both of
        // these, and the circuit accepts neither.
        for len in [0, BEARER_OPENING_LEN - 1, BEARER_OPENING_LEN + 1, 256] {
            let mut r = response();
            r.bearer_opening = vec![0; len];
            assert_eq!(
                r.validate(),
                Err(TokenExchangeError::BearerOpeningWrongLength(len)),
                "accepted a {len}-byte opening"
            );
        }
    }
}
