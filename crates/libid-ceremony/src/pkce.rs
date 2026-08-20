//! The PKCE construction of ceremony-common section 7.
//!
//! X and GitHub cannot carry the Authorization Digest in their authorization
//! request the way Google carries it in an OIDC `nonce`, so they carry it
//! through the PKCE verifier instead. The verifier is revealed in the
//! notarized token request, and the Platform Verifier recomputes it from the
//! digest and the submitted nonce. Retargeting an attestation to another
//! digest would take a second preimage of that verifier.

use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use libid_crypto::keccak256;
use sha2::{
    Digest,
    Sha256,
};

/// Domain separator, carrying no version of its own: the Authorization Digest
/// already binds `platformVerifierVersion`, and a change to this construction
/// changes the proof statement, which bumps that version (REQ-COMMON-12).
pub const PKCE_DOMAIN_STRING: &str = "libid.identity.pkce";

/// Both the verifier and the challenge are exactly this many unpadded
/// base64url characters.
pub const PKCE_LEN: usize = 43;

/// `keccak256(PKCE_DOMAIN_STRING)`.
pub fn pkce_domain() -> [u8; 32] {
    keccak256(PKCE_DOMAIN_STRING.as_bytes())
}

/// `SHA256(PKCE_DOMAIN || authorizationDigest || pkceNonce)`.
pub fn verifier_hash(authorization_digest: &[u8; 32], pkce_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pkce_domain());
    hasher.update(authorization_digest);
    hasher.update(pkce_nonce);
    hasher.finalize().into()
}

/// `BASE64URL_NOPAD(verifierHash)` -- the `code_verifier` the token request
/// carries and the Platform Verifier recomputes.
///
/// `pkce_nonce` is drawn freshly per authorization attempt: the nonce becomes
/// public at submission, so reusing one across attempts of a single digest
/// publishes the verifier of an earlier attempt whose code may still be live
/// (REQ-COMMON-13).
pub fn code_verifier(authorization_digest: &[u8; 32], pkce_nonce: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(verifier_hash(authorization_digest, pkce_nonce))
}

/// `BASE64URL_NOPAD(SHA256(ASCII(code_verifier)))` -- the S256 challenge sent
/// in the authorization request.
pub fn code_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Authorization Digest of the section 5 vector.
    const DIGEST: [u8; 32] = [
        0xb3, 0x18, 0xfb, 0x55, 0x9e, 0x16, 0xa1, 0x79, 0xb8, 0x53, 0xed, 0x28, 0x53,
        0x57, 0x6c, 0xda, 0x16, 0x03, 0x2d, 0x93, 0xb0, 0x83, 0x9b, 0xb8, 0x1a, 0x55,
        0x13, 0x5d, 0x33, 0x4c, 0x0a, 0xf5,
    ];
    const NONCE: [u8; 32] = [0x44; 32];

    #[test]
    fn matches_the_specification_vector() {
        assert_eq!(
            hex::encode(pkce_domain()),
            "3961dfe56cd0f2d94e72a15b96df889fbb46968cdb37518830fc0077b0730a01"
        );
        assert_eq!(
            hex::encode(verifier_hash(&DIGEST, &NONCE)),
            "88c493361ea0424467046958d5cd0c50eb03ecc08ee06f02ee9875fe0219b392"
        );
        let verifier = code_verifier(&DIGEST, &NONCE);
        assert_eq!(verifier, "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I");
        assert_eq!(
            code_challenge(&verifier),
            "BhFqYIY1YnHafYOrrblUswFnjxFF97UvGjSgqugPQvA"
        );
    }

    #[test]
    fn both_values_are_forty_three_unpadded_characters() {
        let verifier = code_verifier(&DIGEST, &NONCE);
        let challenge = code_challenge(&verifier);
        assert_eq!(verifier.len(), PKCE_LEN);
        assert_eq!(challenge.len(), PKCE_LEN);
        for value in [&verifier, &challenge] {
            assert!(!value.contains('='), "padding leaked into {value}");
            assert!(!value.contains('+'), "not base64url: {value}");
            assert!(!value.contains('/'), "not base64url: {value}");
        }
    }

    #[test]
    fn the_verifier_is_a_pkce_charset_string() {
        // RFC 7636 unreserved set, which base64url is a subset of.
        let verifier = code_verifier(&DIGEST, &NONCE);
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn a_different_digest_gives_a_different_verifier() {
        // This is the binding. If it failed, one notarized token request would
        // serve any transaction.
        let mut other = DIGEST;
        other[0] ^= 1;
        assert_ne!(
            code_verifier(&DIGEST, &NONCE),
            code_verifier(&other, &NONCE)
        );
    }

    #[test]
    fn a_different_nonce_gives_a_different_verifier() {
        // Which is what makes a retry of one digest unpredictable to anyone
        // holding only the public digest.
        let mut other = NONCE;
        other[31] ^= 1;
        assert_ne!(
            code_verifier(&DIGEST, &NONCE),
            code_verifier(&DIGEST, &other)
        );
    }

    #[test]
    fn the_domain_separates_this_hash_from_a_bare_one() {
        let bare: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(DIGEST);
            h.update(NONCE);
            h.finalize().into()
        };
        assert_ne!(verifier_hash(&DIGEST, &NONCE), bare);
    }
}
