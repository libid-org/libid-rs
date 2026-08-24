//! The launch platform profiles, and the protocol parameters governance owns.
//!
//! # Nothing in Rust reads these
//!
//! A Platform Profile is what a Platform Verifier pins and what a browser
//! runtime selects. Neither is Rust: the verifier is Solidity and the runtime
//! is TypeScript. The notary, which IS Rust, is forbidden from deciding
//! anything profile-specific (REQ-COMMON-33) -- it stamps the three tags of
//! [`super::profile`] and derives nothing else.
//!
//! These records exist as a third reading of the specification's published
//! constants, so the conformance suite can check the Solidity and TypeScript
//! ones against something written independently. That makes them a test
//! oracle, which is why they are behind a feature no service enables. Compiled
//! into the notary they would be dead weight, and a mistake in them would be
//! invisible.

use crate::profile::{
    IDENTITY_SESSION_TAG,
    TOKEN_SESSION_TAG,
};

/// How a profile binds the Authorization Digest to its evidence
/// (REQ-COMMON-02C). Exactly one of the two, never both and never neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestBinding {
    /// Google: the digest is a public proof input the verifier compares.
    PublicProofInput,
    /// X and GitHub: the verifier recomputes the revealed `code_verifier`.
    RevealedCodeVerifier,
}

/// One notarized session of a ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionProfile {
    /// The `operationTag` this session's attestation must carry.
    pub operation_tag: &'static str,
    /// The TLS server name the notary must have authenticated, in the
    /// canonical form of section 9: lowercase ASCII, no trailing dot. It
    /// reaches the verifier as `authorityId`, never as a transcript range,
    /// because the transcript holds it only in a prover-composed `Host` header.
    pub authority: &'static str,
    /// Exact uppercase HTTP method, compared against a revealed range.
    pub method: &'static str,
    /// Origin-form path, no query, compared against a revealed range.
    pub path: &'static str,
}

/// The five parameters of platform-ceremonies section 2.1a.
///
/// `is_email` supersedes the two booleans below it (REQ-PLAT-67); they are
/// stated because REQ-PLAT-72 requires a profile to fix all five.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleRules {
    pub max_length: u16,
    pub strip_leading_at: bool,
    pub is_email: bool,
    pub allow_underscore: bool,
    pub allow_hyphen: bool,
}

/// An immutable, independently versioned ceremony profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformProfile {
    /// Preimage of `platformId` (REQ-COMMON-55).
    pub name: &'static str,
    /// Carried in the Authorization Digest and the submission. Launch profiles
    /// use 1 (REQ-PLAT-01).
    pub platform_verifier_version: u16,
    pub digest_binding: DigestBinding,
    /// The token or token-exchange session, where the profile has one.
    pub token_session: Option<SessionProfile>,
    /// The identity session, where the profile has one.
    pub identity_session: Option<SessionProfile>,
    pub handle: HandleRules,
}

impl PlatformProfile {
    /// Derived, never stated beside the session list: the profile fixes the
    /// list and the count is its size (REQ-COMMON-41).
    pub fn attestation_count(&self) -> u8 {
        self.token_session.is_some() as u8 + self.identity_session.is_some() as u8
    }

    /// A profile verifying no attestation reaches no Notary Service and pays
    /// nothing (REQ-COMMON-05D, REQ-COMMON-06E).
    pub fn verifies_attestations(&self) -> bool {
        self.attestation_count() > 0
    }
}

/// `google/v1` -- authentication-only OIDC. No token exchange, no client
/// secret, no PKCE, no notarized session, and therefore no Notary Fee.
pub const GOOGLE_V1: PlatformProfile = PlatformProfile {
    name: "google",
    platform_verifier_version: 1,
    digest_binding: DigestBinding::PublicProofInput,
    token_session: None,
    identity_session: None,
    handle: HandleRules {
        max_length: 62,
        strip_leading_at: false,
        is_email: true,
        allow_underscore: false,
        allow_hyphen: false,
    },
};

/// `x/v1` -- a public client with S256 PKCE and two browser-owned sessions.
pub const X_V1: PlatformProfile = PlatformProfile {
    name: "x",
    platform_verifier_version: 1,
    digest_binding: DigestBinding::RevealedCodeVerifier,
    token_session: Some(SessionProfile {
        operation_tag: TOKEN_SESSION_TAG,
        authority: "api.x.com",
        method: "POST",
        path: "/2/oauth2/token",
    }),
    identity_session: Some(SessionProfile {
        operation_tag: IDENTITY_SESSION_TAG,
        authority: "api.x.com",
        method: "GET",
        path: "/2/users/me",
    }),
    handle: HandleRules {
        max_length: 15,
        strip_leading_at: true,
        is_email: false,
        allow_underscore: true,
        allow_hyphen: false,
    },
};

/// `github/v1` -- a confidential client, so the exchange runs in the
/// deployment's Token-Exchange Service and that service is the notarized party
/// for the token session. Note the two authorities differ.
pub const GITHUB_V1: PlatformProfile = PlatformProfile {
    name: "github",
    platform_verifier_version: 1,
    digest_binding: DigestBinding::RevealedCodeVerifier,
    token_session: Some(SessionProfile {
        operation_tag: TOKEN_SESSION_TAG,
        authority: "github.com",
        method: "POST",
        path: "/login/oauth/access_token",
    }),
    identity_session: Some(SessionProfile {
        operation_tag: IDENTITY_SESSION_TAG,
        authority: "api.github.com",
        method: "GET",
        path: "/user",
    }),
    handle: HandleRules {
        max_length: 39,
        strip_leading_at: true,
        is_email: false,
        allow_underscore: false,
        allow_hyphen: true,
    },
};

pub const LAUNCH_PROFILES: [PlatformProfile; 3] = [GOOGLE_V1, X_V1, GITHUB_V1];

/// Governance-owned unsigned 64-bit values in seconds, read where they are
/// enforced (libid.md protocol parameters).
///
/// The Platform Verifier reads the current value when it verifies; a browser
/// read is advisory. Lowering one may reject an outstanding proof and raising
/// one may extend an outstanding X or GitHub proof, so they are authority
/// rather than configuration (REQ-PARAM-01, REQ-PARAM-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolParameters {
    /// Maximum age of the X token attestation.
    pub proof_lifetime_x: u64,
    /// Maximum age of the GitHub token-exchange attestation.
    pub proof_lifetime_github: u64,
    /// Maximum X or GitHub attestation lead over chain time.
    pub max_future_attestation_skew: u64,
}

/// The launch values.
pub const LAUNCH_PARAMETERS: ProtocolParameters = ProtocolParameters {
    proof_lifetime_x: 3600,
    proof_lifetime_github: 3600,
    max_future_attestation_skew: 300,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::tag;

    #[test]
    fn attestation_counts_match_the_profiles() {
        // Google verifies none and pays nothing; X and GitHub verify two each,
        // so one submission on either path pays two Notary Fees.
        assert_eq!(GOOGLE_V1.attestation_count(), 0);
        assert!(!GOOGLE_V1.verifies_attestations());
        assert_eq!(X_V1.attestation_count(), 2);
        assert_eq!(GITHUB_V1.attestation_count(), 2);
    }

    #[test]
    fn digest_binding_is_one_method_per_profile() {
        // REQ-COMMON-02C: never both, never neither. Google carries no
        // code_verifier; X and GitHub expose no digest public input.
        assert_eq!(GOOGLE_V1.digest_binding, DigestBinding::PublicProofInput);
        assert_eq!(X_V1.digest_binding, DigestBinding::RevealedCodeVerifier);
        assert_eq!(
            GITHUB_V1.digest_binding,
            DigestBinding::RevealedCodeVerifier
        );
    }

    #[test]
    fn the_two_sessions_of_a_profile_carry_different_tags() {
        // Otherwise a token attestation and an identity attestation of one
        // ceremony would be interchangeable (REQ-COMMON-55).
        for profile in [X_V1, GITHUB_V1] {
            let token = profile.token_session.unwrap();
            let identity = profile.identity_session.unwrap();
            assert_ne!(tag(token.operation_tag), tag(identity.operation_tag));
        }
    }

    #[test]
    fn github_notarizes_two_different_authorities() {
        // The exchange is served by github.com and the identity read by
        // api.github.com, so one pinned authority per profile would be wrong.
        let profile = GITHUB_V1;
        assert_eq!(profile.token_session.unwrap().authority, "github.com");
        assert_eq!(
            profile.identity_session.unwrap().authority,
            "api.github.com"
        );
        assert_ne!(
            tag(profile.token_session.unwrap().authority),
            tag(profile.identity_session.unwrap().authority)
        );
    }

    #[test]
    fn platform_ids_are_distinct() {
        let ids: Vec<_> = LAUNCH_PROFILES.iter().map(|p| tag(p.name)).collect();
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
    }

    #[test]
    fn authorities_are_canonical() {
        // Section 9: lowercase ASCII DNS name, no trailing dot, no scheme,
        // no port.
        for profile in LAUNCH_PROFILES {
            for session in [profile.token_session, profile.identity_session]
                .into_iter()
                .flatten()
            {
                let a = session.authority;
                assert_eq!(a, a.to_ascii_lowercase(), "authority not lowercase: {a}");
                assert!(!a.ends_with('.'), "trailing dot: {a}");
                assert!(
                    !a.contains('/') && !a.contains(':'),
                    "not a bare DNS name: {a}"
                );
                assert!(
                    session.path.starts_with('/'),
                    "path not origin-form: {}",
                    session.path
                );
                assert!(
                    !session.path.contains('?'),
                    "path carries a query: {}",
                    session.path
                );
                assert_eq!(session.method, session.method.to_ascii_uppercase());
            }
        }
    }

    #[test]
    fn handle_rules_match_the_published_parameter_table() {
        // platform-ceremonies section 2.1a.
        assert_eq!(
            (
                GOOGLE_V1.handle.max_length,
                GOOGLE_V1.handle.strip_leading_at,
                GOOGLE_V1.handle.is_email
            ),
            (62, false, true)
        );
        assert_eq!(
            (
                X_V1.handle.max_length,
                X_V1.handle.strip_leading_at,
                X_V1.handle.allow_underscore
            ),
            (15, true, true)
        );
        assert_eq!(
            (
                GITHUB_V1.handle.max_length,
                GITHUB_V1.handle.strip_leading_at,
                GITHUB_V1.handle.allow_hyphen
            ),
            (39, true, true)
        );
    }

    #[test]
    fn launch_parameters_match_the_published_values() {
        assert_eq!(LAUNCH_PARAMETERS.proof_lifetime_x, 3600);
        assert_eq!(LAUNCH_PARAMETERS.proof_lifetime_github, 3600);
        assert_eq!(LAUNCH_PARAMETERS.max_future_attestation_skew, 300);
    }
}
