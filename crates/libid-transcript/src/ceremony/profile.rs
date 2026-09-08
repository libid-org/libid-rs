//! The launch profiles, as the chain pins them.
//!
//! Every value a prover has to get exactly right, and a Platform Verifier
//! compares byte for byte, lives here once. Before this module each caller kept
//! its own copies -- the authority it named, the path it requested, the field
//! names it revealed -- and a wrong one failed on chain, where the error names
//! an offset rather than the constant behind it.
//!
//! # These are pinned, not stated
//!
//! The chain holds its own copy in `CeremonyProfile.sol` and the per-platform
//! verifiers, and the specification fixes no literal of its own: REQ-PLAT-01
//! fixes the profile NAMES, and the bytes are the profile author's. So a table
//! here is a second copy, and a second copy that nothing checks is worse than
//! no table at all -- it looks authoritative and drifts silently.
//!
//! What makes it safe is that both sides assert against the same numbers,
//! computed independently. `CeremonyProfile.t.sol` pins each platform id and
//! authority id to a `cast keccak` value; the `profile_vectors` test in
//! `libid-tlsn` hashes the strings below and asserts the same hex. Change a
//! string on either side and one of the two fails.
//!
//! The request lines and field names have no such vector on the contract side
//! yet -- they are pinned there by the fixtures its verifier tests decode, and
//! here by [`Session::request_line`] against the contract's literals. That is
//! weaker, and it is worth closing.

use super::IdShape;

/// One notarized session: which server, and which request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    /// The TLS server name the notary authenticates, lowercase and with no
    /// trailing dot. `authorityId` is its keccak256, which the verifier
    /// compares against the constant its profile pins (REQ-COMMON-21A).
    ///
    /// It is also the `Host` header, which is why one field serves both: the
    /// header is prover-composed and says nothing on its own, and the value the
    /// notary observed is this.
    pub authority: &'static str,
    pub method: &'static str,
    pub path: &'static str,
}

impl Session {
    /// The request-line prefix the Platform Verifier compares byte for byte,
    /// trailing space included -- `_tokenRequestLine` and
    /// `_identityRequestLine` on chain.
    ///
    /// The space is what stops `/user` matching `/users/me`. Derived rather
    /// than stored so the method and path cannot disagree with it.
    pub fn request_line(&self) -> String {
        format!("{} {} ", self.method, self.path)
    }

    /// The absolute URI `prover_generic` takes. It derives the server to reach
    /// from the authority and rewrites the target to origin-form before the
    /// request goes on the wire.
    pub fn uri(&self) -> String {
        format!("https://{}{}", self.authority, self.path)
    }
}

/// The token session: the OAuth exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenSession {
    pub session: Session,
    /// The body field committed rather than revealed, ordered last in the body
    /// so the committed run is a suffix (REQ-COMMON-22). `None` for a public
    /// client, whose request hides nothing and is revealed whole -- which is
    /// the `_tokenSentCommitments()` of 0 against GitHub's 1.
    pub secret_field: Option<&'static str>,
}

/// The identity session: the authenticated read that names the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentitySession {
    pub session: Session,
    /// The immutable account identifier and the shape it takes, and the handle.
    /// `_identityFields()` on chain returns exactly this triple.
    pub id_field: &'static str,
    pub id_shape: IdShape,
    pub handle_field: &'static str,
}

/// One platform's ceremony profile at one Platform Ceremony Version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The platform name. `platformId` is its keccak256.
    pub platform: &'static str,
    /// The Platform Ceremony Version. A profile is the pair, not the name
    /// (REQ-PLAT-01).
    pub version: u16,
    /// `None` where the profile notarizes nothing, as Google's does not.
    pub token: Option<TokenSession>,
    pub identity: Option<IdentitySession>,
}

impl Profile {
    /// How many attestations a submission for this profile carries.
    ///
    /// Derived from the sessions rather than stated beside them, which is what
    /// REQ-COMMON-41 asks and what `CeremonyProfile.attestationCount` does: a
    /// count written down separately is a count that can disagree with the list
    /// it counts.
    pub const fn attestation_count(&self) -> u8 {
        self.token.is_some() as u8 + self.identity.is_some() as u8
    }
}

/// The version every launch profile is at (`CeremonyProfile.LAUNCH_VERSION`).
pub const LAUNCH_VERSION: u16 = 1;

/// `google/v1`. It notarizes nothing: the evidence is a signed token verified
/// against Google's published keys, so there is no session and no fee.
pub const GOOGLE: Profile = Profile {
    platform: "google",
    version: LAUNCH_VERSION,
    token: None,
    identity: None,
};

/// `x/v1`. A public client, so the exchange hides nothing, and both sessions
/// are served by the same host.
pub const X: Profile = Profile {
    platform: "x",
    version: LAUNCH_VERSION,
    token: Some(TokenSession {
        session: Session {
            authority: "api.x.com",
            method: "POST",
            path: "/2/oauth2/token",
        },
        secret_field: None,
    }),
    identity: Some(IdentitySession {
        session: Session {
            authority: "api.x.com",
            method: "GET",
            path: "/2/users/me",
        },
        id_field: "id",
        id_shape: IdShape::JsonString,
        handle_field: "username",
    }),
};

/// `github/v1`. A confidential client, so the exchange commits its secret and
/// runs in the deployment; the two sessions are served by DIFFERENT hosts,
/// which is why one pinned authority per profile would be wrong.
pub const GITHUB: Profile = Profile {
    platform: "github",
    version: LAUNCH_VERSION,
    token: Some(TokenSession {
        session: Session {
            authority: "github.com",
            method: "POST",
            path: "/login/oauth/access_token",
        },
        secret_field: Some("client_secret"),
    }),
    identity: Some(IdentitySession {
        session: Session {
            authority: "api.github.com",
            method: "GET",
            path: "/user",
        },
        id_field: "id",
        id_shape: IdShape::JsonInteger,
        handle_field: "login",
    }),
};

/// The closed launch list: `("google", 1)`, `("x", 1)`, `("github", 1)`
/// (TEST-PLAT-17). A platform outside it has no profile, and
/// `CeremonyProfile.attestationCount` reverts on one.
pub const LAUNCH: &[Profile] = &[GOOGLE, X, GITHUB];

/// The launch profile for a platform name, or nothing.
///
/// Nothing, rather than a default: a caller that cannot name the platform has
/// nothing to notarize, and guessing produces evidence no verifier registered
/// for that platform accepts.
pub fn launch(platform: &str) -> Option<&'static Profile> {
    LAUNCH.iter().find(|p| p.platform == platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request-line prefixes `_tokenRequestLine` and
    /// `_identityRequestLine` return, transcribed from the verifiers. The
    /// derivation must produce these bytes exactly -- a missing trailing space
    /// would let `/user` match `/users/me`.
    #[test]
    fn the_request_lines_are_the_ones_the_verifiers_pin() {
        assert_eq!(
            X.token.unwrap().session.request_line(),
            "POST /2/oauth2/token "
        );
        assert_eq!(
            X.identity.unwrap().session.request_line(),
            "GET /2/users/me "
        );
        assert_eq!(
            GITHUB.token.unwrap().session.request_line(),
            "POST /login/oauth/access_token "
        );
        assert_eq!(
            GITHUB.identity.unwrap().session.request_line(),
            "GET /user "
        );
    }

    #[test]
    fn the_uri_is_absolute_and_names_the_authority() {
        // `prover_generic` reads the server to reach from this and rewrites the
        // target to origin-form before sending.
        assert_eq!(
            GITHUB.token.unwrap().session.uri(),
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(
            X.identity.unwrap().session.uri(),
            "https://api.x.com/2/users/me"
        );
    }

    #[test]
    fn the_counts_follow_the_sessions() {
        // Google's path stops at the Platform Verifier and pays no notary fee.
        assert_eq!(GOOGLE.attestation_count(), 0);
        assert_eq!(X.attestation_count(), 2);
        assert_eq!(GITHUB.attestation_count(), 2);
    }

    #[test]
    fn github_notarizes_two_different_authorities() {
        // The exchange is served by github.com and the identity read by
        // api.github.com. X uses one host for both.
        let token = GITHUB.token.unwrap().session.authority;
        let identity = GITHUB.identity.unwrap().session.authority;
        assert_ne!(token, identity);
        assert_eq!(
            X.token.unwrap().session.authority,
            X.identity.unwrap().session.authority
        );
    }

    #[test]
    fn only_the_confidential_client_commits_a_body_field() {
        // `_tokenSentCommitments()` is 1 for GitHub and 0 for X, and this is
        // the same fact stated where a prover reads it.
        assert_eq!(GITHUB.token.unwrap().secret_field, Some("client_secret"));
        assert_eq!(X.token.unwrap().secret_field, None);
    }

    #[test]
    fn the_launch_list_is_closed() {
        assert_eq!(launch("x"), Some(&X));
        assert_eq!(launch("github"), Some(&GITHUB));
        assert_eq!(launch("google"), Some(&GOOGLE));
        // A suffixed name is not one of these profiles (TEST-PLAT-17).
        assert_eq!(launch("x2"), None);
        assert_eq!(launch("mastodon"), None);
        assert_eq!(LAUNCH.len(), 3);
        for profile in LAUNCH {
            assert_eq!(profile.version, LAUNCH_VERSION);
        }
    }

    #[test]
    fn the_identity_fields_are_the_ones_the_verifiers_read() {
        let x = X.identity.unwrap();
        assert_eq!(
            (x.id_field, x.id_shape, x.handle_field),
            ("id", IdShape::JsonString, "username")
        );
        let gh = GITHUB.identity.unwrap();
        assert_eq!(
            (gh.id_field, gh.id_shape, gh.handle_field),
            ("id", IdShape::JsonInteger, "login")
        );
    }
}
