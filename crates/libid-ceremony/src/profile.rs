//! The three tags the notary stamps into attested data.
//!
//! This is the whole of what Rust needs from a Platform Profile. The notary
//! decides nothing profile-specific (REQ-COMMON-33): it names the byte layout,
//! says which session an attestation covers, and stops. Which ranges a profile
//! expects and what their bytes must contain belong to the Platform Verifier.
//!
//! The launch profiles themselves -- endpoints, authorities, handle rules,
//! protocol parameters -- are in [`crate::launch`], behind a feature, because
//! nothing in Rust reads them.
//!
//! # These strings are ours, not the specification's
//!
//! The specification fixes exactly one literal: `libid.identity.pkce`, in
//! ceremony-common section 7. `formatTag` (REQ-COMMON-53) and `operationTag`
//! (REQ-COMMON-55) are required to exist and required to be pinned, but their
//! bytes are left to the profile author. Those requirement numbers come from
//! libid PR #12, which was closed without merging, so a reader will not find
//! them on main.
//!
//! That makes these constants a cross-implementation agreement rather than a
//! reading of the specification. A notary emitting `libid.attestation.v1` and a
//! verifier pinning anything else derives a key nobody trusts and rejects every
//! genuine attestation, with no error that says why.

/// Names this attestation byte layout and its version (REQ-COMMON-53).
///
/// A change to the field list, to a field's width, or to a field's meaning
/// takes a new version string rather than another field.
pub const FORMAT_TAG: &str = "libid.attestation.v1";

/// Which session of the ceremony an attestation covers (REQ-COMMON-55).
///
/// One ceremony notarizes more than one session, and two attestations that
/// differ only in which session they came from would otherwise be
/// interchangeable.
pub const TOKEN_SESSION_TAG: &str = "libid.ceremony.session.token.v1";
pub const IDENTITY_SESSION_TAG: &str = "libid.ceremony.session.identity.v1";
