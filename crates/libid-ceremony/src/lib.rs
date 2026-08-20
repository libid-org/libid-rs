//! Wire constructions of the libID identity ceremony.
//!
//! One implementation of each construction the specification fixes, so the
//! notary, the backend and the conformance suite cannot disagree about bytes:
//!
//! * [`authorization`] -- the Authorization Digest of ceremony-common
//!   section 5, which binds one authorization to the transaction that will
//!   consume it.
//! * [`pkce`] -- the derived `code_verifier` of section 7, which is how X and
//!   GitHub carry that digest through an OAuth authorization.
//! * [`attestation`] -- the attested-data byte layout of section 9.1, which is
//!   what the Notary Service signs and what the Platform Verifier rebuilds.
//!
//! Each module's tests pin it to the conformance vectors the specification
//! publishes, taken from the specification rather than from this code.

pub mod attestation;
pub mod authorization;
pub mod pkce;

pub use attestation::{
    AttestationError,
    AttestedData,
    DirectionBlock,
    RangeCommitment,
    RevealedRange,
};
pub use authorization::{
    AuthorizationError,
    AuthorizationPreimage,
};
pub use pkce::{
    code_challenge,
    code_verifier,
};
