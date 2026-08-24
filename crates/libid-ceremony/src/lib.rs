//! Wire constructions of the libID identity ceremony.
//!
//! # What Rust actually needs, and what is here for the vectors
//!
//! The notary is the only service that touches these bytes in production, and
//! it needs two things: [`attestation`], to build and sign the attested data of
//! ceremony-common section 9.1, and the three tags of [`profile`] to stamp into
//! it. [`token_exchange`] is the GitHub Token-Exchange Service's request and
//! response records, which that service will encode.
//!
//! Everything else is behind the `vectors` feature, off by default:
//!
//! * [`authorization`] -- the Authorization Digest of section 5.
//! * [`pkce`] -- the derived `code_verifier` of section 7.
//! * [`launch`] -- the launch platform profiles and protocol parameters.
//!
//! Nothing in Rust builds a digest, derives a verifier, or reads a profile
//! record. The browser builds the first two and the contracts recompute them;
//! a Platform Verifier pins the third. These modules exist so the conformance
//! suite can check those two implementations against a third, written
//! independently from the published vectors -- which makes them a test oracle.
//! An oracle compiled into every consumer is code nothing calls, and a mistake
//! in it is invisible. Hence the feature.
//!
//! Each module's tests pin it to the conformance vectors the specification
//! publishes, taken from the specification rather than from this code.

pub mod attestation;
pub mod profile;
pub mod token_exchange;

#[cfg(any(test, feature = "vectors"))]
pub mod authorization;
#[cfg(any(test, feature = "vectors"))]
pub mod launch;
#[cfg(any(test, feature = "vectors"))]
pub mod pkce;

pub use attestation::{
    AttestationError,
    AttestedData,
    DirectionBlock,
    RangeCommitment,
    RevealedRange,
};
#[cfg(any(test, feature = "vectors"))]
pub use authorization::{
    AuthorizationError,
    AuthorizationPreimage,
};
#[cfg(any(test, feature = "vectors"))]
pub use pkce::{
    code_challenge,
    code_verifier,
};
