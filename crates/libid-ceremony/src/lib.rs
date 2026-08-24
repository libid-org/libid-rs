//! What the notary needs to sign a ceremony attestation, and nothing else.
//!
//! # Why this crate is small
//!
//! The notary's whole job is to record what it observed and sign it. It does
//! not judge that record: whether the ranges tile the transcript, whether a
//! request carries exactly one authorization header, whether the framing bytes
//! are right -- every one of those is the Platform Verifier's decision, and the
//! Platform Verifier is Solidity.
//!
//! A copy of those checks here would be a second opinion nobody asked for. Its
//! only power would be to refuse to sign a session the notary really did
//! observe, which is a denial of service by a party with no standing to judge.
//! REQ-COMMON-33 says it more plainly: the notary decides nothing
//! profile-specific.
//!
//! Where a check IS wanted before spending gas, it belongs in the client as a
//! dry run -- and it already lives there. `@libid/contracts` exports
//! `decodeAttestedData`, `validate`, `requireExactCoverage` and
//! `requireBearerHeaderRequest` in TypeScript, which is what REQ-PLAT-44 has
//! the Canonical Runtime call before it spends a second session on an
//! attestation.
//!
//! The same reasoning removed the last labels. The notary used to stamp a
//! format tag, a platform id and a session tag; it observed none of them. The
//! format is fixed by the notary key a profile pins alongside it
//! (REQ-COMMON-18); the platform is the host it connected to; and which session
//! this is, is the request line it recorded. All three were a party naming
//! things it was told rather than things it saw.
//!
//! So this crate holds one direction of one thing:
//!
//! * [`attestation`] -- the types of ceremony-common section 9.1 and the
//!   encoder that lays them out. No decoder: whoever decodes also checks, and
//!   that is the chain and the client.
//! * [`token_exchange`] -- the GitHub Token-Exchange Service's own request and
//!   response records. Its validation stays, because REQ-PLAT-37 to -40 put
//!   that service's input validation on that service; no contract sees it.

pub mod attestation;
pub mod token_exchange;

pub use attestation::{
    AttestedData,
    DirectionBlock,
    RangeCommitment,
    RevealedRange,
};
