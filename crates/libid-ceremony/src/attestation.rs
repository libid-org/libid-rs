//! The attestation format of ceremony-common section 9.1.
//!
//! An attestation is a byte string and a signature over it. The Notary Service
//! signs off chain, where it holds the transcript, and verifies on chain, where
//! it holds none. The verifying side therefore rebuilds these exact bytes from
//! what it was handed and derives the signing key from them: a field reordered,
//! omitted, or encoded differently on either side derives a key nobody trusts
//! (REQ-COMMON-47).
//!
//! Every boundary is derivable from bytes that precede it, so decoding is one
//! forward pass and two different attestations cannot share one preimage by
//! shifting a boundary (REQ-COMMON-48).
//!
//! # Where these requirement numbers come from
//!
//! The `REQ-COMMON-47` through `REQ-COMMON-61` cited below are NOT in the
//! published specification. They were written in libid PR #12, which defined
//! this byte layout and was closed on 2026-08-20 without merging; PR #15 does
//! not restore it. What survives on main is `REQ-COMMON-18`, which requires a
//! Platform Profile to PIN the attestation format it accepts and leaves the
//! format itself to the profile author.
//!
//! So this module is the definition, not a reading of one. The numbering is
//! kept because it is the specification's own, and the intent is to upstream
//! this layout under those identifiers -- the specification follows what the
//! implementation needs. Until it does, a reader looking these up will not
//! find them, and every rule they name is stated in full here.
//!
//! Four components must agree on these bytes: this crate, the Solidity
//! decoder, the TypeScript mirror, and the notary that signs them. A
//! divergence is silent -- the signature derives a key nobody trusts and every
//! genuine attestation is rejected with no error saying why.

use libid_crypto::keccak256;

/// Offsets are zero-based into that direction's complete transcript, `start`
/// inclusive and `end` exclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevealedRange {
    pub start: u32,
    pub end: u32,
    pub bytes: Vec<u8>,
}

/// A hidden range, carried as its offsets and a blinded commitment. The
/// plaintext of a committed range never appears in the attested data
/// (REQ-COMMON-60).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeCommitment {
    pub start: u32,
    pub end: u32,
    pub commitment: [u8; 32],
}

/// One direction of the session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectionBlock {
    pub revealed: Vec<RevealedRange>,
    pub commitments: Vec<RangeCommitment>,
}

/// The signed bytes.
///
/// The attested data describes the observed session and says nothing about
/// where the evidence will be spent: no chain, no verifier identity. The
/// Authorization Digest already commits the chain, and binding an attestation
/// to one verifier would stop a newly registered version checking attestations
/// made before it existed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedData {
    pub format_tag: [u8; 32],
    pub platform_id: [u8; 32],
    pub operation_tag: [u8; 32],
    pub authority_id: [u8; 32],
    pub created_at: u64,
    pub sent_transcript_length: u32,
    pub recv_transcript_length: u32,
    pub sent: DirectionBlock,
    pub received: DirectionBlock,
}

/// Bytes before the first direction block: four 32-byte tags, `createdAt`, and
/// the two transcript lengths.
pub const HEADER_LEN: usize = 32 * 4 + 8 + 4 + 4;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("attested data ends inside the {field} field")]
    Truncated { field: &'static str },
    #[error("{0} bytes remain after the received direction block")]
    TrailingBytes(usize),
    #[error("a direction holds {0} entries, which does not fit the two-byte count")]
    CountTooLarge(usize),
    #[error("revealed range {index} of the {direction} direction carries {carried} bytes for offsets {start}..{end}")]
    RangeLengthMismatch {
        direction: &'static str,
        index: usize,
        start: u32,
        end: u32,
        carried: usize,
    },
    #[error("{kind} {index} of the {direction} direction is empty at offset {start}")]
    EmptyRange {
        direction: &'static str,
        kind: &'static str,
        index: usize,
        start: u32,
    },
    #[error("{kind} {index} of the {direction} direction starts at {start}, behind the previous end {previous_end}")]
    OutOfOrder {
        direction: &'static str,
        kind: &'static str,
        index: usize,
        start: u32,
        previous_end: u32,
    },
    #[error("{kind} {index} of the {direction} direction ends at {end}, past the signed transcript length {length}")]
    PastTranscriptEnd {
        direction: &'static str,
        kind: &'static str,
        index: usize,
        end: u32,
        length: u32,
    },
    #[error("a commitment of the {direction} direction overlaps a revealed range at {start}..{end}")]
    CommitmentOverlapsRevealed {
        direction: &'static str,
        start: u32,
        end: u32,
    },
    #[error("transcript bytes {from}..{to} of the {direction} direction are covered by nothing")]
    CoverageGap {
        direction: &'static str,
        from: u32,
        to: u32,
    },
    #[error("spans of the {direction} direction overlap at {at}")]
    SpansOverlap { direction: &'static str, at: u32 },
    #[error("the {direction} direction holds {count} commitments, but this request commits exactly one credential")]
    NotOneCommitment {
        direction: &'static str,
        count: usize,
    },
    #[error("the revealed {direction} bytes carry an obsolete line fold at {at}")]
    ObsoleteLineFold { direction: &'static str, at: usize },
    #[error(
        "the revealed {direction} bytes hold {count} authorization header lines, not one"
    )]
    NotOneAuthorizationHeader {
        direction: &'static str,
        count: usize,
    },
    #[error("the committed range of the {direction} direction is not framed by an authorization header line")]
    BadBearerFraming { direction: &'static str },
}

/// Derive a 32-byte tag from a libID-namespaced ASCII string.
///
/// Used for `formatTag` (REQ-COMMON-53), `platformId` and `operationTag`
/// (REQ-COMMON-55), and `authorityId` over the canonical authority bytes
/// (REQ-COMMON-56).
pub fn tag(namespaced: &str) -> [u8; 32] {
    keccak256(namespaced.as_bytes())
}

impl DirectionBlock {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.revealed.len() as u16).to_be_bytes());
        for range in &self.revealed {
            out.extend_from_slice(&range.start.to_be_bytes());
            out.extend_from_slice(&range.end.to_be_bytes());
            out.extend_from_slice(&range.bytes);
        }
        out.extend_from_slice(&(self.commitments.len() as u16).to_be_bytes());
        for commitment in &self.commitments {
            out.extend_from_slice(&commitment.start.to_be_bytes());
            out.extend_from_slice(&commitment.end.to_be_bytes());
            out.extend_from_slice(&commitment.commitment);
        }
    }
}

impl AttestedData {
    /// Lay the record out. This does NOT judge it: a malformed record is the
    /// prover's problem, the Platform Verifier's decision, and the client's to
    /// catch in a dry run. Refusing to sign here would only withhold a session
    /// the notary really did observe.
    pub fn encode(&self) -> Result<Vec<u8>, AttestationError> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&self.format_tag);
        out.extend_from_slice(&self.platform_id);
        out.extend_from_slice(&self.operation_tag);
        out.extend_from_slice(&self.authority_id);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.sent_transcript_length.to_be_bytes());
        out.extend_from_slice(&self.recv_transcript_length.to_be_bytes());
        self.sent.encode_into(&mut out);
        self.received.encode_into(&mut out);
        Ok(out)
    }

    /// Parse and validate. Trailing bytes are refused: the layout accounts for
    /// every byte, so a suffix is a second message hiding behind the first.
    pub fn digest(&self) -> Result<[u8; 32], AttestationError> {
        Ok(keccak256(&self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AttestedData {
        // Shaped like the X identity session: the request reveals everything
        // but the bearer, which is committed and framed by the header bytes.
        AttestedData {
            format_tag: tag("libid.attestation.v1"),
            platform_id: tag("x"),
            operation_tag: tag("libid.ceremony.session.identity.v1"),
            authority_id: tag("api.x.com"),
            created_at: 1_770_000_000,
            sent_transcript_length: 60,
            recv_transcript_length: 40,
            sent: DirectionBlock {
                revealed: vec![
                    RevealedRange {
                        start: 0,
                        end: 20,
                        bytes: vec![b'a'; 20],
                    },
                    RevealedRange {
                        start: 40,
                        end: 60,
                        bytes: vec![b'b'; 20],
                    },
                ],
                commitments: vec![RangeCommitment {
                    start: 20,
                    end: 40,
                    commitment: [7u8; 32],
                }],
            },
            received: DirectionBlock {
                revealed: vec![RevealedRange {
                    start: 0,
                    end: 10,
                    bytes: vec![b'c'; 10],
                }],
                commitments: vec![RangeCommitment {
                    start: 10,
                    end: 40,
                    commitment: [9u8; 32],
                }],
            },
        }
    }

    /// The exact bytes `solidity/contracts/ceremony/test/CeremonyAttestation.t.sol`
    /// decodes. Both sides carry this fixture, so a change to either encoder
    /// breaks loudly here rather than diverging quietly and rejecting every
    /// genuine attestation on chain.
    const CROSS_LANGUAGE_FIXTURE: &str = "f1b67c286f7f90224eb4661a5922406b5092042b9515e4e9e448ec1d4f55b352\
7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83\
e7b961087ec316778e6885d11145cc06f1d75360430f461d0322fb7f105899dd\
4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d\
0000000069800e800000003c00000028000200000000000000146161616161616161616161616161616161616161\
000000280000003c62626262626262626262626262626262626262620001000000140000002807070707070707070707070707070707070707070707070707070707070707070001000000000000000a6363636363636363636300010000000a000000280909090909090909090909090909090909090909090909090909090909090909";

    const CROSS_LANGUAGE_DIGEST: &str =
        "511d91f8a3c13c1824fd1d3e7c011caf09f2f0763f1ede5c786839592ae8d252";

    #[test]
    fn agrees_with_the_solidity_decoder() {
        let encoded = sample().encode().unwrap();
        assert_eq!(hex::encode(&encoded), CROSS_LANGUAGE_FIXTURE);
        assert_eq!(
            hex::encode(sample().digest().unwrap()),
            CROSS_LANGUAGE_DIGEST
        );
    }

    #[test]
    fn header_is_one_hundred_and_forty_four_bytes() {
        let mut data = sample();
        data.sent = DirectionBlock::default();
        data.received = DirectionBlock::default();
        data.sent_transcript_length = 0;
        data.recv_transcript_length = 0;
        // Header plus two empty counts per direction.
        assert_eq!(data.encode().unwrap().len(), HEADER_LEN + 4 + 4);
        assert_eq!(HEADER_LEN, 144);
    }

    #[test]
    fn every_header_field_changes_the_digest() {
        let base = sample().digest().unwrap();
        for mutate in [
            (|d: &mut AttestedData| d.format_tag[0] ^= 1) as fn(&mut AttestedData),
            |d| d.platform_id[0] ^= 1,
            |d| d.operation_tag[0] ^= 1,
            |d| d.authority_id[0] ^= 1,
            |d| d.created_at += 1,
        ] {
            let mut data = sample();
            mutate(&mut data);
            assert_ne!(data.digest().unwrap(), base);
        }
    }

    #[test]
    fn two_sessions_of_one_ceremony_are_not_interchangeable() {
        // REQ-COMMON-55: without operationTag the token and identity
        // attestations of one ceremony would differ in nothing a verifier reads.
        let mut token = sample();
        token.operation_tag = tag("libid.ceremony.session.token.v1");
        assert_ne!(token.digest().unwrap(), sample().digest().unwrap());
    }

    #[test]
    fn a_shifted_boundary_cannot_produce_one_preimage() {
        // Moving a byte from a revealed range into the next one changes the
        // encoding, because both offsets and both lengths are written down.
        let mut moved = sample();
        moved.sent.revealed[0].end = 19;
        moved.sent.revealed[0].bytes.pop();
        moved.sent.commitments[0].start = 19;
        assert_ne!(moved.digest().unwrap(), sample().digest().unwrap());
    }
}
