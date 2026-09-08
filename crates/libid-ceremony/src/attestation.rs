//! The attested-data format the launch profiles pin.
//!
//! THE LAYOUT IS THE PROFILE'S, NOT THE SPECIFICATION'S. `REQ-COMMON-18` has a
//! Platform Profile fix the attestation format it accepts and leaves the format
//! itself to the profile author. So this module is the definition, not a
//! reading of one, and every rule it keeps is stated here in full.
//!
//! An attestation is a byte string and a signature over it. The Notary Service
//! signs off chain, where it holds the transcript, and verifies on chain, where
//! it holds none. The verifying side therefore rebuilds these exact bytes from
//! what it was handed and derives the signing key from them: a field reordered,
//! omitted, or encoded differently on either side derives a key nobody trusts,
//! and `REQ-COMMON-33` leaves it nothing else to check the signature against.
//!
//! Every boundary is derivable from bytes that precede it, so decoding is one
//! forward pass and two different attestations cannot share one preimage by
//! shifting a boundary.
//!
//! Four components must agree on these bytes: this crate, the Solidity
//! decoder, the TypeScript mirror, and the notary that signs them. A
//! divergence is silent -- the signature derives a key nobody trusts and every
//! genuine attestation is rejected with no error saying why.

use libid_crypto::keccak256;

/// Offsets are zero-based into that direction's complete transcript, `start`
/// inclusive and `end` exclusive.
#[derive(Clone, Debug, PartialEq, Eq, bincode::Encode)]
pub struct RevealedRange {
    pub start: u32,
    /// The range's plaintext. Its length IS the range's length -- there is no
    /// `end`, because two ways to say the same thing is one way to disagree.
    /// The decoder computes `end = start + bytes.len()`.
    pub bytes: Vec<u8>,
}

/// A hidden range, carried as its offsets and a blinded commitment. The
/// plaintext of a committed range never appears in the attested data.
#[derive(Clone, Debug, PartialEq, Eq, bincode::Encode)]
pub struct RangeCommitment {
    pub start: u32,
    pub end: u32,
    pub commitment: [u8; 32],
}

/// One direction of the session.
#[derive(Clone, Debug, Default, PartialEq, Eq, bincode::Encode)]
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
#[derive(Clone, Debug, PartialEq, Eq, bincode::Encode)]
pub struct AttestedData {
    /// The TLS server name the notary authenticated, hashed.
    ///
    /// This is the only identity in the record, and the notary observed it
    /// rather than being told it. Which platform that host belongs to, and
    /// which session of a ceremony this is, are read from the revealed request
    /// line by the party that pins those constants.
    pub authority_id: [u8; 32],
    pub created_at: u64,
    pub sent_transcript_length: u32,
    pub recv_transcript_length: u32,
    pub sent: DirectionBlock,
    pub received: DirectionBlock,
}

/// Bytes before the first direction block: the authority, `createdAt`, and the
/// two transcript lengths.
pub const HEADER_LEN: usize = 32 + 8 + 4 + 4;

/// Big-endian, fixed-width, no varints: the decoder is Solidity, which has no
/// use for a compact integer that costs a branch to read.
///
/// Pinned to one exact bincode version in `Cargo.toml`. These bytes are a
/// signed preimage, so a layout change in a patch release would silently
/// change what every notary signs -- and the cross-language fixture below is
/// what would catch it.
const WIRE: bincode::config::Configuration<
    bincode::config::BigEndian,
    bincode::config::Fixint,
> = bincode::config::standard()
    .with_big_endian()
    .with_fixed_int_encoding();

impl AttestedData {
    /// The `authority_id` of a record covering a session with `server_name`:
    /// keccak256 over the canonical authority bytes (REQ-COMMON-21,
    /// REQ-COMMON-21A).
    ///
    /// An associated function on the record rather than a free `tag`, because
    /// the free form said nothing about what may be hashed. The one input this
    /// field accepts is the TLS server name the notary AUTHENTICATED. A `Host`
    /// header the prover composed hashes just as well and yields a record
    /// naming an authority nobody observed -- and that substitution is one the
    /// transcript cannot rule out, since the request carries the authority only
    /// where the prover wrote it. Naming the record puts the rule beside the
    /// field.
    ///
    /// A string rather than a server-name type: this crate is published and
    /// knows nothing about how a TLS library models a name, which is also what
    /// keeps this mapping testable without a session.
    ///
    /// The record's one remaining 32-byte tag. It used to serve three more --
    /// format, platform and session -- and those went with the fields the
    /// notary was handed rather than saw.
    pub fn authority_id_of(server_name: &str) -> [u8; 32] {
        keccak256(server_name.as_bytes())
    }

    /// Lay the record out. This does NOT judge it: a malformed record is the
    /// prover's problem, the Platform Verifier's decision, and the client's to
    /// catch in a dry run. Refusing to sign here would only withhold a session
    /// the notary really did observe.
    ///
    /// The layout is the struct above, in declaration order. Nothing here
    /// restates it, so nothing here can drift from it.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::error::EncodeError> {
        bincode::encode_to_vec(self, WIRE)
    }

    /// What the notary signs, and the only preimage it ever signs
    /// (REQ-COMMON-33).
    pub fn digest(&self) -> Result<[u8; 32], bincode::error::EncodeError> {
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
            authority_id: AttestedData::authority_id_of("api.x.com"),
            created_at: 1_770_000_000,
            sent_transcript_length: 60,
            recv_transcript_length: 40,
            sent: DirectionBlock {
                revealed: vec![
                    RevealedRange {
                        start: 0,
                        bytes: vec![b'a'; 20],
                    },
                    RevealedRange {
                        start: 40,
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
    const CROSS_LANGUAGE_FIXTURE: &str = "4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d0000000069800e800000003c00000028000000000000000200000000000000000000001461616161616161616161616161616161616161610000002800000000000000146262626262626262626262626262626262626262000000000000000100000014000000280707070707070707070707070707070707070707070707070707070707070707000000000000000100000000000000000000000a6363636363636363636300000000000000010000000a000000280909090909090909090909090909090909090909090909090909090909090909";

    const CROSS_LANGUAGE_DIGEST: &str =
        "48162f05bdb27b19b3544bf2aae608745861bf357bb31e07f536b6fb50e95936";

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
        // Four counts, one per direction per list, eight bytes each.
        assert_eq!(data.encode().unwrap().len(), HEADER_LEN + 4 * 8);
        assert_eq!(HEADER_LEN, 48);
    }

    #[test]
    fn every_header_field_changes_the_digest() {
        let base = sample().digest().unwrap();
        for mutate in [
            (|d: &mut AttestedData| d.authority_id[0] ^= 1) as fn(&mut AttestedData),
            |d| d.created_at += 1,
        ] {
            let mut data = sample();
            mutate(&mut data);
            assert_ne!(data.digest().unwrap(), base);
        }
    }

    #[test]
    fn two_sessions_of_one_ceremony_are_not_interchangeable() {
        // Nothing in the record labels which session it covers, and nothing
        // needs to: the sessions differ in what the notary OBSERVED. The
        // request line is a revealed range, and the verifier compares it
        // against the path its profile pins, so a token attestation offered in
        // the identity slot fails on bytes the notary actually saw rather than
        // on a label it was handed.
        let mut token = sample();
        token.sent.revealed[0].bytes = b"POST /2/oauth2/token ".to_vec();
        assert_ne!(token.digest().unwrap(), sample().digest().unwrap());
    }

    #[test]
    fn a_shifted_boundary_cannot_produce_one_preimage() {
        // Moving a byte from a revealed range into the next one changes the
        // encoding: the range's length is its bytes, and the following span
        // starts one earlier.
        let mut moved = sample();
        moved.sent.revealed[0].bytes.pop();
        moved.sent.commitments[0].start = 19;
        assert_ne!(moved.digest().unwrap(), sample().digest().unwrap());
    }
}
