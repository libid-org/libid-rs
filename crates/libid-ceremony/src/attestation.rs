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
    fn validate(
        &self,
        direction: &'static str,
        length: u32,
    ) -> Result<(), AttestationError> {
        if self.revealed.len() > u16::MAX as usize {
            return Err(AttestationError::CountTooLarge(self.revealed.len()));
        }
        if self.commitments.len() > u16::MAX as usize {
            return Err(AttestationError::CountTooLarge(self.commitments.len()));
        }

        let mut previous_end = 0u32;
        for (index, range) in self.revealed.iter().enumerate() {
            check_span(
                direction,
                "revealed range",
                index,
                range.start,
                range.end,
                length,
                &mut previous_end,
            )?;
            let want = (range.end - range.start) as usize;
            if range.bytes.len() != want {
                return Err(AttestationError::RangeLengthMismatch {
                    direction,
                    index,
                    start: range.start,
                    end: range.end,
                    carried: range.bytes.len(),
                });
            }
        }

        let mut previous_end = 0u32;
        for (index, commitment) in self.commitments.iter().enumerate() {
            check_span(
                direction,
                "commitment",
                index,
                commitment.start,
                commitment.end,
                length,
                &mut previous_end,
            )?;
            // A committed range that overlaps a revealed one would let the
            // same bytes be both read and hidden.
            for revealed in &self.revealed {
                if commitment.start < revealed.end && revealed.start < commitment.end {
                    return Err(AttestationError::CommitmentOverlapsRevealed {
                        direction,
                        start: commitment.start,
                        end: commitment.end,
                    });
                }
            }
        }
        Ok(())
    }

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

fn check_span(
    direction: &'static str,
    kind: &'static str,
    index: usize,
    start: u32,
    end: u32,
    length: u32,
    previous_end: &mut u32,
) -> Result<(), AttestationError> {
    if end <= start {
        return Err(AttestationError::EmptyRange {
            direction,
            kind,
            index,
            start,
        });
    }
    if start < *previous_end {
        return Err(AttestationError::OutOfOrder {
            direction,
            kind,
            index,
            start,
            previous_end: *previous_end,
        });
    }
    if end > length {
        return Err(AttestationError::PastTranscriptEnd {
            direction,
            kind,
            index,
            end,
            length,
        });
    }
    *previous_end = end;
    Ok(())
}

/// A forward cursor that never panics on a short buffer.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(
        &mut self,
        n: usize,
        field: &'static str,
    ) -> Result<&'a [u8], AttestationError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(AttestationError::Truncated { field })?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(AttestationError::Truncated { field })?;
        self.at = end;
        Ok(slice)
    }

    fn take32(&mut self, field: &'static str) -> Result<[u8; 32], AttestationError> {
        Ok(self.take(32, field)?.try_into().expect("checked length"))
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, AttestationError> {
        Ok(u16::from_be_bytes(
            self.take(2, field)?.try_into().expect("checked length"),
        ))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, AttestationError> {
        Ok(u32::from_be_bytes(
            self.take(4, field)?.try_into().expect("checked length"),
        ))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, AttestationError> {
        Ok(u64::from_be_bytes(
            self.take(8, field)?.try_into().expect("checked length"),
        ))
    }

    fn direction(&mut self) -> Result<DirectionBlock, AttestationError> {
        let revealed_count = self.u16("revealed range count")? as usize;
        let mut revealed = Vec::with_capacity(revealed_count);
        for _ in 0..revealed_count {
            let start = self.u32("revealed range start")?;
            let end = self.u32("revealed range end")?;
            // A start past its end would wrap; the validate pass rejects the
            // shape, so read nothing here rather than compute a huge length.
            let len = end.saturating_sub(start) as usize;
            revealed.push(RevealedRange {
                start,
                end,
                bytes: self.take(len, "revealed range bytes")?.to_vec(),
            });
        }

        let commitment_count = self.u16("commitment count")? as usize;
        let mut commitments = Vec::with_capacity(commitment_count);
        for _ in 0..commitment_count {
            commitments.push(RangeCommitment {
                start: self.u32("commitment start")?,
                end: self.u32("commitment end")?,
                commitment: self.take32("commitment value")?,
            });
        }

        Ok(DirectionBlock {
            revealed,
            commitments,
        })
    }
}

impl DirectionBlock {
    /// Require the revealed ranges and commitments to tile `[0, length)`
    /// exactly, with no gap and no overlap (REQ-COMMON-35).
    ///
    /// Only for a direction whose profile demands exact coverage. The rule is
    /// conditional: REQ-COMMON-43 withholds it from a credential committed in
    /// a request body, which is GitHub's `client_secret`, so [`validate`] does
    /// not apply it and a caller asks for it where the profile does.
    ///
    /// A gap is where a prover hides bytes. Exact coverage leaves the committed
    /// range as the only region the verifier cannot read and makes its offset
    /// and length follow from the ranges around it.
    ///
    /// [`validate`]: AttestedData::validate
    pub fn require_exact_coverage(
        &self,
        direction: &'static str,
        length: u32,
    ) -> Result<(), AttestationError> {
        let mut spans: Vec<(u32, u32)> =
            Vec::with_capacity(self.revealed.len() + self.commitments.len());
        spans.extend(self.revealed.iter().map(|r| (r.start, r.end)));
        spans.extend(self.commitments.iter().map(|c| (c.start, c.end)));
        spans.sort_unstable();

        let mut at = 0u32;
        for (start, end) in spans {
            // Overlap is `validate`'s job, but a caller may hand-build a block
            // and skip it. Naming it here beats reporting a backwards gap.
            if start < at {
                return Err(AttestationError::SpansOverlap {
                    direction,
                    at: start,
                });
            }
            if start != at {
                return Err(AttestationError::CoverageGap {
                    direction,
                    from: at,
                    to: start,
                });
            }
            at = end;
        }
        if at != length {
            return Err(AttestationError::CoverageGap {
                direction,
                from: at,
                to: length,
            });
        }
        Ok(())
    }
}

/// `\r\nauthorization: Bearer ` -- the raw bytes REQ-COMMON-40 requires
/// immediately before the committed range.
pub const BEARER_PREFIX: &[u8] = b"\r\nauthorization: Bearer ";
/// The raw bytes REQ-COMMON-40 requires immediately after it.
pub const BEARER_SUFFIX: &[u8] = b"\r\n";
/// The normalized, line-anchored needle REQ-COMMON-39 counts.
pub const AUTHORIZATION_NEEDLE: &[u8] = b"\r\nauthorization:bearer";

/// Lowercase ASCII and drop every space and horizontal tab, keeping CR and LF
/// (REQ-COMMON-39).
///
/// HTTP field names and the auth-scheme token are case-insensitive and the
/// colon admits optional whitespace, so a literal search over raw bytes is
/// evadable. Removing only bytes absent from the needle can create a spurious
/// match, which over-rejects and is safe, but can never hide a real one.
/// Keeping CR and LF is what makes the needle count header lines rather than
/// any substring.
fn normalize_header_bytes(raw: &[u8]) -> Vec<u8> {
    raw.iter()
        .filter(|b| **b != b' ' && **b != b'\t')
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

/// Read `[from, to)` of the transcript out of the revealed ranges, or `None`
/// if any byte of it is not revealed.
fn revealed_slice(block: &DirectionBlock, from: usize, to: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(to.checked_sub(from)?);
    let mut at = from;
    while at < to {
        let range = block
            .revealed
            .iter()
            .find(|r| (r.start as usize) <= at && at < (r.end as usize))?;
        let offset = at - range.start as usize;
        let take = (range.bytes.len() - offset).min(to - at);
        out.extend_from_slice(&range.bytes[offset..offset + take]);
        at += take;
    }
    Some(out)
}

fn count_needle(haystack: &[u8]) -> usize {
    if haystack.len() < AUTHORIZATION_NEEDLE.len() {
        return 0;
    }
    haystack
        .windows(AUTHORIZATION_NEEDLE.len())
        .filter(|w| *w == AUTHORIZATION_NEEDLE)
        .count()
}

impl DirectionBlock {
    /// Concatenate the revealed bytes in offset order.
    fn revealed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for range in &self.revealed {
            out.extend_from_slice(&range.bytes);
        }
        out
    }
}

impl AttestedData {
    /// Reject a shape the Platform Verifier must refuse: ranges out of order,
    /// overlapping, empty, or ending past the signed transcript length
    /// (REQ-COMMON-59, REQ-COMMON-60).
    pub fn validate(&self) -> Result<(), AttestationError> {
        self.sent.validate("sent", self.sent_transcript_length)?;
        self.received
            .validate("received", self.recv_transcript_length)
    }

    /// Serialize exactly the byte concatenation of section 9.1.
    pub fn encode(&self) -> Result<Vec<u8>, AttestationError> {
        self.validate()?;
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
    pub fn decode(bytes: &[u8]) -> Result<Self, AttestationError> {
        let mut reader = Reader { bytes, at: 0 };
        let decoded = AttestedData {
            format_tag: reader.take32("formatTag")?,
            platform_id: reader.take32("platformId")?,
            operation_tag: reader.take32("operationTag")?,
            authority_id: reader.take32("authorityId")?,
            created_at: reader.u64("createdAt")?,
            sent_transcript_length: reader.u32("sentTranscriptLength")?,
            recv_transcript_length: reader.u32("recvTranscriptLength")?,
            sent: reader.direction()?,
            received: reader.direction()?,
        };
        if reader.at != bytes.len() {
            return Err(AttestationError::TrailingBytes(bytes.len() - reader.at));
        }
        decoded.validate()?;
        Ok(decoded)
    }

    /// Every check REQ-COMMON-35, -39 and -40 require of an identity-session
    /// request that commits a credential in an HTTP `Authorization` header.
    ///
    /// At launch that is X's `/2/users/me` request and GitHub's `/user`
    /// request, and nothing else. A credential committed in a request body is
    /// a different case with its own rules, and REQ-COMMON-43 forbids applying
    /// these three to it -- GitHub's token exchange commits `client_secret` in
    /// a form body, so demanding a CRLF-framed header around that range would
    /// reject every valid exchange.
    ///
    /// The three are one call because they are one property, and because two
    /// of them are worthless alone. The uniqueness scan counts the needle
    /// across REVEALED bytes only, so a byte covered by nothing is a byte it
    /// never reads: without coverage a prover hides a second authorization
    /// header in a gap, the count stays at one, and the platform honours
    /// whichever header it likes. Coverage is what makes the scan complete.
    ///
    /// Returns the committed bearer range, which the Platform Verifier then
    /// matches against the circuit's identity-bearer public input.
    pub fn require_bearer_header_request(
        &self,
        direction: &'static str,
        block: &DirectionBlock,
        length: u32,
    ) -> Result<RangeCommitment, AttestationError> {
        // One committed range, so "the committed range" of REQ-COMMON-35 and
        // REQ-COMMON-40 and the commitment the circuit opens are the same
        // object. REQ-COMMON-60 permits several per direction, and nothing
        // else here would tie the framed range to the proved one.
        if block.commitments.len() != 1 {
            return Err(AttestationError::NotOneCommitment {
                direction,
                count: block.commitments.len(),
            });
        }
        let commitment = block.commitments[0].clone();

        block.require_exact_coverage(direction, length)?;

        let revealed = block.revealed_bytes();

        // Obsolete line folding is illegal in HTTP/1.1, and it defeats the
        // needle: `authorization:\r\n Bearer x` normalizes to
        // `authorization:\r\nbearer`, because normalization strips the space
        // but keeps the CRLF that the fold introduced. The header is then not
        // counted, and a server that honours the fold authenticates with it.
        for i in 0..revealed.len().saturating_sub(2) {
            if revealed[i] == b'\r'
                && revealed[i + 1] == b'\n'
                && (revealed[i + 2] == b' ' || revealed[i + 2] == b'\t')
            {
                return Err(AttestationError::ObsoleteLineFold { direction, at: i });
            }
        }

        // Count over each region separately rather than over a concatenation,
        // so joining the two cannot manufacture a match at the seam.
        let mut count = 0;
        for range in &block.revealed {
            count += count_needle(&normalize_header_bytes(&range.bytes));
        }
        if count != 1 {
            return Err(AttestationError::NotOneAuthorizationHeader { direction, count });
        }

        // Framing, on RAW bytes at known offsets. Two fixed comparisons make
        // the committed range one header line's value by construction, so the
        // credential cannot be hidden inside another header's value.
        let before_end = commitment.start as usize;
        let prefix_start = before_end.checked_sub(BEARER_PREFIX.len());
        let ok_prefix = match prefix_start {
            Some(from) => {
                revealed_slice(block, from, before_end) == Some(BEARER_PREFIX.to_vec())
            }
            None => false,
        };
        let after_start = commitment.end as usize;
        let ok_suffix =
            revealed_slice(block, after_start, after_start + BEARER_SUFFIX.len())
                == Some(BEARER_SUFFIX.to_vec());
        if !ok_prefix || !ok_suffix {
            return Err(AttestationError::BadBearerFraming { direction });
        }

        Ok(commitment)
    }

    /// `keccak256(attestedData)` -- the only preimage the notary signs
    /// (REQ-COMMON-47).
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
    fn coverage_accepts_an_exact_tiling() {
        let data = sample();
        data.sent
            .require_exact_coverage("sent", data.sent_transcript_length)
            .expect("the sample tiles 0..20, 20..40, 40..60");
    }

    #[test]
    fn coverage_rejects_a_gap() {
        // `validate` accepts this on purpose: coverage is conditional under
        // REQ-COMMON-43. The identity-session verifier is what must refuse it.
        let mut data = sample();
        data.sent.commitments[0].start = 21;
        data.validate().expect("shape alone still passes");
        assert_eq!(
            data.sent
                .require_exact_coverage("sent", data.sent_transcript_length),
            Err(AttestationError::CoverageGap {
                direction: "sent",
                from: 20,
                to: 21
            })
        );
    }

    #[test]
    fn coverage_rejects_a_trailing_gap() {
        // Bytes past the last range are invisible without the signed length to
        // close them (REQ-COMMON-36).
        let data = sample();
        assert_eq!(
            data.sent.require_exact_coverage("sent", 80),
            Err(AttestationError::CoverageGap {
                direction: "sent",
                from: 60,
                to: 80
            })
        );
    }

    #[test]
    fn round_trips() {
        let data = sample();
        assert_eq!(AttestedData::decode(&data.encode().unwrap()).unwrap(), data);
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
    fn rejects_out_of_order_revealed_ranges() {
        let mut data = sample();
        data.sent.revealed.swap(0, 1);
        assert!(matches!(
            data.encode(),
            Err(AttestationError::OutOfOrder {
                direction: "sent",
                ..
            })
        ));
    }

    #[test]
    fn rejects_overlapping_revealed_ranges() {
        let mut data = sample();
        data.sent.revealed[1].start = 10;
        data.sent.revealed[1].bytes = vec![b'b'; 50];
        assert!(matches!(
            data.encode(),
            Err(AttestationError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn rejects_an_empty_range() {
        let mut data = sample();
        data.sent.revealed[0].end = 0;
        data.sent.revealed[0].bytes.clear();
        assert!(matches!(
            data.encode(),
            Err(AttestationError::EmptyRange { .. })
        ));
    }

    #[test]
    fn rejects_a_range_past_the_signed_transcript_length() {
        // The signed length is what makes bytes past the last revealed range
        // visible at all (REQ-COMMON-36).
        let mut data = sample();
        data.sent_transcript_length = 50;
        assert!(matches!(
            data.encode(),
            Err(AttestationError::PastTranscriptEnd {
                end: 60,
                length: 50,
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_commitment_overlapping_a_revealed_range() {
        let mut data = sample();
        data.sent.commitments[0].start = 10;
        assert!(matches!(
            data.encode(),
            Err(AttestationError::CommitmentOverlapsRevealed { .. })
        ));
    }

    #[test]
    fn rejects_a_range_whose_bytes_disagree_with_its_offsets() {
        let mut data = sample();
        data.sent.revealed[0].bytes.push(b'a');
        assert!(matches!(
            data.encode(),
            Err(AttestationError::RangeLengthMismatch { carried: 21, .. })
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = sample().encode().unwrap();
        encoded.push(0);
        assert_eq!(
            AttestedData::decode(&encoded),
            Err(AttestationError::TrailingBytes(1))
        );
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        // Never panics, whatever a caller hands it.
        let encoded = sample().encode().unwrap();
        for cut in 0..encoded.len() {
            assert!(
                AttestedData::decode(&encoded[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
    }

    #[test]
    fn rejects_a_count_that_outruns_the_buffer() {
        // A declared count of 0xffff with no entries behind it must not
        // allocate its way to a panic.
        let mut encoded = sample().encode().unwrap();
        encoded[HEADER_LEN] = 0xff;
        encoded[HEADER_LEN + 1] = 0xff;
        assert!(AttestedData::decode(&encoded).is_err());
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

    // --- The identity-session request checks -------------------------------

    const BEARER: &[u8] = b"AAAAbbbbCCCCdddd";

    /// A real `/2/users/me` request: four headers, the bearer committed, every
    /// other byte revealed, tiled exactly.
    fn identity_request(
        extra_header: &str,
        bearer_prefix: &str,
    ) -> (DirectionBlock, u32) {
        let head = format!(
            "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\n{extra_header}{bearer_prefix}"
        );
        let tail = "\r\nconnection: close\r\n\r\n";
        let start = head.len() as u32;
        let end = start + BEARER.len() as u32;
        let length = end + tail.len() as u32;
        (
            DirectionBlock {
                revealed: vec![
                    RevealedRange {
                        start: 0,
                        end: start,
                        bytes: head.into_bytes(),
                    },
                    RevealedRange {
                        start: end,
                        end: length,
                        bytes: tail.as_bytes().to_vec(),
                    },
                ],
                commitments: vec![RangeCommitment {
                    start,
                    end,
                    commitment: [5u8; 32],
                }],
            },
            length,
        )
    }

    fn honest() -> (DirectionBlock, u32) {
        identity_request("", "\r\nauthorization: Bearer ")
    }

    fn check(
        block: &DirectionBlock,
        length: u32,
    ) -> Result<RangeCommitment, AttestationError> {
        let mut data = sample();
        data.sent = block.clone();
        data.sent_transcript_length = length;
        data.require_bearer_header_request("sent", block, length)
    }

    #[test]
    fn accepts_an_honest_identity_request() {
        let (block, length) = honest();
        let commitment = check(&block, length).expect("an honest request must verify");
        assert_eq!(commitment.commitment, [5u8; 32]);
    }

    #[test]
    fn rejects_a_second_authorization_header() {
        // The plain form: a planted header in revealed bytes. Coverage forces
        // it to be revealed, and the scan counts two.
        let (block, length) = identity_request(
            "authorization: Bearer stolen\r\n",
            "\r\nauthorization: Bearer ",
        );
        assert!(matches!(
            check(&block, length),
            Err(AttestationError::NotOneAuthorizationHeader { count: 2, .. })
        ));
    }

    #[test]
    fn rejects_a_case_and_whitespace_evaded_second_header() {
        // Field names and the scheme token are case-insensitive and the colon
        // admits whitespace, so a literal search would miss this one.
        let (block, length) = identity_request(
            "AuThOrIzAtIoN:\tBeArEr stolen\r\n",
            "\r\nauthorization: Bearer ",
        );
        assert!(matches!(
            check(&block, length),
            Err(AttestationError::NotOneAuthorizationHeader { count: 2, .. })
        ));
    }

    #[test]
    fn rejects_an_obsolete_line_fold() {
        // The gap a security review found: `authorization:\r\n Bearer x`
        // normalizes to `authorization:\r\nbearer`, so the needle does not
        // match and the header is never counted. A server honouring the fold
        // would authenticate with it.
        let (block, length) = identity_request(
            "authorization:\r\n Bearer stolen\r\n",
            "\r\nauthorization: Bearer ",
        );
        assert!(matches!(
            check(&block, length),
            Err(AttestationError::ObsoleteLineFold { .. })
        ));
    }

    #[test]
    fn rejects_a_request_with_no_authorization_header_at_all() {
        let (block, length) = identity_request("", "\r\nx-other: ");
        assert!(matches!(
            check(&block, length),
            Err(AttestationError::NotOneAuthorizationHeader { count: 0, .. })
        ));
    }

    #[test]
    fn rejects_a_gap_the_scan_would_never_read() {
        // This is why the three are one call. Open a gap and the hidden bytes
        // are not scanned at all.
        let (mut block, length) = honest();
        block.revealed[0].end -= 1;
        block.revealed[0].bytes.pop();
        assert!(matches!(
            check(&block, length),
            Err(AttestationError::CoverageGap { .. })
        ));
    }

    #[test]
    fn rejects_a_commitment_that_is_not_the_header_value() {
        // Framing on its own. The authorization header here is whole and
        // revealed, so the needle counts once and coverage is exact -- but the
        // committed range sits in the `host` header instead. Without
        // REQ-COMMON-40 nothing would notice that the proved commitment and
        // the credential are different objects.
        let head = "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\n\
authorization: Bearer TOKEN123\r\nhost: ";
        let committed = "api.";
        let tail = "x.com\r\nconnection: close\r\n\r\n";
        let start = head.len() as u32;
        let end = start + committed.len() as u32;
        let length = end + tail.len() as u32;
        let block = DirectionBlock {
            revealed: vec![
                RevealedRange {
                    start: 0,
                    end: start,
                    bytes: head.as_bytes().to_vec(),
                },
                RevealedRange {
                    start: end,
                    end: length,
                    bytes: tail.as_bytes().to_vec(),
                },
            ],
            commitments: vec![RangeCommitment {
                start,
                end,
                commitment: [5u8; 32],
            }],
        };
        assert!(matches!(
            check(&block, length),
            Err(AttestationError::BadBearerFraming { .. })
        ));
    }

    #[test]
    fn rejects_more_than_one_commitment() {
        // REQ-COMMON-60 permits several per direction, but then nothing ties
        // the framed range to the one the circuit opens.
        let (mut block, length) = honest();
        let extra = RangeCommitment {
            start: 0,
            end: 1,
            commitment: [6u8; 32],
        };
        block.commitments.insert(0, extra);
        assert!(matches!(
            check(&block, length),
            Err(AttestationError::NotOneCommitment { count: 2, .. })
        ));
    }

    #[test]
    fn coverage_names_an_overlap_rather_than_a_backwards_gap() {
        let mut block = honest().0;
        block.revealed[1].start -= 2;
        assert!(matches!(
            block.require_exact_coverage("sent", 0),
            Err(AttestationError::SpansOverlap { .. })
        ));
    }
}
