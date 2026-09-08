//! Turn what a notarized session produced into the attested data a launch
//! profile pins.
//!
//! This is the only place tlsn's view of a transcript meets libID's. The
//! layering is deliberate: `libid-ceremony` owns the bytes and is publishable,
//! this crate owns the translation and is git-only because tlsn is. Nothing
//! above needs to know that a `RangeSet` exists.
//!
//! The byte layout itself is the profile's rather than the specification's;
//! `libid_ceremony::attestation` says under which requirement, and states each
//! rule it keeps in full.

use libid_ceremony::attestation::{
    AttestedData,
    DirectionBlock,
    RangeCommitment,
    RevealedRange,
};
use tlsn::{
    hash::HashAlgId,
    transcript::{
        Direction,
        PartialTranscript,
        TranscriptCommitment,
    },
};

/// One notarized session, as the notary observed it.
///
/// Every field here is something the notary SAW: the transcript it helped
/// decrypt, the server name it authenticated against WebPKI, the commitments
/// the prover made inside the session, and the moment its own clock said the
/// session closed. That is the line REQ-COMMON-33 draws between what a notary
/// may sign and what it may not, and a type is how the line is kept -- a value
/// the notary was merely TOLD has no field to arrive in, so it cannot reach the
/// signed bytes by being appended to an argument list.
///
/// It borrows rather than owns. The party that ran the session already holds
/// every one of these, and copying a whole transcript across in order to
/// describe it would double the peak memory of a notarization to say nothing
/// new. `Copy` for the same reason: handing the same view to two calls should
/// not mean restating it.
///
/// Deliberately not `Debug`. Printing one prints the revealed transcript --
/// the prover's request with its credential framing around it -- into whatever
/// log line was being written at the time.
#[derive(Clone, Copy)]
pub struct ObservedSession<'a> {
    /// The transcript with the prover's revealed ranges opened and the rest
    /// still closed. Both directions and both signed lengths are read from this
    /// one value, so there is no pair of lengths that can disagree with the
    /// ranges they bound.
    pub transcript: &'a PartialTranscript,
    /// The DNS name the notary authenticated, which the caller takes from
    /// `ServerName::Dns`.
    ///
    /// It arrives as a string rather than as tlsn's name type so this mapping
    /// stays testable and so nothing here depends on how upstream models a
    /// server name. It reaches the record as a signed field rather than as a
    /// transcript range because the transcript carries the authority only in a
    /// prover-composed `Host` header, which says nothing about which server
    /// answered (REQ-COMMON-21, REQ-COMMON-21A).
    pub authority: &'a str,
    /// Every commitment the session produced, both directions together, in
    /// whatever order the prover made them.
    /// [`AttestedData::from_observed`] splits them by direction and sorts
    /// them by offset, so a caller passes on
    /// what it was handed rather than pre-sorting a list the format reorders
    /// anyway.
    pub commitments: &'a [TranscriptCommitment],
    /// The notary's OWN clock reading when the session completed.
    ///
    /// Never the prover's, never a response header, never any other party's:
    /// the verifier's freshness window is measured from this, so a reading the
    /// observed party could choose would be a window it could choose. It is a
    /// field rather than a call to the clock here so a test can pin it; the
    /// caller must pass its own.
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error(
        "a commitment uses {0:?}, but REQ-COMMON-38 pins SHA-256 for launch profiles"
    )]
    WrongCommitmentAlgorithm(HashAlgId),
    #[error("a commitment covers {0} disjoint ranges; the format carries one range per commitment")]
    DisjointCommitment(usize),
    #[error("a commitment hash is {0} bytes, not 32")]
    BadCommitmentLength(usize),
    #[error("transcript offset {0} does not fit the format's 32-bit field")]
    OffsetTooLarge(usize),
}

fn u32_of(value: usize) -> Result<u32, AttestError> {
    u32::try_from(value).map_err(|_| AttestError::OffsetTooLarge(value))
}

/// One direction of an [`ObservedSession`], which is what a [`DirectionBlock`]
/// is built from.
///
/// A pair rather than two arguments, for the reason the session is a struct
/// rather than four: a transcript and a commitment list must come from the SAME
/// session or the block describes bytes nobody observed together. Carrying the
/// whole session makes that pairing unspellable-wrong rather than merely
/// uncommon, and leaves the direction as the only thing a caller chooses.
#[derive(Clone, Copy)]
pub struct ObservedDirection<'a> {
    /// The session both directions are read from.
    pub session: ObservedSession<'a>,
    /// Which of its two directions this block covers.
    pub direction: Direction,
}

/// Building a `libid-ceremony` record out of what this crate observed.
///
/// A trait, because both records belong to `libid-ceremony`, which is on the
/// release job's publish list and so must never name a tlsn type -- `tlsn` is
/// an unpublished git dependency, and a crate that names it cannot go to
/// crates.io at all. That is what keeps an inherent `impl` for either record
/// out of this crate. A LOCAL trait can, and may be
/// implemented for any type at all, so each constructor lands on the type it
/// constructs and every call site names what is being built before it names
/// what it is built from.
///
/// Two implementors, and the pair is the layering: an [`AttestedData`] is a
/// header plus two [`DirectionBlock`]s, and its impl below is written that way
/// rather than inlining the direction walk twice.
///
/// It is not an abstraction over records and no third implementor is expected.
/// It is the way to put a constructor where coherence would otherwise refuse
/// one. Bring it into scope to use it, as any extension trait is brought in.
pub trait FromObserved<Source>: Sized {
    /// The record `source` describes, or the reason the format cannot describe
    /// it.
    fn from_observed(source: Source) -> Result<Self, AttestError>;
}

impl FromObserved<ObservedSession<'_>> for AttestedData {
    /// The record of a session, in the layout the launch profiles pin.
    ///
    /// Section 9.1 of ceremony-common is attestation verification and its fee;
    /// it fixes no byte of this. REQ-COMMON-18 leaves the format to the profile
    /// author, which is why `libid_ceremony::attestation` is the definition
    /// rather than a reading of one.
    ///
    /// The four values this reads were never four unrelated things: they are
    /// four readings of ONE session, which a caller previously had to keep in
    /// step by hand across an argument list.
    ///
    /// The notary places nothing here that it derived by applying a profile
    /// rule -- no handle, no account identifier, no client identifier, no chain
    /// address (REQ-COMMON-33). Every such value is already derivable from the
    /// revealed ranges, a second signed copy can disagree with the bytes it
    /// came from, and producing one would make the Notary Service decide
    /// something profile-specific. What is signed is what [`ObservedSession`]
    /// holds, in the order the record declares it.
    ///
    /// This fails only where the session cannot be described by the format at
    /// all: an offset past its 32-bit field, a commitment under the wrong hash,
    /// a commitment over disjoint ranges, a commitment hash that is not 32
    /// bytes. It judges nothing else. Whether the
    /// ranges tile, whether the request carries exactly one credential header
    /// -- those are the Platform Verifier's decision and the client's dry run,
    /// and refusing here would only withhold a session the notary really did
    /// observe.
    fn from_observed(session: ObservedSession<'_>) -> Result<Self, AttestError> {
        let of = |direction| ObservedDirection { session, direction };
        Ok(AttestedData {
            authority_id: AttestedData::authority_id_of(session.authority),
            created_at: session.created_at,
            sent_transcript_length: u32_of(session.transcript.len_sent())?,
            recv_transcript_length: u32_of(session.transcript.len_received())?,
            sent: DirectionBlock::from_observed(of(Direction::Sent))?,
            received: DirectionBlock::from_observed(of(Direction::Received))?,
        })
    }
}

impl FromObserved<ObservedDirection<'_>> for DirectionBlock {
    /// One direction's revealed runs and its commitments, both in ascending
    /// start order.
    ///
    /// Written once and asked twice rather than written twice and compared: the
    /// two directions differ only in which pair of accessors they read, and a
    /// second copy of this loop is a second place for the offset arithmetic to
    /// drift.
    fn from_observed(source: ObservedDirection<'_>) -> Result<Self, AttestError> {
        let (authed, data) = match source.direction {
            Direction::Sent => (
                source.session.transcript.sent_authed(),
                source.session.transcript.sent_unsafe(),
            ),
            Direction::Received => (
                source.session.transcript.received_authed(),
                source.session.transcript.received_unsafe(),
            ),
        };

        // One entry per revealed range, in ascending start order, each carrying
        // where it sat and what it held. Revealed bytes signed without their
        // offsets say that some bytes were disclosed but not where they sat, which
        // is not enough to tile a transcript. The end is the bytes' own length, so
        // it is not written down twice.
        let mut revealed = Vec::new();
        for range in authed.iter() {
            // Still checked, even though only `start` is encoded: a range whose end
            // does not fit is a transcript this record cannot describe.
            u32_of(range.end)?;
            revealed.push(RevealedRange {
                start: u32_of(range.start)?,
                bytes: data[range.clone()].to_vec(),
            });
        }

        let mut out = Vec::new();
        for commitment in source.session.commitments {
            // The enum is non-exhaustive upstream, so an unknown commitment kind
            // is skipped rather than assumed to be a hash.
            let TranscriptCommitment::Hash(hash) = commitment else {
                continue;
            };
            if hash.direction != source.direction {
                continue;
            }
            // The notarization library defaults to BLAKE3 while the Proving Circuit
            // computes SHA-256, so a prover left on library defaults produces
            // commitments the circuit cannot open (REQ-COMMON-38).
            if hash.hash.alg != HashAlgId::SHA256 {
                return Err(AttestError::WrongCommitmentAlgorithm(hash.hash.alg));
            }

            // A `RangeSet` may be disjoint, but the format pairs one commitment
            // value with one offset pair. A hash over a union cannot be split
            // between two entries without inventing a value for each.
            let ranges: Vec<_> = hash.idx.iter().collect();
            let [range] = ranges.as_slice() else {
                return Err(AttestError::DisjointCommitment(ranges.len()));
            };

            let value = hash.hash.value.as_bytes();
            let value: [u8; 32] = value
                .try_into()
                .map_err(|_| AttestError::BadCommitmentLength(value.len()))?;

            out.push(RangeCommitment {
                start: u32_of(range.start)?,
                end: u32_of(range.end)?,
                commitment: value,
            });
        }
        out.sort_by_key(|c| c.start);

        Ok(DirectionBlock {
            revealed,
            commitments: out,
        })
    }
}

#[cfg(test)]
mod tests {
    /// The Platform Verifier requires the revealed ranges and the commitments
    /// to account for the signed length exactly. That is its rule to enforce,
    /// not ours -- but a layout that cannot satisfy it produces attestations no
    /// verifier accepts, so it is worth asserting here on the way out.
    fn assert_tiles(block: &libid_ceremony::DirectionBlock, length: u32) {
        let mut spans: Vec<(u32, u32)> = block
            .revealed
            .iter()
            .map(|r| (r.start, r.start + r.bytes.len() as u32))
            .chain(block.commitments.iter().map(|c| (c.start, c.end)))
            .collect();
        spans.sort_unstable();
        let mut at = 0u32;
        for (start, end) in spans {
            assert_eq!(start, at, "gap or overlap before {start}");
            at = end;
        }
        assert_eq!(at, length, "the spans do not reach the signed length");
    }

    use super::*;
    use libid_transcript::ceremony::{
        profiles,
        Layout,
    };
    use rangeset::set::RangeSet;
    use tlsn::{
        hash::TypedHash,
        transcript::{
            hash::PlaintextHash,
            Transcript,
            TranscriptCommitment,
        },
    };

    const SENT: &[u8] = b"GET /2/users/me HTTP/1.1\r\nauthorization: Bearer TOK\r\n\r\n";
    const RECV: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"7\"}";

    /// The session as the notary saw it, for the tests that vary only the
    /// transcript and the commitments over it.
    fn observed<'a>(
        transcript: &'a PartialTranscript,
        commitments: &'a [TranscriptCommitment],
    ) -> ObservedSession<'a> {
        observed_at(transcript, commitments, "api.x.com")
    }

    /// The same, for the one test that varies the authority.
    fn observed_at<'a>(
        transcript: &'a PartialTranscript,
        commitments: &'a [TranscriptCommitment],
        authority: &'a str,
    ) -> ObservedSession<'a> {
        ObservedSession {
            transcript,
            authority,
            commitments,
            created_at: 1_770_000_000,
        }
    }

    /// `Hash` has no public constructor, so build it the way upstream
    /// deserializes it: a sequence of bytes.
    fn hash32(byte: u8) -> TypedHash {
        TypedHash {
            alg: HashAlgId::SHA256,
            value: serde_json::from_value(serde_json::json!(vec![byte; 32])).unwrap(),
        }
    }

    /// Reveal everything except the bearer, and commit the bearer -- the shape
    /// an identity session actually produces.
    fn session() -> (PartialTranscript, Vec<TranscriptCommitment>) {
        let bearer = 45..48; // "TOK"
        let transcript = Transcript::new(SENT, RECV);
        let sent_revealed = RangeSet::from(vec![0..bearer.start, bearer.end..SENT.len()]);
        let partial = transcript.to_partial(sent_revealed, RangeSet::from(0..RECV.len()));
        let commitments = vec![TranscriptCommitment::Hash(PlaintextHash {
            direction: Direction::Sent,
            idx: RangeSet::from(bearer),
            hash: hash32(7),
        })];
        (partial, commitments)
    }

    #[test]
    fn carries_the_signed_transcript_lengths() {
        // These appear nowhere in any signed field today, and REQ-COMMON-36
        // makes them the only source of the length the coverage check uses.
        let (partial, commitments) = session();
        let data = AttestedData::from_observed(observed(&partial, &commitments)).unwrap();
        assert_eq!(data.sent_transcript_length, SENT.len() as u32);
        assert_eq!(data.recv_transcript_length, RECV.len() as u32);
    }

    #[test]
    fn encodes_to_the_length_its_own_fields_imply() {
        let (partial, commitments) = session();
        let data = AttestedData::from_observed(observed(&partial, &commitments)).unwrap();
        let encoded = data.encode().unwrap();

        // No decoder here to round-trip against: decoding is the chain's and
        // the client's. What stays checkable on this side is that every byte
        // the fields describe is present, which is the property the layout
        // gives the forward-parsing decoder something to walk.
        let mut want = libid_ceremony::attestation::HEADER_LEN;
        for d in [&data.sent, &data.received] {
            want += 8 + 8; // one eight-byte count per list
            for r in &d.revealed {
                want += 4 + 8 + r.bytes.len(); // start, byte length, bytes
            }
            want += d.commitments.len() * (4 + 4 + 32); // start, end, commitment
        }
        assert_eq!(encoded.len(), want);
    }

    #[test]
    fn tiles_the_request_exactly() {
        // The whole point: what the notary emits must satisfy the coverage
        // check the Platform Verifier runs, or no genuine session ever passes.
        let (partial, commitments) = session();
        let data = AttestedData::from_observed(observed(&partial, &commitments)).unwrap();
        assert_tiles(&data.sent, data.sent_transcript_length);
    }

    #[test]
    fn authority_is_the_authenticated_server_name() {
        let (partial, commitments) = session();
        let data = AttestedData::from_observed(observed(&partial, &commitments)).unwrap();
        assert_eq!(
            data.authority_id,
            AttestedData::authority_id_of("api.x.com")
        );
        // And it is NOT taken from a Host header the prover composed.
        assert_ne!(
            data.authority_id,
            AttestedData::authority_id_of("evil.example")
        );
    }

    #[test]
    fn the_authority_is_canonicalized_on_the_way_into_the_record() {
        // The rule used to be kept here, by this call site remembering to
        // lowercase. It now belongs to the constructor, so what this asserts is
        // that the record still comes out canonical when the caller does not.
        let (partial, commitments) = session();
        let data =
            AttestedData::from_observed(observed_at(&partial, &commitments, "API.X.com"))
                .unwrap();
        assert_eq!(
            data.authority_id,
            AttestedData::authority_id_of("api.x.com")
        );
    }

    #[test]
    fn the_record_names_the_authority_this_session_carried() {
        // Every other test here observes `api.x.com`, so a record that ignored
        // the session and hardcoded that host would satisfy all of them --
        // including the two beside this one, whose names promise otherwise.
        // This observes a different host, so only a record that reads the
        // session can pass.
        let (partial, commitments) = session();
        let data = AttestedData::from_observed(observed_at(
            &partial,
            &commitments,
            "api.github.com",
        ))
        .unwrap();
        assert_eq!(
            data.authority_id,
            AttestedData::authority_id_of("api.github.com")
        );
        assert_ne!(
            data.authority_id,
            AttestedData::authority_id_of("api.x.com")
        );
    }

    #[test]
    fn the_notarys_clock_reading_reaches_the_record() {
        // The verifier's freshness window is measured from this field, so a
        // record that dropped it would be judged on a time nobody observed.
        // Nothing asserted it: `created_at: 0` passed the entire suite.
        let (partial, commitments) = session();
        let mut session_view = observed(&partial, &commitments);
        session_view.created_at = 1_800_000_123;
        let data = AttestedData::from_observed(session_view).unwrap();
        assert_eq!(data.created_at, 1_800_000_123);
    }

    #[test]
    fn refuses_a_blake3_commitment() {
        // The notarization library's default. The circuit computes SHA-256, so
        // a prover left on defaults produces commitments it cannot open.
        let (partial, mut commitments) = session();
        let TranscriptCommitment::Hash(ref mut h) = commitments[0] else {
            unreachable!()
        };
        h.hash.alg = HashAlgId::BLAKE3;
        assert!(matches!(
            AttestedData::from_observed(observed(&partial, &commitments)),
            Err(AttestError::WrongCommitmentAlgorithm(_))
        ));
    }

    #[test]
    fn refuses_a_commitment_over_disjoint_ranges() {
        // The format pairs one commitment value with one offset pair; a hash
        // over a union cannot be split without inventing a value for each.
        let (partial, _) = session();
        let commitments = vec![TranscriptCommitment::Hash(PlaintextHash {
            direction: Direction::Sent,
            idx: RangeSet::from(vec![10..12, 20..22]),
            hash: hash32(7),
        })];
        assert!(matches!(
            AttestedData::from_observed(observed(&partial, &commitments)),
            Err(AttestError::DisjointCommitment(2))
        ));
    }

    #[test]
    fn places_no_profile_derived_value_in_the_signed_bytes() {
        // REQ-COMMON-33: the Notary Service decides nothing profile-specific,
        // so the notary places no value it obtained by applying a profile rule
        // -- no handle, no account identifier, no client identifier, no chain
        // address. Every one is already derivable
        // from the revealed ranges, and a second signed representation can
        // disagree with the bytes it was taken from.
        //
        // Tested structurally: two sessions whose responses name different
        // accounts must produce IDENTICAL header bytes. If any identity field
        // were signed into the header, it would differ here.
        let other_recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"9\"}";
        assert_eq!(
            other_recv.len(),
            RECV.len(),
            "the two responses must be the same length"
        );

        let bearer = 45..48;
        let sent_revealed = RangeSet::from(vec![0..bearer.start, bearer.end..SENT.len()]);
        let commitments = vec![TranscriptCommitment::Hash(PlaintextHash {
            direction: Direction::Sent,
            idx: RangeSet::from(bearer),
            hash: hash32(7),
        })];

        let mut headers = Vec::new();
        for recv in [RECV, other_recv] {
            let partial = Transcript::new(SENT, recv)
                .to_partial(sent_revealed.clone(), RangeSet::from(0..recv.len()));
            let data =
                AttestedData::from_observed(observed(&partial, &commitments)).unwrap();
            headers.push(data.encode().unwrap()[..144].to_vec());
        }
        assert_eq!(
            headers[0], headers[1],
            "an identity field leaked into the signed header"
        );

        // And the accounts really are different, so the test is not vacuous.
        let a = Transcript::new(SENT, RECV)
            .to_partial(sent_revealed.clone(), RangeSet::from(0..RECV.len()));
        let b = Transcript::new(SENT, other_recv)
            .to_partial(sent_revealed, RangeSet::from(0..other_recv.len()));
        assert_ne!(
            AttestedData::from_observed(observed(&a, &commitments))
                .unwrap()
                .encode()
                .unwrap(),
            AttestedData::from_observed(observed(&b, &commitments))
                .unwrap()
                .encode()
                .unwrap(),
            "the two sessions must differ somewhere -- in the revealed range"
        );
    }

    // --- The layouts the prover selects must satisfy the verifier ----------

    /// Build a session from a real transcript plus the layout the ceremony
    /// selects for it, and check the attested data it produces TILES.
    ///
    /// This is the property no unit test on either side reaches on its own. The
    /// verifier demands exact coverage; the prover chooses the ranges. If they
    /// disagree, every check passes in isolation and no honest ceremony
    /// verifies -- a liveness failure that only shows up in an end-to-end run.
    fn round_trip(
        sent: &[u8],
        recv: &[u8],
        sent_layout: &Layout,
        recv_layout: &Layout,
    ) -> AttestedData {
        let transcript = Transcript::new(sent, recv);
        let partial = transcript.to_partial(
            RangeSet::from(sent_layout.reveal.clone()),
            RangeSet::from(recv_layout.reveal.clone()),
        );
        let mut commitments = Vec::new();
        for (direction, l) in [
            (Direction::Sent, sent_layout),
            (Direction::Received, recv_layout),
        ] {
            for range in &l.commit {
                commitments.push(TranscriptCommitment::Hash(PlaintextHash {
                    direction,
                    idx: RangeSet::from(range.clone()),
                    hash: hash32(1),
                }));
            }
        }
        AttestedData::from_observed(observed(&partial, &commitments)).unwrap()
    }

    #[test]
    fn the_identity_session_layout_tiles_both_directions() {
        let sent: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer TOKENVALUE\r\nconnection: close\r\n\r\n";
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"alice\"}}";

        let s = Layout::identity_request(sent).unwrap();
        let r = Layout::identity_response(recv, &profiles::X.identity.unwrap()).unwrap();
        let data = round_trip(sent, recv, &s, &r);
        assert_tiles(&data.sent, data.sent_transcript_length);
        assert_tiles(&data.received, data.recv_transcript_length);

        // And exactly one credential is hidden in the request, which is what
        // ties the framed range to the one the circuit opens.
        assert_eq!(data.sent.commitments.len(), 1);
    }

    #[test]
    fn the_x_token_session_layout_tiles() {
        let sent: &[u8] = b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=abc&code_verifier=xyz";
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"SECRETBEARER\"}";

        let s = Layout::token_request(sent, &profiles::X.token.unwrap()).unwrap();
        let r = Layout::token_response(recv).unwrap();
        let data = round_trip(sent, recv, &s, &r);
        assert_tiles(&data.sent, data.sent_transcript_length);
        // X reveals its token request whole, so the verifier can see the head
        // boundary and locate the body by the framing the server parsed.
        assert!(data.sent.commitments.is_empty());
        assert_eq!(data.sent.revealed.len(), 1);
        assert_eq!(data.sent.revealed[0].start, 0);
    }

    #[test]
    fn the_github_exchange_layout_commits_a_suffix() {
        let sent: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=Iv1.x&code=abc&code_verifier=xyz&client_secret=deadbeef";
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"gho_SECRET\"}";

        let s = Layout::token_request(sent, &profiles::GITHUB.token.unwrap()).unwrap();
        let r = Layout::token_response(recv).unwrap();
        let data = round_trip(sent, recv, &s, &r);
        assert_tiles(&data.sent, data.sent_transcript_length);
        assert_eq!(data.sent.revealed.len(), 1);
        assert_eq!(data.sent.commitments.len(), 1);
        // Ordered last, so the commitment reaches the transcript end.
        assert_eq!(data.sent.commitments[0].end, data.sent_transcript_length);
    }
}
