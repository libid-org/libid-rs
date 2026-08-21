//! Turn what a notarized session produced into the attested data of
//! ceremony-common section 9.1.
//!
//! This is the only place tlsn's view of a transcript meets libID's. The
//! layering is deliberate: `libid-ceremony` owns the bytes and is publishable,
//! this crate owns the translation and is git-only because tlsn is. Nothing
//! above needs to know that a `RangeSet` exists.
//!
//! The `REQ-COMMON-56`/`-57`/`-59`/`-61` cited below are from libid PR #12,
//! which was closed without merging. `libid_ceremony::attestation` carries the
//! provenance note and states each rule in full.

use libid_ceremony::attestation::{
    tag,
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

/// What the profile pins, and what only the notary knows.
pub struct AttestationInput<'a> {
    /// The libID-namespaced string naming this attestation format and version.
    pub format_tag: &'a str,
    /// The identity-platform name.
    pub platform_name: &'a str,
    /// The libID-namespaced string naming which session this covers.
    pub operation_tag: &'a str,
    /// The notary's OWN clock reading when the session completed.
    ///
    /// REQ-COMMON-57 forbids taking this from the prover, from a response
    /// header, or from any other party. It is an argument rather than a call to
    /// the clock here so a test can pin it; the caller must pass its own.
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

/// Build the attested data for one notarized session.
///
/// The notary places nothing here that it derived by applying a profile rule --
/// no handle, no account identifier, no client identifier, no chain address
/// (REQ-COMMON-61). Every such value is already derivable from the revealed
/// ranges, a second signed copy can disagree with the bytes it came from, and
/// producing one would make the Notary Service decide something
/// profile-specific.
/// `authority` is the DNS name the notary authenticated, which the caller
/// takes from `ServerName::Dns`. It arrives as a string rather than as tlsn's
/// name type so this mapping stays testable and so nothing here depends on how
/// upstream models a server name.
pub fn attested_data(
    partial: &PartialTranscript,
    authority: &str,
    commitments: &[TranscriptCommitment],
    input: AttestationInput<'_>,
) -> Result<AttestedData, AttestError> {
    Ok(AttestedData {
        format_tag: tag(input.format_tag),
        platform_id: tag(input.platform_name),
        operation_tag: tag(input.operation_tag),
        // The canonical authority of section 9: the lowercase ASCII TLS server
        // name the notary authenticated, with no trailing dot. It is a signed
        // field rather than a transcript range because the transcript carries
        // the authority only in a prover-composed `Host` header, which says
        // nothing about which server answered (REQ-COMMON-21, REQ-COMMON-56).
        authority_id: tag(&authority.to_ascii_lowercase()),
        created_at: input.created_at,
        sent_transcript_length: u32_of(partial.len_sent())?,
        recv_transcript_length: u32_of(partial.len_received())?,
        sent: direction_block(partial, commitments, Direction::Sent)?,
        received: direction_block(partial, commitments, Direction::Received)?,
    })
}

fn direction_block(
    partial: &PartialTranscript,
    commitments: &[TranscriptCommitment],
    direction: Direction,
) -> Result<DirectionBlock, AttestError> {
    let (authed, data) = match direction {
        Direction::Sent => (partial.sent_authed(), partial.sent_unsafe()),
        Direction::Received => (partial.received_authed(), partial.received_unsafe()),
    };

    // One entry per revealed range, in ascending start order, each carrying its
    // offsets and exactly `end - start` bytes. Revealed bytes signed without
    // their offsets say that some bytes were disclosed but not where they sat,
    // which is not enough to tile a transcript (REQ-COMMON-59).
    let mut revealed = Vec::new();
    for range in authed.iter() {
        revealed.push(RevealedRange {
            start: u32_of(range.start)?,
            end: u32_of(range.end)?,
            bytes: data[range.clone()].to_vec(),
        });
    }

    let mut out = Vec::new();
    for commitment in commitments {
        // The enum is non-exhaustive upstream, so an unknown commitment kind
        // is skipped rather than assumed to be a hash.
        let TranscriptCommitment::Hash(hash) = commitment else {
            continue;
        };
        if hash.direction != direction {
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

#[cfg(test)]
mod tests {
    use super::*;
    use libid_transcript::ceremony::{
        self,
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

    fn input<'a>() -> AttestationInput<'a> {
        AttestationInput {
            format_tag: "libid.attestation.v1",
            platform_name: "x",
            operation_tag: "libid.ceremony.session.identity.v1",
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
        let data = attested_data(&partial, "api.x.com", &commitments, input()).unwrap();
        assert_eq!(data.sent_transcript_length, SENT.len() as u32);
        assert_eq!(data.recv_transcript_length, RECV.len() as u32);
    }

    #[test]
    fn produces_an_attestation_the_codec_accepts() {
        let (partial, commitments) = session();
        let data = attested_data(&partial, "api.x.com", &commitments, input()).unwrap();
        let encoded = data.encode().expect("the notary must emit a valid shape");
        assert_eq!(
            libid_ceremony::AttestedData::decode(&encoded).unwrap(),
            data
        );
    }

    #[test]
    fn tiles_the_request_exactly() {
        // The whole point: what the notary emits must satisfy the coverage
        // check the Platform Verifier runs, or no genuine session ever passes.
        let (partial, commitments) = session();
        let data = attested_data(&partial, "api.x.com", &commitments, input()).unwrap();
        data.sent
            .require_exact_coverage("sent", data.sent_transcript_length)
            .expect("an honest identity request tiles exactly");
    }

    #[test]
    fn authority_is_the_authenticated_server_name() {
        let (partial, commitments) = session();
        let data = attested_data(&partial, "api.x.com", &commitments, input()).unwrap();
        assert_eq!(data.authority_id, tag("api.x.com"));
        // And it is NOT taken from a Host header the prover composed.
        assert_ne!(data.authority_id, tag("evil.example"));
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
            attested_data(&partial, "api.x.com", &commitments, input()),
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
            attested_data(&partial, "api.x.com", &commitments, input()),
            Err(AttestError::DisjointCommitment(2))
        ));
    }

    #[test]
    fn places_no_profile_derived_value_in_the_signed_bytes() {
        // REQ-COMMON-61: the notary must place no value it obtained by
        // applying a profile rule -- no handle, no account identifier, no
        // client identifier, no chain address. Every one is already derivable
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
                attested_data(&partial, "api.x.com", &commitments, input()).unwrap();
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
            attested_data(&a, "api.x.com", &commitments, input())
                .unwrap()
                .encode()
                .unwrap(),
            attested_data(&b, "api.x.com", &commitments, input())
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
        attested_data(&partial, "api.x.com", &commitments, input()).unwrap()
    }

    #[test]
    fn the_identity_session_layout_tiles_both_directions() {
        let sent: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer TOKENVALUE\r\nconnection: close\r\n\r\n";
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"alice\"}}";

        let s = ceremony::identity_request(sent).unwrap();
        let r = ceremony::identity_response(
            recv,
            "id",
            ceremony::IdShape::JsonString,
            "username",
        )
        .unwrap();
        let data = round_trip(sent, recv, &s, &r);

        data.sent
            .require_exact_coverage("sent", data.sent_transcript_length)
            .expect("the identity request must satisfy REQ-COMMON-35");
        data.received
            .require_exact_coverage("received", data.recv_transcript_length)
            .expect("the identity response must tile too");

        // And exactly one credential is hidden in the request, which is what
        // ties the framed range to the one the circuit opens.
        assert_eq!(data.sent.commitments.len(), 1);
    }

    #[test]
    fn the_x_token_session_layout_tiles() {
        let sent: &[u8] = b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=abc&code_verifier=xyz";
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"SECRETBEARER\"}";

        let s = ceremony::token_request(sent, None).unwrap();
        let r = ceremony::token_response(recv).unwrap();
        let data = round_trip(sent, recv, &s, &r);

        data.sent
            .require_exact_coverage("sent", data.sent_transcript_length)
            .expect("the token request must tile");
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

        let s = ceremony::token_request(sent, Some("client_secret")).unwrap();
        let r = ceremony::token_response(recv).unwrap();
        let data = round_trip(sent, recv, &s, &r);

        data.sent
            .require_exact_coverage("sent", data.sent_transcript_length)
            .expect("the exchange must tile");
        assert_eq!(data.sent.revealed.len(), 1);
        assert_eq!(data.sent.commitments.len(), 1);
        // Ordered last, so the commitment reaches the transcript end.
        assert_eq!(data.sent.commitments[0].end, data.sent_transcript_length);
    }
}
