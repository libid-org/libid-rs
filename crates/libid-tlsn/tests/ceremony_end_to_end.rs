//! The stitch between choosing a layout and what the verifier demands of it.
//!
//! Every piece of the ceremony has its own tests. What had none is the JOIN:
//! `libid_transcript::ceremony` picks the ranges, `libid_tlsn::attest` turns a
//! session into the section 9.1 record, and a Platform Verifier on chain then
//! applies rules neither of them states. A layout can be internally consistent,
//! encode cleanly, and still be refused.
//!
//! So this drives all three for both X sessions and asserts, on the decoded
//! record, the rules the Solidity side enforces. It is not a network test —
//! there is no TLS here — but it is the only place the two halves meet before
//! a deployment does.
//!
//! Each assertion below names the check it mirrors, so a rule that changes on
//! chain has one place to change here.

use libid_ceremony::attestation::{
    AttestedData,
    DirectionBlock,
};
use libid_tlsn::attest::{
    attested_data,
    AttestationInput,
};
use libid_transcript::ceremony::{
    self,
    IdShape,
    Layout,
};
use rangeset::set::RangeSet;
use tlsn::{
    hash::{
        HashAlgId,
        TypedHash,
    },
    transcript::{
        hash::PlaintextHash,
        Direction,
        Transcript,
        TranscriptCommitment,
    },
};

const TOKEN_SENT: &[u8] = b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=abc&code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";
const TOKEN_RECV: &[u8] =
    b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"SECRETBEARER\"}";
const ID_SENT: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer SECRETBEARER\r\nconnection: close\r\n\r\n";
const ID_RECV: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"alice\"}}";

fn hash32(byte: u8) -> TypedHash {
    TypedHash {
        alg: HashAlgId::SHA256,
        value: serde_json::from_value(serde_json::json!(vec![byte; 32])).unwrap(),
    }
}

/// Turn a pair of layouts into what a notary's verifier hands `attested_data`.
///
/// This is the step a real session performs inside MPC: the prover states what
/// it reveals, and the verifier ends up holding the revealed transcript and a
/// commitment per hidden run. Reproducing it here is what makes the record
/// below the one a real session would produce.
fn record(
    sent: &[u8],
    recv: &[u8],
    sl: &Layout,
    rl: &Layout,
    created_at: u64,
) -> AttestedData {
    let transcript = Transcript::new(sent, recv);
    let partial = transcript.to_partial(
        RangeSet::from(sl.reveal.clone()),
        RangeSet::from(rl.reveal.clone()),
    );

    let mut commitments = Vec::new();
    for (i, c) in sl.commit.iter().enumerate() {
        commitments.push(TranscriptCommitment::Hash(PlaintextHash {
            direction: Direction::Sent,
            idx: RangeSet::from(c.clone()),
            hash: hash32(i as u8 + 1),
        }));
    }
    for (i, c) in rl.commit.iter().enumerate() {
        commitments.push(TranscriptCommitment::Hash(PlaintextHash {
            direction: Direction::Received,
            idx: RangeSet::from(c.clone()),
            hash: hash32(i as u8 + 100),
        }));
    }

    attested_data(
        &partial,
        "api.x.com",
        &commitments,
        AttestationInput { created_at },
    )
    .expect("the layouts produce an attestable session")
}

/// `CeremonyAttestation.requireExactCoverage`: revealed ranges and commitments
/// account for `[0, length)` with no gap and no overlap.
fn assert_tiles(block: &DirectionBlock, length: u32, what: &str) {
    let mut spans: Vec<(u32, u32)> = block
        .revealed
        .iter()
        .map(|r| (r.start, r.start + r.bytes.len() as u32))
        .chain(block.commitments.iter().map(|c| (c.start, c.end)))
        .collect();
    spans.sort_by_key(|s| s.0);
    let mut at = 0u32;
    for (start, end) in spans {
        assert_eq!(start, at, "{what}: gap or overlap at {at}");
        assert!(end > start, "{what}: empty span at {start}");
        at = end;
    }
    assert_eq!(
        at, length,
        "{what}: coverage stops short of the signed length"
    );
}

/// The revealed bytes of one direction, joined in offset order — what the
/// verifier's cross-range delimiter count reads.
fn joined(block: &DirectionBlock) -> Vec<u8> {
    let mut ranges: Vec<_> = block.revealed.iter().collect();
    ranges.sort_by_key(|r| r.start);
    ranges.iter().flat_map(|r| r.bytes.clone()).collect()
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn the_token_session_produces_a_record_the_verifier_accepts() {
    let sl = ceremony::token_request(TOKEN_SENT, None).unwrap();
    let rl = ceremony::token_response(TOKEN_RECV).unwrap();
    let data = record(TOKEN_SENT, TOKEN_RECV, &sl, &rl, 1_770_000_000);

    assert_tiles(&data.sent, data.sent_transcript_length, "token request");
    assert_tiles(
        &data.received,
        data.recv_transcript_length,
        "token response",
    );

    // `_tokenBody`: ONE revealed sent range, anchored at the origin. X carries
    // no secret, so the request is revealed entire.
    assert_eq!(data.sent.revealed.len(), 1);
    assert_eq!(data.sent.revealed[0].start, 0);
    assert!(data.sent.commitments.is_empty());
    assert!(data.sent.revealed[0]
        .bytes
        .starts_with(b"POST /2/oauth2/token "));

    // `_tokenBody` again: exactly one head boundary, or the body is ambiguous.
    assert_eq!(count(&data.sent.revealed[0].bytes, b"\r\n\r\n"), 1);

    // REQ-COMMON-15A: the digest binding is the revealed `code_verifier`.
    assert_eq!(count(&data.sent.revealed[0].bytes, b"code_verifier="), 1);

    // `requireFramedCommitment`: one commitment carries the framing, and the
    // bearer is not readable anywhere.
    let framed: Vec<_> = data
        .received
        .commitments
        .iter()
        .filter(|c| {
            data.received.revealed.iter().any(|r| {
                r.start + r.bytes.len() as u32 == c.start
                    && r.bytes.ends_with(b"\"access_token\":\"")
            })
        })
        .collect();
    assert_eq!(
        framed.len(),
        1,
        "exactly one commitment is framed as the bearer"
    );
    assert_eq!(count(&joined(&data.received), b"SECRETBEARER"), 0);
}

#[test]
fn the_identity_session_produces_a_record_the_verifier_accepts() {
    let sl = ceremony::identity_request(ID_SENT).unwrap();
    let rl = ceremony::identity_response(ID_RECV, "id", IdShape::JsonString, "username")
        .unwrap();
    let data = record(ID_SENT, ID_RECV, &sl, &rl, 1_770_000_000);

    assert_tiles(&data.sent, data.sent_transcript_length, "identity request");
    assert_tiles(
        &data.received,
        data.recv_transcript_length,
        "identity response",
    );

    // `_identitySession`: the request line sits at offset 0.
    let first = data.sent.revealed.iter().min_by_key(|r| r.start).unwrap();
    assert_eq!(first.start, 0);
    assert!(first.bytes.starts_with(b"GET /2/users/me "));

    // `requireBearerHeaderRequest`: exactly one commitment, framed by the
    // header bytes REQ-COMMON-40 names.
    assert_eq!(data.sent.commitments.len(), 1);
    let bearer = &data.sent.commitments[0];
    let before = data
        .sent
        .revealed
        .iter()
        .find(|r| r.start + r.bytes.len() as u32 == bearer.start)
        .expect("a revealed range ends where the commitment begins");
    assert!(before.bytes.ends_with(b"\r\nauthorization: Bearer "));
    let after = data
        .sent
        .revealed
        .iter()
        .find(|r| r.start == bearer.end)
        .expect("a revealed range begins where the commitment ends");
    assert!(after.bytes.starts_with(b"\r\n"));

    // REQ-COMMON-39, counted over the CONCATENATION: one authorization header.
    let mut normalized = joined(&data.sent).to_ascii_lowercase();
    normalized.retain(|&b| b != b' ' && b != b'\t');
    assert_eq!(count(&normalized, b"\r\nauthorization:bearer"), 1);

    // `requireFullyRevealed`: the response hides nothing, so the duplicate
    // scan below can see the whole document.
    assert!(
        data.received.commitments.is_empty(),
        "a commitment here would hide a duplicate member from every reader"
    );

    // And what that buys: each identity member appears exactly once in bytes
    // the verifier can read.
    let body = joined(&data.received);
    assert_eq!(count(&body, b"\"id\":\""), 1);
    assert_eq!(count(&body, b"\"username\":\""), 1);
}

/// The record has to survive the wire, not merely exist: the encoding is what
/// the notary signs and what the Solidity decoder reads.
#[test]
fn both_sessions_encode_and_carry_their_own_lengths() {
    for (sent, recv, sl, rl) in [
        (
            TOKEN_SENT,
            TOKEN_RECV,
            ceremony::token_request(TOKEN_SENT, None).unwrap(),
            ceremony::token_response(TOKEN_RECV).unwrap(),
        ),
        (
            ID_SENT,
            ID_RECV,
            ceremony::identity_request(ID_SENT).unwrap(),
            ceremony::identity_response(ID_RECV, "id", IdShape::JsonString, "username")
                .unwrap(),
        ),
    ] {
        let data = record(sent, recv, &sl, &rl, 1_770_000_000);
        assert_eq!(data.sent_transcript_length as usize, sent.len());
        assert_eq!(data.recv_transcript_length as usize, recv.len());
        let encoded = data.encode().expect("encodes");
        assert!(encoded.len() > 48, "at least the header");
        assert_ne!(data.digest().unwrap(), [0u8; 32]);
    }
}

/// The GitHub token exchange is the one session whose REQUEST hides something,
/// and the shape it must take is a prefix: the commitment reaches the
/// transcript end, so the revealed run has no hole in it.
#[test]
fn the_github_exchange_commits_a_suffix_and_nothing_else() {
    const SENT: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=Iv1.x&code=abc&code_verifier=xyz&client_secret=deadbeef";
    const RECV: &[u8] =
        b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"SECRETBEARER\"}";

    let sl = ceremony::token_request(SENT, Some("client_secret")).unwrap();
    let rl = ceremony::token_response(RECV).unwrap();
    let data = record(SENT, RECV, &sl, &rl, 1_770_000_000);

    assert_tiles(&data.sent, data.sent_transcript_length, "github exchange");
    assert_eq!(data.sent.revealed.len(), 1);
    assert_eq!(data.sent.revealed[0].start, 0);
    assert_eq!(data.sent.commitments.len(), 1);
    assert_eq!(data.sent.commitments[0].end, SENT.len() as u32);
    assert_eq!(count(&joined(&data.sent), b"deadbeef"), 0);
}
