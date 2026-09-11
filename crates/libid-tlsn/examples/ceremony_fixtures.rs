//! The ceremony session fixtures the contracts verify, generated.
//!
//! Four records, two per launch platform, built the way a ceremony builds
//! them minus the MPC. Each request is composed as the browser or the
//! Token-Exchange Service composes it and driven through hyper's http1
//! client, the encoder under tlsn's prover, against a scripted platform
//! answering as X and GitHub answer. The reveal layouts are
//! `libid_transcript::ceremony`'s, the commitments are tlsn's SHA-256
//! plaintext hashes, the record is `AttestedData::from_observed`, which is
//! the notary's path, and the signature is the notary's: EIP-191 over the
//! record's keccak, by anvil #0, the key the contract tests trust.
//!
//! What a real session adds is the MPC and the platform's own bytes. What
//! this adds over the hand-composed fixtures is everything else: hyper's
//! spelling of the head, the layouts as the crate computes them, the record
//! as the notary encodes it, and a verifier derived from the same digest the
//! contracts derive, so the records verify with these signatures unedited.
//!
//! Deterministic: a fixed clock, fixed blinders, fixed bodies. Regenerate and
//! compare.
//!
//! ```sh
//! cargo run -p libid-tlsn --example ceremony_fixtures -- <dir>
//! ```

use std::path::PathBuf;

use http_body_util::{
    BodyExt,
    Full,
};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use libid_ceremony::attestation::AttestedData;
use libid_crypto::{
    hex_to_signing_key,
    keccak256,
    pubkey_to_eth_address,
    sign_eth_claim,
};
use libid_tlsn::attest::{
    FromObserved,
    ObservedSession,
};
use libid_transcript::ceremony::{
    profiles,
    Layout,
};
use serde_json::json;
use tlsn::{
    config::prove::ProveConfig,
    hash::{
        HashAlgorithm,
        Sha256,
        TypedHash,
    },
    transcript::{
        hash::PlaintextHash,
        Direction,
        Transcript,
        TranscriptCommitConfig,
        TranscriptCommitment,
        TranscriptCommitmentKind,
    },
};
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};

#[path = "ceremony/common.rs"]
mod common;
use common::*;

/// The clock the contract suites warp to.
const T0: u64 = 1_770_000_000;

/// The same rewrite `prover_generic` applies before sending: the wire
/// carries the request-target in origin-form.
fn origin_form<B>(request: &mut hyper::Request<B>) {
    let target = match request.uri().path_and_query() {
        Some(path) => {
            let mut parts = hyper::http::uri::Parts::default();
            parts.path_and_query = Some(path.clone());
            hyper::Uri::from_parts(parts).expect("origin-form")
        }
        None => hyper::Uri::default(),
    };
    *request.uri_mut() = target;
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn declared_length(head: &[u8]) -> usize {
    let lower = head.to_ascii_lowercase();
    let Some(at) = find(&lower, b"\r\ncontent-length:") else {
        return 0;
    };
    let rest = &lower[at + 17..];
    let end = find(rest, b"\r\n").unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end])
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Drive `request` through hyper's http1 client over an in-memory pipe and
/// answer it with `response`. Returns the bytes the client put on the wire.
async fn exchange(
    mut request: hyper::Request<Full<Bytes>>,
    response: Vec<u8>,
) -> Vec<u8> {
    origin_form(&mut request);
    let (client_io, mut server_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut sent = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = server_io.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            sent.extend_from_slice(&buf[..n]);
            if let Some(at) = find(&sent, b"\r\n\r\n") {
                if sent.len() >= at + 4 + declared_length(&sent[..at]) {
                    break;
                }
            }
        }
        server_io.write_all(&response).await.expect("write");
        server_io.shutdown().await.expect("shutdown");
        sent
    });
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(client_io))
            .await
            .expect("handshake");
    let connection = tokio::spawn(connection);
    let answer = sender.send_request(request).await.expect("send");
    assert_eq!(answer.status(), 200);
    let _ = answer.into_body().collect().await.expect("body");
    let _ = connection.await;
    server.await.expect("server")
}

fn request(
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: &str,
) -> hyper::Request<Full<Bytes>> {
    let mut builder = hyper::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("valid request")
}

/// A platform's answer: status, a JSON body under `content-length`.
fn answer(content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A fixed blinder per session and commitment, so the files reproduce.
fn blinder(session: &str, index: usize) -> [u8; 16] {
    let seed = keccak256(format!("libid ceremony fixture {session} {index}").as_bytes());
    seed[..16].try_into().expect("16 bytes")
}

struct Record {
    data: AttestedData,
    openings: Vec<serde_json::Value>,
}

/// `prover_generic`'s reveal and commit configuration, then the verifier's
/// record construction, with tlsn's own commitment hashes in between.
fn build(
    session: &str,
    sent: &[u8],
    recv: &[u8],
    sl: &Layout,
    rl: &Layout,
    authority: &str,
) -> Record {
    let transcript = Transcript::new(sent, recv);

    let mut commits = TranscriptCommitConfig::builder(&transcript);
    commits.default_kind(TranscriptCommitmentKind::Hash {
        alg: tlsn::hash::HashAlgId::SHA256,
    });
    for range in &sl.commit {
        commits.commit_sent(range).expect("sent commitment");
    }
    for range in &rl.commit {
        commits.commit_recv(range).expect("received commitment");
    }
    let commits = commits.build().expect("commit config");

    let mut prove = ProveConfig::builder(&transcript);
    prove.server_identity();
    for range in &sl.reveal {
        prove.reveal_sent(range).expect("sent reveal");
    }
    for range in &rl.reveal {
        prove.reveal_recv(range).expect("received reveal");
    }
    prove.transcript_commit(commits.clone());
    let prove = prove.build().expect("prove config");
    let (reveal_sent, reveal_recv) = prove.reveal().expect("reveals");
    let partial = transcript.to_partial(reveal_sent.clone(), reveal_recv.clone());

    // Sorted the way the record sorts them, so the blinder index is stable
    // whatever order the builder's set yields.
    // The type of the index is tlsn's and not nameable from here, so the
    // triple is left to inference: direction, tlsn's index, the plain ranges.
    let mut ordered = commits
        .iter_hash()
        .map(|((direction, idx), _)| {
            (direction.to_owned(), idx.clone(), idx.clone().into_inner())
        })
        .collect::<Vec<_>>();
    ordered.sort_by_key(|(direction, _, ranges)| {
        (*direction == Direction::Received, ranges[0].start)
    });

    let hasher = Sha256::default();
    let mut openings = Vec::new();
    let commitments: Vec<TranscriptCommitment> = ordered
        .iter()
        .enumerate()
        .map(|(index, (direction, idx, ranges))| {
            let bytes = match direction {
                Direction::Sent => sent,
                Direction::Received => recv,
            };
            let plaintext: Vec<u8> = ranges.iter().flat_map(|r| bytes[r.clone()].to_vec()).collect();
            let blinder = blinder(session, index);
            let value = hasher.hash_prefixed(&plaintext, &blinder);
            openings.push(json!({
                "direction": direction.to_string(),
                "ranges": ranges.iter().map(|r| json!([r.start, r.end])).collect::<Vec<_>>(),
                "blinder": format!("0x{}", hex::encode(blinder)),
            }));
            TranscriptCommitment::Hash(PlaintextHash {
                direction: direction.to_owned(),
                idx: idx.clone(),
                hash: TypedHash {
                    alg: tlsn::hash::HashAlgId::SHA256,
                    value,
                },
            })
        })
        .collect();

    let data = AttestedData::from_observed(ObservedSession {
        transcript: &partial,
        authority,
        commitments: &commitments,
        created_at: T0,
    })
    .expect("record");
    Record { data, openings }
}

fn session_json(
    endpoint: &str,
    sent: &[u8],
    recv: &[u8],
    record: &Record,
    sign: &dyn Fn(&[u8; 32]) -> Vec<u8>,
) -> serde_json::Value {
    let attested = record.data.encode().expect("encode");
    let signature = sign(&keccak256(&attested));
    json!({
        "endpoint": endpoint,
        "sent": hex0x(sent),
        "received": hex0x(recv),
        "attested_data": hex0x(&attested),
        "notary_signature": hex0x(&signature),
        "openings": record.openings,
    })
}

#[tokio::main]
async fn main() {
    let out: PathBuf = std::env::args()
        .nth(1)
        .expect("usage: ceremony_fixtures <dir>")
        .into();
    std::fs::create_dir_all(&out).expect("output directory");
    let key = hex_to_signing_key(NOTARY_KEY).expect("notary key");
    let notary = hex0x(&pubkey_to_eth_address(key.verifying_key()));
    let sign = |digest: &[u8; 32]| sign_eth_claim(&key, digest).expect("sign");
    let verifier = code_verifier();

    let common = |platform: &str| {
        let mut file = submission_json(platform, &notary);
        file["generator"] = serde_json::json!(
            "libid-rs: cargo run -p libid-tlsn --example ceremony_fixtures -- <dir>"
        );
        file["created_at"] = serde_json::json!(T0);
        file
    };

    // ── X: the browser's two sessions ────────────────────────────────
    let x = profiles::X;
    let body = format!(
        "grant_type=authorization_code&client_id=myClient-1&code=abc123&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier={verifier}"
    );
    // As `buildTokenRequest` sets them, `content-length` third and its own.
    let sent = exchange(
        request(
            "POST",
            "https://api.x.com/2/oauth2/token",
            &[
                ("Host", "api.x.com".into()),
                ("Content-Type", "application/x-www-form-urlencoded".into()),
                ("Content-Length", body.len().to_string()),
                ("Accept", "application/json".into()),
                ("Connection", "close".into()),
            ],
            &body,
        ),
        answer(
            "application/json;charset=utf-8",
            r#"{"token_type":"bearer","expires_in":7200,"access_token":"VGhpcyBpcyBub3QgYSByZWFsIGJlYXJlcg","scope":"users.read tweet.read"}"#,
        ),
    )
    .await;
    let recv = answer(
        "application/json;charset=utf-8",
        r#"{"token_type":"bearer","expires_in":7200,"access_token":"VGhpcyBpcyBub3QgYSByZWFsIGJlYXJlcg","scope":"users.read tweet.read"}"#,
    );
    let token = build(
        "x token",
        &sent,
        &recv,
        &Layout::token_request(&sent, &x.token.unwrap()).expect("x token layout"),
        &Layout::token_response(&recv).expect("x token response layout"),
        "api.x.com",
    );
    let x_token = session_json(
        "https://api.x.com/2/oauth2/token",
        &sent,
        &recv,
        &token,
        &sign,
    );

    let recv = answer(
        "application/json;charset=utf-8",
        r#"{"data":{"id":"2244994945","name":"Al Ice","username":"alice"}}"#,
    );
    let sent = exchange(
        request(
            "GET",
            "https://api.x.com/2/users/me",
            &[
                (
                    "Authorization",
                    "Bearer VGhpcyBpcyBub3QgYSByZWFsIGJlYXJlcg".into(),
                ),
                ("Accept", "application/json".into()),
                ("Host", "api.x.com".into()),
                ("Connection", "close".into()),
            ],
            "",
        ),
        recv.clone(),
    )
    .await;
    let identity = build(
        "x identity",
        &sent,
        &recv,
        &Layout::identity_request(&sent).expect("x identity layout"),
        &Layout::identity_response(&recv, &x.identity.unwrap())
            .expect("x identity response layout"),
        "api.x.com",
    );
    let x_identity = session_json(
        "https://api.x.com/2/users/me",
        &sent,
        &recv,
        &identity,
        &sign,
    );

    let mut file = common("x");
    file["token"] = x_token;
    file["identity"] = x_identity;
    std::fs::write(
        out.join("x-ceremony-session.json"),
        serde_json::to_string_pretty(&file).unwrap() + "\n",
    )
    .expect("write");

    // ── GitHub: the service's exchange, the browser's identity read ──
    let github = profiles::GITHUB;
    let body = format!(
        "client_id=Iv1.8a61f9b3a7aba766&code=abc123&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier={verifier}&client_secret=0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    let recv = answer(
        "application/json; charset=utf-8",
        r#"{"access_token":"gho_VGhpcyBpcyBub3QgYSByZWFsIGJlYXJlcg","token_type":"bearer","scope":""}"#,
    );
    // As `libid-server-rs` sets them; hyper appends the length.
    let sent = exchange(
        request(
            "POST",
            "https://github.com/login/oauth/access_token",
            &[
                ("host", "github.com".into()),
                ("content-type", "application/x-www-form-urlencoded".into()),
                ("accept", "application/json".into()),
                ("connection", "close".into()),
            ],
            &body,
        ),
        recv.clone(),
    )
    .await;
    let token = build(
        "github token",
        &sent,
        &recv,
        &Layout::token_request(&sent, &github.token.unwrap())
            .expect("github token layout"),
        &Layout::token_response(&recv).expect("github token response layout"),
        "github.com",
    );
    let github_token = session_json(
        "https://github.com/login/oauth/access_token",
        &sent,
        &recv,
        &token,
        &sign,
    );

    // As GitHub serves `/user` for the media type the profile pins: pretty
    // printed, a newline and two spaces before every member and a space after
    // every colon. A compact body here once let this fixture pass a verifier
    // that refused every real read; the formatting is the platform's, and
    // the fixture carries it.
    let recv = answer(
        "application/json; charset=utf-8",
        "{\n  \"login\": \"octocat\",\n  \"id\": 583231,\n  \"node_id\": \"MDQ6VXNlcjU4MzIzMQ==\",\n  \"avatar_url\": \"https://avatars.githubusercontent.com/u/583231?v=4\",\n  \"type\": \"User\",\n  \"name\": \"The Octocat\"\n}",
    );
    // As `identityRequest` sets them, the browser's own user-agent among them.
    let sent = exchange(
        request(
            "GET",
            "https://api.github.com/user",
            &[
                ("Host", "api.github.com".into()),
                (
                    "Authorization",
                    "Bearer gho_VGhpcyBpcyBub3QgYSByZWFsIGJlYXJlcg".into(),
                ),
                ("Accept", "application/vnd.github+json".into()),
                ("User-Agent", BROWSER_AGENT.into()),
                ("X-GitHub-Api-Version", "2022-11-28".into()),
                ("Connection", "close".into()),
            ],
            "",
        ),
        recv.clone(),
    )
    .await;
    let identity = build(
        "github identity",
        &sent,
        &recv,
        &Layout::identity_request(&sent).expect("github identity layout"),
        &Layout::identity_response(&recv, &github.identity.unwrap())
            .expect("github identity response layout"),
        "api.github.com",
    );
    let github_identity = session_json(
        "https://api.github.com/user",
        &sent,
        &recv,
        &identity,
        &sign,
    );

    let mut file = common("github");
    file["token"] = github_token;
    file["identity"] = github_identity;
    std::fs::write(
        out.join("github-ceremony-session.json"),
        serde_json::to_string_pretty(&file).unwrap() + "\n",
    )
    .expect("write");
    println!("wrote {}", out.display());
}
