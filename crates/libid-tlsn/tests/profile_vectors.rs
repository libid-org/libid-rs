//! The profile strings hash to the numbers the chain pins.
//!
//! # Why a literal and not a derivation
//!
//! Hashing the strings in [`libid_transcript::ceremony::profile`] is easy, and
//! on its own it checks nothing: a derivation follows whatever string is there,
//! so `"gitgub"` would produce a new number and agree with itself perfectly
//! while naming a platform no verifier is registered for.
//!
//! What makes these vectors a pin is that they are the SAME numbers
//! `CeremonyProfile.t.sol` asserts, computed with `cast keccak` independently
//! of either implementation. Two copies of the table now check themselves
//! against one set of constants, so a string edited on either side turns one of
//! them red -- instead of both staying green and disagreeing on chain, where
//! the failure is an attestation rejected with no error that says why.
//!
//! This lives in `libid-tlsn` rather than beside the table because
//! `libid-transcript` carries no crypto and should not grow a keccak
//! dependency to hash six strings; the caller that needs an id -- the notary,
//! building an attestation -- already has [`tag`].

use libid_ceremony::attestation::tag;
use libid_transcript::ceremony::profile::{
    self,
    Profile,
};

/// `CeremonyProfile.PLATFORM_*`, from `CeremonyProfile.t.sol`.
const PLATFORM_GOOGLE: [u8; 32] =
    hex_literal("8f2f90d8304f6eb382d037c47a041d8c8b4d18bdd8b082fa32828e016a584ca7");
const PLATFORM_X: [u8; 32] =
    hex_literal("7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83");
const PLATFORM_GITHUB: [u8; 32] =
    hex_literal("07a17bd3c7c8d7b88e93a4d9007e3bc230b0a586a434de0bed6500e9f343deb7");

/// `CeremonyProfile.AUTHORITY_*`, from the same test.
const AUTHORITY_X_API: [u8; 32] =
    hex_literal("4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d");
const AUTHORITY_GITHUB: [u8; 32] =
    hex_literal("06785da520052bf40d5bf506fb493c41162f55d4e17dffa8b21f02598e981533");
const AUTHORITY_GITHUB_API: [u8; 32] =
    hex_literal("a5d9c1d593bc385a23a2d56116aab1951e3c66296476c7a7396a515105e8b2c1");

/// Decode a 64-character hex string at compile time, so the vectors above read
/// as the hex the contract prints rather than as a byte array nobody can
/// compare by eye against `cast keccak` output.
const fn hex_literal(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 64, "a 32-byte vector is 64 hex characters");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(bytes[i * 2]) << 4 | nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("lowercase hex only"),
    }
}

fn assert_tag(value: &str, expected: [u8; 32], what: &str) {
    assert_eq!(tag(value), expected, "{what}: {value:?} hashes elsewhere");
}

#[test]
fn platform_ids_are_the_ones_the_chain_pins() {
    assert_tag(profile::GOOGLE.platform, PLATFORM_GOOGLE, "google");
    assert_tag(profile::X.platform, PLATFORM_X, "x");
    assert_tag(profile::GITHUB.platform, PLATFORM_GITHUB, "github");
}

#[test]
fn authority_ids_are_the_ones_the_chain_pins() {
    let authorities = |p: &Profile| {
        (
            p.token.map(|s| s.session.authority),
            p.identity.map(|s| s.session.authority),
        )
    };

    let (token, identity) = authorities(&profile::X);
    assert_tag(token.unwrap(), AUTHORITY_X_API, "x token");
    assert_tag(identity.unwrap(), AUTHORITY_X_API, "x identity");

    let (token, identity) = authorities(&profile::GITHUB);
    assert_tag(token.unwrap(), AUTHORITY_GITHUB, "github token");
    assert_tag(identity.unwrap(), AUTHORITY_GITHUB_API, "github identity");
}

#[test]
fn the_authority_is_hashed_as_the_notary_writes_it() {
    // `attested_data` lowercases before hashing, and these are already
    // lowercase -- so the id a session carries is the id the verifier pins.
    // A profile string with an upper-case byte would pass the vectors above
    // and produce a different `authorityId` at run time.
    for p in profile::LAUNCH {
        for authority in [
            p.token.map(|s| s.session.authority),
            p.identity.map(|s| s.session.authority),
        ]
        .into_iter()
        .flatten()
        {
            assert_eq!(
                authority,
                authority.to_ascii_lowercase(),
                "{authority:?} must already be lowercase"
            );
            assert!(
                !authority.ends_with('.'),
                "{authority:?} must carry no trailing dot"
            );
        }
    }
}

#[test]
fn the_vectors_are_distinct() {
    // Three platforms sharing a number would make the table look consistent
    // while two profiles dispatched to one verifier.
    let ids = [PLATFORM_GOOGLE, PLATFORM_X, PLATFORM_GITHUB];
    for (i, a) in ids.iter().enumerate() {
        for b in &ids[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_ne!(AUTHORITY_GITHUB, AUTHORITY_GITHUB_API);
}
