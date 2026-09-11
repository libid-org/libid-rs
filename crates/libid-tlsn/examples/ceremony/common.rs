//! What the contract suites verify against, shared by the fixture generator
//! and the capture tool: the notary key they trust, the submission whose
//! Authorization Digest the records must be bound to, and the derivations
//! ceremony-common fixes in sections 5 and 7.
//!
//! Included by `#[path]` from each example; not an example of its own.

#![allow(dead_code)]

use libid_crypto::keccak256;
use sha2::Digest as _;

/// anvil #0, the key the contract suites trust.
pub const NOTARY_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// The suites' chain, domain, nonce and transaction data.
pub const CHAIN_ID: u64 = 31337;
pub const OPERATION_DOMAIN: &[u8] = b"libid.claim-identity";
pub const AUTHORIZATION_NONCE: [u8; 32] = [0x55; 32];
pub const CEREMONY_VERSION: u16 = 1;
/// The user agent the browser sends on GitHub's identity read.
pub const BROWSER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

/// `abi.encode(address(0xBEEF))`.
pub fn transaction_data() -> Vec<u8> {
    let mut data = vec![0u8; 32];
    data[30] = 0xBE;
    data[31] = 0xEF;
    data
}

/// The Authorization Digest of ceremony-common section 5, as
/// `CeremonyAuthorization.digestFor` computes it on the test chain.
pub fn authorization_digest() -> [u8; 32] {
    let mut chain = [0u8; 32];
    chain[24..].copy_from_slice(&CHAIN_ID.to_be_bytes());
    let data = transaction_data();
    let mut preimage = Vec::with_capacity(102 + data.len());
    preimage.extend_from_slice(&keccak256(OPERATION_DOMAIN));
    preimage.extend_from_slice(&CEREMONY_VERSION.to_be_bytes());
    preimage.extend_from_slice(&keccak256(&chain));
    preimage.extend_from_slice(&AUTHORIZATION_NONCE);
    preimage.extend_from_slice(&(data.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&data);
    keccak256(&preimage)
}

/// The PKCE verifier of section 7: `BASE64URL_NOPAD(SHA256(digest || nonce))`.
pub fn code_verifier() -> String {
    let mut binding = [0u8; 64];
    binding[..32].copy_from_slice(&authorization_digest());
    binding[32..].copy_from_slice(&AUTHORIZATION_NONCE);
    base64url_nopad(&sha2::Sha256::digest(binding))
}

/// The S256 challenge of that verifier, what the authorization request carries.
pub fn code_challenge() -> String {
    base64url_nopad(&sha2::Sha256::digest(code_verifier().as_bytes()))
}

pub fn base64url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let keep = chunk.len() + 1;
        for i in 0..keep {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// The JSON every fixture starts with: which submission the records are
/// bound to, and who signed them.
pub fn submission_json(platform: &str, notary: &str) -> serde_json::Value {
    serde_json::json!({
        "platform": platform,
        "ceremony_version": CEREMONY_VERSION,
        "chain_id": CHAIN_ID,
        "notary": notary,
        "operation_domain": hex0x(&keccak256(OPERATION_DOMAIN)),
        "authorization_nonce": hex0x(&AUTHORIZATION_NONCE),
        "transaction_data": hex0x(&transaction_data()),
        "authorization_digest": hex0x(&authorization_digest()),
        "code_verifier": code_verifier(),
    })
}
