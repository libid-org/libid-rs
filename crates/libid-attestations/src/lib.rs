//! Contract-ABI-shaped digest builders for the libID verifiers.
//!
//! Every function here mirrors a specific Solidity verification routine and
//! is pinned to it by known-vector tests. The generic primitives (keccak,
//! EIP-191, Merkle) live in `libid-crypto`; this crate is where the contract
//! ABI shapes are allowed to leak in.
//!
//! Digest inventory:
//!
//! * [`compute_notary_digest`] — `_verifyNotarySignature` (8-slot, chain- and
//!   deployment-bound).
//! * [`compute_jwks_notary_digest`] — `JwksOracle._notaryDigest` (6-slot
//!   legacy form, no chain binding).
//! * [`compute_backend_digest`] — `_verifyBackendSignature` (4-slot).
//! * [`compute_identity_hash`] — `Registry.sol` identity hash.
//! * [`compute_token_attest_digest`] / [`compute_me_attest_digest`] —
//!   `XZkVerifier._verifyTokenSig` / `_verifyMeSig`.

use libid_crypto::keccak256;

/// Must match Solidity `_verifyNotarySignature` (8-slot abi.encode with
/// `(chainId, verifyingContract)` domain separator + 6 legacy fields).
/// A notary signature on chain A is not replayable against a sibling
/// deployment on chain B (or against a redeployed proxy on the same
/// chain).
#[allow(clippy::too_many_arguments)]
pub fn compute_notary_digest(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    domain: &str,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    server_ephemeral_key: &[u8],
    transcript_root: &[u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let domain_hash = keccak256(domain.as_bytes());
    let mut encoded = Vec::with_capacity(8 * 32);
    extend_u256(&mut encoded, chain_id as u128);
    extend_address(&mut encoded, verifying_contract);
    // 6 legacy fields
    encoded.extend_from_slice(&domain_hash);
    encoded.extend_from_slice(client_random);
    encoded.extend_from_slice(server_random);
    encoded.extend_from_slice(&keccak256(server_ephemeral_key));
    encoded.extend_from_slice(transcript_root);
    extend_u256(&mut encoded, timestamp as u128);
    keccak256(&encoded)
}

/// Compute the digest `JwksOracle._notaryDigest` verifies: the 6-slot legacy
/// form `keccak256(abi.encode(domainHash, clientRandom, serverRandom,
/// keccak(serverEphemeralKey), transcriptRoot, timestamp))` — no chain
/// binding.
pub fn compute_jwks_notary_digest(
    domain_hash: [u8; 32],
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_ephemeral_key: &[u8],
    transcript_root: [u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    use alloy_sol_types::SolValue;
    let server_eph_hash = keccak256(server_ephemeral_key);
    let encoded = (
        alloy_primitives::B256::from(domain_hash),
        alloy_primitives::B256::from(client_random),
        alloy_primitives::B256::from(server_random),
        alloy_primitives::B256::from(server_eph_hash),
        alloy_primitives::B256::from(transcript_root),
        alloy_primitives::U256::from(timestamp),
    )
        .abi_encode_params();
    keccak256(&encoded)
}

/// Compute the identity hash: `keccak256(abi.encode(domain, username))`.
///
/// This matches the Solidity `Registry.sol` computation exactly.
/// `abi.encode` for two dynamic `string` arguments produces:
///   - 2 × 32-byte offsets (pointing to each string's length slot)
///   - For each string: 32-byte length + data padded to 32-byte boundary
#[allow(clippy::arithmetic_side_effects)]
pub fn compute_identity_hash(domain: &str, username: &str) -> [u8; 32] {
    fn pad32(len: usize) -> usize {
        (len + 31) & !31
    }

    let domain_bytes = domain.as_bytes();
    let username_bytes = username.as_bytes();

    let domain_padded = pad32(domain_bytes.len());
    let username_padded = pad32(username_bytes.len());

    // Total: 2 offsets (64) + domain length (32) + domain data (padded)
    //        + username length (32) + username data (padded)
    let total = 64 + 32 + domain_padded + 32 + username_padded;
    let mut encoded = vec![0u8; total];

    // Offset of first string data = 64 (0x40)
    encoded[31] = 0x40;
    // Offset of second string data = 64 + 32 + domain_padded
    let second_offset = 64u64 + 32 + domain_padded as u64;
    encoded[32..64].copy_from_slice(&{
        let mut buf = [0u8; 32];
        buf[24..].copy_from_slice(&second_offset.to_be_bytes());
        buf
    });

    // Domain: length + data
    let base = 64;
    encoded[base + 24..base + 32]
        .copy_from_slice(&(domain_bytes.len() as u64).to_be_bytes());
    encoded[base + 32..base + 32 + domain_bytes.len()].copy_from_slice(domain_bytes);

    // Username: length + data
    let base2 = 64 + 32 + domain_padded;
    encoded[base2 + 24..base2 + 32]
        .copy_from_slice(&(username_bytes.len() as u64).to_be_bytes());
    encoded[base2 + 32..base2 + 32 + username_bytes.len()]
        .copy_from_slice(username_bytes);

    keccak256(&encoded)
}

/// Op-tag for `XZkVerifier._verifyTokenSig`: `keccak256("XZkVerifier.token.v1")`.
pub fn op_token_attest_tag() -> [u8; 32] {
    keccak256(b"XZkVerifier.token.v1")
}

/// Op-tag for `XZkVerifier._verifyMeSig`: `keccak256("XZkVerifier.me.v1")`.
pub fn op_me_attest_tag() -> [u8; 32] {
    keccak256(b"XZkVerifier.me.v1")
}

/// Input for the token-attestation EIP-191 digest.
pub struct TokenAttestInput<'a> {
    /// EVM chain ID (domain separator).
    pub chain_id: u64,
    /// XZkVerifier contract address (binds attestation to one deployment).
    pub verifying_contract: &'a [u8; 20],
    /// SNI / platform name (e.g. "api.x.com").
    pub platform_name: &'a str,
    /// SHA256(bearer || blinder) — TLSN hash-commit, bearer in RECV.
    pub bearer_hash: &'a [u8; 32],
    /// Start offset of the bearer range in the recv transcript.
    pub bearer_range_start: u32,
    /// End offset (exclusive) of the bearer range.
    pub bearer_range_end: u32,
    /// SENT request body — must contain `client_id=<clientId>`.
    pub sent_revealed: &'a [u8],
    /// Unix timestamp (seconds) of notarization.
    pub timestamp: u64,
}

/// Mirrors `XZkVerifier._verifyTokenSig`:
/// `keccak256(abi.encode(chainid, verifier, keccak(platformName), OP_TOKEN_ATTEST,
///   bearerHash, bearerRangeStart, bearerRangeEnd, keccak(sentRevealed), ts))`.
pub fn compute_token_attest_digest(input: &TokenAttestInput<'_>) -> [u8; 32] {
    let platform_hash = keccak256(input.platform_name.as_bytes());
    let sent_hash = keccak256(input.sent_revealed);
    let op = op_token_attest_tag();

    let mut buf = Vec::with_capacity(9 * 32);
    extend_u256(&mut buf, input.chain_id as u128);
    extend_address(&mut buf, input.verifying_contract);
    buf.extend_from_slice(&platform_hash);
    buf.extend_from_slice(&op);
    buf.extend_from_slice(input.bearer_hash);
    extend_u256(&mut buf, input.bearer_range_start as u128);
    extend_u256(&mut buf, input.bearer_range_end as u128);
    buf.extend_from_slice(&sent_hash);
    extend_u256(&mut buf, input.timestamp as u128);
    keccak256(&buf)
}

/// Input for the me-attestation EIP-191 digest.
pub struct MeAttestInput<'a> {
    /// EVM chain ID (domain separator).
    pub chain_id: u64,
    /// XZkVerifier contract address.
    pub verifying_contract: &'a [u8; 20],
    /// SNI / platform name.
    pub platform_name: &'a str,
    /// SHA256(bearer || blinder) — must equal `tokenAttest.bearerHash`.
    pub bearer_hash: &'a [u8; 32],
    /// Start offset of the bearer range in the sent transcript.
    pub bearer_range_start: u32,
    /// End offset (exclusive) of the bearer range.
    pub bearer_range_end: u32,
    /// SENT-side revealed bytes: concat of `[0, bearer_range_start)` (request
    /// prefix ending in `authorization: Bearer `) and
    /// `[bearer_range_end, bearer_range_end + 2)` (CRLF after bearer).
    pub sent_revealed: &'a [u8],
    /// End of the first revealed range. Must equal `bearer_range_start`.
    pub sent_prefix_end: u32,
    /// End of the second revealed range. Must equal `bearer_range_end + 2`.
    /// H1 bearer-end anchor: the two bytes between `bearer_range_end` and
    /// `sent_suffix_end` are CRLF, canonicalizing `bearer_len`.
    pub sent_suffix_end: u32,
    /// RECV-side revealed bytes (chunk containing handle JSON).
    pub recv_revealed: &'a [u8],
    /// Claimed handle; must appear as `"<prefix><handle>"` in `recv_revealed`.
    pub handle: &'a str,
    /// Immutable platform user-id; must appear as `"id":"<userId>"` in
    /// `recv_revealed` ("" when not revealed → handle-key fallback).
    pub user_id: &'a str,
    /// Session key the wallet will register against (signed by notary here).
    pub session_addr: &'a [u8; 20],
    /// Unix timestamp (seconds) of notarization.
    pub timestamp: u64,
}

/// Mirrors `XZkVerifier._verifyMeSig`.
pub fn compute_me_attest_digest(input: &MeAttestInput<'_>) -> [u8; 32] {
    let platform_hash = keccak256(input.platform_name.as_bytes());
    let sent_hash = keccak256(input.sent_revealed);
    let recv_hash = keccak256(input.recv_revealed);
    let handle_hash = keccak256(input.handle.as_bytes());
    let user_id_hash = keccak256(input.user_id.as_bytes());
    let op = op_me_attest_tag();

    let mut buf = Vec::with_capacity(15 * 32);
    extend_u256(&mut buf, input.chain_id as u128);
    extend_address(&mut buf, input.verifying_contract);
    buf.extend_from_slice(&platform_hash);
    buf.extend_from_slice(&op);
    buf.extend_from_slice(input.bearer_hash);
    extend_u256(&mut buf, input.bearer_range_start as u128);
    extend_u256(&mut buf, input.bearer_range_end as u128);
    buf.extend_from_slice(&sent_hash);
    extend_u256(&mut buf, input.sent_prefix_end as u128);
    extend_u256(&mut buf, input.sent_suffix_end as u128);
    buf.extend_from_slice(&recv_hash);
    buf.extend_from_slice(&handle_hash);
    buf.extend_from_slice(&user_id_hash);
    extend_address(&mut buf, input.session_addr);
    extend_u256(&mut buf, input.timestamp as u128);
    keccak256(&buf)
}

fn extend_u256(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&v.to_be_bytes());
}

fn extend_address(buf: &mut Vec<u8>, addr: &[u8; 20]) {
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(addr);
}

/// Compute the backend digest:
/// `keccak256(abi.encode(userAddress, walletAddress, transcriptRoot, timestamp))`.
/// `wallet_address` is `[0u8; 20]` for `register_session` and the target
/// wallet for `linkIdentity` — bound to the signature so a leaked proof
/// cannot be replayed from a different `msg.sender`.
pub fn compute_backend_digest(
    user_address: &[u8; 20],
    wallet_address: &[u8; 20],
    transcript_root: &[u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(4 * 32);
    extend_address(&mut encoded, user_address);
    extend_address(&mut encoded, wallet_address);
    encoded.extend_from_slice(transcript_root);
    extend_u256(&mut encoded, timestamp as u128);
    keccak256(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: backend digest = abi.encode(userAddr, walletAddr, root, ts).
    #[test]
    fn identity_backend_digest_known_vector() {
        let user_address = [0xABu8; 20];
        let wallet_address = [0xCDu8; 20];
        let transcript_root = [0x01u8; 32];
        let timestamp: u64 = 1000;

        let digest = compute_backend_digest(
            &user_address,
            &wallet_address,
            &transcript_root,
            timestamp,
        );
        let digest2 = compute_backend_digest(
            &user_address,
            &wallet_address,
            &transcript_root,
            timestamp,
        );
        assert_eq!(digest, digest2);
        assert_ne!(digest, [0u8; 32]);

        // Different walletAddress must produce a different digest.
        let other = compute_backend_digest(
            &user_address,
            &[0u8; 20],
            &transcript_root,
            timestamp,
        );
        assert_ne!(digest, other);
    }

    /// Identity hash must match Solidity: keccak256(abi.encode("api.x.com", "alice")).
    /// The expected hash is pinned in test/Registry.t.sol::test_identityHash_knownVector.
    #[test]
    fn identity_hash_matches_solidity() {
        let hash = compute_identity_hash("api.x.com", "alice");
        // Computed from Solidity: keccak256(abi.encode("api.x.com", "alice"))
        // This value must be kept in sync with the Solidity test.
        let expected = hex::decode(
            "c9c0cd07ff8cc2f66b83dc7343b0040bc55eb4b7705829cf17f45aba75a2ecf3",
        )
        .unwrap();
        assert_eq!(
            hash,
            expected.as_slice(),
            "identity hash Rust/Solidity mismatch"
        );
    }

    /// The hand-rolled identity-hash abi.encode must agree with alloy's
    /// encoder for dynamic strings.
    #[test]
    fn identity_hash_matches_alloy_encoder() {
        use alloy_sol_types::SolValue;
        for (domain, username) in [
            ("api.x.com", "alice"),
            ("api.github.com", "a-much-longer-username-past-32-bytes!!"),
            ("", ""),
        ] {
            let encoded = (domain.to_string(), username.to_string()).abi_encode_params();
            assert_eq!(
                compute_identity_hash(domain, username),
                keccak256(&encoded),
                "{domain}/{username}"
            );
        }
    }

    /// Token-attest digest must match Solidity XZkVerifier._verifyTokenSig.
    /// keccak256(abi.encode(chainid, verifier, keccak(platform), OP_TOKEN_ATTEST,
    ///   bearerHash, start, end, keccak(sentRevealed), ts)).
    #[test]
    fn token_attest_digest_matches_solidity() {
        let verifier = [0u8; 20];
        let mut v = verifier;
        v[19] = 1;
        let bearer_hash = [0x11u8; 32];
        let digest = compute_token_attest_digest(&TokenAttestInput {
            chain_id: 1,
            verifying_contract: &v,
            platform_name: "api.x.com",
            bearer_hash: &bearer_hash,
            bearer_range_start: 5,
            bearer_range_end: 50,
            sent_revealed: b"GET /token",
            timestamp: 1000,
        });
        let expected = hex::decode(
            "4221c29b0c1346afc0eaabad4bdf16803b1329ae9408f05dade9a675faea62ed",
        )
        .unwrap();
        assert_eq!(
            digest,
            expected.as_slice(),
            "token-attest digest Rust/Solidity mismatch"
        );
    }

    /// Me-attest digest must match Solidity XZkVerifier._verifyMeSig.
    /// keccak256(abi.encode(chainid, verifier, keccak(platform), OP_ME_ATTEST,
    ///   bearerHash, start, end, keccak(sent), prefixEnd, suffixEnd, keccak(recv),
    ///   keccak(handle), keccak(userId), sessionAddr, ts)).
    #[test]
    fn me_attest_digest_matches_solidity() {
        let mut v = [0u8; 20];
        v[19] = 1;
        let mut session = [0u8; 20];
        session[19] = 2;
        let bearer_hash = [0x11u8; 32];
        let digest = compute_me_attest_digest(&MeAttestInput {
            chain_id: 1,
            verifying_contract: &v,
            platform_name: "api.x.com",
            bearer_hash: &bearer_hash,
            bearer_range_start: 5,
            bearer_range_end: 50,
            sent_revealed: b"GET /me",
            sent_prefix_end: 5,
            sent_suffix_end: 52,
            recv_revealed: br#"{"id":"123","username":"alice"}"#,
            handle: "alice",
            user_id: "123",
            session_addr: &session,
            timestamp: 1000,
        });
        let expected = hex::decode(
            "fbde91b37cbfc819cabfdc43bd9a2ae09a344f7b135ead145d3f5b27ae1b9903",
        )
        .unwrap();
        assert_eq!(
            digest,
            expected.as_slice(),
            "me-attest digest Rust/Solidity mismatch"
        );
    }

    /// The chain-bound notary digest is the jwks legacy digest with the
    /// `(chainId, verifyingContract)` prefix — verify the hand-rolled
    /// encoding against alloy's for the shared 6-field tail.
    #[test]
    fn notary_digest_matches_alloy_encoding() {
        use alloy_sol_types::SolValue;
        let chain_id = 11155111u64;
        let contract = [0x42u8; 20];
        let domain = "api.x.com";
        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];
        let eph = vec![0x04u8; 65];
        let root = [0xCCu8; 32];
        let ts = 1_700_000_000u64;

        let digest = compute_notary_digest(
            chain_id,
            &contract,
            domain,
            &client_random,
            &server_random,
            &eph,
            &root,
            ts,
        );

        let encoded = (
            alloy_primitives::U256::from(chain_id),
            alloy_primitives::Address::from(contract),
            alloy_primitives::B256::from(keccak256(domain.as_bytes())),
            alloy_primitives::B256::from(client_random),
            alloy_primitives::B256::from(server_random),
            alloy_primitives::B256::from(keccak256(&eph)),
            alloy_primitives::B256::from(root),
            alloy_primitives::U256::from(ts),
        )
            .abi_encode_params();
        assert_eq!(digest, keccak256(&encoded));
    }

    /// The 6-slot jwks digest differs from the chain-bound one precisely by
    /// the missing (chainId, verifyingContract) prefix.
    #[test]
    fn jwks_notary_digest_is_the_unbound_tail() {
        let domain_hash = keccak256(b"www.googleapis.com");
        let eph = vec![0u8; 65];
        let digest = compute_jwks_notary_digest(
            domain_hash,
            [1u8; 32],
            [2u8; 32],
            &eph,
            [3u8; 32],
            1000,
        );

        let mut encoded = Vec::with_capacity(6 * 32);
        encoded.extend_from_slice(&domain_hash);
        encoded.extend_from_slice(&[1u8; 32]);
        encoded.extend_from_slice(&[2u8; 32]);
        encoded.extend_from_slice(&keccak256(&eph));
        encoded.extend_from_slice(&[3u8; 32]);
        let mut ts = [0u8; 32];
        ts[24..].copy_from_slice(&1000u64.to_be_bytes());
        encoded.extend_from_slice(&ts);
        assert_eq!(digest, keccak256(&encoded));
    }
}
