//! Contract-agnostic crypto primitives shared across the libID stack.
//!
//! Everything here is generic Ethereum-flavoured cryptography: keccak256,
//! EIP-191 signing/recovery, a sorted-pair keccak Merkle tree byte-compatible
//! with OpenZeppelin's `MerkleProof`, and address helpers. Nothing in this
//! crate knows about any specific contract ABI — the contract-shaped digest
//! builders live in `libid-attestations`.

use k256::ecdsa::{
    signature::hazmat::PrehashSigner,
    RecoveryId,
    Signature,
    SigningKey,
    VerifyingKey,
};
use rand::rngs::OsRng;
use tiny_keccak::{
    Hasher,
    Keccak,
};

/// Errors from crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A cryptographic operation failed.
    #[error("{op}: {detail}")]
    CryptoFailed {
        /// The operation that failed.
        op: String,
        /// Human-readable failure detail.
        detail: String,
    },
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Generate a new secp256k1 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::random(&mut OsRng);
    let vk = *sk.verifying_key();
    (sk, vk)
}

/// Keccak256 hash.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Sign a message with a secp256k1 private key (Ethereum-style: keccak256
/// prehash). Returns a 65-byte signature: r (32) || s (32) || v (1), with the
/// raw 0/1 recovery byte (no EVM offset — see [`sign_eth_claim`] for the
/// 27/28 convention).
pub fn sign_message(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>> {
    let digest = keccak256(message);
    let (sig, recid) = key.sign_prehash(&digest).map_err(|e| Error::CryptoFailed {
        op: "sign".into(),
        detail: format!("{e}"),
    })?;
    let sig: Signature = sig;
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&sig.to_bytes());
    out.push(recid.to_byte());
    Ok(out)
}

/// Recover the public key from a 65-byte signature and the original message.
pub fn recover_public_key(signature: &[u8], message: &[u8]) -> Result<VerifyingKey> {
    if signature.len() != 65 {
        return Err(Error::CryptoFailed {
            op: "verify signature".into(),
            detail: "signature must be 65 bytes".into(),
        });
    }
    let sig =
        Signature::from_slice(&signature[..64]).map_err(|e| Error::CryptoFailed {
            op: "parse signature".into(),
            detail: format!("{e}"),
        })?;
    let recid =
        RecoveryId::from_byte(signature[64]).ok_or_else(|| Error::CryptoFailed {
            op: "parse recovery id".into(),
            detail: "invalid recovery id".into(),
        })?;
    let digest = keccak256(message);
    VerifyingKey::recover_from_prehash(&digest, &sig, recid).map_err(|e| {
        Error::CryptoFailed {
            op: "recover public key".into(),
            detail: format!("{e}"),
        }
    })
}

/// Convert a public key to an Ethereum address (last 20 bytes of keccak256 of
/// the uncompressed point).
pub fn pubkey_to_eth_address(key: &VerifyingKey) -> [u8; 20] {
    let uncompressed = key.to_encoded_point(false);
    let hash = keccak256(&uncompressed.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Hex-encode a compressed public key (33 bytes).
pub fn pubkey_to_hex(key: &VerifyingKey) -> String {
    hex::encode(key.to_sec1_bytes())
}

/// EIP-191 sign a 32-byte digest. Returns a 65-byte signature: r || s || v.
pub fn sign_eth_claim(key: &SigningKey, digest: &[u8; 32]) -> Result<Vec<u8>> {
    let mut prefixed = Vec::with_capacity(60);
    prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    prefixed.extend_from_slice(digest);
    let eth_hash = keccak256(&prefixed);
    let (sig, recid): (Signature, RecoveryId) =
        key.sign_prehash(&eth_hash)
            .map_err(|e| Error::CryptoFailed {
                op: "EIP-191 sign".into(),
                detail: format!("{e}"),
            })?;
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&sig.to_bytes());
    // k256 emits the recovery byte as 0/1; Solidity (and OZ `ECDSA.recover`)
    // expect 27/28. Bake the EVM offset in so on-chain consumers don't need
    // to know which convention the signer used. `recover_eth_claim` strips
    // it back before handing to `k256::RecoveryId::from_byte`.
    out.push(recid.to_byte().wrapping_add(27));
    Ok(out)
}

/// Recover the public key from an EIP-191 signature over a 32-byte digest.
pub fn recover_eth_claim(signature: &[u8], digest: &[u8; 32]) -> Result<VerifyingKey> {
    if signature.len() != 65 {
        return Err(Error::CryptoFailed {
            op: "verify signature".into(),
            detail: "signature must be 65 bytes".into(),
        });
    }
    let sig =
        Signature::from_slice(&signature[..64]).map_err(|e| Error::CryptoFailed {
            op: "parse signature".into(),
            detail: format!("{e}"),
        })?;
    // Solidity-canonical signatures store v as 27/28; strip the offset
    // before parsing into a k256 RecoveryId (which only accepts 0..=3).
    // Accept either convention so we're robust against pre-EVM-offset sigs.
    let v_raw = signature[64];
    let recid_byte = if v_raw >= 27 {
        v_raw.wrapping_sub(27)
    } else {
        v_raw
    };
    let recid = RecoveryId::from_byte(recid_byte).ok_or_else(|| Error::CryptoFailed {
        op: "parse recovery id".into(),
        detail: format!("invalid recovery id byte: {v_raw}"),
    })?;
    let mut prefixed = Vec::with_capacity(60);
    prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    prefixed.extend_from_slice(digest);
    let eth_hash = keccak256(&prefixed);
    VerifyingKey::recover_from_prehash(&eth_hash, &sig, recid).map_err(|e| {
        Error::CryptoFailed {
            op: "EIP-191 recover".into(),
            detail: format!("{e}"),
        }
    })
}

/// Build an OpenZeppelin-compatible keccak256 Merkle tree root from leaves.
pub fn build_merkle_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(chunk[0], chunk[1]));
            } else {
                next.push(chunk[0]);
            }
        }
        layer = next;
    }
    layer[0]
}

/// Generate a Merkle inclusion proof for the leaf at `index`.
///
/// # Panics
///
/// Panics if `index >= leaves.len()`.
#[allow(clippy::arithmetic_side_effects)] // Index arithmetic is bounded by layer.len()
pub fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    assert!(index < leaves.len(), "index out of range");
    let mut proof = Vec::new();
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    while layer.len() > 1 {
        if idx.is_multiple_of(2) {
            if idx + 1 < layer.len() {
                proof.push(layer[idx + 1]);
            }
        } else {
            proof.push(layer[idx - 1]);
        }
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            next.push(if chunk.len() == 2 {
                hash_pair(chunk[0], chunk[1])
            } else {
                chunk[0]
            });
        }
        layer = next;
        idx /= 2;
    }
    proof
}

/// Verify a Merkle inclusion proof produced by [`merkle_proof`] against a
/// root produced by [`build_merkle_tree`]. Byte-compatible with OpenZeppelin's
/// `MerkleProof.verify`.
pub fn merkle_verify(proof: &[[u8; 32]], root: [u8; 32], leaf: [u8; 32]) -> bool {
    let mut cur = leaf;
    for sibling in proof {
        cur = hash_pair(cur, *sibling);
    }
    cur == root
}

/// Sorted-pair keccak hash — the OpenZeppelin node combine step.
pub fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    if a < b {
        keccak256(&[a.as_slice(), b.as_slice()].concat())
    } else {
        keccak256(&[b.as_slice(), a.as_slice()].concat())
    }
}

/// Double-hashed Merkle leaf (OpenZeppelin style, prevents second-preimage):
/// `keccak256(keccak256(prefix || value))`.
///
/// `prefix` accepts both `&str` (`"recv:"`) and `&[u8]` (`b"recv:"`) tags.
pub fn double_hash_leaf(prefix: impl AsRef<[u8]>, value: &[u8]) -> [u8; 32] {
    let mut inner = Vec::with_capacity(prefix.as_ref().len().saturating_add(value.len()));
    inner.extend_from_slice(prefix.as_ref());
    inner.extend_from_slice(value);
    let inner_hash = keccak256(&inner);
    keccak256(&inner_hash)
}

/// Parse a hex string (with or without a "0x" prefix) into a 20-byte
/// Ethereum address.
pub fn hex_to_address(hex_str: &str) -> Result<[u8; 20]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| Error::CryptoFailed {
        op: "parse address hex".into(),
        detail: format!("{e}"),
    })?;
    if bytes.len() != 20 {
        return Err(Error::CryptoFailed {
            op: "parse address".into(),
            detail: "address must be 20 bytes".into(),
        });
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

/// Parse a hex string (with or without a "0x" prefix) into a secp256k1
/// signing key.
pub fn hex_to_signing_key(hex_str: &str) -> Result<SigningKey> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| Error::CryptoFailed {
        op: "parse signing key hex".into(),
        detail: format!("{e}"),
    })?;
    SigningKey::from_slice(&bytes).map_err(|e| Error::CryptoFailed {
        op: "parse signing key".into(),
        detail: format!("{e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical anvil account #0 key. Public test material, not a secret.
    const ANVIL_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_ADDR: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    #[test]
    fn roundtrip_sign_recover() {
        let (sk, vk) = generate_keypair();
        let msg = b"hello world";
        let sig = sign_message(&sk, msg).unwrap();
        let recovered = recover_public_key(&sig, msg).unwrap();
        assert_eq!(vk, recovered);
    }

    #[test]
    fn eth_address_deterministic() {
        let (_, vk) = generate_keypair();
        let addr1 = pubkey_to_eth_address(&vk);
        let addr2 = pubkey_to_eth_address(&vk);
        assert_eq!(addr1, addr2);
        assert_ne!(addr1, [0u8; 20]);
    }

    #[test]
    fn anvil_key_derives_known_address() {
        let sk = hex_to_signing_key(ANVIL_KEY).unwrap();
        let addr = pubkey_to_eth_address(sk.verifying_key());
        assert_eq!(hex::encode(addr), ANVIL_ADDR);
    }

    #[test]
    fn sign_eth_claim_produces_65_bytes() {
        let (sk, _) = generate_keypair();
        let digest = keccak256(b"test claim");
        let sig = sign_eth_claim(&sk, &digest).unwrap();
        assert_eq!(sig.len(), 65);
        assert!(matches!(sig[64], 27 | 28));
    }

    /// EIP-191 known vector: RFC 6979 makes ECDSA deterministic, so the exact
    /// signature bytes for a fixed key + digest are pinned. If this ever
    /// changes — v encoding, s normalisation, prefix — proofs signed by a
    /// newer build would be rejected on-chain with no useful error.
    #[test]
    fn sign_eth_claim_known_vector() {
        let sk = hex_to_signing_key(ANVIL_KEY).unwrap();
        let digest = keccak256(b"libid eip191 vector");
        let sig = sign_eth_claim(&sk, &digest).unwrap();
        assert_eq!(
            hex::encode(&sig),
            "d3e3c9a6f434a15ec60ed58d80936c8180142e748ac6af44efa23d21f77671f1\
             244ed128a1a57c5e3a067a30b7c7b6635562b56766cda7819706b21a5108ad20\
             1c",
        );
    }

    #[test]
    fn eth_claim_roundtrip_both_v_conventions() {
        let (sk, vk) = generate_keypair();
        let digest = keccak256(b"claim");
        let mut sig = sign_eth_claim(&sk, &digest).unwrap();
        // Canonical 27/28 form recovers…
        assert_eq!(recover_eth_claim(&sig, &digest).unwrap(), vk);
        // …and so does the raw 0/1 form.
        sig[64] = sig[64].wrapping_sub(27);
        assert_eq!(recover_eth_claim(&sig, &digest).unwrap(), vk);
    }

    #[test]
    fn merkle_tree_empty_and_single_leaf() {
        assert_eq!(build_merkle_tree(&[]), [0u8; 32]);
        let leaf = keccak256(b"leaf");
        assert_eq!(build_merkle_tree(&[leaf]), leaf);
    }

    #[test]
    fn merkle_tree_two_leaves() {
        let a = keccak256(b"a");
        let b = keccak256(b"b");
        let root = build_merkle_tree(&[a, b]);
        let expected = hash_pair(a, b);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_proof_roundtrip() {
        // Odd count exercises the promoted-node path.
        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| keccak256(&[i])).collect();
        let root = build_merkle_tree(&leaves);

        for i in 0..leaves.len() {
            let proof = merkle_proof(&leaves, i);
            assert!(merkle_verify(&proof, root, leaves[i]), "leaf {}", i);
        }
    }

    #[test]
    fn merkle_proof_roundtrip_double_hashed_leaves() {
        // The shape the notaries use: double-hashed prefixed leaves.
        let leaves: Vec<[u8; 32]> = ["a", "b", "c", "d"]
            .iter()
            .map(|s| double_hash_leaf("recv:", s.as_bytes()))
            .collect();
        let root = build_merkle_tree(&leaves);
        for i in 0..leaves.len() {
            let proof = merkle_proof(&leaves, i);
            assert!(merkle_verify(&proof, root, leaves[i]), "leaf {i}");
        }
    }

    #[test]
    fn merkle_proof_rejects_wrong_leaf() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| keccak256(&[i])).collect();
        let root = build_merkle_tree(&leaves);
        let proof = merkle_proof(&leaves, 0);
        assert!(!merkle_verify(&proof, root, keccak256(b"forged")));
    }

    #[test]
    fn double_hash_leaf_matches_solidity() {
        let value = keccak256(b"x123");
        let leaf = double_hash_leaf("identity", &value);
        let mut inner = Vec::new();
        inner.extend_from_slice(b"identity");
        inner.extend_from_slice(&value);
        let expected = keccak256(&keccak256(&inner));
        assert_eq!(leaf, expected);
    }

    #[test]
    fn double_hash_leaf_str_and_bytes_prefixes_agree() {
        // The dyaka call sites pass `"recv:"`, the jwks prover passed
        // `b"recv:"` — both must hash identically now that they share one
        // implementation.
        assert_eq!(
            double_hash_leaf("recv:", b"payload"),
            double_hash_leaf(b"recv:".as_slice(), b"payload"),
        );
    }

    /// Regression: comment-uid encoding must match Solidity
    /// abi.encodePacked(platform, ":", resourceType, ":", resourceId). The
    /// expected hash is pinned by the Solidity known-vector test.
    #[test]
    fn uid_matches_solidity() {
        let uid = keccak256(b"github:issue_comment:42");
        let expected = hex::decode(
            "6320000930f13d9eea4e06e615a5aac92a38d47b43d11c811cd5dea58cfd392f",
        )
        .unwrap();
        assert_eq!(uid, expected.as_slice(), "uid Rust/Solidity mismatch");
    }

    /// Regression: backend digest known-vector — keccak256(abi.encodePacked(
    /// uid, revealed, timestamp)). The expected hash is pinned by the
    /// Solidity known-vector test.
    #[test]
    fn packed_backend_digest_matches_solidity() {
        let uid = keccak256(b"github:issue_comment:42");
        let revealed = b"hello";
        let timestamp: u64 = 1000;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&uid);
        preimage.extend_from_slice(revealed);
        let mut ts_bytes = [0u8; 32];
        ts_bytes[24..].copy_from_slice(&timestamp.to_be_bytes());
        preimage.extend_from_slice(&ts_bytes);
        let digest = keccak256(&preimage);

        let expected = hex::decode(
            "37a9e3d754ccbc2f90ffb54751c1cc858827f1e6af5d7f541d03c1c070712764",
        )
        .unwrap();
        assert_eq!(
            digest,
            expected.as_slice(),
            "backend digest Rust/Solidity mismatch"
        );
    }
}
