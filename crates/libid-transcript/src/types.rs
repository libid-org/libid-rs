//! Proof-related types: EVM proofs and notary responses.
//!
//! These are the notary's outputs as consumed by backends, ZK provers and
//! on-chain verifiers. With the `ts` feature enabled they additionally derive
//! `ts_rs::TS` so TypeScript bindings can be generated.

use serde::{
    Deserialize,
    Serialize,
};

/// TLS handshake data for EVM proof construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshakeData {
    /// TLS client random (32 bytes).
    pub client_random: [u8; 32],
    /// TLS server random (32 bytes).
    pub server_random: [u8; 32],
    /// Server ephemeral public key (uncompressed, 65 bytes).
    pub server_ephemeral_key: Vec<u8>,
}

/// EVM-compatible proof for on-chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct EvmProof {
    /// The domain being attested, taken directly from TLS SNI (authenticated
    /// by the CA hierarchy during the MPC-TLS handshake).
    pub domain: String,
    /// The endpoint (method + path), extracted from the revealed HTTP request
    /// line in the transcript (e.g., "GET /2/users/me").
    pub endpoint: String,
    /// TLS client random (32 bytes).
    pub client_random: [u8; 32],
    /// TLS server random (32 bytes).
    pub server_random: [u8; 32],
    /// Server ephemeral public key.
    pub server_ephemeral_key: Vec<u8>,
    /// Merkle root over `[domain_leaf, endpoint_leaf, recv_seg_0, ...]`.
    pub transcript_root: [u8; 32],
    /// Merkle leaves (domain, endpoint, and recv segment hashes).
    pub leaves: Vec<[u8; 32]>,
    /// Unix timestamp of proof generation.
    pub timestamp: u64,
    /// Notary signature over the proof digest.
    pub notary_signature: Vec<u8>,
    /// Raw revealed recv segments (plaintext bytes) — used as ZK circuit
    /// private input. Each element corresponds to a Merkle leaf in
    /// `leaves[2..]`.
    #[serde(default)]
    pub recv_segments: Vec<Vec<u8>>,
    /// Explicit nonce (8 bytes) from the first AppData TLS record.
    /// Only set in ZK proxy path. Combined with server_write_iv to form the
    /// 12-byte GCM nonce.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub explicit_nonce: Vec<u8>,
    /// First 160 bytes of the first AppData TLS record ciphertext.
    /// Only set in ZK proxy path. Circuit input for AES-128-CTR decryption.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_ciphertext: Vec<u8>,
}

/// Response from the notary server containing attestation and proof.
///
/// The notary is fully platform-agnostic: it never imports platform
/// definitions, never parses the API response, and never validates domains
/// against a whitelist. It attests to the domain (from TLS SNI), the endpoint
/// (from the revealed HTTP request line), and returns the raw response body
/// for the backend to parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct NotaryResponse {
    /// TLSNotary attestation bytes.
    pub attestation: Vec<u8>,
    /// EVM-compatible proof.
    ///
    /// - `domain`: from TLS SNI, authenticated by the CA hierarchy.
    /// - `endpoint`: from the revealed HTTP request line in the transcript.
    /// - `transcript_root`: Merkle root over
    ///   `[domain_leaf, endpoint_leaf, recv_seg_0, recv_seg_1, ...]`.
    pub evm_proof: EvmProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proof() -> EvmProof {
        EvmProof {
            domain: "api.x.com".into(),
            endpoint: "GET /2/users/me".into(),
            client_random: [1u8; 32],
            server_random: [2u8; 32],
            server_ephemeral_key: vec![4u8; 65],
            transcript_root: [3u8; 32],
            leaves: vec![[5u8; 32], [6u8; 32]],
            timestamp: 1_700_000_000,
            notary_signature: vec![7u8; 65],
            recv_segments: vec![br#""username":"alice""#.to_vec()],
            explicit_nonce: Vec::new(),
            app_ciphertext: Vec::new(),
        }
    }

    #[test]
    fn evm_proof_serde_round_trip() {
        let proof = sample_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let back: EvmProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back.domain, proof.domain);
        assert_eq!(back.transcript_root, proof.transcript_root);
        assert_eq!(back.recv_segments, proof.recv_segments);
        // Empty ZK-proxy fields are skipped on the wire…
        assert!(!json.contains("explicit_nonce"));
        // …and default back to empty on read.
        assert!(back.explicit_nonce.is_empty());
    }

    #[test]
    fn evm_proof_reads_legacy_payload_without_optional_fields() {
        // Payloads produced before recv_segments/nonce/ciphertext existed
        // must still parse (serde defaults).
        let json = r#"{
            "domain": "api.x.com",
            "endpoint": "GET /2/users/me",
            "client_random": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "server_random": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "server_ephemeral_key": [],
            "transcript_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "leaves": [],
            "timestamp": 0,
            "notary_signature": []
        }"#;
        let proof: EvmProof = serde_json::from_str(json).unwrap();
        assert!(proof.recv_segments.is_empty());
    }

    #[test]
    fn notary_response_serde_round_trip() {
        let resp = NotaryResponse {
            attestation: vec![9u8; 16],
            evm_proof: sample_proof(),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let back: NotaryResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.attestation, resp.attestation);
        assert_eq!(back.evm_proof.endpoint, resp.evm_proof.endpoint);
    }
}
