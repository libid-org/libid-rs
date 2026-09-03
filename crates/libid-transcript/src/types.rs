//! What a prover reads off a completed TLS session, beyond the transcript.

/// TLS handshake data: the randoms and the server's ephemeral key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshakeData {
    /// TLS client random (32 bytes).
    pub client_random: [u8; 32],
    /// TLS server random (32 bytes).
    pub server_random: [u8; 32],
    /// Server ephemeral public key (uncompressed, 65 bytes).
    pub server_ephemeral_key: Vec<u8>,
}
