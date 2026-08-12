//! MPC-TLS session driver for platform API notarization using TLSNotary.
//!
//! This crate provides prover and verifier functionality for establishing
//! TLS connections to any HTTPS API while generating cryptographic proofs
//! that can be verified by a third party. It is the only crate in the libID
//! workspace that touches `tlsn` types — everything byte-oriented (range
//! math, wire protocol, proof types) lives in `libid-transcript`, which is
//! published to crates.io. This crate is git-only until upstream tlsn is
//! published (see Cargo.toml).
//!
//! # Cryptographic Guarantee: Why the Prover Cannot Fake Revealed Data
//!
//! TLSNotary uses a multi-party computation (MPC) protocol to split the TLS
//! session keys between the prover and the verifier (notary). Neither party
//! holds the full key material alone — the TLS MAC key and encryption key are
//! secret-shared. During the TLS session, both parties jointly compute the
//! HMAC and decryption operations via 2PC (two-party computation), so the
//! actual plaintext is only assembled inside the MPC circuit.
//!
//! When the prover later reveals portions of the transcript, the verifier can
//! confirm authenticity because:
//!
//! 1. **Commitment phase**: During the MPC-TLS session, the prover commits to
//!    the full transcript (sent and received bytes) using hash-based
//!    commitments. These commitments are bound to the ciphertext that both
//!    parties observed on the wire.
//!
//! 2. **Selective disclosure**: After the session closes, the prover opens
//!    specific byte ranges of the transcript by revealing the plaintext and
//!    the corresponding commitment opening. The verifier checks that the
//!    opened plaintext, when encrypted under the jointly-held session key,
//!    produces the exact ciphertext that was recorded during the live TLS
//!    session.
//!
//! 3. **Server identity binding**: The TLS handshake — including the server's
//!    certificate chain, ephemeral key, and ServerHello random — is verified
//!    by the notary against the WebPKI root store during the MPC-TLS session.
//!    The server name (SNI) is therefore authenticated by the CA hierarchy,
//!    not merely asserted by the prover.
//!
//! Because the session keys are never fully available to the prover alone, the
//! prover cannot forge a valid ciphertext/plaintext pair. Any attempt to alter
//! the revealed plaintext would fail the commitment verification: the modified
//! plaintext would not match the ciphertext that was jointly observed and
//! committed to during the live session. This makes the revealed data as
//! trustworthy as the TLS session itself — the prover can choose *which* parts
//! to reveal, but cannot fabricate *what* those parts contain.
//!
//! # Why the Notary Does Not Need a Domain Whitelist
//!
//! The TLS server name (SNI) is authenticated by the WebPKI certificate chain
//! during the MPC-TLS handshake. The notary (verifier) validates the server's
//! certificate against the WebPKI root store in real time, as part of the
//! joint TLS computation. Because the handshake keys are secret-shared, the
//! prover cannot substitute a different certificate or redirect the connection
//! to a different server without breaking the MPC-TLS protocol. The domain
//! extracted from SNI is therefore a cryptographic fact — not an assertion by
//! the prover — and the notary can safely use it without maintaining any
//! platform-specific domain list.

mod session;

pub use session::{
    extract_handshake_data,
    prover,
    prover_generic,
    root_store,
    verifier,
    HttpRequestSpec,
    ProverResult,
    ProverStep,
    UserInfoParams,
    VerifierResult,
    MAX_RECV_DATA,
    MAX_SENT_DATA,
};

/// Errors from MPC-TLS session driving.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The MPC-TLS protocol failed.
    #[error("MPC-TLS failed: {detail}")]
    MpcTlsFailed {
        /// Human-readable failure detail.
        detail: String,
    },
    /// The TLS session used a version the proof pipeline does not support.
    #[error("unsupported TLS version: {detail}")]
    UnsupportedTlsVersion {
        /// Human-readable failure detail.
        detail: String,
    },
    /// Socket I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Transcript parsing failed.
    #[error(transparent)]
    Transcript(#[from] libid_transcript::Error),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
