//! The tlsn-free half of the libID MPC-TLS toolkit.
//!
//! Everything in this crate operates on plain bytes and sockets — no
//! TLSNotary types appear in the public API, which is what lets it publish to
//! crates.io while the `tlsn` dependency itself is git-only. The session
//! driver that produces these transcripts lives in `libid-tlsn`.
//!
//! * [`ranges`] — HTTP/JSON byte-range math for selective disclosure: locate
//!   headers, response bodies (chunked or not), and JSON field/snippet ranges
//!   in a raw TLS transcript, and map them back to absolute transcript
//!   offsets that become Merkle leaves.
//! * [`wire`] — the length-prefixed JSON protocol the notary and prover speak
//!   over the recovered socket after MPC-TLS closes.
//! * [`types`] — [`TlsHandshakeData`],
//!   the notary's output as consumed by backends and on-chain verifiers.

pub mod ceremony;
pub mod ranges;
pub mod types;
pub mod wire;

pub use ranges::{
    compute_field_reveal_range,
    compute_field_snippet_range,
    compute_id_snippet_range,
    compute_id_snippet_range_after,
    extract_header,
    extract_response_body,
    find_header_range,
    find_json_bare_snippet_range,
    find_json_field_range,
    find_json_snippet_range,
    find_notary_reveal_ranges,
    find_presentation_commit_ranges,
    find_request_line_range,
    find_response_body_range,
};
pub use types::TlsHandshakeData;
pub use wire::{
    read_msg,
    write_msg,
};

/// Errors from transcript parsing and the wire protocol.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Socket I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// A wire-protocol invariant was violated.
    #[error("wire protocol: {detail}")]
    WireProtocol {
        /// Human-readable failure detail.
        detail: String,
    },
    /// The transcript did not contain what was expected.
    #[error("transcript: {detail}")]
    Transcript {
        /// Human-readable failure detail.
        detail: String,
    },
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
