//! Length-prefixed JSON wire protocol for post-MPC-TLS communication.
//!
//! After the MPC-TLS session closes, the notary and prover recover the
//! underlying socket and keep talking over it. Each message is prefixed with
//! a 4-byte length (big-endian) followed by a JSON payload.

use serde::{
    de::DeserializeOwned,
    Serialize,
};
use tokio::io::{
    AsyncRead,
    AsyncReadExt,
    AsyncWrite,
    AsyncWriteExt,
};

use crate::{
    Error,
    Result,
};

/// Maximum allowed message size (10 MB).
const MAX_MSG_SIZE: usize = 10 * 1024 * 1024;

/// Write a message with length prefix.
///
/// The message is serialized as JSON, then prefixed with a 4-byte
/// big-endian length before being sent over the wire.
pub async fn write_msg<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = u32::try_from(json.len())
        .map_err(|_| Error::WireProtocol {
            detail: format!("message too large to encode: {} bytes", json.len()),
        })?
        .to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&json).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed message.
///
/// Reads a 4-byte big-endian length prefix, then reads that many
/// bytes and deserializes them as JSON.
pub async fn read_msg<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        return Err(Error::WireProtocol {
            detail: format!("message too large: {} bytes", len),
        });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Ping {
        seq: u32,
        payload: Vec<u8>,
        note: String,
    }

    #[tokio::test]
    async fn round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let msg = Ping {
            seq: 7,
            payload: vec![0, 1, 2, 255],
            note: "hello notary".into(),
        };
        write_msg(&mut a, &msg).await.unwrap();
        let got: Ping = read_msg(&mut b).await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn round_trip_sequence_preserves_framing() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        for seq in 0..3u32 {
            let msg = Ping {
                seq,
                payload: vec![seq as u8; seq as usize * 100],
                note: format!("msg {seq}"),
            };
            write_msg(&mut a, &msg).await.unwrap();
        }
        for seq in 0..3u32 {
            let got: Ping = read_msg(&mut b).await.unwrap();
            assert_eq!(got.seq, seq);
        }
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        // 11 MB claimed length — must be rejected before any allocation.
        a.write_all(&(11u32 * 1024 * 1024).to_be_bytes())
            .await
            .unwrap();
        let err = read_msg::<_, Ping>(&mut b).await.unwrap_err();
        assert!(matches!(err, Error::WireProtocol { .. }), "got: {err}");
    }

    #[tokio::test]
    async fn garbage_payload_is_a_json_error() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&4u32.to_be_bytes()).await.unwrap();
        a.write_all(b"\xff\xfe\x00\x01").await.unwrap();
        let err = read_msg::<_, Ping>(&mut b).await.unwrap_err();
        assert!(matches!(err, Error::Json(_)), "got: {err}");
    }
}
