//! Signing backends for libID services.
//!
//! Backends, notaries and deploy tooling sign one of two ways:
//!
//!   * a raw hex private key — for anvil and local rehearsal, where the key is
//!     a well-known test key and secrecy is irrelevant;
//!   * an AWS KMS secp256k1 key — the production path. The private material is
//!     generated inside KMS and cannot be exported, so services call
//!     `kms:Sign` and get a signature back. There is no key in a secret store
//!     to leak, and revoking access is an IAM change rather than a key
//!     rotation.
//!
//! WHY THE ADDRESS IS DISCOVERED, NOT CONFIGURED: a KMS key is identified by an
//! ARN or alias; its Ethereum address is the keccak of the public key, which
//! KMS only reveals via `GetPublicKey`. `AwsSigner::new` performs that call, so
//! constructing the signer is async and can fail on permissions. That is a
//! feature — it fails at startup with a clear AWS error instead of at the first
//! transaction with an opaque one.
//!
//! EIP-2 LOW-S: AWS returns DER-encoded ECDSA signatures and, unlike GCP, does
//! not normalise `s` to the lower half of the curve order. Ethereum rejects
//! high-s signatures as malleable. `AwsSigner` handles the DER decode and the
//! low-s flip; do not reimplement it.

use alloy::{
    network::EthereumWallet,
    primitives::{
        Address,
        FixedBytes,
    },
    signers::{
        aws::AwsSigner,
        local::PrivateKeySigner,
        // Brings `address()` and `set_chain_id()` into scope for both signer
        // types; neither is an inherent method.
        Signer,
    },
};

/// Errors from signer configuration and construction.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// A key spec was malformed or ambiguous.
    #[error("signer configuration: {detail}")]
    SignerConfig {
        /// Human-readable failure detail.
        detail: String,
    },
    /// Building or using a signer failed — a malformed local key, or KMS
    /// refusing GetPublicKey/Sign (usually a missing IAM grant).
    #[error("{op}: {detail}")]
    SignerBuild {
        /// The operation that failed.
        op: String,
        /// Human-readable failure detail.
        detail: String,
    },
}

/// Result alias for signer construction.
pub type Result<T> = std::result::Result<T, SignerError>;

/// Where a signing key lives.
#[derive(Debug, Clone)]
pub enum SignerSource {
    /// Hex-encoded secp256k1 private key, with or without a `0x` prefix.
    PrivateKey(String),
    /// An AWS KMS key id, alias (`alias/testnet-notary`) or full ARN.
    /// Region and credentials come from the ambient AWS config chain
    /// (AWS_REGION, profile, IRSA/IMDS) — there is nothing to configure here.
    Kms(String),
}

impl SignerSource {
    /// Classifies a key spec by SHAPE — no prefixes, no configuration.
    ///
    /// The two forms are structurally disjoint, so nothing else is needed:
    /// a secp256k1 private key is exactly 64 hex chars (optionally `0x`-
    /// prefixed), while every KMS identifier contains a non-hex character —
    /// key ids are UUIDs (dashes), alias names start `alias/`, ARNs have
    /// colons. Anything that parses as a key is a key; anything else is
    /// handed to KMS.
    ///
    /// The one dangerous middle case is handled explicitly: an ALL-HEX value
    /// of the wrong length is a mangled private key (truncated paste, missing
    /// byte), not a KMS id. Treating it as one would ship the mistake to AWS
    /// and come back as a confusing NotFoundException — so it is rejected
    /// here, by name.
    ///
    /// Use this everywhere a key is configured, so "switch a component to
    /// KMS" is a config edit, not a code change.
    pub fn from_spec(spec: &str) -> Result<Self> {
        let entry = spec.trim();
        if entry.is_empty() {
            return Err(SignerError::SignerConfig {
                detail: "empty signing key spec".into(),
            });
        }
        let hexish = entry.strip_prefix("0x").unwrap_or(entry);
        if hexish.chars().all(|c| c.is_ascii_hexdigit()) {
            if hexish.len() == 64 {
                return Ok(Self::PrivateKey(entry.to_string()));
            }
            return Err(SignerError::SignerConfig {
                detail: format!(
                    "'{}…' looks like a hex private key but has {} hex chars, \
                     expected 64 — refusing to treat it as a KMS key id",
                    &entry[..entry.len().min(8)],
                    hexish.len()
                ),
            });
        }
        Ok(Self::Kms(entry.to_string()))
    }

    /// Parses a comma-separated list of specs:
    ///
    /// ```text
    /// alias/testnet-wallet-0,alias/testnet-wallet-1
    /// ```
    ///
    /// Each entry goes through [`Self::from_spec`]; the only logic on top is
    /// the duplicate guard, which is domain-specific and no library provides:
    /// two pool slots sharing one key share a nonce sequence, silently
    /// reintroducing the contention a wallet pool exists to remove —
    /// surfacing as sporadic "nonce too low" under load rather than a config
    /// error.
    pub fn parse_list(spec: &str) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for raw in spec.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                continue;
            }
            if !seen.insert(entry.to_string()) {
                return Err(SignerError::SignerConfig {
                    detail: format!(
                        "duplicate pool signer '{entry}' — each slot needs its own key"
                    ),
                });
            }
            out.push(Self::from_spec(entry)?);
        }
        if out.is_empty() {
            return Err(SignerError::SignerConfig {
                detail: "signer list is set but names no signers".into(),
            });
        }
        Ok(out)
    }

    /// A description safe to log. Never contains key material.
    pub fn describe(&self) -> String {
        match self {
            Self::PrivateKey(_) => "local private key".into(),
            Self::Kms(key_id) => format!("AWS KMS {key_id}"),
        }
    }

    /// Builds a wallet and reports the address it signs as.
    ///
    /// `chain_id` is stamped into the signer for EIP-155 replay protection.
    pub async fn build_wallet(
        &self,
        chain_id: Option<u64>,
    ) -> Result<(EthereumWallet, Address)> {
        let managed = self.build_managed(chain_id).await?;
        let address = managed.address();
        Ok((managed.into_wallet(), address))
    }

    /// Builds a [`ManagedSigner`] — the full-capability handle. Prefer this
    /// over `build_wallet` anywhere a component needs to sign digests as well
    /// as transactions.
    pub async fn build_managed(&self, chain_id: Option<u64>) -> Result<ManagedSigner> {
        match self {
            Self::PrivateKey(hex_key) => {
                let raw = hex_key.strip_prefix("0x").unwrap_or(hex_key);
                let bytes = hex::decode(raw).map_err(|e| SignerError::SignerBuild {
                    op: "decode signing key".into(),
                    detail: format!("{e}"),
                })?;
                // from_slice panics on a length mismatch, so check first and
                // return a readable error instead of aborting the process.
                if bytes.len() != 32 {
                    return Err(SignerError::SignerBuild {
                        op: "decode signing key".into(),
                        detail: format!("expected 32 bytes, got {}", bytes.len()),
                    });
                }
                let sk: FixedBytes<32> = FixedBytes::from_slice(&bytes);
                let mut signer = PrivateKeySigner::from_bytes(&sk).map_err(|e| {
                    SignerError::SignerBuild {
                        op: "create signer".into(),
                        detail: format!("{e}"),
                    }
                })?;
                if let Some(id) = chain_id {
                    signer.set_chain_id(Some(id));
                }
                Ok(ManagedSigner::Local(signer))
            }
            Self::Kms(key_id) => {
                // `from_env()` is deprecated; `defaults()` requires an explicit
                // behaviour version so an SDK upgrade cannot silently change
                // retry/timeout semantics underneath a deploy. Region comes
                // from the ambient chain (AWS_REGION, profile, IRSA/IMDS).
                let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .load()
                    .await;
                let client = aws_sdk_kms::Client::new(&cfg);

                // Fetch the public key ourselves before handing the client to
                // AwsSigner: a notary serves its uncompressed public key over
                // /info, and AwsSigner does not expose it. A DER-encoded
                // secp256k1 SubjectPublicKeyInfo always ends with the 65-byte
                // uncompressed point (0x04 || X || Y).
                let der = client
                    .get_public_key()
                    .key_id(key_id.clone())
                    .send()
                    .await
                    .map_err(|e| SignerError::SignerBuild {
                        op: format!("kms:GetPublicKey for {key_id}"),
                        detail: format!("{e}"),
                    })?
                    .public_key
                    .ok_or_else(|| SignerError::SignerBuild {
                        op: format!("kms:GetPublicKey for {key_id}"),
                        detail: "response carried no public key".into(),
                    })?;
                let der = der.as_ref();
                if der.len() < 65 || der[der.len() - 65] != 0x04 {
                    return Err(SignerError::SignerBuild {
                        op: format!("parse public key for {key_id}"),
                        detail: format!(
                            "expected DER ending in a 65-byte uncompressed point, got {} bytes",
                            der.len()
                        ),
                    });
                }
                let mut public_key = [0u8; 65];
                public_key.copy_from_slice(&der[der.len() - 65..]);

                // Performs its own GetPublicKey to derive the address; this is
                // where a missing kms:Sign/GetPublicKey grant surfaces, at
                // startup rather than on the first transaction.
                let signer = AwsSigner::new(client, key_id.clone(), chain_id)
                    .await
                    .map_err(|e| SignerError::SignerBuild {
                        op: format!("create KMS signer for {key_id}"),
                        detail: format!("{e}"),
                    })?;
                Ok(ManagedSigner::Kms {
                    signer: Box::new(signer),
                    public_key,
                })
            }
        }
    }
}

/// A signing identity that works the same whether the key is a local hex key
/// or lives in AWS KMS.
///
/// This is THE abstraction backends, sponsors and notaries share. It exists
/// because those components need more than transaction signing:
///
///   * `sign_claim`  — EIP-191 over a 32-byte digest, the format the on-chain
///     backend-signature and notary-attestation verifiers recover;
///   * `wallet`      — transaction signing (alloy `EthereumWallet`);
///   * `public_key`  — a notary serves its uncompressed key over `/info`;
///   * `raw_key_bytes` — ONLY available for local keys. tlsn's
///     `CryptoProvider::set_secp256k1eth` ingests raw key material, so
///     attestation paths that sign through tlsn cannot use KMS until tlsn
///     accepts a signer trait. Everything else works with either backend.
#[derive(Debug, Clone)]
pub enum ManagedSigner {
    /// In-process key. Anvil, tests, local rehearsal — and tlsn-signing
    /// notaries, until tlsn can sign through a trait.
    Local(PrivateKeySigner),
    /// AWS KMS key. The private material never exists outside the HSM; every
    /// signature is a `kms:Sign` round-trip (~20–50 ms).
    Kms {
        /// Boxed: `AwsSigner` is large, and clippy's `large_enum_variant` is
        /// right that an unboxed variant would bloat every `Local` too.
        signer: Box<AwsSigner>,
        /// Uncompressed SEC1 point (0x04 || X || Y), captured at construction.
        public_key: [u8; 65],
    },
}

impl ManagedSigner {
    /// The Ethereum address this signer signs as.
    pub fn address(&self) -> Address {
        match self {
            Self::Local(s) => s.address(),
            Self::Kms { signer, .. } => signer.address(),
        }
    }

    /// EIP-191 signature over a 32-byte digest: 65 bytes `r || s || v`,
    /// `v ∈ {27, 28}`, low-s.
    ///
    /// Byte-compatible with `libid_crypto::sign_eth_claim` — on-chain
    /// verifiers cannot tell which produced a signature. There is a test
    /// pinning that equivalence.
    pub async fn sign_claim(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        // `sign_message` applies the "\x19Ethereum Signed Message:\n32" prefix;
        // alloy's `Signature::as_bytes` emits v as 27/28 and both signer
        // implementations normalise to low-s (for KMS this matters: AWS does
        // NOT normalise server-side, alloy does it client-side).
        let sig = match self {
            Self::Local(s) => s.sign_message(digest).await,
            Self::Kms { signer, .. } => signer.sign_message(digest).await,
        }
        .map_err(|e| SignerError::SignerBuild {
            op: "sign claim digest".into(),
            detail: format!("{e}"),
        })?;
        Ok(sig.as_bytes().to_vec())
    }

    /// Recoverable signature over an ALREADY-HASHED 32-byte digest: 65 bytes
    /// `r || s || v`, `v ∈ {27, 28}`, low-s. No EIP-191 prefix is applied —
    /// the caller chose the hash.
    ///
    /// This is the tlsn attestation format (`Secp256k1EthSigner`): tlsn
    /// keccaks the attestation body itself and signs the bare digest, unlike
    /// the claim path above.
    pub async fn sign_prehash(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let hash = alloy::primitives::B256::from(*digest);
        let sig = match self {
            Self::Local(s) => s.sign_hash(&hash).await,
            Self::Kms { signer, .. } => signer.sign_hash(&hash).await,
        }
        .map_err(|e| SignerError::SignerBuild {
            op: "sign prehashed digest".into(),
            detail: format!("{e}"),
        })?;
        Ok(sig.as_bytes().to_vec())
    }

    /// A transaction-signing wallet for this identity.
    pub fn wallet(&self) -> EthereumWallet {
        match self {
            Self::Local(s) => EthereumWallet::from(s.clone()),
            Self::Kms { signer, .. } => EthereumWallet::from((**signer).clone()),
        }
    }

    /// Consumes self into a wallet (avoids one clone on the deploy path).
    pub fn into_wallet(self) -> EthereumWallet {
        match self {
            Self::Local(s) => EthereumWallet::from(s),
            Self::Kms { signer, .. } => EthereumWallet::from(*signer),
        }
    }

    /// Uncompressed SEC1 public key (0x04 || X || Y).
    pub fn uncompressed_public_key(&self) -> [u8; 65] {
        match self {
            Self::Local(s) => {
                let point = s.credential().verifying_key().to_encoded_point(false);
                let mut out = [0u8; 65];
                out.copy_from_slice(point.as_bytes());
                out
            }
            Self::Kms { public_key, .. } => *public_key,
        }
    }

    /// Compressed SEC1 public key (33 bytes), the format k256's
    /// `to_sec1_bytes` emits — kept so a notary's `/info` output is
    /// byte-identical across a local→KMS migration.
    pub fn compressed_public_key(&self) -> [u8; 33] {
        let full = self.uncompressed_public_key();
        let mut out = [0u8; 33];
        // Prefix encodes Y's parity; X is bytes 1..33 of the uncompressed form.
        out[0] = 0x02 | (full[64] & 1);
        out[1..].copy_from_slice(&full[1..33]);
        out
    }

    /// Raw private-key bytes — local keys only.
    ///
    /// Exists solely for tlsn's `CryptoProvider::set_secp256k1eth`, which
    /// ingests key material rather than accepting a signer. Returns `None` for
    /// KMS on purpose: callers must fail with a clear message instead of
    /// pretending the export is possible.
    pub fn raw_key_bytes(&self) -> Option<[u8; 32]> {
        match self {
            Self::Local(s) => Some(s.credential().to_bytes().into()),
            Self::Kms { .. } => None,
        }
    }

    /// Safe-to-log description.
    pub fn describe(&self) -> String {
        match self {
            Self::Local(_) => "local private key".into(),
            Self::Kms { signer, .. } => format!("AWS KMS ({:#x})", signer.address()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical anvil account #0 key, used across the local rehearsal
    // scripts. Public test material, not a secret.
    const ANVIL_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn spec_detects_by_shape() {
        // 64 hex chars (with or without 0x) is a private key…
        assert!(matches!(SignerSource::from_spec(ANVIL_KEY).unwrap(),
            SignerSource::PrivateKey(k) if k == ANVIL_KEY));
        assert!(matches!(
            SignerSource::from_spec(&format!("0x{ANVIL_KEY}")).unwrap(),
            SignerSource::PrivateKey(_)
        ));
        // …and every real KMS identifier contains a non-hex character.
        for id in [
            "alias/testnet-deployer",
            "bfa1bb3b-53a5-491b-a825-32998fd43a3d",
            "arn:aws:kms:eu-central-1:000000000000:key/abc",
        ] {
            assert!(
                matches!(SignerSource::from_spec(id).unwrap(),
                SignerSource::Kms(k) if k == id),
                "{id}"
            );
        }
    }

    #[test]
    fn wrong_length_hex_is_rejected_not_sent_to_kms() {
        // A truncated paste of a private key must fail HERE with a message
        // naming the problem, not travel to AWS as a bogus key id.
        let err = SignerSource::from_spec("0xdeadbeef").unwrap_err();
        assert!(format!("{err}").contains("expected 64"), "got: {err}");
        assert!(SignerSource::from_spec("").is_err());
    }

    #[test]
    fn list_rejects_duplicates_and_empty() {
        let err =
            SignerSource::parse_list(&format!("{ANVIL_KEY},{ANVIL_KEY}")).unwrap_err();
        assert!(format!("{err}").contains("duplicate"), "got: {err}");
        assert!(SignerSource::parse_list(" , ,").is_err());
        assert_eq!(
            SignerSource::parse_list(&format!("{ANVIL_KEY},alias/x"))
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn private_key_derives_expected_address() {
        let src = SignerSource::from_spec(ANVIL_KEY).unwrap();
        let (_, addr) = src.build_wallet(Some(31337)).await.unwrap();
        assert_eq!(addr.to_string().to_lowercase(), ANVIL_ADDR.to_lowercase());
    }

    #[tokio::test]
    async fn private_key_accepts_0x_prefix() {
        let src = SignerSource::from_spec(&format!("0x{ANVIL_KEY}")).unwrap();
        let (_, addr) = src.build_wallet(Some(31337)).await.unwrap();
        assert_eq!(addr.to_string().to_lowercase(), ANVIL_ADDR.to_lowercase());
    }

    #[test]
    fn describe_never_leaks_key_material() {
        let src = SignerSource::PrivateKey(ANVIL_KEY.into());
        assert!(!src.describe().contains(ANVIL_KEY));
    }

    /// Pins ManagedSigner::sign_claim to the exact bytes
    /// `libid_crypto::sign_eth_claim` produces. Every on-chain verifier
    /// recovers signatures in this format; if the two paths ever diverge —
    /// v encoding, s normalisation, prefix — proofs signed after a KMS
    /// migration would be rejected on-chain with no useful error. This test
    /// is the tripwire.
    #[tokio::test]
    async fn managed_signer_matches_sign_eth_claim() {
        let sk = libid_crypto::hex_to_signing_key(ANVIL_KEY).unwrap();
        let managed = ManagedSigner::Local(PrivateKeySigner::from(sk.clone()));

        for digest in [[0u8; 32], [0xAB; 32], {
            let mut d = [0u8; 32];
            d[31] = 1;
            d
        }] {
            let legacy = libid_crypto::sign_eth_claim(&sk, &digest).unwrap();
            let via_managed = managed.sign_claim(&digest).await.unwrap();
            assert_eq!(legacy, via_managed, "digest {digest:02x?}");
            assert_eq!(via_managed.len(), 65);
            assert!(matches!(via_managed[64], 27 | 28));
        }
    }

    /// Public key accessors agree with libid-crypto's derivations, and the
    /// compressed form matches k256's `to_sec1_bytes` byte-for-byte.
    #[test]
    fn public_key_accessors_match_k256() {
        let sk = libid_crypto::hex_to_signing_key(ANVIL_KEY).unwrap();
        let managed = ManagedSigner::Local(PrivateKeySigner::from(sk.clone()));

        assert_eq!(
            hex::encode(managed.compressed_public_key()),
            libid_crypto::pubkey_to_hex(sk.verifying_key()),
        );
        assert_eq!(
            managed.address().into_array(),
            libid_crypto::pubkey_to_eth_address(sk.verifying_key()),
        );
        assert_eq!(managed.raw_key_bytes(), Some(sk.to_bytes().into()));
    }
}
