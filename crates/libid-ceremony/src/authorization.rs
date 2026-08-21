//! The Authorization Digest of ceremony-common section 5.
//!
//! One value binds one authorization to the transaction that will consume it.
//! The Canonical Runtime builds it before the ceremony starts; the Proof
//! Verifier rebuilds it from the submission and its own observed chain id, and
//! the two must agree or nothing verifies.

use libid_crypto::keccak256;

/// Fixed-width part of the preimage: 32 + 2 + 32 + 32 + 4.
pub const PREIMAGE_FIXED_LEN: usize = 102;

/// The Authorized Transaction Data length is carried in four bytes, so this is
/// the longest payload the layout can describe.
pub const MAX_TRANSACTION_DATA_LEN: usize = u32::MAX as usize;

/// Everything the digest commits to.
///
/// `chain_id` is the keccak256 of whatever bytes a chain's own identifier
/// contributes, never the raw identifier: chains name themselves
/// incompatibly, and some too wide for 64 bits (REQ-COMMON-01C).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationPreimage {
    pub operation_domain: [u8; 32],
    pub platform_verifier_version: u16,
    pub chain_id: [u8; 32],
    pub authorization_nonce: [u8; 32],
    pub transaction_data: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error(
        "transaction data is {0} bytes, which does not fit the four-byte length field"
    )]
    TransactionDataTooLong(usize),
}

/// Derive an operation domain from its string.
///
/// The Consumer fixes one libID-namespaced ASCII string per transaction kind.
/// A new operation, or a change to one operation's transaction-data meaning,
/// takes a new string rather than another digest field (REQ-COMMON-01A).
pub fn operation_domain(domain_string: &str) -> [u8; 32] {
    keccak256(domain_string.as_bytes())
}

/// Derive a chain id from the exact bytes its Chain Profile fixes.
pub fn chain_id(identifier_bytes: &[u8]) -> [u8; 32] {
    keccak256(identifier_bytes)
}

impl AuthorizationPreimage {
    /// Serialize exactly the byte concatenation of section 5.
    ///
    /// Only the transaction data varies in length, so every other field sits
    /// at a fixed offset and no boundary can be shifted to reinterpret the
    /// preimage as a different authorization (REQ-COMMON-01).
    pub fn encode(&self) -> Result<Vec<u8>, AuthorizationError> {
        let len = self.transaction_data.len();
        if len > MAX_TRANSACTION_DATA_LEN {
            return Err(AuthorizationError::TransactionDataTooLong(len));
        }

        let mut out = Vec::with_capacity(PREIMAGE_FIXED_LEN + len);
        out.extend_from_slice(&self.operation_domain);
        out.extend_from_slice(&self.platform_verifier_version.to_be_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.authorization_nonce);
        out.extend_from_slice(&(len as u32).to_be_bytes());
        out.extend_from_slice(&self.transaction_data);
        Ok(out)
    }

    /// `keccak256` of the encoded preimage.
    pub fn digest(&self) -> Result<[u8; 32], AuthorizationError> {
        Ok(keccak256(&self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conformance vector of ceremony-common section 5, transcribed from
    /// the specification and reproduced independently with `cast keccak`.
    fn spec_vector() -> AuthorizationPreimage {
        AuthorizationPreimage {
            operation_domain: operation_domain("libid.claim-identity"),
            platform_verifier_version: 1,
            chain_id: chain_id(b"example:1"),
            authorization_nonce: [0x55; 32],
            transaction_data: vec![0x00, 0x01, 0x02, 0x03],
        }
    }

    #[test]
    fn derived_constants_match_the_specification() {
        assert_eq!(
            hex::encode(operation_domain("libid.claim-identity")),
            "cb29bed0428519ef88a3d670e8203db76e06f41aca3e684e2c63b516c9b93e1b"
        );
        assert_eq!(
            hex::encode(chain_id(b"example:1")),
            "38064d82f31db40935cc75f2a0d07dcfb448d7c08e7484fc30f5de95484a4066"
        );
    }

    #[test]
    fn preimage_matches_the_specification_vector() {
        let expected = "cb29bed0428519ef88a3d670e8203db76e06f41aca3e684e2c63b516c9b93e1b\
                        0001\
                        38064d82f31db40935cc75f2a0d07dcfb448d7c08e7484fc30f5de95484a4066\
                        5555555555555555555555555555555555555555555555555555555555555555\
                        00000004\
                        00010203";
        assert_eq!(hex::encode(spec_vector().encode().unwrap()), expected);
    }

    #[test]
    fn digest_matches_the_specification_vector() {
        assert_eq!(
            hex::encode(spec_vector().digest().unwrap()),
            "b318fb559e16a179b853ed2853576cda16032d93b0839bb81a55135d334c0af5"
        );
    }

    #[test]
    fn fixed_part_is_one_hundred_and_two_bytes() {
        let mut p = spec_vector();
        p.transaction_data.clear();
        assert_eq!(p.encode().unwrap().len(), PREIMAGE_FIXED_LEN);
    }

    #[test]
    fn every_field_changes_the_digest() {
        let base = spec_vector().digest().unwrap();

        let mut p = spec_vector();
        p.operation_domain[0] ^= 1;
        assert_ne!(p.digest().unwrap(), base, "operation domain does not bind");

        let mut p = spec_vector();
        p.platform_verifier_version = 2;
        assert_ne!(p.digest().unwrap(), base, "verifier version does not bind");

        let mut p = spec_vector();
        p.chain_id[31] ^= 1;
        assert_ne!(p.digest().unwrap(), base, "chain id does not bind");

        let mut p = spec_vector();
        p.authorization_nonce[0] ^= 1;
        assert_ne!(p.digest().unwrap(), base, "nonce does not bind");

        let mut p = spec_vector();
        p.transaction_data.push(0x04);
        assert_ne!(p.digest().unwrap(), base, "transaction data does not bind");
    }

    #[test]
    fn length_prefix_separates_a_shifted_boundary() {
        // Without the explicit length, transaction data whose leading bytes
        // could be read as part of the nonce would collide. The prefix is what
        // makes every boundary derivable.
        let mut a = spec_vector();
        a.transaction_data = vec![0x00, 0x01];
        let mut b = spec_vector();
        b.transaction_data = vec![0x00, 0x01, 0x00, 0x00];
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    }
}
