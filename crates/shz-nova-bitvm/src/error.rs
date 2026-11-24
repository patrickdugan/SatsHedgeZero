//! Error types and verification honesty flags for `shz-nova-bitvm`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Unified error type for `shz-nova-bitvm`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NovaBitvmError {
    #[error("statement error: {0}")]
    Statement(String),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("taproot derivation error: {0}")]
    Taproot(String),
    #[error("merkle/nullifier error: {0}")]
    Merkle(String),
    #[error("BIP-340 signature error: {0}")]
    Signature(String),
    #[error("Nova transcript/state error: {0}")]
    Nova(String),
    #[error("Secq BIP-340 claim error: {0}")]
    SecqClaim(String),
    #[error("BitVM3 settlement statement error: {0}")]
    BitVm3(String),
    #[error("SatsHedgeZero bridge error: {0}")]
    Bridge(String),
}

pub type Result<T> = std::result::Result<T, NovaBitvmError>;

/// Explicit verification boundary and honesty flags attached to all native outputs.
///
/// Native verification checks the full application statement, 600-byte Nova transcript tie-out,
/// Secq BIP-340 signature claim binding, and 304-byte BitVM3 settlement statement encoding.
/// It does NOT claim an out-of-process Nova SNARK proof or on-chain BitVM3 Groth16 dispute
/// verification has completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationHonestyFlags {
    pub native_statement_verified: bool,
    pub nova_snark_verified: bool,
    pub bitvm3_onchain_verified: bool,
    pub production_ready: bool,
}

impl VerificationHonestyFlags {
    /// Honest defaults for native Rust verification prior to external `lnm-nova verify`
    /// and on-chain BitVM3 settlement verification.
    pub const fn native_only() -> Self {
        Self {
            native_statement_verified: true,
            nova_snark_verified: false,
            bitvm3_onchain_verified: false,
            production_ready: false,
        }
    }

    ///Honest flags when an external `lnm-nova verify` process has cryptographically verified
    /// a `CompressedSNARK` (`nova-snark 0.76.0`) against independently supplied receiver pins.
    /// `bitvm3_onchain_verified` and `production_ready` remain `false`.
    pub const fn with_external_nova_snark_verified() -> Self {
        Self {
            native_statement_verified: true,
            nova_snark_verified: true,
            bitvm3_onchain_verified: false,
            production_ready: false,
        }
    }
}
