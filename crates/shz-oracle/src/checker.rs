//! Unified Multi-Source Oracle Checker System (`checker.rs`).
//!
//! Synthesizes:
//! 1. Native Pyth Pro (`pyth-lazer`) Ed25519 Solana envelope verification pinned against an
//!    independently supplied `trusted_registry_sha256` (refusing unpinned registries).
//! 2. Distinct secondary economic source verification: either a Merkle-verified `TradeLayerVwapProof`
//!    (wash-trade filtered BTC/USD or BTC/TL-USDC spot fills) OR a separately pinned Ed25519
//!    secondary report (e.g., Chainlink / Switchboard / TL-USDC index), strictly forbidding
//!    duplicate Pyth signers or domains from counting as a second source.
//! 3. Exact `SHZ-NOVA-G16-01` bounded dual-oracle integer relation (zero floating-point math):
//!    - `2 * index_e8 == primary_e8 + secondary_e8 + parity` (`parity in {0, 1}`)
//!    - `abs_diff = |primary_e8 - secondary_e8|`
//!    - `max_spread_bps * (primary_e8 + secondary_e8) - 20_000 * abs_diff == spread_slack >= 0`
//! 4. Replay-nullified monotonic epoch state (`OracleCheckerEngine`) and collision-safe `2 x 128-bit`
//!    big-endian public-input limb packing (avoiding 256-bit modulo reduction into BN254 `Fr`).

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    OracleError,
    pyth_lazer::{
        PinnedPythSignerRegistry, PythProBtcUsdPolicy, VerifiedPythProBtcUsdReceipt,
        verify_pyth_pro_btc_usd_solana_envelope,
    },
    tradelayer::TradeLayerVwapProof,
};

pub const DEFAULT_MAX_DUAL_SPREAD_BPS: u128 = 50;

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Splits a 32-byte SHA-256 digest into two unsigned big-endian 128-bit limbs so downstream
/// BN254 Groth16 / Pallas-Vesta Nova circuits never reduce 256-bit hashes modulo the scalar field.
pub fn split_digest_be_u128(digest: &[u8; 32]) -> [u128; 2] {
    let hi = u128::from_be_bytes(digest[..16].try_into().unwrap());
    let lo = u128::from_be_bytes(digest[16..].try_into().unwrap());
    [hi, lo]
}

/// Computes the canonical SHA-256 pin of a `PinnedPythSignerRegistry` (`Borsh` encoding).
pub fn compute_pyth_registry_sha256(registry: &PinnedPythSignerRegistry) -> [u8; 32] {
    let encoded = borsh::to_vec(registry).expect("Borsh serialize PinnedPythSignerRegistry");
    sha256_bytes(&encoded)
}

/// Separately pinned non-Pyth Ed25519 oracle report (e.g., Chainlink DON / Switchboard / TL-USDC spot).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SecondarySignedPriceReport {
    /// Must NOT start with `"pyth"` — enforces distinct economic source domain.
    pub source_id: String,
    pub event_id: String,
    pub publish_time_us: u64,
    pub price_e8: u64,
    pub signer_pubkey: [u8; 32],
    pub signature_bytes: Vec<u8>,
}

impl SecondarySignedPriceReport {
    pub fn signing_payload(
        source_id: &str,
        event_id: &str,
        publish_time_us: u64,
        price_e8: u64,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"SHZ/ORACLE-CHECKER/SECONDARY-REPORT/V1\0");
        h.update((source_id.len() as u32).to_le_bytes());
        h.update(source_id.as_bytes());
        h.update((event_id.len() as u32).to_le_bytes());
        h.update(event_id.as_bytes());
        h.update(publish_time_us.to_le_bytes());
        h.update(price_e8.to_le_bytes());
        h.finalize().into()
    }

    pub fn verify_against_allowlist(
        &self,
        expected_event_id: &str,
        allowlisted_signers: &[[u8; 32]],
        pyth_signer_pubkey: &[u8; 32],
        now_us: u64,
        max_age_us: u64,
    ) -> Result<[u8; 32], OracleError> {
        let lower = self.source_id.trim().to_ascii_lowercase();
        if lower.is_empty() || lower.contains("pyth") {
            return Err(OracleError::InvalidObservation(
                "secondary oracle source must be economically distinct from Pyth",
            ));
        }
        if self.event_id != expected_event_id || self.price_e8 == 0 {
            return Err(OracleError::InvalidObservation(
                "secondary report event_id mismatch or zero price",
            ));
        }
        if &self.signer_pubkey == pyth_signer_pubkey
            || !allowlisted_signers.contains(&self.signer_pubkey)
        {
            return Err(OracleError::UntrustedFeedSigner);
        }
        if self.publish_time_us > now_us || now_us - self.publish_time_us > max_age_us {
            return Err(OracleError::StaleObservation);
        }
        let sig_arr: [u8; 64] = self
            .signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| OracleError::InvalidObservation("secondary signature must be 64 bytes"))?;
        let vk = VerifyingKey::from_bytes(&self.signer_pubkey)
            .map_err(|_| OracleError::UntrustedFeedSigner)?;
        let digest = Self::signing_payload(
            &self.source_id,
            &self.event_id,
            self.publish_time_us,
            self.price_e8,
        );
        vk.verify(&digest, &Signature::from_bytes(&sig_arr))
            .map_err(|_| OracleError::UntrustedFeedSigner)?;
        Ok(digest)
    }
}

/// Secondary reference input paired with the primary Pyth Pro Solana envelope.
#[derive(Debug, Clone)]
pub enum SecondaryOracleInput<'a> {
    TradeLayerVwap {
        proof: &'a TradeLayerVwapProof,
        trusted_witness_pubkeys_x: &'a [[u8; 32]],
        min_witnesses: usize,
    },
    SignedSecondaryReport {
        report: &'a SecondarySignedPriceReport,
        allowlisted_signers: &'a [[u8; 32]],
        max_age_us: u64,
    },
}

/// Verified witness for the `SHZ-NOVA-G16-01` bounded dual-oracle midpoint relation:
/// `2 * index_e8 = pyth_price_e8 + secondary_price_e8 + parity_bit`
/// `max_spread_bps * (pyth_price_e8 + secondary_price_e8) - 20_000 * abs_diff_e8 = spread_slack`
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct DualOracleMidpointWitness {
    pub pyth_price_e8: u64,
    pub secondary_price_e8: u64,
    pub index_price_e8: u64,
    pub index_whole_usd: u64,
    pub abs_diff_e8: u64,
    pub parity_bit: u8,
    pub max_spread_bps: u64,
    pub observed_spread_bps: u64,
    pub spread_slack: u128,
}

impl DualOracleMidpointWitness {
    pub fn compute_and_verify(
        pyth_price_e8: u64,
        secondary_price_e8: u64,
        max_spread_bps: u64,
    ) -> Result<Self, OracleError> {
        if pyth_price_e8 == 0 || secondary_price_e8 == 0 || max_spread_bps == 0 {
            return Err(OracleError::InvalidObservation(
                "dual-oracle prices and max_spread_bps must be positive",
            ));
        }
        let a = pyth_price_e8 as u128;
        let b = secondary_price_e8 as u128;
        let sum = a + b;
        // Round-half-up midpoint: `index_e8 = (a + b + 1) / 2`, so `2 * index_e8 = a + b + parity_bit`!
        let parity_bit = (sum & 1) as u8;
        let index_e8 = ((sum + (parity_bit as u128)) / 2) as u64;
        debug_assert_eq!(2 * (index_e8 as u128), sum + (parity_bit as u128));

        let abs_diff = a.abs_diff(b);
        let lhs = (max_spread_bps as u128) * sum;
        let rhs = 20_000u128 * abs_diff;
        let observed_spread_bps = ((20_000u128 * abs_diff) / sum) as u64;
        if lhs < rhs {
            return Err(OracleError::ProviderDivergence {
                spread_bps: observed_spread_bps,
                max_bps: max_spread_bps,
            });
        }
        let spread_slack = lhs - rhs;
        // Enforce `< 2^96` range bound matching `SHZ-NOVA-G16-01` §4
        if spread_slack >= (1u128 << 96) {
            return Err(OracleError::InvalidObservation(
                "spread_slack exceeded 96-bit circuit bound",
            ));
        }

        let index_whole_usd = ((index_e8 as u128 + 50_000_000) / 100_000_000) as u64;
        Ok(Self {
            pyth_price_e8,
            secondary_price_e8,
            index_price_e8: index_e8,
            index_whole_usd,
            abs_diff_e8: abs_diff as u64,
            parity_bit,
            max_spread_bps,
            observed_spread_bps,
            spread_slack,
        })
    }
}

/// Complete, domain-separated verdict emitted by [`OracleCheckerEngine::verify_and_commit_epoch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCheckerVerdict {
    pub epoch_id: u64,
    pub event_id: String,
    pub primary_pyth_receipt: VerifiedPythProBtcUsdReceipt,
    pub secondary_source_kind: String,
    pub secondary_commitment_hash: [u8; 32],
    pub midpoint: DualOracleMidpointWitness,
    pub epoch_commitment_hash: [u8; 32],
    pub epoch_commitment_limbs_be_u128: [u128; 2],
    pub native_dual_source_verified: bool,
    pub near_groth16_onchain_verified: bool,
    pub near_finality_verified: bool,
    pub bitcoin_spend_enforced: bool,
}

/// Stateful, replay-protected Oracle Checker Engine pinning trusted source registries.
#[derive(Debug, Clone)]
pub struct OracleCheckerEngine {
    pub last_committed_epoch: u64,
    pub trusted_pyth_registry_sha256: [u8; 32],
    pub max_spread_bps: u64,
    pub consumed_event_ids: BTreeSet<String>,
    pub consumed_payload_hashes: BTreeSet<[u8; 32]>,
}

impl OracleCheckerEngine {
    pub fn new(trusted_pyth_registry_sha256: [u8; 32], max_spread_bps: u64) -> Self {
        Self {
            last_committed_epoch: 0,
            trusted_pyth_registry_sha256,
            max_spread_bps,
            consumed_event_ids: BTreeSet::new(),
            consumed_payload_hashes: BTreeSet::new(),
        }
    }

    pub fn update_trusted_pyth_registry(&mut self, registry: &PinnedPythSignerRegistry) {
        self.trusted_pyth_registry_sha256 = compute_pyth_registry_sha256(registry);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_commit_epoch(
        &mut self,
        epoch_id: u64,
        event_id: &str,
        pyth_solana_envelope: &[u8],
        pyth_registry: &PinnedPythSignerRegistry,
        pyth_policy: &PythProBtcUsdPolicy,
        secondary: SecondaryOracleInput<'_>,
        now_us: u64,
    ) -> Result<OracleCheckerVerdict, OracleError> {
        if epoch_id <= self.last_committed_epoch || event_id.trim().is_empty() {
            return Err(OracleError::InvalidObservation(
                "oracle checker requires strictly monotonic epoch_id and non-empty event_id",
            ));
        }
        if self.consumed_event_ids.contains(event_id) {
            return Err(OracleError::InvalidObservation(
                "event_id already consumed in oracle checker nullifier set",
            ));
        }

        // 1. Verify caller's Pyth signer registry matches the independently pinned SHA-256!
        let actual_reg_sha = compute_pyth_registry_sha256(pyth_registry);
        if actual_reg_sha != self.trusted_pyth_registry_sha256 {
            return Err(OracleError::UntrustedFeedSigner);
        }

        // 2. Re-verify raw Pyth Pro Ed25519 Solana envelope
        let pyth_receipt = verify_pyth_pro_btc_usd_solana_envelope(
            pyth_solana_envelope,
            pyth_registry,
            pyth_policy,
            now_us,
        )?;
        if self
            .consumed_payload_hashes
            .contains(&pyth_receipt.signed_payload_sha256)
        {
            return Err(OracleError::InvalidObservation(
                "replayed Pyth signed_payload_sha256 rejected by oracle checker",
            ));
        }
        let pyth_price_e8 = u64::try_from(pyth_receipt.raw_price_mantissa)
            .map_err(|_| OracleError::InvalidObservation("negative Pyth price mantissa"))?;
        let pyth_signer_pk: [u8; 32] = hex::decode(&pyth_receipt.signer_pubkey_hex)
            .map_err(|_| OracleError::UntrustedFeedSigner)?
            .try_into()
            .map_err(|_| OracleError::UntrustedFeedSigner)?;

        // 3. Verify distinct secondary source
        let (secondary_kind, secondary_price_e8, secondary_hash) = match secondary {
            SecondaryOracleInput::TradeLayerVwap {
                proof,
                trusted_witness_pubkeys_x,
                min_witnesses,
            } => {
                proof.verify_witness_quorum(trusted_witness_pubkeys_x, min_witnesses.max(1))?;
                let tl_e8 = proof
                    .vwap_price_usd
                    .checked_mul(100_000_000)
                    .ok_or(OracleError::InvalidObservation("TradeLayer e8 overflow"))?;
                (
                    format!("tradelayer-vwap:{}", proof.property_pair),
                    tl_e8,
                    proof.signing_digest(),
                )
            }
            SecondaryOracleInput::SignedSecondaryReport {
                report,
                allowlisted_signers,
                max_age_us,
            } => {
                let digest = report.verify_against_allowlist(
                    event_id,
                    allowlisted_signers,
                    &pyth_signer_pk,
                    now_us,
                    max_age_us,
                )?;
                (
                    format!("secondary-ed25519:{}", report.source_id),
                    report.price_e8,
                    digest,
                )
            }
        };

        // 4. Enforce `SHZ-NOVA-G16-01` bounded midpoint + spread_slack constraints
        let midpoint = DualOracleMidpointWitness::compute_and_verify(
            pyth_price_e8,
            secondary_price_e8,
            self.max_spread_bps,
        )?;

        let mut commit = Sha256::new();
        commit.update(b"SHZ/ORACLE-CHECKER/EPOCH-COMMITMENT/V1\0");
        commit.update(epoch_id.to_le_bytes());
        commit.update((event_id.len() as u32).to_le_bytes());
        commit.update(event_id.as_bytes());
        commit.update(self.trusted_pyth_registry_sha256);
        commit.update(pyth_receipt.receipt_hash);
        commit.update(secondary_hash);
        commit.update(midpoint.index_price_e8.to_le_bytes());
        commit.update([midpoint.parity_bit]);
        commit.update(midpoint.spread_slack.to_le_bytes());
        let epoch_commitment_hash: [u8; 32] = commit.finalize().into();

        // Commit nullifiers ONLY after all checks succeed!
        self.last_committed_epoch = epoch_id;
        self.consumed_event_ids.insert(event_id.to_owned());
        self.consumed_payload_hashes
            .insert(pyth_receipt.signed_payload_sha256);

        Ok(OracleCheckerVerdict {
            epoch_id,
            event_id: event_id.to_owned(),
            primary_pyth_receipt: pyth_receipt,
            secondary_source_kind: secondary_kind,
            secondary_commitment_hash: secondary_hash,
            midpoint,
            epoch_commitment_hash,
            epoch_commitment_limbs_be_u128: split_digest_be_u128(&epoch_commitment_hash),
            native_dual_source_verified: true,
            near_groth16_onchain_verified: false,
            near_finality_verified: false,
            bitcoin_spend_enforced: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::{
        pyth_lazer::{
            PYTH_PRO_BTC_USD_FEED_ID, PYTH_PRO_CHANNEL_FIXED_200MS,
            build_signed_pyth_pro_btc_usd_envelope,
        },
        tradelayer::{TradeLayerFill, TradeLayerVwapConfig, build_tradelayer_vwap_proof},
    };

    #[test]
    fn test_oracle_checker_verifies_pyth_plus_tradelayer_and_rejects_duplicate_pyth_or_wide_spread() {
        let pyth_sk = [0x51u8; 32];
        let (pyth_env, pyth_pk) = build_signed_pyth_pro_btc_usd_envelope(
            &pyth_sk,
            1_795_800_000_000_000,
            1_795_800_000_000_000,
            PYTH_PRO_CHANNEL_FIXED_200MS,
            PYTH_PRO_BTC_USD_FEED_ID,
            12_000_000_000_000, // $120,000.00000000
            -8,
            1_000_000_000,
        );
        let reg = PinnedPythSignerRegistry::new_static(vec![pyth_pk]).unwrap();
        let reg_sha = compute_pyth_registry_sha256(&reg);

        let fills = vec![
            TradeLayerFill {
                txid: [0x01; 32],
                block_height: 890_500,
                property_pair: "TL-BTC/USDC".into(),
                price_usd: 120_100,
                volume_sats: 10_000_000,
                maker_id: [1; 20],
                taker_id: [2; 20],
            },
            TradeLayerFill {
                txid: [0x02; 32],
                block_height: 890_501,
                property_pair: "TL-BTC/USDC".into(),
                price_usd: 120_300,
                volume_sats: 10_000_000,
                maker_id: [3; 20],
                taker_id: [4; 20],
            },
        ];
        let tl_cfg = TradeLayerVwapConfig::default();
        let w1 = [0x61; 32];
        let w2 = [0x62; 32];
        let tl_pubkeys = [
            shz_dlc::pubkey_x_from_secret(&w1).unwrap(),
            shz_dlc::pubkey_x_from_secret(&w2).unwrap(),
        ];
        let (tl_proof, _) = build_tradelayer_vwap_proof(
            "TL-BTC/USDC",
            890_500,
            890_505,
            1_795_800_000,
            &fills,
            &tl_cfg,
            &[w1, w2],
        )
        .unwrap();

        let mut checker = OracleCheckerEngine::new(reg_sha, DEFAULT_MAX_DUAL_SPREAD_BPS as u64);
        let verdict = checker
            .verify_and_commit_epoch(
                1,
                "SHZ/BTCUSD/EPOCH-1",
                &pyth_env,
                &reg,
                &PythProBtcUsdPolicy::default(),
                SecondaryOracleInput::TradeLayerVwap {
                    proof: &tl_proof,
                    trusted_witness_pubkeys_x: &tl_pubkeys,
                    min_witnesses: 2,
                },
                1_795_800_001_000_000,
            )
            .unwrap();

        // Midpoint of $120,000 and $120,200 is exact $120,100 (`spread = 16 bps <= 50 bps`)!
        assert_eq!(verdict.midpoint.index_whole_usd, 120_100);
        assert_eq!(verdict.midpoint.parity_bit, 0);
        assert_eq!(verdict.midpoint.observed_spread_bps, 16);
        assert!(verdict.native_dual_source_verified);
        assert!(!verdict.near_groth16_onchain_verified);

        // Replay of the same event_id or payload hash is immediately rejected!
        assert!(
            checker
                .verify_and_commit_epoch(
                    2,
                    "SHZ/BTCUSD/EPOCH-1",
                    &pyth_env,
                    &reg,
                    &PythProBtcUsdPolicy::default(),
                    SecondaryOracleInput::TradeLayerVwap {
                        proof: &tl_proof,
                        trusted_witness_pubkeys_x: &tl_pubkeys,
                        min_witnesses: 2,
                    },
                    1_795_800_001_000_000,
                )
                .is_err()
        );

        // Attempting to pass a duplicate Pyth relay (`source_id = "pyth-mirror"`) as secondary fails closed!
        let (pyth_env2, _) = build_signed_pyth_pro_btc_usd_envelope(
            &pyth_sk,
            1_795_800_002_000_000,
            1_795_800_002_000_000,
            PYTH_PRO_CHANNEL_FIXED_200MS,
            PYTH_PRO_BTC_USD_FEED_ID,
            12_000_000_000_000,
            -8,
            1_000_000_000,
        );
        let cl_sk = SigningKey::from_bytes(&[0x77; 32]);
        let cl_pk = cl_sk.verifying_key().to_bytes();
        let bad_digest = SecondarySignedPriceReport::signing_payload(
            "pyth-mirror",
            "SHZ/BTCUSD/EPOCH-2",
            1_795_800_002_000_000,
            12_005_000_000_000,
        );
        let dup_pyth_report = SecondarySignedPriceReport {
            source_id: "pyth-mirror".into(),
            event_id: "SHZ/BTCUSD/EPOCH-2".into(),
            publish_time_us: 1_795_800_002_000_000,
            price_e8: 12_005_000_000_000,
            signer_pubkey: cl_pk,
            signature_bytes: cl_sk.sign(&bad_digest).to_bytes().to_vec(),
        };
        assert!(
            checker
                .verify_and_commit_epoch(
                    2,
                    "SHZ/BTCUSD/EPOCH-2",
                    &pyth_env2,
                    &reg,
                    &PythProBtcUsdPolicy::default(),
                    SecondaryOracleInput::SignedSecondaryReport {
                        report: &dup_pyth_report,
                        allowlisted_signers: &[cl_pk],
                        max_age_us: 5_000_000,
                    },
                    1_795_800_003_000_000,
                )
                .is_err()
        );

        // Divergent secondary report (> 50 bps spread: $122,000 vs $120,000 = 165 bps) fails closed!
        let wide_digest = SecondarySignedPriceReport::signing_payload(
            "chainlink-btc-usd",
            "SHZ/BTCUSD/EPOCH-2",
            1_795_800_002_000_000,
            12_200_000_000_000,
        );
        let wide_report = SecondarySignedPriceReport {
            source_id: "chainlink-btc-usd".into(),
            event_id: "SHZ/BTCUSD/EPOCH-2".into(),
            publish_time_us: 1_795_800_002_000_000,
            price_e8: 12_200_000_000_000,
            signer_pubkey: cl_pk,
            signature_bytes: cl_sk.sign(&wide_digest).to_bytes().to_vec(),
        };
        assert!(matches!(
            checker
                .verify_and_commit_epoch(
                    2,
                    "SHZ/BTCUSD/EPOCH-2",
                    &pyth_env2,
                    &reg,
                    &PythProBtcUsdPolicy::default(),
                    SecondaryOracleInput::SignedSecondaryReport {
                        report: &wide_report,
                        allowlisted_signers: &[cl_pk],
                        max_age_us: 5_000_000,
                    },
                    1_795_800_003_000_000,
                )
                .unwrap_err(),
            OracleError::ProviderDivergence { .. }
        ));
    }
}
