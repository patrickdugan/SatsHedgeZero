//! `shz-oracle` — Pluggable oracle feeds (`TradeLayer` L1 VWAP + `Pyth` et al. NEAR Borsh relay),
//! `t-of-n` FROST state oracle confederation, and NEAR-compatible bonded fraud proofs.

pub mod fraud_proofs;
pub mod frost;
pub mod pyth_near_relay;
pub mod tradelayer;

use shz_dlc::DlcError;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OracleError {
    #[error("DLC cryptographic error: {0}")]
    Dlc(#[from] DlcError),
    #[error("insufficient TradeLayer liquidity: got {fills} qualifying fills, need {required}")]
    InsufficientLiquidity { fills: usize, required: usize },
    #[error("insufficient oracle quorum: got {got}, required {required}")]
    InsufficientQuorum { got: usize, required: usize },
    #[error("untrusted or duplicate oracle feed signer")]
    UntrustedFeedSigner,
    #[error("stale oracle observation outside allowed window")]
    StaleObservation,
    #[error("feed confidence interval {conf_bps}bps exceeds max {max_bps}bps")]
    ConfidenceTooWide { conf_bps: u64, max_bps: u64 },
    #[error("invalid feed observation: {0}")]
    InvalidObservation(&'static str),
    #[error("invalid FROST signing set: {0}")]
    InvalidFrostSigningSet(&'static str),
    #[error("Byzantine partial signature detected from signer_id {signer_id}")]
    ByzantineFrostShare { signer_id: u16 },
    #[error("bonded oracle vault has already been slashed")]
    VaultAlreadySlashed,
    #[error("fraud proof rejected: {0}")]
    FraudProofRejected(&'static str),
}

#[cfg(test)]
mod tests {
    use super::{
        fraud_proofs::{
            CanonicalReferenceEvidence, DeviationFraudProof, EquivocationFraudProof,
            NearBondedOracleVault, VictimRestitutionClaim,
        },
        frost::FrostConfederation,
        pyth_near_relay::{
            PYTH_BTC_USD_FEED_ID, RelayProviderKind, RelayQuorumPolicy, SignedFeedObservation,
            assemble_near_relay_envelope,
        },
        tradelayer::{TradeLayerFill, TradeLayerVwapConfig, build_tradelayer_vwap_proof},
    };
    use shz_dlc::pubkey_x_from_secret;
    use shz_margin::InverseContractSpec;

    #[test]
    fn test_tradelayer_vwap_wash_filter_and_merkle_proofs() {
        let witness_1 = [0x21u8; 32];
        let witness_2 = [0x22u8; 32];
        let trusted = [
            pubkey_x_from_secret(&witness_1).unwrap(),
            pubkey_x_from_secret(&witness_2).unwrap(),
        ];

        let fills = vec![
            TradeLayerFill {
                txid: [1u8; 32],
                block_height: 880_001,
                property_pair: "TL-BTC/USD".into(),
                price_usd: 100_000,
                volume_sats: 2_000_000,
                maker_id: [0x01; 20],
                taker_id: [0x02; 20],
            },
            TradeLayerFill {
                txid: [2u8; 32],
                block_height: 880_002,
                property_pair: "TL-BTC/USD".into(),
                price_usd: 101_000,
                volume_sats: 6_000_000,
                maker_id: [0x03; 20],
                taker_id: [0x04; 20],
            },
            // Self-cross wash trade at fake $50,000 -> MUST be filtered out!
            TradeLayerFill {
                txid: [3u8; 32],
                block_height: 880_002,
                property_pair: "TL-BTC/USD".into(),
                price_usd: 50_000,
                volume_sats: 99_000_000,
                maker_id: [0x09; 20],
                taker_id: [0x09; 20],
            },
            // Manipulation spike at $250,000 -> filtered by median outlier circuit breaker!
            TradeLayerFill {
                txid: [4u8; 32],
                block_height: 880_003,
                property_pair: "TL-BTC/USD".into(),
                price_usd: 250_000,
                volume_sats: 500_000,
                maker_id: [0x05; 20],
                taker_id: [0x06; 20],
            },
            TradeLayerFill {
                txid: [5u8; 32],
                block_height: 880_003,
                property_pair: "TL-BTC/USD".into(),
                price_usd: 100_500,
                volume_sats: 2_000_000,
                maker_id: [0x07; 20],
                taker_id: [0x08; 20],
            },
        ];

        let cfg = TradeLayerVwapConfig::default();
        let (proof, merkle_proofs) = build_tradelayer_vwap_proof(
            "TL-BTC/USD",
            880_000,
            880_005,
            1_795_000_000,
            &fills,
            &cfg,
            &[witness_1, witness_2],
        )
        .unwrap();

        // Qualifying fills: 2M @ 100k + 6M @ 101k + 2M @ 100.5k = 1,007,000M / 10M = $100,700!
        assert_eq!(proof.qualifying_fill_count, 3);
        assert_eq!(proof.vwap_price_usd, 100_700);
        proof.verify_witness_quorum(&trusted, 2).unwrap();
        for mp in &merkle_proofs {
            assert!(mp.verify(&proof.fills_merkle_root));
        }
    }

    #[test]
    fn test_frost_3_of_5_equivocation_extracts_secret_key_and_slashes_bond() {
        let frost = FrostConfederation::keygen_deterministic(3, 5, &[0x42u8; 32]).unwrap();
        let nonce_state = frost
            .announce_event("BTC-USD-2026-11-23", 1_795_000_000, 20, &[0x77u8; 32])
            .unwrap();

        // Signer subset {1, 3, 5} signs bit 0 on digit 4, while subset {2, 3, 4} signs bit 1 on digit 4!
        let sig_zero = frost
            .threshold_sign_digit(&nonce_state, &[1, 3, 5], 4, 0)
            .unwrap();
        let sig_one = frost
            .threshold_sign_digit(&nonce_state, &[2, 3, 4], 4, 1)
            .unwrap();

        let mut vault = NearBondedOracleVault::new(
            frost.group_pubkey_x,
            10_000_000_000_000_000_000_000_000_000u128, // 10,000 NEAR
            50_000_000,                                 // 0.5 BTC slash bond
            150,
            120,
            1_000_000_000_000_000_000u128,
        );

        let eq_proof = EquivocationFraudProof {
            announcement: nonce_state.announcement.clone(),
            digit_idx: 4,
            sig_bit_zero: sig_zero,
            sig_bit_one: sig_one,
            challenger_near_account: "watchdog.near".into(),
        };

        // Verify Borsh round-trip compatibility on the fraud proof!
        let borsh_bytes = borsh::to_vec(&eq_proof).unwrap();
        let decoded: EquivocationFraudProof = borsh::from_slice(&borsh_bytes).unwrap();

        let verdict = vault.submit_equivocation_fraud_proof(&decoded).unwrap();
        assert!(vault.is_slashed);
        let extracted_sk = verdict.extracted_btc_slash_secret_key.unwrap();
        assert_eq!(pubkey_x_from_secret(&extracted_sk).unwrap(), frost.group_pubkey_x);
    }

    #[test]
    fn test_deviation_fraud_proof_pyth_and_tradelayer_slashes_cheating_frost() {
        let frost = FrostConfederation::keygen_deterministic(3, 5, &[0x55u8; 32]).unwrap();
        let maturity = 1_795_000_000u64;
        let nonce_state = frost
            .announce_event("BTC-USD-PERP-EPOCH-99", maturity, 20, &[0x88u8; 32])
            .unwrap();

        // Colluding 3-of-5 FROST signers {2, 4, 5} attest a manipulated crash price of $88,000
        // (without double-signing any nonce!) when real market price is $100,400!
        let dishonest_attestation = frost
            .threshold_attest_price(&nonce_state, &[2, 4, 5], maturity, 88_000)
            .unwrap();

        // Canonical Pyth + Switchboard relay observations at $100,400:
        let pyth_sk = [0x61u8; 32];
        let swb_sk = [0x62u8; 32];
        let guardians = vec![
            (RelayProviderKind::Pyth, pubkey_x_from_secret(&pyth_sk).unwrap()),
            (
                RelayProviderKind::Switchboard,
                pubkey_x_from_secret(&swb_sk).unwrap(),
            ),
        ];
        let obs_pyth = SignedFeedObservation::new_signed(
            RelayProviderKind::Pyth,
            PYTH_BTC_USD_FEED_ID,
            10_040_000_000_000, // $100,400 * 10^8
            2_500_000_000,      // $25 confidence (~2.5 bps)
            -8,
            10_038_000_000_000,
            maturity - 2,
            &pyth_sk,
        )
        .unwrap();
        let obs_swb = SignedFeedObservation::new_signed(
            RelayProviderKind::Switchboard,
            PYTH_BTC_USD_FEED_ID,
            10_042_000_000_000, // $100,420 * 10^8
            3_000_000_000,
            -8,
            10_040_000_000_000,
            maturity - 1,
            &swb_sk,
        )
        .unwrap();

        let policy = RelayQuorumPolicy::default();
        let relay_env = assemble_near_relay_envelope(
            "shz-oracle-guard.near",
            maturity,
            vec![obs_pyth, obs_swb],
            &guardians,
            &policy,
        )
        .unwrap();

        // Borsh wire round-trip check
        let env_bytes = relay_env.to_borsh_bytes();
        let relay_decoded =
            super::pyth_near_relay::NearRelayEnvelope::from_borsh_bytes(&env_bytes).unwrap();
        assert_eq!(relay_decoded.median_price_usd, 100_410);

        // Victim Long had $1,000 10x contract entered at $100,000 (wiped out by fake $88,000!).
        let victim_spec =
            InverseContractSpec::from_leverages_v0(1_000, 100_000, 100_000, 100_000).unwrap();

        let dev_proof = DeviationFraudProof {
            announcement: nonce_state.announcement.clone(),
            dishonest_attestation,
            reference_evidence: CanonicalReferenceEvidence::NearPythRelay(relay_decoded),
            challenger_near_account: "watcher.near".into(),
            victim_claim: Some(VictimRestitutionClaim {
                victim_near_account: "alice-trader.near".into(),
                victim_is_long: true,
                contract_spec: victim_spec,
            }),
        };

        let mut vault = NearBondedOracleVault::new(
            frost.group_pubkey_x,
            5_000_000_000_000_000_000_000_000_000u128, // 5,000 NEAR bond
            25_000_000,
            150, // 1.50% max deviation
            120,
            10_000_000_000_000_000_000u128, // 0.01 NEAR per satoshi
        );

        let verdict = vault
            .submit_deviation_fraud_proof(&dev_proof, &guardians, &policy, &[], 0)
            .unwrap();
        assert!(vault.is_slashed);
        assert!(verdict.deviation_bps > 1_200); // >12% manipulation caught
        assert_eq!(verdict.victim_shortfall_sats, 104_083); // 100k margin + 4,083 sats honest profit!
        assert!(verdict.victim_restitution_yocto_near > 0);
    }
}
