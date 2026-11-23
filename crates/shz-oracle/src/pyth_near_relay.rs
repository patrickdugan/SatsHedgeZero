//! Multi-provider price relay (`Pyth`, `Switchboard`, `RedStone`, `Chronicle`)
//! producing canonical Borsh-encoded `NearRelayEnvelope` payloads compatible with
//! NEAR smart contracts and Chain Signatures fraud-proof verifiers.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use shz_dlc::{Bip340Signature, bip340_sign, bip340_verify, pubkey_x_from_secret, tagged_hash};

use crate::OracleError;

/// Canonical Pyth BTC/USD feed identifier (`e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43`).
pub const PYTH_BTC_USD_FEED_ID: [u8; 32] = [
    0xe6, 0x2d, 0xf6, 0xc8, 0xb4, 0xa8, 0x5f, 0xe1, 0xa6, 0x7d, 0xb4, 0x4d, 0xc1, 0x2d, 0xe5, 0xdb,
    0x33, 0x0f, 0x7a, 0xc6, 0x6b, 0x72, 0xdc, 0x65, 0x8a, 0xfe, 0xdf, 0x0f, 0x4a, 0x41, 0x5b, 0x43,
];

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum RelayProviderKind {
    Pyth,
    Switchboard,
    RedStone,
    Chronicle,
}

/// Signed Pyth-compatible price observation (`price * 10^expo` USD, `conf * 10^expo` confidence).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SignedFeedObservation {
    pub provider: RelayProviderKind,
    pub feed_id: [u8; 32],
    pub raw_price: i64,
    pub conf: u64,
    pub expo: i32,
    pub ema_price: i64,
    pub publish_time_unix: u64,
    pub signer_pubkey_x: [u8; 32],
    pub signature: Bip340Signature,
}

impl SignedFeedObservation {
    pub fn signing_digest_fields(
        provider: RelayProviderKind,
        feed_id: &[u8; 32],
        raw_price: i64,
        conf: u64,
        expo: i32,
        ema_price: i64,
        publish_time_unix: u64,
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(72);
        buf.push(provider as u8);
        buf.extend_from_slice(feed_id);
        buf.extend_from_slice(&raw_price.to_le_bytes());
        buf.extend_from_slice(&conf.to_le_bytes());
        buf.extend_from_slice(&expo.to_le_bytes());
        buf.extend_from_slice(&ema_price.to_le_bytes());
        buf.extend_from_slice(&publish_time_unix.to_le_bytes());
        tagged_hash(b"SatsHedgeZero/PythNearRelayObs/v0", &buf)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_signed(
        provider: RelayProviderKind,
        feed_id: [u8; 32],
        raw_price: i64,
        conf: u64,
        expo: i32,
        ema_price: i64,
        publish_time_unix: u64,
        signer_secret: &[u8; 32],
    ) -> Result<Self, OracleError> {
        let signer_pubkey_x = pubkey_x_from_secret(signer_secret)?;
        let digest = Self::signing_digest_fields(
            provider,
            &feed_id,
            raw_price,
            conf,
            expo,
            ema_price,
            publish_time_unix,
        );
        let signature = bip340_sign(signer_secret, &digest)?;
        Ok(Self {
            provider,
            feed_id,
            raw_price,
            conf,
            expo,
            ema_price,
            publish_time_unix,
            signer_pubkey_x,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<(), OracleError> {
        let digest = Self::signing_digest_fields(
            self.provider,
            &self.feed_id,
            self.raw_price,
            self.conf,
            self.expo,
            self.ema_price,
            self.publish_time_unix,
        );
        bip340_verify(&self.signer_pubkey_x, &digest, &self.signature)?;
        Ok(())
    }

    /// Normalizes `(raw_price, conf, expo)` into `(price_usd, conf_bps)`.
    pub fn normalized_usd_and_conf_bps(&self) -> Result<(u64, u64), OracleError> {
        if self.raw_price <= 0 {
            return Err(OracleError::InvalidObservation("non-positive price"));
        }
        let raw_u = self.raw_price as u128;
        let price_usd = if self.expo >= 0 {
            let scale = 10u128
                .checked_pow(self.expo as u32)
                .ok_or(OracleError::InvalidObservation("exponent overflow"))?;
            raw_u.saturating_mul(scale)
        } else {
            let scale = 10u128
                .checked_pow((-self.expo) as u32)
                .ok_or(OracleError::InvalidObservation("exponent overflow"))?;
            (raw_u + (scale / 2)) / scale
        };
        if price_usd == 0 || price_usd > u64::MAX as u128 {
            return Err(OracleError::InvalidObservation("normalized USD out of range"));
        }
        let conf_bps = ((self.conf as u128) * 10_000).div_ceil(raw_u) as u64;
        Ok((price_usd as u64, conf_bps))
    }
}

/// Policy governing multi-oracle relay aggregation (`Pyth` + secondary providers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayQuorumPolicy {
    pub min_distinct_providers: usize,
    pub require_pyth_primary: bool,
    pub max_conf_bps: u64,
    pub max_staleness_secs: u64,
}

impl Default for RelayQuorumPolicy {
    fn default() -> Self {
        Self {
            min_distinct_providers: 2,
            require_pyth_primary: true,
            max_conf_bps: 100, // 1.00% max confidence interval width
            max_staleness_secs: 60,
        }
    }
}

/// Borsh-encoded NEAR-compatible multi-oracle relay envelope (`Pyth` + secondary feeds).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct NearRelayEnvelope {
    pub borsh_schema_version: u8,
    pub near_verifier_contract: String,
    pub reference_timestamp_unix: u64,
    pub median_price_usd: u64,
    pub aggregate_conf_bps: u64,
    pub observations: Vec<SignedFeedObservation>,
}

impl NearRelayEnvelope {
    /// Serializes to canonical NEAR Borsh wire bytes.
    pub fn to_borsh_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("NearRelayEnvelope Borsh encoding infallible")
    }

    /// Deserializes from canonical NEAR Borsh wire bytes.
    pub fn from_borsh_bytes(bytes: &[u8]) -> Result<Self, OracleError> {
        borsh::from_slice(bytes)
            .map_err(|_| OracleError::InvalidObservation("Borsh deserialization failed"))
    }

    /// Cryptographically verifies all constituent feed observations against `trusted_guardians`
    /// and re-verifies the quorum median calculation.
    pub fn verify(
        &self,
        trusted_guardians: &[(RelayProviderKind, [u8; 32])],
        policy: &RelayQuorumPolicy,
    ) -> Result<(u64, u64), OracleError> {
        if self.borsh_schema_version != 1 {
            return Err(OracleError::InvalidObservation("unsupported Borsh schema"));
        }
        let mut distinct_providers = Vec::new();
        let mut saw_pyth = false;
        let mut seen_signers = Vec::new();
        let mut valid_prices: Vec<(u64, u64)> = Vec::with_capacity(self.observations.len());

        for obs in &self.observations {
            if !trusted_guardians.contains(&(obs.provider, obs.signer_pubkey_x))
                || seen_signers.contains(&obs.signer_pubkey_x)
            {
                return Err(OracleError::UntrustedFeedSigner);
            }
            if obs.publish_time_unix.abs_diff(self.reference_timestamp_unix)
                > policy.max_staleness_secs
            {
                return Err(OracleError::StaleObservation);
            }
            obs.verify_signature()?;
            let (price_usd, conf_bps) = obs.normalized_usd_and_conf_bps()?;
            if conf_bps > policy.max_conf_bps {
                return Err(OracleError::ConfidenceTooWide {
                    conf_bps,
                    max_bps: policy.max_conf_bps,
                });
            }
            if obs.provider == RelayProviderKind::Pyth {
                saw_pyth = true;
            }
            if !distinct_providers.contains(&obs.provider) {
                distinct_providers.push(obs.provider);
            }
            seen_signers.push(obs.signer_pubkey_x);
            valid_prices.push((price_usd, conf_bps));
        }

        if policy.require_pyth_primary && !saw_pyth {
            return Err(OracleError::InvalidObservation(
                "missing required Pyth primary observation",
            ));
        }
        if distinct_providers.len() < policy.min_distinct_providers {
            return Err(OracleError::InsufficientQuorum {
                got: distinct_providers.len(),
                required: policy.min_distinct_providers,
            });
        }

        valid_prices.sort_by_key(|&(p, _)| p);
        let mid = valid_prices.len() / 2;
        let expected_median = if valid_prices.len() % 2 == 1 {
            valid_prices[mid].0
        } else {
            ((valid_prices[mid - 1].0 as u128 + valid_prices[mid].0 as u128) / 2) as u64
        };
        let max_conf = valid_prices.iter().map(|&(_, c)| c).max().unwrap_or(0);

        if expected_median != self.median_price_usd || max_conf != self.aggregate_conf_bps {
            return Err(OracleError::InvalidObservation(
                "envelope median/conf mismatch",
            ));
        }
        Ok((expected_median, max_conf))
    }
}

/// Aggregates verified multi-provider feeds (`Pyth` + secondary feeds) into a `NearRelayEnvelope`.
pub fn assemble_near_relay_envelope(
    near_verifier_contract: &str,
    reference_timestamp_unix: u64,
    observations: Vec<SignedFeedObservation>,
    trusted_guardians: &[(RelayProviderKind, [u8; 32])],
    policy: &RelayQuorumPolicy,
) -> Result<NearRelayEnvelope, OracleError> {
    let mut prices = Vec::with_capacity(observations.len());
    for obs in &observations {
        let (p, c) = obs.normalized_usd_and_conf_bps()?;
        prices.push((p, c));
    }
    if prices.is_empty() {
        return Err(OracleError::InsufficientQuorum {
            got: 0,
            required: policy.min_distinct_providers,
        });
    }
    prices.sort_by_key(|&(p, _)| p);
    let mid = prices.len() / 2;
    let median_price_usd = if prices.len() % 2 == 1 {
        prices[mid].0
    } else {
        ((prices[mid - 1].0 as u128 + prices[mid].0 as u128) / 2) as u64
    };
    let aggregate_conf_bps = prices.iter().map(|&(_, c)| c).max().unwrap_or(0);

    let env = NearRelayEnvelope {
        borsh_schema_version: 1,
        near_verifier_contract: near_verifier_contract.to_string(),
        reference_timestamp_unix,
        median_price_usd,
        aggregate_conf_bps,
        observations,
    };
    env.verify(trusted_guardians, policy)?;
    Ok(env)
}
