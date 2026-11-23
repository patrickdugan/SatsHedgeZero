//! `shz-margin` — Inverse BTC/USD contract payoff engine, zero-fee invariant,
//! collateral asset abstraction (`VanillaBtc` active in v0 + `TaprootAsset` hook),
//! and adaptive dyadic prefix CET range compression.

pub mod derivatives;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use derivatives::{
    DerivativeContractSpec, InverseOptionSpec, OptionKind, SwapTenor,
    compress_derivative_cet_ranges,
};

pub const SATS_PER_BTC: u128 = 100_000_000;
pub const BPS_DENOMINATOR: u128 = 10_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MarginError {
    #[error("zero-fee protocol invariant violated: maker={maker_bps}bps, taker={taker_bps}bps, settlement={settlement_bps}bps")]
    NonZeroFeeForbidden {
        maker_bps: u16,
        taker_bps: u16,
        settlement_bps: u16,
    },
    #[error("TAP collateral ({asset_id_hex}) is reserved for v1; v0 settles strictly in vanilla BTC UTXOs")]
    TapAssetDisabledInV0 { asset_id_hex: String },
    #[error("invalid contract parameter: {0}")]
    InvalidParameter(&'static str),
    #[error("price bit-width {0} must be in 4..=30")]
    InvalidBitWidth(u8),
}

/// Collateral asset backing the DLC funding UTXO / Lightning subchannel.
///
/// v0 enforces `VanillaBtc` at funding time while preserving deterministic
/// commitment hooks for Taproot Assets (`TAP`) in v1.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum CollateralAsset {
    /// Native Bitcoin UTXO satoshis (`P2TR` 2-of-2 funding output).
    VanillaBtc,
    /// Taproot Assets (`TAP`) UTXO hook for future multi-asset collateralization.
    TaprootAsset {
        asset_id: [u8; 32],
        group_key: Option<[u8; 32]>,
        script_version: u8,
    },
}

impl CollateralAsset {
    pub fn is_v0_supported(&self) -> bool {
        matches!(self, Self::VanillaBtc)
    }

    pub fn validate_v0_funding(&self) -> Result<(), MarginError> {
        match self {
            Self::VanillaBtc => Ok(()),
            Self::TaprootAsset { asset_id, .. } => Err(MarginError::TapAssetDisabledInV0 {
                asset_id_hex: hex::encode(asset_id),
            }),
        }
    }

    /// Computes a domain-separated Taproot Asset commitment leaf digest for future
    /// inclusion in P2TR funding taptrees (`None` for vanilla key-spend/DLC BTC).
    pub fn tap_commitment_leaf_hash(&self, amount_units: u64) -> Option<[u8; 32]> {
        match self {
            Self::VanillaBtc => None,
            Self::TaprootAsset {
                asset_id,
                group_key,
                script_version,
            } => {
                let mut hasher = Sha256::new();
                hasher.update(b"SatsHedgeZero/TapAssetCommitment/v0");
                hasher.update([*script_version]);
                hasher.update(asset_id);
                match group_key {
                    Some(gk) => {
                        hasher.update([1u8]);
                        hasher.update(gk);
                    }
                    None => hasher.update([0u8]),
                }
                hasher.update(amount_units.to_le_bytes());
                Some(hasher.finalize().into())
            }
        }
    }
}

/// Protocol fee schedule. `SatsHedgeZero` enforces strict 0-fee execution across
/// maker, taker, rollover, and settlement paths.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ZeroFeePolicy {
    pub maker_fee_bps: u16,
    pub taker_fee_bps: u16,
    pub settlement_fee_bps: u16,
}

impl ZeroFeePolicy {
    pub const ZERO: Self = Self {
        maker_fee_bps: 0,
        taker_fee_bps: 0,
        settlement_fee_bps: 0,
    };

    pub fn validate(&self) -> Result<(), MarginError> {
        if self.maker_fee_bps != 0 || self.taker_fee_bps != 0 || self.settlement_fee_bps != 0 {
            return Err(MarginError::NonZeroFeeForbidden {
                maker_bps: self.maker_fee_bps,
                taker_bps: self.taker_fee_bps,
                settlement_bps: self.settlement_fee_bps,
            });
        }
        Ok(())
    }
}

/// Exact satoshi conservation split at a given settlement price.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct PayoutSplit {
    pub long_sats: u64,
    pub short_sats: u64,
    pub protocol_fee_sats: u64,
}

impl PayoutSplit {
    pub fn total_sats(&self) -> u64 {
        self.long_sats + self.short_sats + self.protocol_fee_sats
    }
}

/// Inverse-quoted BTC/USD contract specification (XBTUSD / LN Markets style).
///
/// Notional is denominated in integer USD (`$1` per contract), while margin, PnL,
/// and payouts are settled strictly in satoshis (`CollateralAsset::VanillaBtc` in v0).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct InverseContractSpec {
    /// Contract quantity in USD (e.g. `1_000` = $1,000 USD notional).
    pub usd_notional: u64,
    /// Entry BTC/USD price in integer USD (e.g. `100_000` = $100,000/BTC).
    pub entry_price_usd: u64,
    /// Long initial margin locked in satoshis.
    pub long_margin_sats: u64,
    /// Short initial margin locked in satoshis.
    pub short_margin_sats: u64,
    /// Backing collateral descriptor (`VanillaBtc` for v0).
    pub collateral: CollateralAsset,
    /// Enforced 0-fee schedule.
    pub fee_policy: ZeroFeePolicy,
}

impl InverseContractSpec {
    /// Computes required margin in satoshis (rounded up) for a given USD notional,
    /// entry BTC/USD price, and leverage in basis points (`10_000` = 1.0x, `100_000` = 10.0x).
    pub fn margin_for_leverage_bps(
        usd_notional: u64,
        entry_price_usd: u64,
        leverage_bps: u32,
    ) -> Result<u64, MarginError> {
        if usd_notional == 0 {
            return Err(MarginError::InvalidParameter("usd_notional must be > 0"));
        }
        if entry_price_usd == 0 {
            return Err(MarginError::InvalidParameter("entry_price_usd must be > 0"));
        }
        if leverage_bps == 0 {
            return Err(MarginError::InvalidParameter("leverage_bps must be > 0"));
        }
        let num = (usd_notional as u128) * SATS_PER_BTC * BPS_DENOMINATOR;
        let den = (entry_price_usd as u128) * (leverage_bps as u128);
        let margin = num.div_ceil(den);
        u64::try_from(margin).map_err(|_| MarginError::InvalidParameter("margin overflow"))
    }

    /// Constructs a validated v0 vanilla-BTC inverse contract from Long and Short leverage (in bps).
    pub fn from_leverages_v0(
        usd_notional: u64,
        entry_price_usd: u64,
        long_leverage_bps: u32,
        short_leverage_bps: u32,
    ) -> Result<Self, MarginError> {
        let long_margin_sats =
            Self::margin_for_leverage_bps(usd_notional, entry_price_usd, long_leverage_bps)?;
        let short_margin_sats =
            Self::margin_for_leverage_bps(usd_notional, entry_price_usd, short_leverage_bps)?;
        let spec = Self {
            usd_notional,
            entry_price_usd,
            long_margin_sats,
            short_margin_sats,
            collateral: CollateralAsset::VanillaBtc,
            fee_policy: ZeroFeePolicy::ZERO,
        };
        spec.validate_v0()?;
        Ok(spec)
    }

    /// Validates all parameters and v0 invariants (`VanillaBtc` + `0 fee`).
    pub fn validate_v0(&self) -> Result<(), MarginError> {
        self.fee_policy.validate()?;
        self.collateral.validate_v0_funding()?;
        if self.usd_notional == 0 {
            return Err(MarginError::InvalidParameter("usd_notional must be > 0"));
        }
        if self.entry_price_usd == 0 {
            return Err(MarginError::InvalidParameter("entry_price_usd must be > 0"));
        }
        if self.long_margin_sats == 0 || self.short_margin_sats == 0 {
            return Err(MarginError::InvalidParameter(
                "long_margin_sats and short_margin_sats must be > 0",
            ));
        }
        self.long_margin_sats
            .checked_add(self.short_margin_sats)
            .ok_or(MarginError::InvalidParameter("total collateral overflow"))?;
        Ok(())
    }

    pub fn total_collateral_sats(&self) -> u64 {
        self.long_margin_sats + self.short_margin_sats
    }

    /// Returns `true` when the Short side has posted >= 1.0x BTC value (`Q * 1e8 / P0`),
    /// creating a synthetic-USD hedge that cannot be liquidated at any upside BTC price.
    pub fn is_covered_synthetic_usd_short(&self) -> bool {
        let covered_lhs = (self.short_margin_sats as u128) * (self.entry_price_usd as u128);
        let covered_rhs = (self.usd_notional as u128) * SATS_PER_BTC;
        covered_lhs >= covered_rhs
    }

    /// Unclamped inverse PnL for Long in satoshis at `settlement_price_usd > 0`:
    ///
    /// `PnL_long = round_half_even(Q_usd * 1e8 * (P_T - P_0) / (P_0 * P_T))`
    pub fn unclamped_long_pnl_sats(&self, settlement_price_usd: u64) -> i128 {
        if settlement_price_usd == 0 {
            return -(self.total_collateral_sats() as i128);
        }
        let q_sats_num = (self.usd_notional as u128) * SATS_PER_BTC;
        let p0 = self.entry_price_usd as u128;
        let pt = settlement_price_usd as u128;
        let den = p0 * pt;

        if pt >= p0 {
            let diff = pt - p0;
            round_div_nearest_u128(q_sats_num * diff, den) as i128
        } else {
            let diff = p0 - pt;
            -(round_div_nearest_u128(q_sats_num * diff, den) as i128)
        }
    }

    /// Computes exact clamped DLC payouts `(long_sats, short_sats, 0)` at `settlement_price_usd`.
    /// Strictly preserves `long_sats + short_sats == total_collateral_sats`.
    pub fn payout_at_price(&self, settlement_price_usd: u64) -> PayoutSplit {
        let total = self.total_collateral_sats();
        if settlement_price_usd == 0 {
            return PayoutSplit {
                long_sats: 0,
                short_sats: total,
                protocol_fee_sats: 0,
            };
        }
        let raw_long = (self.long_margin_sats as i128) + self.unclamped_long_pnl_sats(settlement_price_usd);
        let long_sats = raw_long.clamp(0, total as i128) as u64;
        let short_sats = total - long_sats;
        PayoutSplit {
            long_sats,
            short_sats,
            protocol_fee_sats: 0,
        }
    }

    /// Highest integer USD price at or below which Long margin reaches 0 sats:
    /// `P_liq_long = floor(P_0 * Q * 1e8 / (Q * 1e8 + M_long * P_0))`
    pub fn long_liquidation_price_usd(&self) -> u64 {
        let q_sats = (self.usd_notional as u128) * SATS_PER_BTC;
        let p0 = self.entry_price_usd as u128;
        let num = p0 * q_sats;
        let den = q_sats + (self.long_margin_sats as u128) * p0;
        (num / den) as u64
    }

    /// Lowest integer USD price at or above which Short margin reaches 0 sats.
    /// Returns `None` if Short is <= 1.0x leveraged (covered synthetic-USD SatsHedge).
    pub fn short_liquidation_price_usd(&self) -> Option<u64> {
        if self.is_covered_synthetic_usd_short() {
            return None;
        }
        let q_sats = (self.usd_notional as u128) * SATS_PER_BTC;
        let p0 = self.entry_price_usd as u128;
        let m_short_p0 = (self.short_margin_sats as u128) * p0;
        let num = p0 * q_sats;
        let den = q_sats - m_short_p0;
        Some(num.div_ceil(den) as u64)
    }
}

pub(crate) fn round_div_nearest_u128(num: u128, den: u128) -> u128 {
    let q = num / den;
    let r = num % den;
    let twice_r = r.saturating_mul(2);
    if twice_r > den || (twice_r == den && (q & 1) == 1) {
        q + 1
    } else {
        q
    }
}

/// A single compressed CET interval identified by a binary prefix of oracle price digits.
///
/// Every outcome price `P` whose top `prefix_bits.len()` binary digits match `prefix_bits`
/// settles using this single pre-signed Contract Execution Transaction.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct CompressedCetRange {
    /// MSB-first binary digits (`0` or `1`) of length `<= num_bits`.
    pub prefix_bits: Vec<u8>,
    /// Inclusive minimum USD price covered by this dyadic prefix.
    pub min_price_usd: u64,
    /// Inclusive maximum USD price covered by this dyadic prefix.
    pub max_price_usd: u64,
    /// Deterministic payout split assigned to this CET.
    pub payout: PayoutSplit,
}

impl CompressedCetRange {
    /// Checks whether `price_usd` (decomposed into `num_bits` MSB-first binary digits)
    /// matches this CET's prefix.
    pub fn matches_price(&self, price_usd: u64, num_bits: u8) -> bool {
        let clamped = price_usd.min((1u64 << num_bits) - 1);
        clamped >= self.min_price_usd && clamped <= self.max_price_usd
    }
}

/// Compresses the `[0, 2^num_bits - 1]` integer USD price domain into an exact,
/// disjoint, complete binary prefix code of CETs whose payout deviation from the exact
/// inverse payoff never exceeds `max_payout_error_sats`.
///
/// Exploits monotonicity of `payout_at_price(P).long_sats`: on any dyadic interval `[L, R]`,
/// the maximum Long payout variation is `f(R) - f(L)` in `O(1)` evaluations.
pub fn compress_cet_ranges(
    spec: &InverseContractSpec,
    num_bits: u8,
    max_payout_error_sats: u64,
) -> Result<Vec<CompressedCetRange>, MarginError> {
    if !(4..=30).contains(&num_bits) {
        return Err(MarginError::InvalidBitWidth(num_bits));
    }
    let mut out = Vec::new();
    let mut prefix_buf = Vec::with_capacity(num_bits as usize);
    let max_domain_price = (1u64 << num_bits) - 1;
    compress_dyadic_node(
        spec,
        num_bits,
        max_payout_error_sats,
        0,
        max_domain_price,
        &mut prefix_buf,
        &mut out,
    );
    Ok(out)
}

fn compress_dyadic_node(
    spec: &InverseContractSpec,
    num_bits: u8,
    max_error_sats: u64,
    min_price: u64,
    max_price: u64,
    prefix: &mut Vec<u8>,
    out: &mut Vec<CompressedCetRange>,
) {
    let low_split = spec.payout_at_price(min_price);
    let high_split = spec.payout_at_price(max_price);
    let spread = high_split.long_sats.saturating_sub(low_split.long_sats);

    // Since representative midpoint payout sits halfway between low_split and high_split,
    // worst-case error on [min_price, max_price] is ceil(spread / 2).
    // Always split the root (depth 0) so every compressed CET binds at least one oracle digit.
    if !prefix.is_empty()
        && (min_price == max_price
            || prefix.len() == num_bits as usize
            || spread.div_ceil(2) <= max_error_sats)
    {
        let total = spec.total_collateral_sats();
        let rep_long = ((low_split.long_sats as u128 + high_split.long_sats as u128) / 2) as u64;
        let payout = PayoutSplit {
            long_sats: rep_long,
            short_sats: total - rep_long,
            protocol_fee_sats: 0,
        };
        out.push(CompressedCetRange {
            prefix_bits: prefix.clone(),
            min_price_usd: min_price,
            max_price_usd: max_price,
            payout,
        });
        return;
    }

    let mid = min_price + ((max_price - min_price) >> 1);
    prefix.push(0);
    compress_dyadic_node(spec, num_bits, max_error_sats, min_price, mid, prefix, out);
    prefix.pop();

    prefix.push(1);
    compress_dyadic_node(
        spec,
        num_bits,
        max_error_sats,
        mid + 1,
        max_price,
        prefix,
        out,
    );
    prefix.pop();
}

/// Decomposes `price_usd` (clamped to `2^num_bits - 1`) into `num_bits` MSB-first binary digits (`0` or `1`).
pub fn decompose_price_bits(price_usd: u64, num_bits: u8) -> Vec<u8> {
    let max_val = (1u64 << num_bits) - 1;
    let clamped = price_usd.min(max_val);
    (0..num_bits)
        .rev()
        .map(|shift| ((clamped >> shift) & 1) as u8)
        .collect()
}

/// Finds the unique compressed CET matching `price_usd`.
pub fn lookup_cet_for_price(
    cets: &[CompressedCetRange],
    price_usd: u64,
    num_bits: u8,
) -> Option<&CompressedCetRange> {
    let max_val = (1u64 << num_bits) - 1;
    let clamped = price_usd.min(max_val);
    let idx = cets
        .binary_search_by(|cet| {
            if clamped < cet.min_price_usd {
                std::cmp::Ordering::Greater
            } else if clamped > cet.max_price_usd {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()?;
    Some(&cets[idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_covered_1x_short_synthetic_usd_never_liquidates() {
        // $1,000 notional at $100,000 BTC/USD:
        // Long: 5x leverage (200,000 sats), Short: 1x covered SatsHedge (1,000,000 sats = 0.01 BTC).
        let spec = InverseContractSpec::from_leverages_v0(1_000, 100_000, 50_000, 10_000).unwrap();
        assert_eq!(spec.long_margin_sats, 200_000);
        assert_eq!(spec.short_margin_sats, 1_000_000);
        assert!(spec.is_covered_synthetic_usd_short());
        assert_eq!(spec.short_liquidation_price_usd(), None);
        assert_eq!(spec.long_liquidation_price_usd(), 83_333);

        // If BTC doubles to $200,000: Short keeps 500,000 sats = 0.005 BTC * $200,000 = $1,000 USD!
        let p_double = spec.payout_at_price(200_000);
        assert_eq!(p_double.short_sats, 500_000);
        assert_eq!(p_double.long_sats, 700_000);
        assert_eq!(p_double.protocol_fee_sats, 0);
        assert_eq!(p_double.total_sats(), 1_200_000);

        // Even if BTC goes to $10,000,000: Short still holds 10,000 sats = 0.0001 BTC * $10M = $1,000 USD!
        let p_10m = spec.payout_at_price(10_000_000);
        assert_eq!(p_10m.short_sats, 10_000);
        assert_eq!(p_10m.long_sats, 1_190_000);
    }

    #[test]
    fn test_leveraged_long_and_short_liquidation_and_zero_fee_conservation() {
        // $1,000 notional at $100,000, 10x Long (100k sats) vs 10x Short (100k sats).
        let spec = InverseContractSpec::from_leverages_v0(1_000, 100_000, 100_000, 100_000).unwrap();
        assert_eq!(spec.long_liquidation_price_usd(), 90_909);
        assert_eq!(spec.short_liquidation_price_usd(), Some(111_112));

        for price in [0, 1, 50_000, 90_909, 95_000, 100_000, 105_000, 111_112, 250_000] {
            let split = spec.payout_at_price(price);
            assert_eq!(split.protocol_fee_sats, 0);
            assert_eq!(split.total_sats(), 200_000);
        }
        assert_eq!(spec.payout_at_price(90_909).long_sats, 0);
        assert_eq!(spec.payout_at_price(111_112).short_sats, 0);
    }

    #[test]
    fn test_non_zero_fee_and_tap_v0_guards() {
        let mut spec =
            InverseContractSpec::from_leverages_v0(1_000, 100_000, 100_000, 100_000).unwrap();
        spec.fee_policy.taker_fee_bps = 1;
        assert!(matches!(
            spec.validate_v0(),
            Err(MarginError::NonZeroFeeForbidden { .. })
        ));

        spec.fee_policy = ZeroFeePolicy::ZERO;
        let tap = CollateralAsset::TaprootAsset {
            asset_id: [0xAB; 32],
            group_key: None,
            script_version: 0,
        };
        assert!(tap.tap_commitment_leaf_hash(1_000_000).is_some());
        spec.collateral = tap;
        assert!(matches!(
            spec.validate_v0(),
            Err(MarginError::TapAssetDisabledInV0 { .. })
        ));
    }

    #[test]
    fn test_dyadic_cet_compression_completeness_and_error_bound() {
        // 20-bit domain ($0 .. $1,048,575 = 1,048,576 outcomes!) compressed with <= 250 sats error.
        let spec = InverseContractSpec::from_leverages_v0(1_000, 100_000, 100_000, 100_000).unwrap();
        let cets = compress_cet_ranges(&spec, 20, 250).unwrap();

        // Massive compression: 1,048,576 discrete prices -> 643 dyadic prefix CETs (99.94% reduction)!
        assert_eq!(cets.len(), 643);
        assert_eq!(cets.first().unwrap().min_price_usd, 0);
        assert_eq!(cets.last().unwrap().max_price_usd, (1 << 20) - 1);

        // Verify contiguous, disjoint partition across the entire 20-bit space.
        for window in cets.windows(2) {
            assert_eq!(window[0].max_price_usd + 1, window[1].min_price_usd);
        }

        // Verify error bound and binary prefix matching at sampled prices across the whole domain.
        for sample_price in (0..=(1u64 << 20) - 1).step_by(997) {
            let cet = lookup_cet_for_price(&cets, sample_price, 20).unwrap();
            let bits = decompose_price_bits(sample_price, 20);
            assert_eq!(&bits[..cet.prefix_bits.len()], cet.prefix_bits.as_slice());

            let exact = spec.payout_at_price(sample_price);
            let err = cet.payout.long_sats.abs_diff(exact.long_sats);
            assert!(err <= 250, "price {sample_price}: err {err} > 250");
            assert_eq!(cet.payout.total_sats(), spec.total_collateral_sats());
        }
    }
}
