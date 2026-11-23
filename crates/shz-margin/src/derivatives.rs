//! Unified Inverse Swap & European Option Payoff + CET Compression Engine (`derivatives.rs`).
//!
//! Establishes exact integer-satoshi settlement math (`0` maker/taker/protocol fee) for both
//! Deribit/LN-Markets-style BTC-collateralized instrument classes in `SatsHedgeZero`:
//!
//! 1. **Inverse Swaps (`SwapTenor::PerpetualSubchannel` | `SwapTenor::Dated { expiry_timestamp }`)**:
//!    - USD-quoted notional `Q_usd` at entry `P_0`; Long posts `long_margin_sats`, Short posts
//!      `short_margin_sats` (where `1.0x` Short is a liquidation-immune synthetic-USD `SatsHedge`).
//!    - Exact PnL: `round_half_even(Q_usd * 1e8 * (P_T - P_0) / (P_0 * P_T))`.
//!
//! 2. **Inverse BTC-Settled European Vanilla Options (`OptionKind::Call` | `OptionKind::Put`)**:
//!    - Underlying notional `contract_size_sats` (`N_sats`, e.g., `100_000_000` sats = `1.0 BTC`),
//!      strike `strike_price_usd` (`K`), upfront `premium_sats` contributed by the Option Buyer,
//!      and `writer_collateral_sats` locked by the Option Writer inside the shared `P2TR` UTXO.
//!    - Total UTXO collateral pool: `total_collateral_sats = premium_sats + writer_collateral_sats`.
//!    - At expiry mark `P_T > 0`:
//!      - **Call (`max(0, P_T - K) / P_T`):**
//!        `buyer_sats(P_T) = min(total_collateral_sats, round_half_even(N_sats * max(0, P_T - K) / P_T))`
//!      - **Put (`max(0, K - P_T) / P_T`):**
//!        `buyer_sats(P_T) = min(total_collateral_sats, round_half_even(N_sats * max(0, K - P_T) / P_T))`
//!      - `writer_sats(P_T) = total_collateral_sats - buyer_sats(P_T)` (strictly `0` protocol fee!).
//!    - Notice that for a **Covered Call** (`writer_collateral_sats >= contract_size_sats`),
//!      `N_sats * (P_T - K) / P_T < N_sats` for ALL `P_T < infinity`: the Call Writer can NEVER
//!      default at any finite BTC price!
//!    - Both `Call` (monotonically non-decreasing in `P_T`) and `Put` (monotonically non-increasing
//!      in `P_T`) admit exact `O(1)`-per-node dyadic prefix CET compression (`compress_derivative_cet_ranges`),
//!      collapsing the entire OTM region into a handful of prefix leaves!

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    CollateralAsset, CompressedCetRange, InverseContractSpec, MarginError, PayoutSplit,
    ZeroFeePolicy, round_div_nearest_u128,
};

/// Tenor of an inverse swap contract.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum SwapTenor {
    /// Rolling off-chain Lightning DLC subchannel swap backed by periodic L1 CET anchor epochs.
    PerpetualSubchannel,
    /// Fixed-maturity dated inverse swap/future settling at `expiry_timestamp`.
    Dated { expiry_timestamp: u64 },
}

/// Option payoff direction (European exercise at `expiry_timestamp`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum OptionKind {
    Call,
    Put,
}

/// Deribit-style BTC-collateralized, inverse BTC-settled European Vanilla Option specification.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct InverseOptionSpec {
    pub kind: OptionKind,
    /// Strike price `K` in integer USD (`> 0`, e.g., `100_000` = `$100,000`).
    pub strike_price_usd: u64,
    /// Unix timestamp of European option expiry.
    pub expiry_timestamp: u64,
    /// Underlying BTC notional in satoshis (`100_000_000` = `1.0 BTC`, `10_000_000` = `0.1 BTC`).
    pub contract_size_sats: u64,
    /// Upfront option premium in satoshis contributed by Buyer into the shared `P2TR` UTXO
    /// (retained by Writer at expiry, offset against Buyer's intrinsic exercise payout).
    pub premium_sats: u64,
    /// Collateral in satoshis locked by the Option Writer inside the shared `P2TR` UTXO.
    pub writer_collateral_sats: u64,
    pub collateral: CollateralAsset,
    pub fee_policy: ZeroFeePolicy,
}

impl InverseOptionSpec {
    pub fn new_v0(
        kind: OptionKind,
        strike_price_usd: u64,
        expiry_timestamp: u64,
        contract_size_sats: u64,
        premium_sats: u64,
        writer_collateral_sats: u64,
    ) -> Result<Self, MarginError> {
        let spec = Self {
            kind,
            strike_price_usd,
            expiry_timestamp,
            contract_size_sats,
            premium_sats,
            writer_collateral_sats,
            collateral: CollateralAsset::VanillaBtc,
            fee_policy: ZeroFeePolicy::ZERO,
        };
        spec.validate_v0()?;
        Ok(spec)
    }

    pub fn validate_v0(&self) -> Result<(), MarginError> {
        self.fee_policy.validate()?;
        self.collateral.validate_v0_funding()?;
        if self.strike_price_usd == 0 {
            return Err(MarginError::InvalidParameter("strike_price_usd must be > 0"));
        }
        if self.expiry_timestamp == 0 {
            return Err(MarginError::InvalidParameter("expiry_timestamp must be > 0"));
        }
        if self.contract_size_sats == 0 {
            return Err(MarginError::InvalidParameter("contract_size_sats must be > 0"));
        }
        if self.premium_sats == 0 || self.writer_collateral_sats == 0 {
            return Err(MarginError::InvalidParameter(
                "premium_sats and writer_collateral_sats must be > 0",
            ));
        }
        self.premium_sats
            .checked_add(self.writer_collateral_sats)
            .ok_or(MarginError::InvalidParameter("option total collateral overflow"))?;
        Ok(())
    }

    pub fn total_collateral_sats(&self) -> u64 {
        self.premium_sats + self.writer_collateral_sats
    }

    /// For a Call, `writer_collateral_sats >= contract_size_sats` guarantees 100% physical/BTC
    /// coverage at every finite BTC/USD price (`N * (P - K) / P < N`).
    pub fn is_fully_covered_call(&self) -> bool {
        self.kind == OptionKind::Call && self.writer_collateral_sats >= self.contract_size_sats
    }

    /// Uncapped intrinsic settlement value owed to the Option Buyer in satoshis at `settlement_price_usd`.
    pub fn intrinsic_exercise_sats(&self, settlement_price_usd: u64) -> u64 {
        let total = self.total_collateral_sats();
        match self.kind {
            OptionKind::Call => {
                if settlement_price_usd <= self.strike_price_usd {
                    return 0;
                }
                let diff = (settlement_price_usd - self.strike_price_usd) as u128;
                let num = (self.contract_size_sats as u128) * diff;
                let raw = round_div_nearest_u128(num, settlement_price_usd as u128);
                raw.min(total as u128) as u64
            }
            OptionKind::Put => {
                if settlement_price_usd >= self.strike_price_usd {
                    return 0;
                }
                if settlement_price_usd == 0 {
                    return total;
                }
                let diff = (self.strike_price_usd - settlement_price_usd) as u128;
                let num = (self.contract_size_sats as u128) * diff;
                let raw = round_div_nearest_u128(num, settlement_price_usd as u128);
                raw.min(total as u128) as u64
            }
        }
    }

    /// Net realized PnL of the Option Buyer relative to upfront `premium_sats` (`exercise - premium`).
    pub fn buyer_net_pnl_sats(&self, settlement_price_usd: u64) -> i128 {
        (self.intrinsic_exercise_sats(settlement_price_usd) as i128) - (self.premium_sats as i128)
    }

    /// Exact satoshi split `(long_sats = buyer_sats, short_sats = writer_sats, protocol_fee_sats = 0)`
    /// conserving `buyer_sats + writer_sats == premium_sats + writer_collateral_sats`.
    pub fn payout_at_price(&self, settlement_price_usd: u64) -> PayoutSplit {
        let total = self.total_collateral_sats();
        let buyer_sats = self.intrinsic_exercise_sats(settlement_price_usd);
        let writer_sats = total - buyer_sats;
        PayoutSplit {
            long_sats: buyer_sats,
            short_sats: writer_sats,
            protocol_fee_sats: 0,
        }
    }
}

/// Unified bilateral Taproot derivative contract specification: either an **Inverse Swap**
/// (`Holder = Long`, `Counterparty = Short`) or a **European Vanilla Option**
/// (`Holder = Option Buyer`, `Counterparty = Option Writer`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum DerivativeContractSpec {
    InverseSwap {
        tenor: SwapTenor,
        spec: InverseContractSpec,
    },
    EuropeanOption(InverseOptionSpec),
}

impl DerivativeContractSpec {
    pub fn validate_v0(&self) -> Result<(), MarginError> {
        match self {
            Self::InverseSwap { tenor, spec } => {
                if let SwapTenor::Dated { expiry_timestamp } = tenor
                    && *expiry_timestamp == 0
                {
                    return Err(MarginError::InvalidParameter(
                        "dated swap expiry_timestamp must be > 0",
                    ));
                }
                spec.validate_v0()
            }
            Self::EuropeanOption(opt) => opt.validate_v0(),
        }
    }

    /// Initial contribution locked by the `Holder` (`Swap Long` margin or `Option Buyer` premium).
    pub fn holder_contribution_sats(&self) -> u64 {
        match self {
            Self::InverseSwap { spec, .. } => spec.long_margin_sats,
            Self::EuropeanOption(opt) => opt.premium_sats,
        }
    }

    /// Initial contribution locked by the `Counterparty` (`Swap Short` margin or `Option Writer` collateral).
    pub fn counterparty_contribution_sats(&self) -> u64 {
        match self {
            Self::InverseSwap { spec, .. } => spec.short_margin_sats,
            Self::EuropeanOption(opt) => opt.writer_collateral_sats,
        }
    }

    pub fn total_collateral_sats(&self) -> u64 {
        self.holder_contribution_sats() + self.counterparty_contribution_sats()
    }

    /// Exact conserved payout `(long_sats = holder, short_sats = counterparty, 0)` at `price_usd`.
    pub fn payout_at_price(&self, price_usd: u64) -> PayoutSplit {
        match self {
            Self::InverseSwap { spec, .. } => spec.payout_at_price(price_usd),
            Self::EuropeanOption(opt) => opt.payout_at_price(price_usd),
        }
    }

    /// Net realized PnL of `Holder` vs their initial contribution (`payout.long_sats - holder_contribution_sats`).
    pub fn holder_realized_pnl_sats(&self, price_usd: u64) -> i128 {
        let split = self.payout_at_price(price_usd);
        (split.long_sats as i128) - (self.holder_contribution_sats() as i128)
    }
}

/// Compresses `[0, 2^num_bits - 1]` into an exact, complete binary prefix code of CETs for ANY
/// `DerivativeContractSpec` (`InverseSwap`, `Call` Option, or `Put` Option) whose payout error
/// never exceeds `max_payout_error_sats`.
///
/// Works in `O(1)` per dyadic node because `holder_sats(P)` is monotonic on `[L, R]` for all
/// three payoff curves (non-decreasing for Swap Long & Call Buyer, non-increasing for Put Buyer)!
pub fn compress_derivative_cet_ranges(
    contract: &DerivativeContractSpec,
    num_bits: u8,
    max_payout_error_sats: u64,
) -> Result<Vec<CompressedCetRange>, MarginError> {
    contract.validate_v0()?;
    if !(4..=30).contains(&num_bits) {
        return Err(MarginError::InvalidBitWidth(num_bits));
    }
    let mut out = Vec::new();
    let mut prefix_buf = Vec::with_capacity(num_bits as usize);
    let max_domain_price = (1u64 << num_bits) - 1;
    compress_monotonic_derivative_node(
        contract,
        num_bits,
        max_payout_error_sats,
        0,
        max_domain_price,
        &mut prefix_buf,
        &mut out,
    );
    Ok(out)
}

fn compress_monotonic_derivative_node(
    contract: &DerivativeContractSpec,
    num_bits: u8,
    max_error_sats: u64,
    min_price: u64,
    max_price: u64,
    prefix: &mut Vec<u8>,
    out: &mut Vec<CompressedCetRange>,
) {
    let low_split = contract.payout_at_price(min_price);
    let high_split = contract.payout_at_price(max_price);
    let spread = low_split.long_sats.abs_diff(high_split.long_sats);

    if !prefix.is_empty()
        && (min_price == max_price
            || prefix.len() == num_bits as usize
            || spread.div_ceil(2) <= max_error_sats)
    {
        let total = contract.total_collateral_sats();
        let rep_holder =
            ((low_split.long_sats as u128 + high_split.long_sats as u128) / 2) as u64;
        out.push(CompressedCetRange {
            prefix_bits: prefix.clone(),
            min_price_usd: min_price,
            max_price_usd: max_price,
            payout: PayoutSplit {
                long_sats: rep_holder,
                short_sats: total - rep_holder,
                protocol_fee_sats: 0,
            },
        });
        return;
    }

    let mid = min_price + ((max_price - min_price) >> 1);
    prefix.push(0);
    compress_monotonic_derivative_node(
        contract,
        num_bits,
        max_error_sats,
        min_price,
        mid,
        prefix,
        out,
    );
    prefix.pop();

    prefix.push(1);
    compress_monotonic_derivative_node(
        contract,
        num_bits,
        max_error_sats,
        mid + 1,
        max_price,
        prefix,
        out,
    );
    prefix.pop();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inverse_call_and_put_option_payoffs_conservation_and_cet_compression() {
        // 1.0 BTC Call @ K = $100,000, premium = 5,000,000 sats (0.05 BTC), covered writer = 100,000,000 sats
        let call = InverseOptionSpec::new_v0(
            OptionKind::Call,
            100_000,
            1_800_000_000,
            100_000_000,
            5_000_000,
            100_000_000,
        )
        .unwrap();
        assert!(call.is_fully_covered_call());

        // OTM ($95,000): Buyer gets 0 exercise, Writer keeps 105,000,000 sats (collateral + premium)
        let otm = call.payout_at_price(95_000);
        assert_eq!(otm.long_sats, 0);
        assert_eq!(otm.short_sats, 105_000_000);
        assert_eq!(call.buyer_net_pnl_sats(95_000), -5_000_000);

        // ITM ($125,000): Intrinsic = 100M * (125k - 100k) / 125k = 20,000,000 sats (0.20 BTC = $25,000)!
        // Buyer net profit = 20M - 5M = +15,000,000 sats!
        let itm = call.payout_at_price(125_000);
        assert_eq!(itm.long_sats, 20_000_000);
        assert_eq!(itm.short_sats, 85_000_000);
        assert_eq!(call.buyer_net_pnl_sats(125_000), 15_000_000);

        // Compress 20-bit price domain ($0 .. $1,048,575) within <= 25,000 sats (2.5 bps on 1.0 BTC) error:
        let call_spec = DerivativeContractSpec::EuropeanOption(call);
        let call_cets = compress_derivative_cet_ranges(&call_spec, 20, 25_000).unwrap();
        assert!(call_cets.len() < 4_500); // > 99.5% compression from 1,048,576 outcomes!
        assert_eq!(call_cets.first().unwrap().min_price_usd, 0);
        assert_eq!(call_cets.last().unwrap().max_price_usd, (1 << 20) - 1);

        // 1.0 BTC Put @ K = $100,000, premium = 4,000,000 sats, writer = 50,000,000 sats
        let put = InverseOptionSpec::new_v0(
            OptionKind::Put,
            100_000,
            1_800_000_000,
            100_000_000,
            4_000_000,
            50_000_000,
        )
        .unwrap();
        // At $80,000: Intrinsic = 100M * (100k - 80k) / 80k = 25,000,000 sats (0.25 BTC = $20,000)!
        let put_itm = put.payout_at_price(80_000);
        assert_eq!(put_itm.long_sats, 25_000_000);
        assert_eq!(put_itm.short_sats, 29_000_000);
        assert_eq!(put_itm.total_sats(), 54_000_000);

        // Verify Put dyadic compression preserves error bound across test points
        let put_spec = DerivativeContractSpec::EuropeanOption(put);
        let put_cets = compress_derivative_cet_ranges(&put_spec, 18, 5_000).unwrap();
        for p in [40_000u64, 65_000, 80_000, 99_999, 100_000, 150_000] {
            let exact = put_spec.payout_at_price(p).long_sats;
            let cet = put_cets.iter().find(|c| c.matches_price(p, 18)).unwrap();
            assert!(exact.abs_diff(cet.payout.long_sats) <= 5_000);
        }
    }
}
