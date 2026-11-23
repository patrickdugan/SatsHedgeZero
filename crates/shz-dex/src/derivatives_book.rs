//! Bilateral 0-Fee Taproot Orderbook for **European Vanilla Options** and **Inverse Swaps**
//! (`derivatives_book.rs`).
//!
//! Matches non-custodial BIP-340 signed P2P intents (`SignedDerivativeOrderIntent`) across:
//! 1. **Inverse Swaps** (`PerpetualSubchannel` and `Dated { expiry_timestamp }`):
//!    - Price-time priority matching by `limit_price_usd` (`bid.limit_price_usd >= ask.limit_price_usd`)
//!      with partial USD notional fills at resting maker price.
//! 2. **European Vanilla Options** (`OptionKind::Call` and `OptionKind::Put` per `(strike, expiry, lot_size, writer_collateral)` series):
//!    - Price-time priority matching by `limit_premium_per_lot_sats`
//!      (`buyer.limit_premium >= writer.limit_premium`) with partial lot fills at resting maker premium.
//!
//! Every matched fill immediately derives its deterministic **4-leaf `UTXORef` NUMS `P2TR` Taproot
//! contract descriptor (`TaprootDerivativeTree`)** with strictly `0` maker/taker/protocol fees.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use shz_dlc::{
    Bip340Signature, BtcOutPoint, bip340_sign, bip340_verify, pubkey_x_from_secret, tagged_hash,
    taproot_derivatives::TaprootDerivativeTree,
};
use shz_margin::{
    CollateralAsset, DerivativeContractSpec, InverseContractSpec, InverseOptionSpec, OptionKind,
    SwapTenor,
};

use crate::{DexError, OracleSettlementPolicy, OrderSide};

/// Canonical instrument series key partitioning resting liquidity books.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DerivativeSeriesKey {
    InverseSwap {
        tenor: SwapTenor,
        oracle_policy: u8,
    },
    EuropeanOption {
        kind: OptionKind,
        strike_price_usd: u64,
        expiry_timestamp: u64,
        lot_size_sats: u64,
        writer_collateral_per_lot_sats: u64,
        oracle_policy: u8,
    },
}

/// Instrument-specific order terms signed by the trader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivativeOrderTerms {
    InverseSwap {
        tenor: SwapTenor,
        usd_notional: u64,
        open_usd_notional: u64,
        limit_price_usd: u64,
        leverage_bps: u32,
    },
    EuropeanOption {
        kind: OptionKind,
        strike_price_usd: u64,
        expiry_timestamp: u64,
        lot_size_sats: u64,
        lots: u64,
        open_lots: u64,
        limit_premium_per_lot_sats: u64,
        writer_collateral_per_lot_sats: u64,
    },
}

impl DerivativeOrderTerms {
    pub fn series_key(&self, oracle_policy: OracleSettlementPolicy) -> DerivativeSeriesKey {
        match self {
            Self::InverseSwap { tenor, .. } => DerivativeSeriesKey::InverseSwap {
                tenor: *tenor,
                oracle_policy: oracle_policy as u8,
            },
            Self::EuropeanOption {
                kind,
                strike_price_usd,
                expiry_timestamp,
                lot_size_sats,
                writer_collateral_per_lot_sats,
                ..
            } => DerivativeSeriesKey::EuropeanOption {
                kind: *kind,
                strike_price_usd: *strike_price_usd,
                expiry_timestamp: *expiry_timestamp,
                lot_size_sats: *lot_size_sats,
                writer_collateral_per_lot_sats: *writer_collateral_per_lot_sats,
                oracle_policy: oracle_policy as u8,
            },
        }
    }

    pub fn sort_price_key(&self) -> u64 {
        match self {
            Self::InverseSwap {
                limit_price_usd, ..
            } => *limit_price_usd,
            Self::EuropeanOption {
                limit_premium_per_lot_sats,
                ..
            } => *limit_premium_per_lot_sats,
        }
    }

    pub fn has_open_quantity(&self) -> bool {
        match self {
            Self::InverseSwap {
                open_usd_notional, ..
            } => *open_usd_notional > 0,
            Self::EuropeanOption { open_lots, .. } => *open_lots > 0,
        }
    }

    fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Self::InverseSwap {
                tenor,
                usd_notional,
                limit_price_usd,
                leverage_bps,
                ..
            } => {
                out.push(1);
                match tenor {
                    SwapTenor::PerpetualSubchannel => {
                        out.push(0);
                        out.extend_from_slice(&0u64.to_le_bytes());
                    }
                    SwapTenor::Dated { expiry_timestamp } => {
                        out.push(1);
                        out.extend_from_slice(&expiry_timestamp.to_le_bytes());
                    }
                }
                out.extend_from_slice(&usd_notional.to_le_bytes());
                out.extend_from_slice(&limit_price_usd.to_le_bytes());
                out.extend_from_slice(&leverage_bps.to_le_bytes());
            }
            Self::EuropeanOption {
                kind,
                strike_price_usd,
                expiry_timestamp,
                lot_size_sats,
                lots,
                limit_premium_per_lot_sats,
                writer_collateral_per_lot_sats,
                ..
            } => {
                out.push(2);
                out.push(match kind {
                    OptionKind::Call => 1,
                    OptionKind::Put => 2,
                });
                out.extend_from_slice(&strike_price_usd.to_le_bytes());
                out.extend_from_slice(&expiry_timestamp.to_le_bytes());
                out.extend_from_slice(&lot_size_sats.to_le_bytes());
                out.extend_from_slice(&lots.to_le_bytes());
                out.extend_from_slice(&limit_premium_per_lot_sats.to_le_bytes());
                out.extend_from_slice(&writer_collateral_per_lot_sats.to_le_bytes());
            }
        }
        out
    }
}

/// BIP-340 signed non-custodial order intent for either an Inverse Swap or a European Option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDerivativeOrderIntent {
    pub order_id: [u8; 32],
    pub trader_pubkey_x: [u8; 32],
    pub funding_outpoint: BtcOutPoint,
    /// `Long` = Swap Long OR Option Buyer; `Short` = Swap Short OR Option Writer.
    pub side: OrderSide,
    pub terms: DerivativeOrderTerms,
    pub oracle_policy: OracleSettlementPolicy,
    pub collateral: CollateralAsset,
    pub sequence_no: u64,
    pub signature: Bip340Signature,
}

impl SignedDerivativeOrderIntent {
    pub fn compute_order_id(
        trader_pubkey_x: &[u8; 32],
        funding_outpoint: &BtcOutPoint,
        side: OrderSide,
        terms: &DerivativeOrderTerms,
        oracle_policy: OracleSettlementPolicy,
        sequence_no: u64,
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(144);
        buf.extend_from_slice(trader_pubkey_x);
        buf.extend_from_slice(&funding_outpoint.txid);
        buf.extend_from_slice(&funding_outpoint.vout.to_le_bytes());
        buf.push(match side {
            OrderSide::Long => 1,
            OrderSide::Short => 2,
        });
        buf.extend_from_slice(&terms.canonical_signing_bytes());
        buf.push(oracle_policy as u8);
        buf.extend_from_slice(&sequence_no.to_le_bytes());
        tagged_hash(b"SatsHedgeZero/TaprootDerivativeOrder/v1", &buf)
    }

    pub fn new_signed(
        trader_secret: &[u8; 32],
        funding_outpoint: BtcOutPoint,
        side: OrderSide,
        terms: DerivativeOrderTerms,
        oracle_policy: OracleSettlementPolicy,
        sequence_no: u64,
    ) -> Result<Self, DexError> {
        match &terms {
            DerivativeOrderTerms::InverseSwap {
                tenor,
                usd_notional,
                open_usd_notional,
                limit_price_usd,
                leverage_bps,
            } => {
                if *usd_notional == 0 || *open_usd_notional != *usd_notional || *limit_price_usd == 0
                {
                    return Err(DexError::InvalidOrder("invalid swap notional or limit_price_usd"));
                }
                if let SwapTenor::Dated { expiry_timestamp } = tenor
                    && *expiry_timestamp == 0
                {
                    return Err(DexError::InvalidOrder("dated swap expiry_timestamp must be > 0"));
                }
                if !(1_000..=1_000_000).contains(leverage_bps) {
                    return Err(DexError::InvalidOrder("swap leverage_bps out of bounds"));
                }
            }
            DerivativeOrderTerms::EuropeanOption {
                strike_price_usd,
                expiry_timestamp,
                lot_size_sats,
                lots,
                open_lots,
                limit_premium_per_lot_sats,
                writer_collateral_per_lot_sats,
                ..
            } => {
                if *strike_price_usd == 0
                    || *expiry_timestamp == 0
                    || *lot_size_sats == 0
                    || *lots == 0
                    || *open_lots != *lots
                    || *limit_premium_per_lot_sats == 0
                    || *writer_collateral_per_lot_sats == 0
                {
                    return Err(DexError::InvalidOrder(
                        "option strike, expiry, lots, premium, and writer collateral must be > 0",
                    ));
                }
            }
        }

        let trader_pubkey_x = pubkey_x_from_secret(trader_secret)?;
        let order_id = Self::compute_order_id(
            &trader_pubkey_x,
            &funding_outpoint,
            side,
            &terms,
            oracle_policy,
            sequence_no,
        );
        let signature = bip340_sign(trader_secret, &order_id)?;
        Ok(Self {
            order_id,
            trader_pubkey_x,
            funding_outpoint,
            side,
            terms,
            oracle_policy,
            collateral: CollateralAsset::VanillaBtc,
            sequence_no,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), DexError> {
        self.collateral.validate_v0_funding()?;
        let expected = Self::compute_order_id(
            &self.trader_pubkey_x,
            &self.funding_outpoint,
            self.side,
            &self.terms,
            self.oracle_policy,
            self.sequence_no,
        );
        if expected != self.order_id {
            return Err(DexError::InvalidOrder("derivative order_id mismatch"));
        }
        bip340_verify(&self.trader_pubkey_x, &self.order_id, &self.signature)
            .map_err(|_| DexError::InvalidOrderSignature)?;
        Ok(())
    }
}

/// Zero-fee bilateral Taproot match ticket carrying its exact 4-leaf `UTXORef` NUMS `P2TR` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedTaprootDerivativeTicket {
    pub match_id: [u8; 32],
    pub holder_order_id: [u8; 32],
    pub counterparty_order_id: [u8; 32],
    pub holder_pubkey_x: [u8; 32],
    pub counterparty_pubkey_x: [u8; 32],
    pub clearing_guard_pubkey_x: [u8; 32],
    pub contract_spec: DerivativeContractSpec,
    pub taproot_tree: TaprootDerivativeTree,
    pub execution_quote: u64,
    pub maker_fee_sats: u64,
    pub taker_fee_sats: u64,
    pub protocol_fee_sats: u64,
}

#[derive(Debug, Default, Clone)]
struct SeriesBook {
    bids: Vec<SignedDerivativeOrderIntent>,
    asks: Vec<SignedDerivativeOrderIntent>,
}

/// Multi-series 0-fee bilateral Taproot matching engine for Options and Swaps.
#[derive(Debug, Clone)]
pub struct TaprootDerivativesOrderBook {
    pub clearing_guard_pubkey_x: [u8; 32],
    pub default_maturity_height: u32,
    pub default_grace_blocks: u32,
    pub default_refund_delay_blocks: u32,
    books: BTreeMap<DerivativeSeriesKey, SeriesBook>,
    match_nonce: u64,
}

impl TaprootDerivativesOrderBook {
    pub fn new(
        clearing_guard_pubkey_x: [u8; 32],
        default_maturity_height: u32,
        default_grace_blocks: u32,
        default_refund_delay_blocks: u32,
    ) -> Self {
        Self {
            clearing_guard_pubkey_x,
            default_maturity_height,
            default_grace_blocks,
            default_refund_delay_blocks,
            books: BTreeMap::new(),
            match_nonce: 0,
        }
    }

    pub fn resting_counts(&self, key: &DerivativeSeriesKey) -> (usize, usize) {
        self.books
            .get(key)
            .map_or((0, 0), |b| (b.bids.len(), b.asks.len()))
    }

    pub fn submit_order(
        &mut self,
        mut incoming: SignedDerivativeOrderIntent,
    ) -> Result<Vec<MatchedTaprootDerivativeTicket>, DexError> {
        incoming.verify()?;
        let key = incoming.terms.series_key(incoming.oracle_policy);
        let guard_pk = self.clearing_guard_pubkey_x;
        let mat = self.default_maturity_height;
        let grace = self.default_grace_blocks;
        let refund_delay = self.default_refund_delay_blocks;

        let book = self.books.entry(key).or_default();
        let mut fills = Vec::new();

        match incoming.side {
            OrderSide::Long => {
                let mut idx = 0;
                while idx < book.asks.len() && incoming.terms.has_open_quantity() {
                    if book.asks[idx].terms.sort_price_key() > incoming.terms.sort_price_key() {
                        break;
                    }
                    if book.asks[idx].trader_pubkey_x == incoming.trader_pubkey_x
                        || book.asks[idx].trader_pubkey_x == guard_pk
                        || incoming.trader_pubkey_x == guard_pk
                    {
                        idx += 1;
                        continue;
                    }

                    let resting_quote = book.asks[idx].terms.sort_price_key();
                    let spec = Self::cross_and_decrement(
                        &mut incoming.terms,
                        &mut book.asks[idx].terms,
                        resting_quote,
                    )?;
                    self.match_nonce += 1;
                    let match_id = Self::compute_match_id(
                        &incoming.order_id,
                        &book.asks[idx].order_id,
                        self.match_nonce,
                    );
                    let tree = TaprootDerivativeTree::build(
                        incoming.trader_pubkey_x,
                        book.asks[idx].trader_pubkey_x,
                        guard_pk,
                        mat,
                        grace,
                        refund_delay,
                    )?;
                    fills.push(MatchedTaprootDerivativeTicket {
                        match_id,
                        holder_order_id: incoming.order_id,
                        counterparty_order_id: book.asks[idx].order_id,
                        holder_pubkey_x: incoming.trader_pubkey_x,
                        counterparty_pubkey_x: book.asks[idx].trader_pubkey_x,
                        clearing_guard_pubkey_x: guard_pk,
                        contract_spec: spec,
                        taproot_tree: tree,
                        execution_quote: resting_quote,
                        maker_fee_sats: 0,
                        taker_fee_sats: 0,
                        protocol_fee_sats: 0,
                    });

                    if !book.asks[idx].terms.has_open_quantity() {
                        book.asks.remove(idx);
                    } else {
                        idx += 1;
                    }
                }
                if incoming.terms.has_open_quantity() {
                    book.bids.push(incoming);
                    book.bids.sort_by(|a, b| {
                        b.terms
                            .sort_price_key()
                            .cmp(&a.terms.sort_price_key())
                            .then_with(|| a.sequence_no.cmp(&b.sequence_no))
                    });
                }
            }
            OrderSide::Short => {
                let mut idx = 0;
                while idx < book.bids.len() && incoming.terms.has_open_quantity() {
                    if book.bids[idx].terms.sort_price_key() < incoming.terms.sort_price_key() {
                        break;
                    }
                    if book.bids[idx].trader_pubkey_x == incoming.trader_pubkey_x
                        || book.bids[idx].trader_pubkey_x == guard_pk
                        || incoming.trader_pubkey_x == guard_pk
                    {
                        idx += 1;
                        continue;
                    }

                    let resting_quote = book.bids[idx].terms.sort_price_key();
                    let spec = Self::cross_and_decrement(
                        &mut book.bids[idx].terms,
                        &mut incoming.terms,
                        resting_quote,
                    )?;
                    self.match_nonce += 1;
                    let match_id = Self::compute_match_id(
                        &book.bids[idx].order_id,
                        &incoming.order_id,
                        self.match_nonce,
                    );
                    let tree = TaprootDerivativeTree::build(
                        book.bids[idx].trader_pubkey_x,
                        incoming.trader_pubkey_x,
                        guard_pk,
                        mat,
                        grace,
                        refund_delay,
                    )?;
                    fills.push(MatchedTaprootDerivativeTicket {
                        match_id,
                        holder_order_id: book.bids[idx].order_id,
                        counterparty_order_id: incoming.order_id,
                        holder_pubkey_x: book.bids[idx].trader_pubkey_x,
                        counterparty_pubkey_x: incoming.trader_pubkey_x,
                        clearing_guard_pubkey_x: guard_pk,
                        contract_spec: spec,
                        taproot_tree: tree,
                        execution_quote: resting_quote,
                        maker_fee_sats: 0,
                        taker_fee_sats: 0,
                        protocol_fee_sats: 0,
                    });

                    if !book.bids[idx].terms.has_open_quantity() {
                        book.bids.remove(idx);
                    } else {
                        idx += 1;
                    }
                }
                if incoming.terms.has_open_quantity() {
                    book.asks.push(incoming);
                    book.asks.sort_by(|a, b| {
                        a.terms
                            .sort_price_key()
                            .cmp(&b.terms.sort_price_key())
                            .then_with(|| a.sequence_no.cmp(&b.sequence_no))
                    });
                }
            }
        }

        Ok(fills)
    }

    fn compute_match_id(holder_id: &[u8; 32], cp_id: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut buf = [0u8; 72];
        buf[..32].copy_from_slice(holder_id);
        buf[32..64].copy_from_slice(cp_id);
        buf[64..].copy_from_slice(&nonce.to_le_bytes());
        tagged_hash(b"SatsHedgeZero/TaprootDerivativeMatch/v1", &buf)
    }

    fn cross_and_decrement(
        holder_terms: &mut DerivativeOrderTerms,
        cp_terms: &mut DerivativeOrderTerms,
        execution_quote: u64,
    ) -> Result<DerivativeContractSpec, DexError> {
        match (holder_terms, cp_terms) {
            (
                DerivativeOrderTerms::InverseSwap {
                    tenor,
                    open_usd_notional: open_long,
                    leverage_bps: long_lev,
                    ..
                },
                DerivativeOrderTerms::InverseSwap {
                    open_usd_notional: open_short,
                    leverage_bps: short_lev,
                    ..
                },
            ) => {
                let fill_usd = (*open_long).min(*open_short);
                *open_long -= fill_usd;
                *open_short -= fill_usd;
                let spec = InverseContractSpec::from_leverages_v0(
                    fill_usd,
                    execution_quote,
                    *long_lev,
                    *short_lev,
                )?;
                Ok(DerivativeContractSpec::InverseSwap {
                    tenor: *tenor,
                    spec,
                })
            }
            (
                DerivativeOrderTerms::EuropeanOption {
                    kind,
                    strike_price_usd,
                    expiry_timestamp,
                    lot_size_sats,
                    open_lots: open_buyer_lots,
                    writer_collateral_per_lot_sats,
                    ..
                },
                DerivativeOrderTerms::EuropeanOption {
                    open_lots: open_writer_lots,
                    ..
                },
            ) => {
                let fill_lots = (*open_buyer_lots).min(*open_writer_lots);
                *open_buyer_lots -= fill_lots;
                *open_writer_lots -= fill_lots;
                let contract_size_sats = fill_lots
                    .checked_mul(*lot_size_sats)
                    .ok_or(DexError::InvalidOrder("option contract_size overflow"))?;
                let premium_sats = fill_lots
                    .checked_mul(execution_quote)
                    .ok_or(DexError::InvalidOrder("option premium overflow"))?;
                let writer_collateral_sats = fill_lots
                    .checked_mul(*writer_collateral_per_lot_sats)
                    .ok_or(DexError::InvalidOrder("option writer_collateral overflow"))?;
                let opt = InverseOptionSpec::new_v0(
                    *kind,
                    *strike_price_usd,
                    *expiry_timestamp,
                    contract_size_sats,
                    premium_sats,
                    writer_collateral_sats,
                )?;
                Ok(DerivativeContractSpec::EuropeanOption(opt))
            }
            _ => Err(DexError::InvalidOrder("mismatched derivative order kinds")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bilateral_taproot_matching_for_calls_puts_and_inverse_swaps() {
        let alice_sk = [0x11u8; 32];
        let bob_sk = [0x22u8; 32];
        let carol_sk = [0x23u8; 32];
        let guard_pk = pubkey_x_from_secret(&[0x24u8; 32]).unwrap();

        let mut book = TaprootDerivativesOrderBook::new(guard_pk, 200, 20, 60);

        // 1. European Call Option ($110k strike, 0.10 BTC/lot, covered writer = 10,000,000 sats/lot):
        //    Bob posts 3 lots Write @ 450,000 sats/lot; Alice takes 2 lots Buy @ 500,000 sats/lot -> fills at 450,000!
        let bob_write_call = SignedDerivativeOrderIntent::new_signed(
            &bob_sk,
            BtcOutPoint {
                txid: [1; 32],
                vout: 0,
            },
            OrderSide::Short,
            DerivativeOrderTerms::EuropeanOption {
                kind: OptionKind::Call,
                strike_price_usd: 110_000,
                expiry_timestamp: 1_800_000_000,
                lot_size_sats: 10_000_000,
                lots: 3,
                open_lots: 3,
                limit_premium_per_lot_sats: 450_000,
                writer_collateral_per_lot_sats: 10_000_000,
            },
            OracleSettlementPolicy::PythNearRelay,
            1,
        )
        .unwrap();
        assert!(book.submit_order(bob_write_call).unwrap().is_empty());

        let alice_buy_call = SignedDerivativeOrderIntent::new_signed(
            &alice_sk,
            BtcOutPoint {
                txid: [2; 32],
                vout: 0,
            },
            OrderSide::Long,
            DerivativeOrderTerms::EuropeanOption {
                kind: OptionKind::Call,
                strike_price_usd: 110_000,
                expiry_timestamp: 1_800_000_000,
                lot_size_sats: 10_000_000,
                lots: 2,
                open_lots: 2,
                limit_premium_per_lot_sats: 500_000,
                writer_collateral_per_lot_sats: 10_000_000,
            },
            OracleSettlementPolicy::PythNearRelay,
            1,
        )
        .unwrap();
        let call_fills = book.submit_order(alice_buy_call).unwrap();
        assert_eq!(call_fills.len(), 1);
        assert_eq!(call_fills[0].execution_quote, 450_000);
        assert_eq!(call_fills[0].protocol_fee_sats, 0);
        assert_eq!(call_fills[0].taproot_tree.script_pubkey.len(), 34);
        assert_eq!(
            call_fills[0].contract_spec.total_collateral_sats(),
            2 * 450_000 + 2 * 10_000_000
        );

        // 1 resting Call lot remains on Bob's ask
        let call_key = DerivativeSeriesKey::EuropeanOption {
            kind: OptionKind::Call,
            strike_price_usd: 110_000,
            expiry_timestamp: 1_800_000_000,
            lot_size_sats: 10_000_000,
            writer_collateral_per_lot_sats: 10_000_000,
            oracle_policy: OracleSettlementPolicy::PythNearRelay as u8,
        };
        assert_eq!(book.resting_counts(&call_key), (0, 1));

        // 2. Dated Inverse Swap ($20,000 notional @ $105,000): Carol Short 1x vs Alice Long 5x
        let carol_swap_ask = SignedDerivativeOrderIntent::new_signed(
            &carol_sk,
            BtcOutPoint {
                txid: [3; 32],
                vout: 0,
            },
            OrderSide::Short,
            DerivativeOrderTerms::InverseSwap {
                tenor: SwapTenor::Dated {
                    expiry_timestamp: 1_800_000_000,
                },
                usd_notional: 20_000,
                open_usd_notional: 20_000,
                limit_price_usd: 105_000,
                leverage_bps: 10_000,
            },
            OracleSettlementPolicy::PythNearRelay,
            1,
        )
        .unwrap();
        assert!(book.submit_order(carol_swap_ask).unwrap().is_empty());

        let alice_swap_bid = SignedDerivativeOrderIntent::new_signed(
            &alice_sk,
            BtcOutPoint {
                txid: [4; 32],
                vout: 0,
            },
            OrderSide::Long,
            DerivativeOrderTerms::InverseSwap {
                tenor: SwapTenor::Dated {
                    expiry_timestamp: 1_800_000_000,
                },
                usd_notional: 20_000,
                open_usd_notional: 20_000,
                limit_price_usd: 105_500,
                leverage_bps: 50_000,
            },
            OracleSettlementPolicy::PythNearRelay,
            2,
        )
        .unwrap();
        let swap_fills = book.submit_order(alice_swap_bid).unwrap();
        assert_eq!(swap_fills.len(), 1);
        assert_eq!(swap_fills[0].execution_quote, 105_000);
        assert_eq!(swap_fills[0].protocol_fee_sats, 0);
        assert!(
            swap_fills[0]
                .taproot_tree
                .verify_control_block(
                    &swap_fills[0].taproot_tree.coop_novation_script,
                    &swap_fills[0].taproot_tree.coop_novation_control_block,
                )
                .is_ok()
        );
    }
}
