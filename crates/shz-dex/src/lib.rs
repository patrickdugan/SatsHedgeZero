//! `shz-dex` — Decentralized 0-fee P2P inverse orderbook, matching coordinator,
//! non-custodial `LnDlcSubchannel` factory, and live position risk telemetry.

pub mod routing;

use serde::{Deserialize, Serialize};
use shz_dlc::{
    Bip340Signature, BtcOutPoint, DlcError, LnDlcSubchannel, OracleAnnouncement, bip340_sign,
    bip340_verify, pubkey_x_from_secret, tagged_hash,
};
use shz_margin::{CollateralAsset, InverseContractSpec, MarginError, SATS_PER_BTC};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DexError {
    #[error("margin error: {0}")]
    Margin(#[from] MarginError),
    #[error("DLC error: {0}")]
    Dlc(#[from] DlcError),
    #[error("invalid order signature")]
    InvalidOrderSignature,
    #[error("invalid order parameter: {0}")]
    InvalidOrder(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Long,
    Short,
}

/// Oracle settlement policy selected by counterparties on a P2P order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleSettlementPolicy {
    /// Direct TradeLayer L1/meta-layer VWAP oracle feed.
    TradeLayerVwap,
    /// Multi-provider Pyth et al. relay with NEAR Borsh state compatibility.
    PythNearRelay,
    /// `t-of-n` FROST state oracle confederation backed by NEAR slashable fraud proofs
    /// anchored to TradeLayer VWAP + Pyth relay consensus.
    FrostBondedWithFallback,
}

/// Non-custodial BIP-340 signed P2P order intent gossiped to the SatsHedgeZero book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrderIntent {
    pub order_id: [u8; 32],
    pub trader_pubkey_x: [u8; 32],
    pub channel_outpoint: BtcOutPoint,
    pub side: OrderSide,
    pub usd_notional: u64,
    pub open_usd_notional: u64,
    pub limit_price_usd: u64,
    /// Leverage in basis points (`10_000` = 1.0x covered hedge, `100_000` = 10.0x, `500_000` = 50.0x).
    pub leverage_bps: u32,
    pub oracle_policy: OracleSettlementPolicy,
    pub collateral: CollateralAsset,
    pub sequence_no: u64,
    pub signature: Bip340Signature,
}

impl SignedOrderIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_order_id(
        trader_pubkey_x: &[u8; 32],
        channel_outpoint: &BtcOutPoint,
        side: OrderSide,
        usd_notional: u64,
        limit_price_usd: u64,
        leverage_bps: u32,
        oracle_policy: OracleSettlementPolicy,
        sequence_no: u64,
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(98);
        buf.extend_from_slice(trader_pubkey_x);
        buf.extend_from_slice(&channel_outpoint.txid);
        buf.extend_from_slice(&channel_outpoint.vout.to_le_bytes());
        buf.push(match side {
            OrderSide::Long => 1,
            OrderSide::Short => 2,
        });
        buf.extend_from_slice(&usd_notional.to_le_bytes());
        buf.extend_from_slice(&limit_price_usd.to_le_bytes());
        buf.extend_from_slice(&leverage_bps.to_le_bytes());
        buf.push(oracle_policy as u8);
        buf.extend_from_slice(&sequence_no.to_le_bytes());
        tagged_hash(b"SatsHedgeZero/P2POrderIntent/v0", &buf)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_v0(
        trader_secret: &[u8; 32],
        channel_outpoint: BtcOutPoint,
        side: OrderSide,
        usd_notional: u64,
        limit_price_usd: u64,
        leverage_bps: u32,
        oracle_policy: OracleSettlementPolicy,
        sequence_no: u64,
    ) -> Result<Self, DexError> {
        if usd_notional == 0 || limit_price_usd == 0 {
            return Err(DexError::InvalidOrder(
                "usd_notional and limit_price_usd must be > 0",
            ));
        }
        // Cap max leverage at 100x (1_000_000 bps) like LN Markets.
        if !(1_000..=1_000_000).contains(&leverage_bps) {
            return Err(DexError::InvalidOrder(
                "leverage_bps must be in 1_000..=1_000_000 (0.1x..=100x)",
            ));
        }
        let trader_pubkey_x = pubkey_x_from_secret(trader_secret)?;
        let order_id = Self::compute_order_id(
            &trader_pubkey_x,
            &channel_outpoint,
            side,
            usd_notional,
            limit_price_usd,
            leverage_bps,
            oracle_policy,
            sequence_no,
        );
        let signature = bip340_sign(trader_secret, &order_id)?;

        Ok(Self {
            order_id,
            trader_pubkey_x,
            channel_outpoint,
            side,
            usd_notional,
            open_usd_notional: usd_notional,
            limit_price_usd,
            leverage_bps,
            oracle_policy,
            collateral: CollateralAsset::VanillaBtc,
            sequence_no,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), DexError> {
        self.collateral.validate_v0_funding()?;
        let expected_id = Self::compute_order_id(
            &self.trader_pubkey_x,
            &self.channel_outpoint,
            self.side,
            self.usd_notional,
            self.limit_price_usd,
            self.leverage_bps,
            self.oracle_policy,
            self.sequence_no,
        );
        if expected_id != self.order_id {
            return Err(DexError::InvalidOrder("order_id hash mismatch"));
        }
        bip340_verify(&self.trader_pubkey_x, &self.order_id, &self.signature)
            .map_err(|_| DexError::InvalidOrderSignature)?;
        Ok(())
    }
}

/// Zero-fee P2P match ticket ready for non-custodial Lightning DLC subchannel handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedDlcTicket {
    pub match_id: [u8; 32],
    pub execution_price_usd: u64,
    pub matched_usd_notional: u64,
    pub long_order_id: [u8; 32],
    pub short_order_id: [u8; 32],
    pub long_pubkey_x: [u8; 32],
    pub short_pubkey_x: [u8; 32],
    pub shared_funding_outpoint: BtcOutPoint,
    pub oracle_policy: OracleSettlementPolicy,
    pub contract_spec: InverseContractSpec,
    pub maker_fee_sats: u64,
    pub taker_fee_sats: u64,
    pub protocol_fee_sats: u64,
}

impl MatchedDlcTicket {
    /// Materializes the non-custodial `LnDlcSubchannel` offer from this 0-fee match ticket.
    pub fn into_subchannel_offer(
        &self,
        announcement: OracleAnnouncement,
        dispute_csv_blocks: u16,
        max_cet_error_sats: u64,
    ) -> Result<LnDlcSubchannel, DexError> {
        Ok(LnDlcSubchannel::offer_v0(
            self.shared_funding_outpoint.clone(),
            self.contract_spec.clone(),
            self.long_pubkey_x,
            self.short_pubkey_x,
            announcement,
            dispute_csv_blocks,
            max_cet_error_sats,
        )?)
    }
}

/// Price-time priority 0-fee P2P orderbook coordinator (holds zero user funds or keys).
#[derive(Debug, Default, Clone)]
pub struct ZeroFeeOrderBook {
    pub bids: Vec<SignedOrderIntent>,
    pub asks: Vec<SignedOrderIntent>,
    match_nonce: u64,
}

impl ZeroFeeOrderBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies and submits a `SignedOrderIntent`, matching immediately at resting maker price
    /// with strictly `0` maker/taker/protocol fees.
    pub fn submit_order(
        &mut self,
        incoming: SignedOrderIntent,
    ) -> Result<Vec<MatchedDlcTicket>, DexError> {
        incoming.verify()?;
        self.submit_verified_order(incoming)
    }

    /// Submits a `SignedOrderIntent` whose BIP-340 Schnorr signature has ALREADY been verified
    /// on the ingress I/O worker thread outside the orderbook lock (`< 2 µs` critical section!).
    pub fn submit_verified_order(
        &mut self,
        mut incoming: SignedOrderIntent,
    ) -> Result<Vec<MatchedDlcTicket>, DexError> {
        let mut matches = Vec::new();

        match incoming.side {
            OrderSide::Long => {
                let mut idx = 0;
                while idx < self.asks.len() && incoming.open_usd_notional > 0 {
                    let resting_ask = &self.asks[idx];
                    if resting_ask.limit_price_usd > incoming.limit_price_usd {
                        break; // Asks are sorted ascending by price
                    }
                    if resting_ask.trader_pubkey_x == incoming.trader_pubkey_x
                        || resting_ask.oracle_policy != incoming.oracle_policy
                    {
                        idx += 1;
                        continue;
                    }

                    let fill_usd = incoming
                        .open_usd_notional
                        .min(resting_ask.open_usd_notional);
                    let exec_price = resting_ask.limit_price_usd; // Exact resting maker price!
                    let spec = InverseContractSpec::from_leverages_v0(
                        fill_usd,
                        exec_price,
                        incoming.leverage_bps,
                        resting_ask.leverage_bps,
                    )?;

                    self.match_nonce += 1;
                    let match_id = compute_match_id(
                        &incoming.order_id,
                        &resting_ask.order_id,
                        self.match_nonce,
                    );
                    matches.push(MatchedDlcTicket {
                        match_id,
                        execution_price_usd: exec_price,
                        matched_usd_notional: fill_usd,
                        long_order_id: incoming.order_id,
                        short_order_id: resting_ask.order_id,
                        long_pubkey_x: incoming.trader_pubkey_x,
                        short_pubkey_x: resting_ask.trader_pubkey_x,
                        shared_funding_outpoint: incoming.channel_outpoint.clone(),
                        oracle_policy: incoming.oracle_policy,
                        contract_spec: spec,
                        maker_fee_sats: 0,
                        taker_fee_sats: 0,
                        protocol_fee_sats: 0,
                    });

                    incoming.open_usd_notional -= fill_usd;
                    self.asks[idx].open_usd_notional -= fill_usd;
                    if self.asks[idx].open_usd_notional == 0 {
                        self.asks.remove(idx);
                    } else {
                        idx += 1;
                    }
                }

                if incoming.open_usd_notional > 0 {
                    self.bids.push(incoming);
                    self.bids.sort_by(|a, b| {
                        b.limit_price_usd
                            .cmp(&a.limit_price_usd)
                            .then_with(|| a.sequence_no.cmp(&b.sequence_no))
                    });
                }
            }
            OrderSide::Short => {
                let mut idx = 0;
                while idx < self.bids.len() && incoming.open_usd_notional > 0 {
                    let resting_bid = &self.bids[idx];
                    if resting_bid.limit_price_usd < incoming.limit_price_usd {
                        break; // Bids are sorted descending by price
                    }
                    if resting_bid.trader_pubkey_x == incoming.trader_pubkey_x
                        || resting_bid.oracle_policy != incoming.oracle_policy
                    {
                        idx += 1;
                        continue;
                    }

                    let fill_usd = incoming
                        .open_usd_notional
                        .min(resting_bid.open_usd_notional);
                    let exec_price = resting_bid.limit_price_usd; // Exact resting maker price!
                    let spec = InverseContractSpec::from_leverages_v0(
                        fill_usd,
                        exec_price,
                        resting_bid.leverage_bps,
                        incoming.leverage_bps,
                    )?;

                    self.match_nonce += 1;
                    let match_id = compute_match_id(
                        &resting_bid.order_id,
                        &incoming.order_id,
                        self.match_nonce,
                    );
                    matches.push(MatchedDlcTicket {
                        match_id,
                        execution_price_usd: exec_price,
                        matched_usd_notional: fill_usd,
                        long_order_id: resting_bid.order_id,
                        short_order_id: incoming.order_id,
                        long_pubkey_x: resting_bid.trader_pubkey_x,
                        short_pubkey_x: incoming.trader_pubkey_x,
                        shared_funding_outpoint: resting_bid.channel_outpoint.clone(),
                        oracle_policy: incoming.oracle_policy,
                        contract_spec: spec,
                        maker_fee_sats: 0,
                        taker_fee_sats: 0,
                        protocol_fee_sats: 0,
                    });

                    incoming.open_usd_notional -= fill_usd;
                    self.bids[idx].open_usd_notional -= fill_usd;
                    if self.bids[idx].open_usd_notional == 0 {
                        self.bids.remove(idx);
                    } else {
                        idx += 1;
                    }
                }

                if incoming.open_usd_notional > 0 {
                    self.asks.push(incoming);
                    self.asks.sort_by(|a, b| {
                        a.limit_price_usd
                            .cmp(&b.limit_price_usd)
                            .then_with(|| a.sequence_no.cmp(&b.sequence_no))
                    });
                }
            }
        }

        Ok(matches)
    }

    /// Cancels a specific resting order owned by `trader_pubkey_x`.
    pub fn cancel_order(&mut self, trader_pubkey_x: &[u8; 32], order_id: &[u8; 32]) -> bool {
        let before_bids = self.bids.len();
        self.bids
            .retain(|o| !(o.order_id == *order_id && o.trader_pubkey_x == *trader_pubkey_x));
        if self.bids.len() != before_bids {
            return true;
        }
        let before_asks = self.asks.len();
        self.asks
            .retain(|o| !(o.order_id == *order_id && o.trader_pubkey_x == *trader_pubkey_x));
        self.asks.len() != before_asks
    }

    /// Cancels all resting orders owned by `trader_pubkey_x` (used by `private/cancel_all` and `cancel_on_disconnect`).
    pub fn cancel_all_for_trader(&mut self, trader_pubkey_x: &[u8; 32]) -> usize {
        let before = self.bids.len() + self.asks.len();
        self.bids.retain(|o| o.trader_pubkey_x != *trader_pubkey_x);
        self.asks.retain(|o| o.trader_pubkey_x != *trader_pubkey_x);
        before - (self.bids.len() + self.asks.len())
    }

    /// Atomically replaces all resting quotes for `trader_pubkey_x` with up to 40 signed quotes (`private/mass_quote`).
    pub fn replace_mass_quotes(
        &mut self,
        trader_pubkey_x: &[u8; 32],
        quotes: Vec<SignedOrderIntent>,
    ) -> Result<(usize, Vec<MatchedDlcTicket>), DexError> {
        if quotes.len() > 80 {
            return Err(DexError::InvalidOrder(
                "mass_quote exceeds 40 two-sided levels (80 signed orders max)",
            ));
        }
        for q in &quotes {
            if q.trader_pubkey_x != *trader_pubkey_x {
                return Err(DexError::InvalidOrder(
                    "mass_quote contains order for mismatched trader_pubkey_x",
                ));
            }
            q.verify()?;
        }
        let cancelled = self.cancel_all_for_trader(trader_pubkey_x);
        let mut all_matches = Vec::new();
        for q in quotes {
            let mut m = self.submit_verified_order(q)?;
            all_matches.append(&mut m);
        }
        Ok((cancelled, all_matches))
    }

    /// Atomically replaces all resting quotes for `trader_pubkey_x` when quotes were pre-verified
    /// on the WebSocket worker thread outside the orderbook mutex (`< 15 µs` critical section!).
    pub fn replace_verified_mass_quotes(
        &mut self,
        trader_pubkey_x: &[u8; 32],
        quotes: Vec<SignedOrderIntent>,
    ) -> Result<(usize, Vec<MatchedDlcTicket>), DexError> {
        if quotes.len() > 80 {
            return Err(DexError::InvalidOrder(
                "mass_quote exceeds 40 two-sided levels (80 signed orders max)",
            ));
        }
        let cancelled = self.cancel_all_for_trader(trader_pubkey_x);
        let mut all_matches = Vec::new();
        for q in quotes {
            let mut m = self.submit_verified_order(q)?;
            all_matches.append(&mut m);
        }
        Ok((cancelled, all_matches))
    }
}

fn compute_match_id(long_id: &[u8; 32], short_id: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut buf = [0u8; 72];
    buf[..32].copy_from_slice(long_id);
    buf[32..64].copy_from_slice(short_id);
    buf[64..].copy_from_slice(&nonce.to_le_bytes());
    tagged_hash(b"SatsHedgeZero/MatchTicket/v0", &buf)
}

/// Real-time mark-to-market risk snapshot for an active inverse LN-DLC contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionTelemetry {
    pub mark_price_usd: u64,
    pub long_equity_sats: u64,
    pub short_equity_sats: u64,
    pub long_unrealized_pnl_sats: i64,
    pub short_unrealized_pnl_sats: i64,
    pub long_liquidation_price_usd: u64,
    pub short_liquidation_price_usd: Option<u64>,
    pub short_is_synthetic_usd_hedge: bool,
    /// USD value of Short's satoshi equity at `mark_price_usd` (`round(short_equity * mark / 1e8)`).
    pub short_equity_usd_equivalent: u64,
}

pub fn evaluate_position_telemetry(
    spec: &InverseContractSpec,
    mark_price_usd: u64,
) -> PositionTelemetry {
    let split = spec.payout_at_price(mark_price_usd);
    let long_pnl = (split.long_sats as i64) - (spec.long_margin_sats as i64);
    let short_pnl = (split.short_sats as i64) - (spec.short_margin_sats as i64);
    let short_usd = (((split.short_sats as u128) * (mark_price_usd as u128)) + (SATS_PER_BTC / 2))
        / SATS_PER_BTC;

    PositionTelemetry {
        mark_price_usd,
        long_equity_sats: split.long_sats,
        short_equity_sats: split.short_sats,
        long_unrealized_pnl_sats: long_pnl,
        short_unrealized_pnl_sats: short_pnl,
        long_liquidation_price_usd: spec.long_liquidation_price_usd(),
        short_liquidation_price_usd: spec.short_liquidation_price_usd(),
        short_is_synthetic_usd_hedge: spec.is_covered_synthetic_usd_short(),
        short_equity_usd_equivalent: short_usd as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shz_oracle::frost::FrostConfederation;

    #[test]
    fn test_zero_fee_p2p_match_into_full_ln_dlc_lifecycle() {
        let alice_sk = [0xA1u8; 32]; // 10x Long taker
        let bob_sk = [0xB2u8; 32]; // 1x Covered SatsHedge Short maker

        let mut book = ZeroFeeOrderBook::new();

        // Bob posts a resting 1x Short ask for $2,000 at $100,000 (synthetic USD hedge).
        let bob_ask = SignedOrderIntent::new_signed_v0(
            &bob_sk,
            BtcOutPoint {
                txid: [0xCD; 32],
                vout: 1,
            },
            OrderSide::Short,
            2_000,
            100_000,
            10_000, // 1.0x covered synthetic USD!
            OracleSettlementPolicy::FrostBondedWithFallback,
            1,
        )
        .unwrap();
        assert!(book.submit_order(bob_ask).unwrap().is_empty());

        // Alice crosses with a 10x Long bid for $2,000 up to $100,050 -> fills at maker $100,000, 0 fee!
        let alice_bid = SignedOrderIntent::new_signed_v0(
            &alice_sk,
            BtcOutPoint {
                txid: [0xEF; 32],
                vout: 0,
            },
            OrderSide::Long,
            2_000,
            100_050,
            100_000, // 10.0x leverage
            OracleSettlementPolicy::FrostBondedWithFallback,
            2,
        )
        .unwrap();

        let matches = book.submit_order(alice_bid).unwrap();
        assert_eq!(matches.len(), 1);
        let ticket = &matches[0];
        assert_eq!(ticket.execution_price_usd, 100_000);
        assert_eq!(ticket.maker_fee_sats, 0);
        assert_eq!(ticket.taker_fee_sats, 0);
        assert_eq!(ticket.protocol_fee_sats, 0);

        // 3-of-5 FROST confederation announces 20-bit event
        let frost = FrostConfederation::keygen_deterministic(3, 5, &[0x99u8; 32]).unwrap();
        let nonce_state = frost
            .announce_event("SHZ-BTCUSD-EPOCH-1", 1_795_000_000, 20, &[0x71u8; 32])
            .unwrap();

        let mut subchannel = ticket
            .into_subchannel_offer(nonce_state.announcement.clone(), 144, 1_000)
            .unwrap();
        let cet_count = subchannel
            .sign_and_activate_cets(&alice_sk, &bob_sk)
            .unwrap();
        // 1,048,576 discrete prices compressed by >99.8% into <2,000 dyadic prefix CETs!
        assert!(cet_count > 10 && cet_count < 2_000, "cet_count={cet_count}");

        // Check live telemetry at $125,000: Bob's 1x SatsHedge still equals $2,000 USD!
        let tel = evaluate_position_telemetry(&subchannel.spec, 125_000);
        assert!(tel.short_is_synthetic_usd_hedge);
        assert_eq!(tel.short_equity_usd_equivalent, 2_000);

        // Settle unilaterally on L1 using a 3-of-5 FROST attestation at $125,000 (signers {1, 4, 5}):
        let attestation = frost
            .threshold_attest_price(&nonce_state, &[1, 4, 5], 1_795_000_000, 125_000)
            .unwrap();
        let split = subchannel
            .settle_on_chain_with_attestation(&attestation)
            .unwrap();
        assert_eq!(split.protocol_fee_sats, 0);
        assert_eq!(split.total_sats(), subchannel.spec.total_collateral_sats());
        // Bob's exact payout is ~1,600,000 sats (within 1,000-sat CET quantization) = $2,000 @ $125k!
        assert!(split.short_sats.abs_diff(1_600_000) <= 1_000);
    }
}
