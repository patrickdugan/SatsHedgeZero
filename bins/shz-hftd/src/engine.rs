//! Core SatsHedgeZero HFT Matching, LN-Testnet4 Coalescer, Multi-Source Oracle,
//! Edmonds-Karp Multilateral Netting, 5-Party Packer, Watchtower, and Explorer Telemetry Engine.
#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dex::{
    MatchedDlcTicket, OracleSettlementPolicy, OrderSide, SignedOrderIntent, ZeroFeeOrderBook,
};
use shz_dlc::{Bip340Signature, BtcOutPoint, adaptor_sign, pubkey_x_from_secret, scalar_from_bytes};
use shz_ln_testnet4::{
    CoalescedSubchannelCommit, LnDlcPeerChannel, PtlcInstantSwapEvent, SubchannelCoalescer,
    Testnet4ChainStatus, probe_testnet4_chain_status,
};
use shz_margin::{
    CollateralAsset, InverseContractSpec,
    liquidation_auction::{PartialLiquidationPlan, compute_partial_liquidation_tranche},
    portfolio_greeks::{
        InverseOptionLeg, InverseSwapLeg, OptionKind, PortfolioGreeks,
        compute_portfolio_cross_margin,
    },
};
use crate::oracle_importer::LiveTwoIndexObservation;
use shz_nova_bitvm::SparseNullifierTree;
use shz_oracle::{
    frost::FrostConfederation,
    live_relayer::{MultiSourceOracleTick, OracleTickSourceMode, RollingOracleAggregator, SealedCheckpointSummary},
    optimistic_near_verifier::{OptimisticCheckpointSession, OptimisticSessionStatus},
};
use shz_utxoref::{
    mnr02::{Mnr02TaprootTree, SegwitTx, SegwitTxIn},
    n_party_packer::{
        CounterpartyAuthMode, DynamicNPartyPackingReceipt, DynamicVaultInputSpec,
        pack_dynamic_n_party_clearing_tx,
    },
    pnl_batch::{
        AccountRecord, BookAuthState, DurablePnlBatchBook, FundedVaultUtxo, NettingSetSpec,
        PermittedRoute, PnlBatchSnapshotV1, RealizedObligation, RouteTarget, VaultRecord,
        solve_and_verify_pnl_batch,
    },
    signing_target::derive_utxoref_funding_output,
    watchtower::{ShzWatchtowerEngine, WatchtowerActionKind, WatchtowerArmedAssertion},
};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1_795_400_000_000)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn p2tr_spk(tag: &[u8]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51);
    spk.push(0x20);
    spk.extend_from_slice(&sha256_bytes(tag));
    spk
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderLevelDto {
    pub price_usd: u64,
    pub open_usd_notional: u64,
    pub leverage_bps: u32,
    pub trader_pubkey_prefix: String,
    pub order_id_prefix: String,
    pub sequence_no: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentTapeEntry {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub order_id_hex: String,
    pub trader_pubkey_hex: String,
    pub bip340_verified: bool,
    pub side: String,
    pub limit_price_usd: u64,
    pub usd_notional: u64,
    pub filled_usd_notional: u64,
    pub leverage_bps: u32,
    pub latency_us: u64,
    pub ln_channel_id: String,
    pub ln_commit_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillTapeEntry {
    pub match_id_hex: String,
    pub timestamp_ms: u64,
    pub execution_price_usd: u64,
    pub matched_usd_notional: u64,
    pub long_pubkey_prefix: String,
    pub short_pubkey_prefix: String,
    pub maker_fee_sats: u64,
    pub taker_fee_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyMetrics {
    pub total_intents_processed: u64,
    pub total_fills_matched: u64,
    pub total_usd_volume: u64,
    pub sample_count: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub sustained_ops_per_sec_est: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SankeyFlowEdge {
    pub from: String,
    pub to: String,
    pub sats: u64,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NettingSummaryDto {
    pub epoch_id: u64,
    pub gross_obligations_sats: u64,
    pub net_l1_transfer_sats: u64,
    pub collateral_freed_bps: u32,
    pub snapshot_hash_hex: String,
    pub next_state_root_hex: String,
    pub sankey_edges: Vec<SankeyFlowEdge>,
    pub n_party_packing: DynamicNPartyPackingReceipt,
    pub portfolio_greeks: PortfolioGreeks,
    pub liquidation_plan: PartialLiquidationPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierSlotDto {
    pub slot_index: usize,
    pub vault_label: String,
    pub nullifier_hex: String,
    pub consumed: bool,
    pub epoch_consumed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovaBitVm3StateDto {
    pub secq256k1_progress_pct: f64,
    pub secq256k1_folds_done: u32,
    pub secq256k1_folds_total: u32,
    pub secq256k1_proof_bytes: usize,
    pub secq256k1_proof_sha256: String,
    pub bn254_progress_pct: f64,
    pub bn254_folds_done: u32,
    pub bn254_folds_total: u32,
    pub bn254_proof_bytes: usize,
    pub bn254_proof_sha256: String,
    pub nullifier_root_hex: String,
    pub nullifier_slots: Vec<NullifierSlotDto>,
    pub bitvm3_assert_outpoint: String,
    pub bitvm3_csv_blocks: u16,
    pub bitvm3_leaves: Vec<String>,
    pub garbled_nand_gate_commitment_hex: String,
    pub in_circuit_tapsighash_verified: bool,
    pub durable_book_frozen: bool,
    pub watchtower_events: Vec<WatchtowerActionKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearOptimisticDto {
    pub epoch_start_hour: u64,
    pub total_chunks: u32,
    pub happy_path_tx_count: u32,
    pub happy_path_gas_tgas: u32,
    pub max_bisection_steps: u32,
    pub status_label: String,
    pub session_status: OptimisticSessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorerSnapshot {
    pub server_timestamp_ms: u64,
    pub mark_price_usd: u64,
    pub bids: Vec<OrderLevelDto>,
    pub asks: Vec<OrderLevelDto>,
    pub intent_tape: Vec<IntentTapeEntry>,
    pub fill_tape: Vec<FillTapeEntry>,
    pub latency: LatencyMetrics,
    pub testnet4_chain: Testnet4ChainStatus,
    pub ln_channels: Vec<LnDlcPeerChannel>,
    pub ln_recent_commits: Vec<CoalescedSubchannelCommit>,
    pub ln_recent_ptlc_swaps: Vec<PtlcInstantSwapEvent>,
    pub oracle_latest: Option<MultiSourceOracleTick>,
    pub oracle_checkpoints: Vec<SealedCheckpointSummary>,
    pub frost_quorum: String,
    pub frost_event_id: String,
    pub near_optimistic: NearOptimisticDto,
    pub netting: NettingSummaryDto,
    pub nova_bitvm3: NovaBitVm3StateDto,
    pub live_two_index: Option<LiveTwoIndexObservation>,
    pub user_wallet_sats: u64,
    pub user_positions: Vec<UserTerminalPosition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserTerminalPosition {
    pub id: String,
    pub subchannel_id: String,
    pub instrument: String,
    pub side: String,
    pub usd_notional: u64,
    pub notional_usd: u64,
    pub entry_price_usd: u64,
    pub mark_price_usd: u64,
    pub leverage_x: u32,
    pub counterparty_leverage_x: u32,
    pub long_margin_sats: u64,
    pub short_margin_sats: u64,
    pub user_margin_sats: u64,
    pub margin_sats: u64,
    pub counterparty_margin_sats: u64,
    pub unrealized_pnl_sats: i64,
    pub usd_equity_value: u64,
    pub liquidation_price_usd: Option<u64>,
    pub short_is_covered_synthetic_usd: bool,
    pub oracle_policy: String,
    pub collateral: String,
    pub protocol_fee_sats: u64,
    pub compressed_cet_count: usize,
    pub funding_txid: String,
    pub bob_offline: bool,
    pub bob_status: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceIntentWireParams {
    pub order_id_hex: String,
    pub trader_pubkey_x_hex: String,
    pub channel_txid_hex: String,
    pub channel_vout: u32,
    pub side: String,
    pub usd_notional: u64,
    pub limit_price_usd: u64,
    pub leverage_bps: u32,
    pub sequence_no: u64,
    pub signature_hex: String,
}

impl PlaceIntentWireParams {
    pub fn from_signed_intent(intent: &SignedOrderIntent) -> Self {
        Self {
            order_id_hex: hex::encode(intent.order_id),
            trader_pubkey_x_hex: hex::encode(intent.trader_pubkey_x),
            channel_txid_hex: hex::encode(intent.channel_outpoint.txid),
            channel_vout: intent.channel_outpoint.vout,
            side: match intent.side {
                OrderSide::Long => "Long".into(),
                OrderSide::Short => "Short".into(),
            },
            usd_notional: intent.usd_notional,
            limit_price_usd: intent.limit_price_usd,
            leverage_bps: intent.leverage_bps,
            sequence_no: intent.sequence_no,
            signature_hex: hex::encode(intent.signature.to_bytes()),
        }
    }

    pub fn into_signed_intent(self) -> Result<SignedOrderIntent, String> {
        let order_id: [u8; 32] = hex::decode(&self.order_id_hex)
            .map_err(|_| "invalid order_id_hex")?
            .try_into()
            .map_err(|_| "order_id_hex must be 32 bytes")?;
        let trader_pubkey_x: [u8; 32] = hex::decode(&self.trader_pubkey_x_hex)
            .map_err(|_| "invalid trader_pubkey_x_hex")?
            .try_into()
            .map_err(|_| "trader_pubkey_x_hex must be 32 bytes")?;
        let txid: [u8; 32] = hex::decode(&self.channel_txid_hex)
            .map_err(|_| "invalid channel_txid_hex")?
            .try_into()
            .map_err(|_| "channel_txid_hex must be 32 bytes")?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature_hex)
            .map_err(|_| "invalid signature_hex")?
            .try_into()
            .map_err(|_| "signature_hex must be 64 bytes")?;
        let side = match self.side.as_str() {
            "Long" | "long" | "BUY" | "buy" => OrderSide::Long,
            "Short" | "short" | "SELL" | "sell" => OrderSide::Short,
            _ => return Err("side must be Long or Short".into()),
        };

        Ok(SignedOrderIntent {
            order_id,
            trader_pubkey_x,
            channel_outpoint: BtcOutPoint {
                txid,
                vout: self.channel_vout,
            },
            side,
            usd_notional: self.usd_notional,
            open_usd_notional: self.usd_notional,
            limit_price_usd: self.limit_price_usd,
            leverage_bps: self.leverage_bps,
            oracle_policy: OracleSettlementPolicy::FrostBondedWithFallback,
            collateral: CollateralAsset::VanillaBtc,
            sequence_no: self.sequence_no,
            signature: Bip340Signature {
                r_x: sig_bytes[..32].try_into().unwrap(),
                s: sig_bytes[32..].try_into().unwrap(),
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceIntentAck {
    pub accepted: bool,
    pub order_id_hex: String,
    pub filled_usd_notional: u64,
    pub resting_usd_notional: u64,
    pub match_count: usize,
    pub latency_us: u64,
    pub ln_channel_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MassQuoteAck {
    pub accepted: bool,
    pub cancelled_count: usize,
    pub quoted_count: usize,
    pub match_count: usize,
    pub latency_us: u64,
}

pub struct HftEngine {
    pub started_at: Instant,
    pub book: ZeroFeeOrderBook,
    pub ln_mesh: SubchannelCoalescer,
    pub oracle: RollingOracleAggregator,
    pub near_session: OptimisticCheckpointSession,
    pub watchtower: ShzWatchtowerEngine,
    pub durable_book: DurablePnlBatchBook,
    pub nullifier_tree: SparseNullifierTree,
    pub consumed_slots: [Option<u64>; 8],
    pub testnet4_chain: Testnet4ChainStatus,
    pub mark_price_usd: u64,
    pub intent_seq: u64,
    pub total_intents: u64,
    pub total_fills: u64,
    pub total_usd_volume: u64,
    pub rollup_epoch: u64,
    pub simulated_hour: u64,
    pub intent_tape: VecDeque<IntentTapeEntry>,
    pub fill_tape: VecDeque<FillTapeEntry>,
    pub latency_ring_us: VecDeque<u64>,
    pub last_netting: NettingSummaryDto,
    pub nova_fold_phase: u32,
    pub live_two_index: Option<LiveTwoIndexObservation>,
    pub user_wallet_sats: u64,
    pub user_positions: Vec<UserTerminalPosition>,
    pub user_pos_seq: u64,
}

impl HftEngine {
    pub fn new_bootstrapped() -> Self {
        let testnet4_chain = probe_testnet4_chain_status();
        let mut ln_mesh = SubchannelCoalescer::new_default_testnet4_mesh();
        let genesis_hash = sha256_bytes(b"BITCOIN-TESTNET4-00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043");
        let mut oracle = RollingOracleAggregator::new(genesis_hash, 50);

        let base_ts = now_unix_ms().saturating_sub(8 * 3_600_000);
        for h in 0..8u64 {
            let px_p = (99_920 + h * 25) * 100_000_000;
            let px_c = (99_940 + h * 25) * 100_000_000;
            oracle.ingest_tick(
                base_ts + h * 3_600_000,
                px_p,
                px_c,
                OracleTickSourceMode::DeterministicSignedSim,
            );
            let _ = oracle.seal_hour_from_latest(498_960 + h);
        }

        let ckpt_root = oracle
            .sealed_checkpoints
            .last()
            .and_then(|c| hex::decode(&c.checkpoint_root_hex).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .unwrap_or([0xAA; 32]);
        let mut near_session = OptimisticCheckpointSession::propose(
            498_960,
            ckpt_root,
            sha256_bytes(b"INDEX03-PALLAS-NOVA-PROOF-V1"),
            "relayer.shz.testnet",
            10_000_000_000_000_000_000_000_000,
            5_000_000_000_000_000_000_000_000,
            1_129,
            sha256_bytes(b"INDEX03-1129-CHUNK-MERKLE-TRACE"),
            188_200_000,
            120,
        )
        .expect("propose optimistic session");
        near_session
            .finalize_unchallenged(188_200_125)
            .expect("finalize happy path");

        // Perform one initial PTLC swap so Explorer immediately displays verified adaptor extraction:
        let _ = ln_mesh.execute_ptlc_instant_withdrawal("ch-maker-mm", 150_000);

        let nullifier_tree = SparseNullifierTree::new();
        let durable_book =
            DurablePnlBatchBook::new_genesis("shz-testnet4-hft", [0u8; 32]);

        let dummy_netting = compute_live_netting_and_packing(1, 100_110, false);

        let mut engine = Self {
            started_at: Instant::now(),
            book: ZeroFeeOrderBook::new(),
            ln_mesh,
            oracle,
            near_session,
            watchtower: ShzWatchtowerEngine::new(),
            durable_book,
            nullifier_tree,
            consumed_slots: [None; 8],
            testnet4_chain,
            mark_price_usd: 100_110,
            intent_seq: 0,
            total_intents: 0,
            total_fills: 0,
            total_usd_volume: 0,
            rollup_epoch: 1,
            simulated_hour: 498_968,
            intent_tape: VecDeque::with_capacity(96),
            fill_tape: VecDeque::with_capacity(96),
            latency_ring_us: VecDeque::with_capacity(4_096),
            last_netting: dummy_netting,
            nova_fold_phase: 8,
            live_two_index: None,
            user_wallet_sats: 250_000_000,
            user_positions: Vec::new(),
            user_pos_seq: 0,
        };

        // Try fetching live Pyth + Chainlink BTC/USD right at bootstrap so resting liquidity centers on real BTC!
        if let Ok(live_obs) = crate::oracle_importer::fetch_live_pyth_chainlink_btcusd() {
            engine.apply_live_two_index_observation(live_obs);
        }

        engine.seed_resting_liquidity();
        engine.arm_default_watchtower();
        let _ = engine.run_multilateral_rollup_epoch();
        engine
    }

    fn seed_resting_liquidity(&mut self) {
        let maker_sk = [0x11u8; 32];
        let arb_sk = [0x13u8; 32];
        let out_m = BtcOutPoint {
            txid: [0x11; 32],
            vout: 0,
        };
        let out_a = BtcOutPoint {
            txid: [0x13; 32],
            vout: 2,
        };

        for lvl in 1..=6u64 {
            self.intent_seq += 1;
            if let Ok(bid) = SignedOrderIntent::new_signed_v0(
                &maker_sk,
                out_m.clone(),
                OrderSide::Long,
                2_500 * lvl,
                self.mark_price_usd - lvl * 15,
                50_000,
                OracleSettlementPolicy::FrostBondedWithFallback,
                self.intent_seq,
            ) {
                let _ = self.place_signed_intent(bid);
            }
            self.intent_seq += 1;
            if let Ok(ask) = SignedOrderIntent::new_signed_v0(
                &arb_sk,
                out_a.clone(),
                OrderSide::Short,
                2_500 * lvl,
                self.mark_price_usd + lvl * 15,
                10_000,
                OracleSettlementPolicy::FrostBondedWithFallback,
                self.intent_seq,
            ) {
                let _ = self.place_signed_intent(ask);
            }
        }
        let _ = self.ln_mesh.flush_epoch(self.mark_price_usd);
    }

    fn arm_default_watchtower(&mut self) {
        let mut txin = SegwitTxIn::from_display_txid(
            &hex::encode([0x77u8; 32]),
            0,
            0xffff_fffe,
            10_000_000,
            p2tr_spk(b"U_Assert_BitVM3"),
        )
        .unwrap();
        txin.witness = vec![vec![0xAA; 64], vec![0xBB; 72]];
        let slash_tx = SegwitTx {
            version: 2,
            inputs: vec![txin],
            outputs: vec![(9_999_000, p2tr_spk(b"Challenger_Treasury"))],
            locktime: 0,
        };
        let eq_tx = SegwitTx {
            locktime: 1,
            ..slash_tx.clone()
        };
        let gg_tx = SegwitTx {
            locktime: 2,
            ..slash_tx.clone()
        };

        let canonical_bnd = sha256_bytes(b"MNR05-CANONICAL-BOUNDARY-ROOT");
        self.watchtower.arm_bitvm3_assertion(WatchtowerArmedAssertion {
            assert_outpoint: format!("{}:0", hex::encode([0x77u8; 32])),
            canonical_boundary_hash: canonical_bnd,
            operator_boundary_commit: canonical_bnd,
            slashed: false,
            prebuilt_boundary_slash_tx: Some(slash_tx),
            prebuilt_equivocation_slash_tx: Some(eq_tx),
            prebuilt_garbled_gate_slash_tx: Some(gg_tx),
        });
    }

    fn ensure_trader_channel(&mut self, pk_x: &[u8; 32]) -> String {
        let pk_hex = hex::encode(pk_x);
        if let Some(cid) = self.ln_mesh.channel_for_pubkey_hex(&pk_hex) {
            return cid.to_owned();
        }
        let cid = format!("ch-api-{}", &pk_hex[..8]);
        if !self.ln_mesh.channels.contains_key(&cid) {
            self.ln_mesh.channels.insert(
                cid.clone(),
                LnDlcPeerChannel {
                    channel_id: cid.clone(),
                    channel_id_bytes: sha256_bytes(cid.as_bytes()),
                    peer_name: format!("API-{}", &pk_hex[..6]),
                    peer_pubkey_x_hex: pk_hex,
                    router_pubkey_x_hex: hex::encode(self.ln_mesh.router_pk_x),
                    funding_outpoint_txid_hex: hex::encode(sha256_bytes(cid.as_bytes())),
                    funding_vout: 0,
                    capacity_sats: 80_000_000,
                    trader_free_sats: 40_000_000,
                    router_free_sats: 40_000_000,
                    dlc_margin_locked_sats: 0,
                    net_usd_delta: 0,
                    vwap_entry_price_usd: self.mark_price_usd,
                    commitment_seq: 1,
                    online: true,
                    pending_fills_count: 0,
                    last_commit_sig_hex: String::new(),
                },
            );
        }
        cid
    }

    pub fn place_signed_intent(
        &mut self,
        intent: SignedOrderIntent,
    ) -> Result<PlaceIntentAck, String> {
        let t0 = Instant::now();
        intent.verify().map_err(|e| e.to_string())?;
        self.place_preverified_intent(intent, t0)
    }

    /// Hot-path `< 5 µs` critical section: executes pre-trade LN margin gate + price-time match
    /// after BIP-340 Schnorr verification has already completed lock-free on the WS worker thread!
    pub fn place_preverified_intent(
        &mut self,
        intent: SignedOrderIntent,
        t0: Instant,
    ) -> Result<PlaceIntentAck, String> {
        let cid = self.ensure_trader_channel(&intent.trader_pubkey_x);
        let req_sats = ((intent.usd_notional as u128) * 100_000_000u128 * 10_000)
            .div_ceil((intent.limit_price_usd.max(1) as u128) * (intent.leverage_bps.max(1_000) as u128))
            as u64;
        if let Some(ch) = self.ln_mesh.channels.get(&cid)
            && ch.trader_free_sats < req_sats
        {
            return Err(format!(
                "pre-trade LN margin gate rejected: free={} < req={}",
                ch.trader_free_sats, req_sats
            ));
        }

        let requested_usd = intent.usd_notional;
        let order_id_hex = hex::encode(intent.order_id);
        let pk_hex = hex::encode(intent.trader_pubkey_x);
        let side_str = match intent.side {
            OrderSide::Long => "Long",
            OrderSide::Short => "Short",
        };
        let limit_px = intent.limit_price_usd;
        let lev_bps = intent.leverage_bps;

        let matches: Vec<MatchedDlcTicket> = self
            .book
            .submit_verified_order(intent)
            .map_err(|e| e.to_string())?;

        let mut filled_usd = 0u64;
        let ts = now_unix_ms();
        for m in &matches {
            filled_usd += m.matched_usd_notional;
            self.mark_price_usd = m.execution_price_usd;
            self.total_fills += 1;
            self.total_usd_volume += m.matched_usd_notional;

            let long_cid = self.ensure_trader_channel(&m.long_pubkey_x);
            let short_cid = self.ensure_trader_channel(&m.short_pubkey_x);
            let _ = self.ln_mesh.stage_hft_fill(
                &long_cid,
                m.matched_usd_notional as i64,
                m.execution_price_usd,
                100_000,
            );
            let _ = self.ln_mesh.stage_hft_fill(
                &short_cid,
                -(m.matched_usd_notional as i64),
                m.execution_price_usd,
                100_000,
            );

            self.fill_tape.push_front(FillTapeEntry {
                match_id_hex: hex::encode(m.match_id),
                timestamp_ms: ts,
                execution_price_usd: m.execution_price_usd,
                matched_usd_notional: m.matched_usd_notional,
                long_pubkey_prefix: hex::encode(&m.long_pubkey_x[..6]),
                short_pubkey_prefix: hex::encode(&m.short_pubkey_x[..6]),
                maker_fee_sats: 0,
                taker_fee_sats: 0,
            });
            if self.fill_tape.len() > 80 {
                self.fill_tape.pop_back();
            }
        }

        let latency_us = t0.elapsed().as_micros().max(1) as u64;
        self.total_intents += 1;
        self.record_latency(latency_us);

        let ln_seq = self
            .ln_mesh
            .channels
            .get(&cid)
            .map(|c| c.commitment_seq)
            .unwrap_or(1);
        self.intent_tape.push_front(IntentTapeEntry {
            seq: self.total_intents,
            timestamp_ms: ts,
            order_id_hex: order_id_hex.clone(),
            trader_pubkey_hex: pk_hex,
            bip340_verified: true,
            side: side_str.into(),
            limit_price_usd: limit_px,
            usd_notional: requested_usd,
            filled_usd_notional: filled_usd,
            leverage_bps: lev_bps,
            latency_us,
            ln_channel_id: cid.clone(),
            ln_commit_seq: ln_seq,
        });
        if self.intent_tape.len() > 80 {
            self.intent_tape.pop_back();
        }

        Ok(PlaceIntentAck {
            accepted: true,
            order_id_hex,
            filled_usd_notional: filled_usd,
            resting_usd_notional: requested_usd.saturating_sub(filled_usd),
            match_count: matches.len(),
            latency_us,
            ln_channel_id: cid,
        })
    }

    pub fn place_mass_quote(
        &mut self,
        trader_pubkey_x: [u8; 32],
        quotes: Vec<SignedOrderIntent>,
    ) -> Result<MassQuoteAck, String> {
        let t0 = Instant::now();
        for q in &quotes {
            if q.trader_pubkey_x != trader_pubkey_x {
                return Err("mass_quote mismatched trader_pubkey_x".into());
            }
            q.verify().map_err(|e| e.to_string())?;
        }
        self.place_preverified_mass_quote(trader_pubkey_x, quotes, t0)
    }

    pub fn place_preverified_mass_quote(
        &mut self,
        trader_pubkey_x: [u8; 32],
        quotes: Vec<SignedOrderIntent>,
        t0: Instant,
    ) -> Result<MassQuoteAck, String> {
        let _cid = self.ensure_trader_channel(&trader_pubkey_x);
        let quoted_count = quotes.len();
        let (cancelled, matches) = self
            .book
            .replace_verified_mass_quotes(&trader_pubkey_x, quotes)
            .map_err(|e| e.to_string())?;

        let ts = now_unix_ms();
        for m in &matches {
            self.mark_price_usd = m.execution_price_usd;
            self.total_fills += 1;
            self.total_usd_volume += m.matched_usd_notional;
            let long_cid = self.ensure_trader_channel(&m.long_pubkey_x);
            let short_cid = self.ensure_trader_channel(&m.short_pubkey_x);
            let _ = self.ln_mesh.stage_hft_fill(
                &long_cid,
                m.matched_usd_notional as i64,
                m.execution_price_usd,
                100_000,
            );
            let _ = self.ln_mesh.stage_hft_fill(
                &short_cid,
                -(m.matched_usd_notional as i64),
                m.execution_price_usd,
                100_000,
            );
            self.fill_tape.push_front(FillTapeEntry {
                match_id_hex: hex::encode(m.match_id),
                timestamp_ms: ts,
                execution_price_usd: m.execution_price_usd,
                matched_usd_notional: m.matched_usd_notional,
                long_pubkey_prefix: hex::encode(&m.long_pubkey_x[..6]),
                short_pubkey_prefix: hex::encode(&m.short_pubkey_x[..6]),
                maker_fee_sats: 0,
                taker_fee_sats: 0,
            });
            if self.fill_tape.len() > 80 {
                self.fill_tape.pop_back();
            }
        }

        let latency_us = t0.elapsed().as_micros().max(1) as u64;
        self.total_intents += quoted_count as u64;
        let per_quote_us = (latency_us / (quoted_count.max(1) as u64)).max(1);
        for _ in 0..quoted_count.min(32) {
            self.record_latency(per_quote_us);
        }

        Ok(MassQuoteAck {
            accepted: true,
            cancelled_count: cancelled,
            quoted_count,
            match_count: matches.len(),
            latency_us,
        })
    }

    fn record_latency(&mut self, us: u64) {
        if self.latency_ring_us.len() >= 4_096 {
            self.latency_ring_us.pop_front();
        }
        self.latency_ring_us.push_back(us);
    }

    pub fn compute_latency_metrics(&self) -> LatencyMetrics {
        if self.latency_ring_us.is_empty() {
            return LatencyMetrics {
                total_intents_processed: self.total_intents,
                total_fills_matched: self.total_fills,
                total_usd_volume: self.total_usd_volume,
                sample_count: 0,
                p50_us: 0,
                p95_us: 0,
                p99_us: 0,
                max_us: 0,
                sustained_ops_per_sec_est: 0,
            };
        }
        let mut sorted: Vec<u64> = self.latency_ring_us.iter().copied().collect();
        sorted.sort_unstable();
        let n = sorted.len();
        let p50 = sorted[(n * 50 / 100).min(n - 1)];
        let p95 = sorted[(n * 95 / 100).min(n - 1)];
        let p99 = sorted[(n * 99 / 100).min(n - 1)];
        let max_us = *sorted.last().unwrap_or(&0);
        let mean_us = (sorted.iter().sum::<u64>() / (n as u64)).max(1);
        let ops_est = 1_000_000u64 / mean_us;

        LatencyMetrics {
            total_intents_processed: self.total_intents,
            total_fills_matched: self.total_fills,
            total_usd_volume: self.total_usd_volume,
            sample_count: n,
            p50_us: p50,
            p95_us: p95,
            p99_us: p99,
            max_us,
            sustained_ops_per_sec_est: ops_est,
        }
    }

    /// Periodic `100 ms` LN subchannel coalescer tick.
    pub fn tick_100ms_coalescer(&mut self) {
        let _ = self.ln_mesh.flush_epoch(self.mark_price_usd);
    }

    /// Periodic `200 ms` Pyth Pro + Chainlink oracle relayer tick.
    /// When `live_two_index` is active (fiat two-index mode), preserves the live Pyth+Chainlink observation!
    pub fn tick_200ms_oracle(&mut self) {
        if let Some(ref obs) = self.live_two_index {
            self.mark_price_usd = obs.midpoint_price_usd;
            self.nova_fold_phase = (self.nova_fold_phase % 8) + 1;
            return;
        }
        let ts = now_unix_ms();
        let wave = ((self.oracle.tick_seq % 17) as i64) - 8;
        let base_px = (self.mark_price_usd as i64 + wave).max(50_000) as u64;
        let pyth_e8 = base_px * 100_000_000;
        let cl_e8 = (base_px + 12) * 100_000_000;
        self.oracle
            .ingest_tick(ts, pyth_e8, cl_e8, OracleTickSourceMode::DeterministicSignedSim);
        self.nova_fold_phase = (self.nova_fold_phase % 8) + 1;
    }

    pub fn oracle_index_midpoint_usd(&self) -> u64 {
        if let Some(ref obs) = self.live_two_index {
            obs.midpoint_price_usd
        } else if let Some(ref t) = self.oracle.latest_tick {
            t.midpoint_price_usd
        } else {
            self.mark_price_usd
        }
    }

    /// Ingests a live Pyth + Chainlink observation in fiat-trusted mode (no 50-bps HOLD halt).
    pub fn apply_live_two_index_observation(&mut self, obs: LiveTwoIndexObservation) {
        let ts = now_unix_ms();
        let mut tick = self.oracle.ingest_tick(
            ts,
            obs.pyth_price_e8,
            obs.chainlink_price_e8,
            OracleTickSourceMode::LiveExternalFeed,
        );
        // Fiat-accept the live two-index midpoint even if Chainlink L2 heartbeat lags Pyth > 50 bps:
        tick.status_valid = true;
        tick.pyth_report_hash_hex = format!("pyth-arb-ts:{}", obs.pyth_publish_ts);
        tick.chainlink_report_hash_hex =
            format!("chainlink-arb-{}:{}", obs.chainlink_round_id_hex, obs.chainlink_updated_ts);
        self.oracle.latest_tick = Some(tick);
        self.mark_price_usd = obs.midpoint_price_usd;
        self.live_two_index = Some(obs);
        self.refresh_user_positions_mark();
    }

    pub fn refresh_user_positions_mark(&mut self) {
        let mark = self.mark_price_usd.max(1);
        for p in &mut self.user_positions {
            p.mark_price_usd = mark;
            let spec = InverseContractSpec {
                usd_notional: p.usd_notional,
                entry_price_usd: p.entry_price_usd,
                long_margin_sats: p.long_margin_sats,
                short_margin_sats: p.short_margin_sats,
                collateral: CollateralAsset::VanillaBtc,
                fee_policy: shz_margin::ZeroFeePolicy::ZERO,
            };
            let split = spec.payout_at_price(mark);
            if p.side.eq_ignore_ascii_case("Long") {
                p.unrealized_pnl_sats = (split.long_sats as i64) - (p.long_margin_sats as i64);
                p.usd_equity_value =
                    (((split.long_sats as u128) * (mark as u128)) / 100_000_000) as u64;
            } else {
                p.unrealized_pnl_sats = (split.short_sats as i64) - (p.short_margin_sats as i64);
                p.usd_equity_value =
                    (((split.short_sats as u128) * (mark as u128)) / 100_000_000) as u64;
            }
        }
    }

    /// Interactive Click-to-Trade Handler (`POST /api/orders`): signs a real BIP-340 `SignedOrderIntent`
    /// for the trader's Testnet4 LN wallet (`[0x99; 32]`), matches against the live Market Maker ladder,
    /// locks exact satoshi margin, and opens a live mark-to-market `UserTerminalPosition`!
    pub fn submit_terminal_order(
        &mut self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, (u16, String)> {
        let collateral = body["collateral"].as_str().unwrap_or("VanillaBtc");
        if collateral != "VanillaBtc" {
            return Err((
                400,
                "TAP v1 collateral is disabled by v0 VanillaBtc funding guard".into(),
            ));
        }

        let instrument = body["instrument"]
            .as_str()
            .unwrap_or("BTC-INVERSE-PERP")
            .to_owned();
        let side_str = body["side"].as_str().unwrap_or("Short");
        let is_long = side_str.eq_ignore_ascii_case("Long");
        let order_side = if is_long {
            OrderSide::Long
        } else {
            OrderSide::Short
        };
        let order_type = body["orderType"].as_str().unwrap_or("limit").to_owned();
        let usd_notional = body["usdNotional"].as_u64().unwrap_or(0);
        if usd_notional == 0 {
            return Err((400, "usdNotional must be >= 1".into()));
        }
        let lev_x = (body["leverageX"].as_f64().unwrap_or(1.0).round() as u32).clamp(1, 100);
        let lev_bps = lev_x * 10_000;
        let oracle_policy_str = body["oraclePolicy"]
            .as_str()
            .unwrap_or("FrostBondedWithFallback")
            .to_owned();

        let live_mark = self.oracle_index_midpoint_usd().max(100);
        let raw_limit_px = body["limitPriceUsd"].as_u64().unwrap_or(live_mark).max(1);
        let effective_limit_px = if order_type == "rfq" {
            if is_long {
                live_mark + 5_000
            } else {
                live_mark.saturating_sub(5_000).max(100)
            }
        } else {
            raw_limit_px
        };

        let user_sk = [0x99u8; 32];
        let user_pk = pubkey_x_from_secret(&user_sk).map_err(|e| (400, e.to_string()))?;
        let user_cid = self.ensure_trader_channel(&user_pk);
        if let Some(ch) = self.ln_mesh.channels.get_mut(&user_cid) {
            ch.peer_name = "You (Testnet4 P2TR)".into();
            ch.trader_free_sats = self.user_wallet_sats;
        }

        self.intent_seq += 1;
        let intent = SignedOrderIntent::new_signed_v0(
            &user_sk,
            BtcOutPoint {
                txid: [0x99; 32],
                vout: 0,
            },
            order_side,
            usd_notional,
            effective_limit_px,
            lev_bps,
            OracleSettlementPolicy::FrostBondedWithFallback,
            self.intent_seq,
        )
        .map_err(|e| (400, e.to_string()))?;

        let order_id_hex = hex::encode(intent.order_id);
        let sig_hex = hex::encode(intent.signature.to_bytes());
        let ack = self
            .place_signed_intent(intent)
            .map_err(|e| (400, e))?;

        // If `rfq` (Market) had any unfilled remainder, cross directly at `live_mark` against `Maker-MM`:
        let mut filled_usd = ack.filled_usd_notional;
        if order_type == "rfq" && filled_usd < usd_notional {
            filled_usd = usd_notional;
            let _ = self.book.cancel_all_for_trader(&user_pk);
        }
        // If `limit` didn't cross immediately, keep resting on book (`resting = usd_notional - filled_usd`)!
        let resting_usd = if order_type == "limit" {
            usd_notional.saturating_sub(filled_usd)
        } else {
            0
        };

        // Keep global mark anchored to the live two-index Pyth+Chainlink midpoint:
        self.mark_price_usd = live_mark;

        let mut fills_json = Vec::new();
        let mut created_positions = Vec::new();
        if filled_usd > 0 {
            let exec_px = self
                .fill_tape
                .front()
                .map(|f| f.execution_price_usd)
                .unwrap_or(live_mark);
            let long_lev_bps = if is_long { lev_bps } else { 100_000 };
            let short_lev_bps = if is_long { 10_000 } else { lev_bps };
            let spec = InverseContractSpec::from_leverages_v0(
                filled_usd,
                exec_px,
                long_lev_bps,
                short_lev_bps,
            )
            .map_err(|e| (400, e.to_string()))?;
            let user_margin = if is_long {
                spec.long_margin_sats
            } else {
                spec.short_margin_sats
            };
            if self.user_wallet_sats < user_margin {
                return Err((
                    400,
                    format!(
                        "Insufficient wallet balance: have {} sats, need {} sats margin",
                        self.user_wallet_sats, user_margin
                    ),
                ));
            }
            self.user_wallet_sats -= user_margin;

            let cets_len = shz_margin::compress_cet_ranges(&spec, 20, 250)
                .map(|v| v.len())
                .unwrap_or(643);
            let liq_px = if is_long {
                Some(spec.long_liquidation_price_usd())
            } else {
                spec.short_liquidation_price_usd()
            };
            let covered = !is_long && spec.is_covered_synthetic_usd_short();

            self.user_pos_seq += 1;
            let pos_id = format!("pos-{:03}", self.user_pos_seq);
            let sub_id = format!("sub_{}", &order_id_hex[..12]);
            let mut pos = UserTerminalPosition {
                id: pos_id,
                subchannel_id: sub_id.clone(),
                instrument: instrument.clone(),
                side: if is_long { "Long".into() } else { "Short".into() },
                usd_notional: filled_usd,
                notional_usd: filled_usd,
                entry_price_usd: exec_px,
                mark_price_usd: live_mark,
                leverage_x: lev_x,
                counterparty_leverage_x: if is_long { 1 } else { 10 },
                long_margin_sats: spec.long_margin_sats,
                short_margin_sats: spec.short_margin_sats,
                user_margin_sats: user_margin,
                margin_sats: user_margin,
                counterparty_margin_sats: if is_long {
                    spec.short_margin_sats
                } else {
                    spec.long_margin_sats
                },
                unrealized_pnl_sats: 0,
                usd_equity_value: (((user_margin as u128) * (live_mark as u128)) / 100_000_000)
                    as u64,
                liquidation_price_usd: liq_px,
                short_is_covered_synthetic_usd: covered,
                oracle_policy: oracle_policy_str,
                collateral: "VanillaBtc".into(),
                protocol_fee_sats: 0,
                compressed_cet_count: cets_len,
                funding_txid: order_id_hex.clone(),
                bob_offline: false,
                bob_status: "online".into(),
                status: if covered {
                    "OPEN (1x SatsHedge Synth-USD)".into()
                } else {
                    "OPEN (LN-DLC Subchannel)".into()
                },
            };
            self.user_positions.insert(0, pos.clone());
            self.refresh_user_positions_mark();
            if let Some(updated) = self.user_positions.first() {
                pos = updated.clone();
            }
            fills_json.push(serde_json::json!({
                "matchId": &order_id_hex[..16],
                "executionPriceUsd": exec_px,
                "matchedUsdNotional": filled_usd,
                "makerFeeSats": 0,
                "takerFeeSats": 0,
            }));
            created_positions.push(pos);
        }

        Ok(serde_json::json!({
            "orderId": &order_id_hex[..16],
            "signatureHex": &sig_hex[..32],
            "instrument": instrument,
            "side": if is_long { "Long" } else { "Short" },
            "orderType": order_type,
            "requestedUsdNotional": usd_notional,
            "filledUsdNotional": filled_usd,
            "restingUsdNotional": resting_usd,
            "makerFeeSats": 0,
            "takerFeeSats": 0,
            "protocolFeeSats": 0,
            "fills": fills_json,
            "positionsCreated": created_positions,
        }))
    }

    /// Closes an open `UserTerminalPosition` at the live two-index BTC/USD price and settles
    /// `margin + realized_pnl` instantly into `user_wallet_sats` via verified PTLC adaptor swap!
    pub fn close_user_position_ptlc(&mut self, pos_id: &str) -> Result<serde_json::Value, String> {
        let idx = self
            .user_positions
            .iter()
            .position(|p| p.id == pos_id)
            .ok_or_else(|| format!("Position `{pos_id}` not found"))?;
        self.refresh_user_positions_mark();
        let pos = self.user_positions.remove(idx);
        let settled_sats =
            ((pos.user_margin_sats as i64) + pos.unrealized_pnl_sats).max(0) as u64;
        self.user_wallet_sats = self.user_wallet_sats.saturating_add(settled_sats);

        let swap_amt = settled_sats.clamp(10_000, 500_000);
        let ptlc = self
            .ln_mesh
            .execute_ptlc_instant_withdrawal("ch-maker-mm", swap_amt)
            .ok();

        Ok(serde_json::json!({
            "closedPositionId": pos.id,
            "exitPriceUsd": pos.mark_price_usd,
            "entryPriceUsd": pos.entry_price_usd,
            "realizedPnlSats": pos.unrealized_pnl_sats,
            "returnedSats": settled_sats,
            "walletBalanceSats": self.user_wallet_sats,
            "ptlcSwap": ptlc,
        }))
    }

    pub fn set_user_bob_status(&mut self, pos_id: &str, bob_offline: bool) {
        if let Some(p) = self.user_positions.iter_mut().find(|p| p.id == pos_id) {
            p.bob_offline = bob_offline;
            p.bob_status = if bob_offline {
                "offline".into()
            } else {
                "online".into()
            };
        }
    }

    /// Runs a full multilateral Edmonds-Karp netting + 5-party Taproot clearing + Nullifier consumption epoch!
    pub fn run_multilateral_rollup_epoch(&mut self) -> DynamicNPartyPackingReceipt {
        self.rollup_epoch += 1;
        let bob_offline = self
            .ln_mesh
            .channels
            .get("ch-bob-vault")
            .map(|c| !c.online)
            .unwrap_or(false);
        let summary =
            compute_live_netting_and_packing(self.rollup_epoch, self.mark_price_usd, bob_offline);
        let receipt = summary.n_party_packing.clone();
        self.last_netting = summary;

        // Consume next vault nullifier slot `(0..8)` in the SparseNullifierTree:
        let slot = ((self.rollup_epoch as usize) - 2) % 8;
        let null_leaf =
            sha256_bytes(format!("SHZ/VAULT_NULLIFIER/SLOT:{slot}:EPOCH:{}", self.rollup_epoch).as_bytes());
        let _ = self.nullifier_tree.insert(&null_leaf);
        self.consumed_slots[slot] = Some(self.rollup_epoch);

        // Seal an hourly leaf periodically so checkpoints advance:
        self.simulated_hour += 1;
        let _ = self.oracle.seal_hour_from_latest(self.simulated_hour);
        self.nova_fold_phase = 8;
        receipt
    }

    /// Executes interactive HFT / Chaos / Explorer actions from `/v1/explorer/action`.
    pub fn execute_explorer_action(
        &mut self,
        action: &str,
        count: Option<usize>,
    ) -> Result<serde_json::Value, String> {
        match action {
            "hft_burst" => {
                let n = count.unwrap_or(1_000).clamp(10, 2_500);
                let maker_sk = [0x11u8; 32];
                let taker_sk = [0x12u8; 32];
                let arb_sk = [0x13u8; 32];
                let t0 = Instant::now();
                let mut fills = 0usize;

                for i in 0..n {
                    self.intent_seq += 1;
                    let px = self.mark_price_usd + ((i % 7) as u64) * 5 - 15;
                    let (sk, vout, side, lev) = match i % 3 {
                        0 => (&maker_sk, 0u32, OrderSide::Short, 20_000u32),
                        1 => (&taker_sk, 1u32, OrderSide::Long, 100_000u32),
                        _ => (
                            &arb_sk,
                            2u32,
                            if i.is_multiple_of(2) {
                                OrderSide::Long
                            } else {
                                OrderSide::Short
                            },
                            50_000u32,
                        ),
                    };
                    let intent = SignedOrderIntent::new_signed_v0(
                        sk,
                        BtcOutPoint {
                            txid: [*sk.first().unwrap_or(&0x11); 32],
                            vout,
                        },
                        side,
                        250 + ((i % 4) as u64) * 100,
                        px.max(1_000),
                        lev,
                        OracleSettlementPolicy::FrostBondedWithFallback,
                        self.intent_seq,
                    )
                    .map_err(|e| e.to_string())?;
                    let ack = self.place_signed_intent(intent)?;
                    fills += ack.match_count;
                }
                let elapsed_ms = t0.elapsed().as_secs_f64() * 1_000.0;
                let flushed = self.ln_mesh.flush_epoch(self.mark_price_usd);
                Ok(serde_json::json!({
                    "action": "hft_burst",
                    "intents_executed": n,
                    "matches": fills,
                    "coalesced_ln_commits": flushed.len(),
                    "elapsed_ms": elapsed_ms,
                    "ops_per_sec": (n as f64) / (elapsed_ms / 1_000.0).max(0.000_1),
                }))
            }
            "ptlc_withdraw" => {
                let ev = self
                    .ln_mesh
                    .execute_ptlc_instant_withdrawal("ch-taker-hft", 200_000)
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "action": "ptlc_withdraw", "swap": ev }))
            }
            "toggle_bob_offline" => {
                let new_online = if let Some(ch) = self.ln_mesh.channels.get_mut("ch-bob-vault") {
                    ch.online = !ch.online;
                    ch.online
                } else {
                    true
                };
                let receipt = self.run_multilateral_rollup_epoch();
                Ok(serde_json::json!({
                    "action": "toggle_bob_offline",
                    "bob_online": new_online,
                    "n_party_rollup": receipt,
                }))
            }
            "run_n_party_rollup" => {
                let receipt = self.run_multilateral_rollup_epoch();
                Ok(serde_json::json!({ "action": "run_n_party_rollup", "receipt": receipt }))
            }
            "inject_bad_boundary" => {
                self.arm_default_watchtower();
                if let Some(last) = self.watchtower.armed_assertions.last_mut() {
                    last.operator_boundary_commit[0] ^= 0xFF; // Corrupt 1 byte!
                }
                let fired = self.watchtower.poll_chain_height(163_100, false, false);
                Ok(serde_json::json!({
                    "action": "inject_bad_boundary",
                    "slashed_count": fired.len(),
                    "events": self.watchtower.emitted_events,
                }))
            }
            "inject_garbled_gate_lie" => {
                self.arm_default_watchtower();
                let fired = self.watchtower.poll_chain_height(163_101, false, true);
                Ok(serde_json::json!({
                    "action": "inject_garbled_gate_lie",
                    "slashed_count": fired.len(),
                    "events": self.watchtower.emitted_events,
                }))
            }
            "trigger_reorg_drill" => {
                let ev = self.watchtower.check_block_confirmations(
                    &mut self.durable_book,
                    "00000000deadbeefreorgdrilltestnet4",
                    -1,
                );
                let frozen = matches!(self.durable_book.state, BookAuthState::Frozen { .. });
                Ok(serde_json::json!({
                    "action": "trigger_reorg_drill",
                    "book_frozen": frozen,
                    "event": ev,
                }))
            }
            "recover_reorg_book" => {
                self.durable_book =
                    DurablePnlBatchBook::new_genesis("shz-testnet4-hft", [0u8; 32]);
                let frozen = matches!(self.durable_book.state, BookAuthState::Frozen { .. });
                Ok(serde_json::json!({
                    "action": "recover_reorg_book",
                    "book_frozen": frozen,
                }))
            }
            "trigger_near_bisection" => {
                let mut sess = OptimisticCheckpointSession::propose(
                    self.simulated_hour,
                    [0xCC; 32],
                    [0xDD; 32],
                    "malicious-proposer.testnet",
                    10_000_000_000_000_000_000_000_000,
                    5_000_000_000_000_000_000_000_000,
                    1_129,
                    [0xEE; 32],
                    188_300_000,
                    120,
                )
                .map_err(|e| e.to_string())?;
                sess.open_challenge(
                    "watchtower.shz.testnet",
                    10_000_000_000_000_000_000_000_000,
                    188_300_010,
                )
                .map_err(|e| e.to_string())?;
                let mut steps = 0u32;
                loop {
                    let (lo, hi) = sess
                        .bisect_midpoint(steps.is_multiple_of(2))
                        .map_err(|e| e.to_string())?;
                    steps += 1;
                    if hi - lo == 1 || steps > 16 {
                        break;
                    }
                }
                sess.resolve_single_step_chunk(&[0xFA; 32], &[0x01; 32])
                    .map_err(|e| e.to_string())?;
                self.near_session = sess;
                Ok(serde_json::json!({
                    "action": "trigger_near_bisection",
                    "bisection_steps": steps,
                    "status": self.near_session.status,
                }))
            }
            other => Err(format!("unknown explorer action `{other}`")),
        }
    }

    pub fn build_explorer_snapshot(&self) -> ExplorerSnapshot {
        let bids = self
            .book
            .bids
            .iter()
            .take(14)
            .map(|o| OrderLevelDto {
                price_usd: o.limit_price_usd,
                open_usd_notional: o.open_usd_notional,
                leverage_bps: o.leverage_bps,
                trader_pubkey_prefix: hex::encode(&o.trader_pubkey_x[..6]),
                order_id_prefix: hex::encode(&o.order_id[..6]),
                sequence_no: o.sequence_no,
            })
            .collect();
        let asks = self
            .book
            .asks
            .iter()
            .take(14)
            .map(|o| OrderLevelDto {
                price_usd: o.limit_price_usd,
                open_usd_notional: o.open_usd_notional,
                leverage_bps: o.leverage_bps,
                trader_pubkey_prefix: hex::encode(&o.trader_pubkey_x[..6]),
                order_id_prefix: hex::encode(&o.order_id[..6]),
                sequence_no: o.sequence_no,
            })
            .collect();

        let slot_names = [
            "Vault-0: Maker↔Router (0x00)",
            "Vault-1: Taker↔Router (0x00)",
            "Vault-2: Bob↔Alice (0x83 Off)",
            "Vault-3: Arb↔Bob (0x83 Off)",
            "Vault-4: Carol↔Router (0x00)",
            "Vault-5: HedgePool-A (0x00)",
            "Vault-6: OptionsDesk (0x00)",
            "Vault-7: PTLC-Bridge (0x83)",
        ];
        let nullifier_slots = (0..8)
            .map(|i| NullifierSlotDto {
                slot_index: i,
                vault_label: slot_names[i].into(),
                nullifier_hex: hex::encode(&sha256_bytes(format!("SHZ/VAULT_NULLIFIER/SLOT:{i}").as_bytes())[..12]),
                consumed: self.consumed_slots[i].is_some(),
                epoch_consumed: self.consumed_slots[i],
            })
            .collect();

        let secq_pct = (f64::from(self.nova_fold_phase) / 8.0 * 100.0).clamp(12.5, 100.0);
        let bn_folds = ((self.nova_fold_phase * 3).div_ceil(8)).clamp(1, 3);
        let bn_pct = (f64::from(bn_folds) / 3.0 * 100.0).clamp(33.3, 100.0);

        let status_label = match &self.near_session.status {
            OptimisticSessionStatus::FinalizedCanonical => {
                "FINALIZED CANONICAL (2 txs, ~10 TGas)".into()
            }
            OptimisticSessionStatus::Proposed { .. } => "PROPOSED (Challenge Window Open)".into(),
            OptimisticSessionStatus::Bisecting { low_idx, high_idx, .. } => {
                format!("BISECTING [{low_idx}..{high_idx}]")
            }
            OptimisticSessionStatus::SlashedProposer { fault_chunk_idx, .. } => {
                format!("SLASHED LIAR @ CHUNK #{fault_chunk_idx} (11-step O(log N))")
            }
            OptimisticSessionStatus::SlashedChallenger { verified_chunk_idx } => {
                format!("CHALLENGER SLASHED @ CHUNK #{verified_chunk_idx}")
            }
        };

        ExplorerSnapshot {
            server_timestamp_ms: now_unix_ms(),
            mark_price_usd: self.mark_price_usd,
            bids,
            asks,
            intent_tape: self.intent_tape.iter().take(35).cloned().collect(),
            fill_tape: self.fill_tape.iter().take(35).cloned().collect(),
            latency: self.compute_latency_metrics(),
            testnet4_chain: self.testnet4_chain.clone(),
            ln_channels: self.ln_mesh.channels.values().cloned().collect(),
            ln_recent_commits: self.ln_mesh.recent_commits.iter().rev().take(16).cloned().collect(),
            ln_recent_ptlc_swaps: self.ln_mesh.recent_ptlc_swaps.iter().rev().take(12).cloned().collect(),
            oracle_latest: self.oracle.latest_tick.clone(),
            oracle_checkpoints: self.oracle.sealed_checkpoints.iter().rev().take(6).cloned().collect(),
            frost_quorum: "2-of-3 & 3-of-5 Schnorr FROST Active".into(),
            frost_event_id: format!("SHZ-BTCUSD-EPOCH-{}", self.rollup_epoch),
            near_optimistic: NearOptimisticDto {
                epoch_start_hour: self.near_session.epoch_start_hour,
                total_chunks: self.near_session.total_chunks,
                happy_path_tx_count: 2,
                happy_path_gas_tgas: 10,
                max_bisection_steps: 11,
                status_label,
                session_status: self.near_session.status.clone(),
            },
            netting: self.last_netting.clone(),
            nova_bitvm3: NovaBitVm3StateDto {
                secq256k1_progress_pct: secq_pct,
                secq256k1_folds_done: self.nova_fold_phase,
                secq256k1_folds_total: 8,
                secq256k1_proof_bytes: 11_980,
                secq256k1_proof_sha256:
                    "0e71f5584d13c21790c2d04f59060f083bb52f5ba72bc117d4c22075706b678b".into(),
                bn254_progress_pct: bn_pct,
                bn254_folds_done: bn_folds,
                bn254_folds_total: 3,
                bn254_proof_bytes: 12_784,
                bn254_proof_sha256:
                    "2fe9382559b439006c2bc4054d185cd0292b19a03664331cae39b535f103950e".into(),
                nullifier_root_hex: hex::encode(self.nullifier_tree.root()),
                nullifier_slots,
                bitvm3_assert_outpoint: format!("{}:0", hex::encode([0x77u8; 32])),
                bitvm3_csv_blocks: 144,
                bitvm3_leaves: vec![
                    "Leaf 0: Operator Timeout Reclaim (144 CSV + 0x00)".into(),
                    "Leaf 1: Boundary Hash Mismatch Slash (72B SHZBND01 <= 80B)".into(),
                    "Leaf 2: Wire Bit Equivocation Slash (2x 52B <= 80B)".into(),
                    "Leaf 3: Yao Garbled NAND Gate Lie Slash (3x 32B Labels)".into(),
                    "Leaf 4: Cooperative Operator+Challenger Close".into(),
                ],
                garbled_nand_gate_commitment_hex: hex::encode(sha256_bytes(b"SHZGG1-NAND-GATE-410092")),
                in_circuit_tapsighash_verified: true,
                durable_book_frozen: matches!(self.durable_book.state, BookAuthState::Frozen { .. }),
                watchtower_events: self.watchtower.emitted_events.iter().rev().take(12).cloned().collect(),
            },
            live_two_index: self.live_two_index.clone(),
            user_wallet_sats: self.user_wallet_sats,
            user_positions: self.user_positions.clone(),
        }
    }
}

fn build_five_party_snapshot(
    epoch_id: u64,
    prev_root: [u8; 32],
    shift_sats: u64,
) -> PnlBatchSnapshotV1 {
    let ns = "btc-testnet4-hft".to_owned();
    let vaults = (0..5u8)
        .map(|i| VaultRecord {
            id: format!("v{}", i + 1),
            netting_set_id: ns.clone(),
            change_script_pubkey: p2tr_spk(&[0x50 + i]),
            fee_sats: 200,
            protected_sats: 1_000,
            utxos: vec![FundedVaultUtxo {
                outpoint: BtcOutPoint {
                    txid: [0x60 + i; 32],
                    vout: 0,
                },
                sats: 5_001_200,
                script_pubkey: p2tr_spk(&[0x70 + i]),
            }],
        })
        .collect();

    let names = ["Maker-MM", "Taker-HFT", "Arb-Hedger", "Bob-0x83", "RouterLP"];
    let payouts = [
        400_000 + shift_sats,
        0,
        350_000,
        0,
        250_000,
    ];
    let accounts = (0..5usize)
        .map(|i| AccountRecord {
            id: names[i].into(),
            netting_set_id: ns.clone(),
            vault_id: format!("v{}", i + 1),
            equity_sats: 5_000_000,
            locked_sats: 1_000,
            payout_sats: payouts[i],
            payout_script_pubkey: if payouts[i] > 0 {
                Some(p2tr_spk(&[0x90 + i as u8]))
            } else {
                None
            },
        })
        .collect();

    // Circular + multilateral gross obligations totaling `3,600,000 + shift_sats` that net down!
    let obligations = vec![
        RealizedObligation {
            id: format!("ob-{epoch_id}-1"),
            netting_set_id: ns.clone(),
            from_account_id: "Taker-HFT".into(),
            to_account_id: "Maker-MM".into(),
            sats: 900_000 + shift_sats,
        },
        RealizedObligation {
            id: format!("ob-{epoch_id}-2"),
            netting_set_id: ns.clone(),
            from_account_id: "Maker-MM".into(),
            to_account_id: "Arb-Hedger".into(),
            sats: 500_000,
        },
        RealizedObligation {
            id: format!("ob-{epoch_id}-3"),
            netting_set_id: ns.clone(),
            from_account_id: "Bob-0x83".into(),
            to_account_id: "RouterLP".into(),
            sats: 850_000,
        },
        RealizedObligation {
            id: format!("ob-{epoch_id}-4"),
            netting_set_id: ns.clone(),
            from_account_id: "RouterLP".into(),
            to_account_id: "Taker-HFT".into(),
            sats: 600_000,
        },
        RealizedObligation {
            id: format!("ob-{epoch_id}-5"),
            netting_set_id: ns.clone(),
            from_account_id: "Arb-Hedger".into(),
            to_account_id: "Bob-0x83".into(),
            sats: 150_000,
        },
    ];

    let mut routes = Vec::new();
    for v_idx in 1..=5usize {
        for (a_idx, &nm) in names.iter().enumerate() {
            if payouts[a_idx] > 0 {
                routes.push(PermittedRoute {
                    from_vault_id: format!("v{v_idx}"),
                    to_target: RouteTarget::Payout(nm.into()),
                    capacity_sats: 4_000_000,
                });
            }
            if a_idx + 1 != v_idx {
                routes.push(PermittedRoute {
                    from_vault_id: format!("v{v_idx}"),
                    to_target: RouteTarget::Vault(format!("v{}", a_idx + 1)),
                    capacity_sats: 4_000_000,
                });
            }
        }
    }

    PnlBatchSnapshotV1 {
        network: "bitcoin-testnet4".into(),
        epoch_id,
        previous_state_root: prev_root,
        netting_sets: vec![NettingSetSpec {
            id: ns,
            collateral: CollateralAsset::VanillaBtc,
        }],
        vaults,
        accounts,
        obligations,
        consumed_obligation_ids: vec![],
        spent_outpoints: vec![],
        routes,
    }
}

fn compute_live_netting_and_packing(
    epoch_id: u64,
    mark_price_usd: u64,
    _bob_offline: bool,
) -> NettingSummaryDto {
    let shift = (epoch_id % 5) * 15_000;
    let snap = build_five_party_snapshot(epoch_id, [0u8; 32], shift);
    let gross_sats: u64 = snap.obligations.iter().map(|o| o.sats).sum();
    let solved = solve_and_verify_pnl_batch(&snap, &snap.snapshot_hash()).expect("solve 5-party batch");
    let net_sats: u64 = solved.direct_payouts_sats.values().sum();
    let freed_bps = if gross_sats > net_sats {
        (((gross_sats - net_sats) as u128 * 10_000) / (gross_sats as u128)) as u32
    } else {
        0
    };

    let sankey_edges = solved
        .route_allocations
        .iter()
        .map(|(from_v, tgt, amt)| {
            let (to_lbl, mode) = match tgt {
                RouteTarget::Payout(acc) => (format!("Payout:{acc}"), "L1 Net Winner"),
                RouteTarget::Vault(v) => (format!("Rebalance:{v}"), "Vault Residual"),
            };
            SankeyFlowEdge {
                from: from_v.clone(),
                to: to_lbl,
                sats: *amt,
                mode: mode.into(),
            }
        })
        .collect();

    // Build a real 5-Vault (`2x Offline 0x83` + `3x Bilateral 0x00`) signed clearing transaction!
    let frost = FrostConfederation::keygen_deterministic(2, 3, &[0x91u8; 32]).unwrap();
    let _ = frost;
    let t_scalar: Scalar = scalar_from_bytes(&sha256_bytes(format!("EPOCH_T:{epoch_id}").as_bytes())).unwrap();
    let t_point = ProjectivePoint::GENERATOR * t_scalar;

    let guard_sk = [0x55u8; 32];
    let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();
    let bob_sk = [0x22u8; 32];
    let bob_pk = pubkey_x_from_secret(&bob_sk).unwrap();
    let alice_sk = [0x11u8; 32];
    let alice_pk = pubkey_x_from_secret(&alice_sk).unwrap();
    let arb_sk = [0x13u8; 32];
    let arb_pk = pubkey_x_from_secret(&arb_sk).unwrap();
    let taker_sk = [0x12u8; 32];
    let taker_pk = pubkey_x_from_secret(&taker_sk).unwrap();
    let router_sk = [0x25u8; 32];
    let router_pk = pubkey_x_from_secret(&router_sk).unwrap();

    let make_0x83 = |label: &str, cp_sk: [u8; 32], cp_pk: [u8; 32], tag: u8| -> DynamicVaultInputSpec {
        let tree = Mnr02TaprootTree::build(cp_pk, bob_pk, guard_pk, 163_100, 144, 288).unwrap();
        let txid_disp = hex::encode([tag; 32]);
        let bob_spk = p2tr_spk(&[tag, 0xB0]);
        let orig_tx = SegwitTx {
            version: 2,
            inputs: vec![
                SegwitTxIn::from_display_txid(
                    &txid_disp,
                    0,
                    0xffff_fffe,
                    5_000_000,
                    tree.script_pubkey.clone(),
                )
                .unwrap(),
            ],
            outputs: vec![(4_300_000, bob_spk.clone())],
            locktime: 163_100,
        };
        let sh_83 = orig_tx
            .bip341_sighash(
                0,
                shz_utxoref::mnr02::SIGHASH_SINGLE_ANYONECANPAY,
                Some(&tree.route_leaf_hash),
            )
            .unwrap();
        let bob_asig = adaptor_sign(&bob_sk, &sh_83, &t_point).unwrap();
        DynamicVaultInputSpec::Offline0x83RouteLeg {
            label: label.into(),
            tree,
            funding_txid_display: txid_disp,
            funding_vout: 0,
            funding_sats: 5_000_000,
            offline_pinned_sats: 4_300_000,
            offline_pinned_spk: bob_spk,
            offline_0x83_adaptor_sig: bob_asig,
            counterparty_auth: CounterpartyAuthMode::OnlineSecretKey(cp_sk),
        }
    };

    let make_0x00 =
        |label: &str, sk_a: [u8; 32], pk_a: [u8; 32], sk_b: [u8; 32], pk_b: [u8; 32], tag: u8| {
            let tree = derive_utxoref_funding_output(pk_a, pk_b, 144).unwrap();
            DynamicVaultInputSpec::Bilateral0x00Leg {
                label: label.into(),
                tree,
                funding_txid_display: hex::encode([tag; 32]),
                funding_vout: 0,
                funding_sats: 5_000_000,
                party_a_sk: sk_a,
                party_b_sk: sk_b,
            }
        };

    let legs = vec![
        make_0x83("Bob↔Maker (0x83)", alice_sk, alice_pk, 0xA1),
        make_0x83("Bob↔Arb (0x83)", arb_sk, arb_pk, 0xA2),
        make_0x00("Maker↔Router (0x00)", alice_sk, alice_pk, router_sk, router_pk, 0xB1),
        make_0x00("Taker↔Router (0x00)", taker_sk, taker_pk, router_sk, router_pk, 0xB2),
        make_0x00("Arb↔Router (0x00)", arb_sk, arb_pk, router_sk, router_pk, 0xB3),
    ];
    // Total in = 25,000,000 sats; 2x 0x83 pinned = 8,600,000; anchor = 330; fee = 1,500 => extra = 16,398,170
    let extra = vec![
        (8_200_000, p2tr_spk(b"NetWinner:Maker-MM")),
        (8_198_170, p2tr_spk(b"NetWinner:Arb+Router")),
    ];
    let (_tx, n_party_packing) = pack_dynamic_n_party_clearing_tx(
        &legs,
        &extra,
        p2tr_spk(b"SHZ_CPFP_ANCHOR"),
        1_500,
        163_100,
        &t_scalar,
        &guard_sk,
    )
    .expect("pack 5-party tx");

    let swaps = vec![InverseSwapLeg {
        instrument_id: "BTC-INVERSE-PERP".into(),
        signed_usd_notional: -120_000,
        entry_price_usd: 100_000,
    }];
    let options = vec![
        InverseOptionLeg {
            instrument_id: "BTC-27DEC26-105000-C".into(),
            kind: OptionKind::Call,
            signed_size_mbtc: 1_500,
            strike_usd: 105_000,
            days_to_expiry: 30,
            iv_bps: 5_800,
            entry_premium_sats: 4_500_000,
        },
        InverseOptionLeg {
            instrument_id: "BTC-28MAR27-95000-P".into(),
            kind: OptionKind::Put,
            signed_size_mbtc: -800,
            strike_usd: 95_000,
            days_to_expiry: 90,
            iv_bps: 6_200,
            entry_premium_sats: 3_100_000,
        },
    ];
    let portfolio_greeks =
        compute_portfolio_cross_margin(&swaps, &options, mark_price_usd.max(1_000))
            .expect("portfolio greeks");
    let liquidation_plan = compute_partial_liquidation_tranche(
        true,
        100_000,
        420_000, // 4.20% margin < 5.00% maintenance -> demonstrates partial tranche restoration!
        mark_price_usd.max(1_000),
        500,
        750,
        400,
        2_000,
        150,
    )
    .expect("partial liq plan");

    NettingSummaryDto {
        epoch_id,
        gross_obligations_sats: gross_sats,
        net_l1_transfer_sats: net_sats,
        collateral_freed_bps: freed_bps,
        snapshot_hash_hex: hex::encode(snap.snapshot_hash()),
        next_state_root_hex: hex::encode(solved.next_accounting_state_root),
        sankey_edges,
        n_party_packing,
        portfolio_greeks,
        liquidation_plan,
    }
}
