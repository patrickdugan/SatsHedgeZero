//! Automated L1 Reorg, Unilateral `CLTV`, and BitVM3 Fraud-Slash Watchtower Engine (`Track 3`).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::{mnr02::SegwitTx, pnl_batch::DurablePnlBatchBook};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchtowerActionKind {
    FreezeDurableBookOnReorg {
        invalidated_block_hash: String,
        confirmations: i64,
    },
    SlashBitVm3BoundaryMismatch {
        assert_outpoint: String,
        slash_txid: String,
    },
    SlashBitVm3WireEquivocation {
        assert_outpoint: String,
        slash_txid: String,
    },
    SlashBitVm3GarbledGateLie {
        assert_outpoint: String,
        slash_txid: String,
    },
    BroadcastUnilateralCltvExit {
        vault_id: String,
        fallback_txid: String,
        current_height: u32,
    },
}

#[derive(Debug, Clone)]
pub struct WatchtowerArmedUnilateral {
    pub vault_id: String,
    pub unilateral_cltv_height: u32,
    pub cleared_on_l1: bool,
    pub broadcasted: bool,
    pub signed_fallback_tx: SegwitTx,
}

#[derive(Debug, Clone)]
pub struct WatchtowerArmedAssertion {
    pub assert_outpoint: String,
    pub canonical_boundary_hash: [u8; 32],
    pub operator_boundary_commit: [u8; 32],
    pub slashed: bool,
    pub prebuilt_boundary_slash_tx: Option<SegwitTx>,
    pub prebuilt_equivocation_slash_tx: Option<SegwitTx>,
    pub prebuilt_garbled_gate_slash_tx: Option<SegwitTx>,
}

/// Deterministic Watchtower decision engine scanning block height, confirmations, and BitVM3 assertions.
#[derive(Debug, Default, Clone)]
pub struct ShzWatchtowerEngine {
    pub armed_unilaterals: Vec<WatchtowerArmedUnilateral>,
    pub armed_assertions: Vec<WatchtowerArmedAssertion>,
    pub emitted_events: Vec<WatchtowerActionKind>,
}

impl ShzWatchtowerEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arm_unilateral_exit(
        &mut self,
        vault_id: impl Into<String>,
        unilateral_cltv_height: u32,
        signed_fallback_tx: SegwitTx,
    ) {
        self.armed_unilaterals.push(WatchtowerArmedUnilateral {
            vault_id: vault_id.into(),
            unilateral_cltv_height,
            cleared_on_l1: false,
            broadcasted: false,
            signed_fallback_tx,
        });
    }

    pub fn arm_bitvm3_assertion(&mut self, assertion: WatchtowerArmedAssertion) {
        self.armed_assertions.push(assertion);
    }

    /// Evaluates reorg status on a tracked clearing block and freezes `book` immediately if `confirmations < 0`.
    pub fn check_block_confirmations(
        &mut self,
        book: &mut DurablePnlBatchBook,
        block_hash: &str,
        confirmations: i64,
    ) -> Option<WatchtowerActionKind> {
        if confirmations < 0 {
            book.freeze_on_reorg(&format!("watchtower-reorg:{block_hash}:{confirmations}"));
            let ev = WatchtowerActionKind::FreezeDurableBookOnReorg {
                invalidated_block_hash: block_hash.to_owned(),
                confirmations,
            };
            self.emitted_events.push(ev.clone());
            return Some(ev);
        }
        None
    }

    /// Polls armed `U_Assert` contracts and `CLTV` unilateral exits at `current_height`, returning
    /// `(action_kind, raw_signed_segwit_tx)` pairs ready for immediate `sendrawtransaction`!
    pub fn poll_chain_height(
        &mut self,
        current_height: u32,
        equivocation_detected: bool,
        garbled_gate_lie_detected: bool,
    ) -> Vec<(WatchtowerActionKind, SegwitTx)> {
        let mut ready = Vec::new();

        for a in &mut self.armed_assertions {
            if a.slashed {
                continue;
            }
            if a.operator_boundary_commit != a.canonical_boundary_hash
                && let Some(ref tx) = a.prebuilt_boundary_slash_tx
            {
                a.slashed = true;
                let act = WatchtowerActionKind::SlashBitVm3BoundaryMismatch {
                    assert_outpoint: a.assert_outpoint.clone(),
                    slash_txid: tx.txid_hex(),
                };
                self.emitted_events.push(act.clone());
                ready.push((act, tx.clone()));
                continue;
            }
            if equivocation_detected
                && let Some(ref tx) = a.prebuilt_equivocation_slash_tx
            {
                a.slashed = true;
                let act = WatchtowerActionKind::SlashBitVm3WireEquivocation {
                    assert_outpoint: a.assert_outpoint.clone(),
                    slash_txid: tx.txid_hex(),
                };
                self.emitted_events.push(act.clone());
                ready.push((act, tx.clone()));
                continue;
            }
            if garbled_gate_lie_detected
                && let Some(ref tx) = a.prebuilt_garbled_gate_slash_tx
            {
                a.slashed = true;
                let act = WatchtowerActionKind::SlashBitVm3GarbledGateLie {
                    assert_outpoint: a.assert_outpoint.clone(),
                    slash_txid: tx.txid_hex(),
                };
                self.emitted_events.push(act.clone());
                ready.push((act, tx.clone()));
            }
        }

        for u in &mut self.armed_unilaterals {
            if !u.cleared_on_l1 && !u.broadcasted && current_height >= u.unilateral_cltv_height {
                u.broadcasted = true;
                let act = WatchtowerActionKind::BroadcastUnilateralCltvExit {
                    vault_id: u.vault_id.clone(),
                    fallback_txid: u.signed_fallback_tx.txid_hex(),
                    current_height,
                };
                self.emitted_events.push(act.clone());
                ready.push((act, u.signed_fallback_tx.clone()));
            }
        }

        ready
    }
}
