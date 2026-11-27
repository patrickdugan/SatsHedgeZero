//! `UTXORef` PnL Batch Netting (`PNL_BATCH_NETTING.md`), Edmonds-Karp Capacitated
//! Vault Allocation, and Durable Pre-Signing Reservation Book (`PNL_BATCH_EXECUTION.md`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use shz_dlc::{BtcOutPoint, tagged_hash};
use shz_margin::CollateralAsset;

use crate::UtxoRefError;

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct NettingSetSpec {
    pub id: String,
    pub collateral: CollateralAsset,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct FundedVaultUtxo {
    pub outpoint: BtcOutPoint,
    pub sats: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct VaultRecord {
    pub id: String,
    pub netting_set_id: String,
    pub change_script_pubkey: Vec<u8>,
    pub fee_sats: u64,
    pub protected_sats: u64,
    pub utxos: Vec<FundedVaultUtxo>,
}

impl VaultRecord {
    pub fn total_input_sats(&self) -> Result<u64, UtxoRefError> {
        let mut acc = 0u64;
        for u in &self.utxos {
            acc = acc
                .checked_add(u.sats)
                .ok_or(UtxoRefError::AccountingViolation("vault UTXO sum overflow"))?;
        }
        Ok(acc)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct AccountRecord {
    pub id: String,
    pub netting_set_id: String,
    pub vault_id: String,
    pub equity_sats: u64,
    pub locked_sats: u64,
    pub payout_sats: u64,
    pub payout_script_pubkey: Option<Vec<u8>>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct RealizedObligation {
    pub id: String,
    pub netting_set_id: String,
    pub from_account_id: String,
    pub to_account_id: String,
    pub sats: u64,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum RouteTarget {
    Vault(String),
    Payout(String),
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct PermittedRoute {
    pub from_vault_id: String,
    pub to_target: RouteTarget,
    pub capacity_sats: u64,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct PnlBatchSnapshotV1 {
    pub network: String,
    pub epoch_id: u64,
    pub previous_state_root: [u8; 32],
    pub netting_sets: Vec<NettingSetSpec>,
    pub vaults: Vec<VaultRecord>,
    pub accounts: Vec<AccountRecord>,
    pub obligations: Vec<RealizedObligation>,
    pub consumed_obligation_ids: Vec<String>,
    pub spent_outpoints: Vec<BtcOutPoint>,
    pub routes: Vec<PermittedRoute>,
}

impl PnlBatchSnapshotV1 {
    pub fn snapshot_hash(&self) -> [u8; 32] {
        let bytes = borsh::to_vec(self).expect("Borsh serialization infallible");
        tagged_hash(b"SatsHedgeZero/UTXORef/SnapshotV1", &bytes)
    }
}

/// Explicit `UTXORef` evidence gates (`CLAIMS_MATRIX.md` / `PNL_BATCH_NETTING.md`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct BatchEvidenceFlags {
    pub accounting_verified: bool,
    pub execution_verified: bool,
    pub zk_proof_verified: bool,
    pub production_ready: bool,
}

impl BatchEvidenceFlags {
    pub const REFERENCE_ACCOUNTING: Self = Self {
        accounting_verified: true,
        execution_verified: false,
        zk_proof_verified: false,
        production_ready: false,
    };
}

/// Verified output of `solve_and_verify_pnl_batch`.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct VerifiedPnlSettlementBatch {
    pub epoch_id: u64,
    pub snapshot_hash: [u8; 32],
    pub net_account_deltas: BTreeMap<String, i128>,
    pub post_account_equities: BTreeMap<String, u64>,
    pub direct_payouts_sats: BTreeMap<String, u64>,
    pub vault_residuals_sats: BTreeMap<String, u64>,
    pub route_allocations: Vec<(String, RouteTarget, u64)>,
    pub total_input_sats: u64,
    pub total_fee_sats: u64,
    pub next_accounting_state_root: [u8; 32],
    pub evidence_flags: BatchEvidenceFlags,
}

#[derive(Clone)]
struct FlowEdge {
    to: usize,
    rev: usize,
    initial_cap: u64,
    res_cap: u64,
    route_meta: Option<(String, RouteTarget)>,
}

struct MaxFlowGraph {
    adj: Vec<Vec<FlowEdge>>,
}

impl MaxFlowGraph {
    fn new(n: usize) -> Self {
        Self {
            adj: vec![Vec::new(); n],
        }
    }

    fn add_edge(
        &mut self,
        from: usize,
        to: usize,
        cap: u64,
        route_meta: Option<(String, RouteTarget)>,
    ) {
        let from_rev = self.adj[to].len();
        let to_rev = self.adj[from].len();
        self.adj[from].push(FlowEdge {
            to,
            rev: from_rev,
            initial_cap: cap,
            res_cap: cap,
            route_meta,
        });
        self.adj[to].push(FlowEdge {
            to: from,
            rev: to_rev,
            initial_cap: 0,
            res_cap: 0,
            route_meta: None,
        });
    }

    /// Edmonds-Karp shortest-augmenting-path max-flow (`O(V * E^2)`).
    /// Defeats greedy-allocation starvation whenever a feasible alternative routing exists!
    fn edmonds_karp(&mut self, source: usize, sink: usize) -> u64 {
        let n = self.adj.len();
        let mut total_flow = 0u64;

        loop {
            let mut parent: Vec<Option<(usize, usize)>> = vec![None; n];
            let mut queue = VecDeque::new();
            queue.push_back(source);

            while let Some(u) = queue.pop_front() {
                if u == sink {
                    break;
                }
                for (edge_idx, e) in self.adj[u].iter().enumerate() {
                    if e.to != source && parent[e.to].is_none() && e.res_cap > 0 {
                        parent[e.to] = Some((u, edge_idx));
                        queue.push_back(e.to);
                    }
                }
            }

            if parent[sink].is_none() {
                break;
            }

            let mut push = u64::MAX;
            let mut cur = sink;
            while let Some((u, e_idx)) = parent[cur] {
                let rem = self.adj[u][e_idx].res_cap;
                push = push.min(rem);
                cur = u;
            }

            cur = sink;
            while let Some((u, e_idx)) = parent[cur] {
                let rev_idx = self.adj[u][e_idx].rev;
                self.adj[u][e_idx].res_cap -= push;
                self.adj[cur][rev_idx].res_cap += push;
                cur = u;
            }
            total_flow += push;
        }

        total_flow
    }
}

/// Validates account obligations (`b = A * g`), entitlement equations (`e'_i = e_i + b_i - p_i`),
/// collateral domain isolation, replay protection, and solves the exact capacitated vault
/// funding graph via Edmonds-Karp max-flow.
pub fn solve_and_verify_pnl_batch(
    snapshot: &PnlBatchSnapshotV1,
    expected_snapshot_hash: &[u8; 32],
) -> Result<VerifiedPnlSettlementBatch, UtxoRefError> {
    let actual_hash = snapshot.snapshot_hash();
    if &actual_hash != expected_snapshot_hash {
        return Err(UtxoRefError::SnapshotMismatch);
    }

    // 1. Validate netting sets (v0 requires VanillaBtc collateral).
    let mut set_map = BTreeMap::new();
    for ns in &snapshot.netting_sets {
        ns.collateral
            .validate_v0_funding()
            .map_err(|_| UtxoRefError::AccountingViolation("non-BTC netting set disabled in v0"))?;
        if set_map.insert(ns.id.clone(), ns).is_some() {
            return Err(UtxoRefError::AccountingViolation("duplicate netting_set_id"));
        }
    }

    // 2. Validate vaults & UTXO uniqueness against prior spent_outpoints.
    let prior_spent: BTreeSet<(Vec<u8>, u32)> = snapshot
        .spent_outpoints
        .iter()
        .map(|o| (o.txid.to_vec(), o.vout))
        .collect();
    let mut seen_outpoints = BTreeSet::new();
    let mut vault_map = BTreeMap::new();
    let mut total_input_sats = 0u64;
    let mut total_fee_sats = 0u64;

    for (v_idx, v) in snapshot.vaults.iter().enumerate() {
        if !set_map.contains_key(&v.netting_set_id) {
            return Err(UtxoRefError::DomainSubstitution(
                "vault references unknown netting_set_id",
            ));
        }
        for u in &v.utxos {
            let key = (u.outpoint.txid.to_vec(), u.outpoint.vout);
            if prior_spent.contains(&key) || !seen_outpoints.insert(key) {
                return Err(UtxoRefError::ReplayDetected(
                    "duplicate or previously spent vault UTXO",
                ));
            }
        }
        let v_in = v.total_input_sats()?;
        if v_in < v.fee_sats {
            return Err(UtxoRefError::AccountingViolation(
                "vault inputs cannot cover vault fee_sats",
            ));
        }
        total_input_sats = total_input_sats
            .checked_add(v_in)
            .ok_or(UtxoRefError::AccountingViolation("total input overflow"))?;
        total_fee_sats = total_fee_sats
            .checked_add(v.fee_sats)
            .ok_or(UtxoRefError::AccountingViolation("total fee overflow"))?;
        if vault_map.insert(v.id.clone(), (v_idx, v)).is_some() {
            return Err(UtxoRefError::AccountingViolation("duplicate vault_id"));
        }
    }

    // 3. Validate accounts & vault domain membership.
    let mut acct_map = BTreeMap::new();
    let mut net_deltas: BTreeMap<String, i128> = BTreeMap::new();
    for (a_idx, a) in snapshot.accounts.iter().enumerate() {
        let Some(&(_, home_vault)) = vault_map.get(&a.vault_id) else {
            return Err(UtxoRefError::DomainSubstitution(
                "account references unknown vault_id",
            ));
        };
        if home_vault.netting_set_id != a.netting_set_id {
            return Err(UtxoRefError::DomainSubstitution(
                "account netting_set_id does not match vault netting_set_id",
            ));
        }
        if a.payout_sats > 0 && a.payout_script_pubkey.is_none() {
            return Err(UtxoRefError::AccountingViolation(
                "payout_sats > 0 requires authorized payout_script_pubkey",
            ));
        }
        if acct_map.insert(a.id.clone(), (a_idx, a)).is_some() {
            return Err(UtxoRefError::AccountingViolation("duplicate account_id"));
        }
        net_deltas.insert(a.id.clone(), 0);
    }

    // 4. Validate obligations (`b = A * g`) & replay history.
    let consumed_prior: BTreeSet<&str> = snapshot
        .consumed_obligation_ids
        .iter()
        .map(String::as_str)
        .collect();
    let mut seen_obs = BTreeSet::new();
    for ob in &snapshot.obligations {
        if consumed_prior.contains(ob.id.as_str()) || !seen_obs.insert(ob.id.as_str()) {
            return Err(UtxoRefError::ReplayDetected(
                "duplicate or already-consumed obligation_id",
            ));
        }
        let Some(&(_, debtor)) = acct_map.get(&ob.from_account_id) else {
            return Err(UtxoRefError::AccountingViolation("unknown debtor account"));
        };
        let Some(&(_, creditor)) = acct_map.get(&ob.to_account_id) else {
            return Err(UtxoRefError::AccountingViolation("unknown creditor account"));
        };
        if debtor.netting_set_id != ob.netting_set_id || creditor.netting_set_id != ob.netting_set_id
        {
            return Err(UtxoRefError::DomainSubstitution(
                "cross-domain obligation forbidden",
            ));
        }
        *net_deltas.get_mut(&ob.from_account_id).unwrap() -= ob.sats as i128;
        *net_deltas.get_mut(&ob.to_account_id).unwrap() += ob.sats as i128;
    }

    debug_assert_eq!(net_deltas.values().sum::<i128>(), 0);

    // 5. Compute post-batch equities `e'_i = e_i + b_i - p_i` & per-vault liability demands.
    let mut post_equities = BTreeMap::new();
    let mut direct_payouts = BTreeMap::new();
    let mut vault_retained_demand: BTreeMap<String, u64> = snapshot
        .vaults
        .iter()
        .map(|v| (v.id.clone(), v.protected_sats))
        .collect();

    for a in &snapshot.accounts {
        let b_i = net_deltas[&a.id];
        let max_payout = b_i.max(0) as u64;
        if a.payout_sats > max_payout {
            return Err(UtxoRefError::AccountingViolation(
                "payout_sats exceeds positive net PnL in current batch",
            ));
        }
        let e_next_i128 = (a.equity_sats as i128) + b_i - (a.payout_sats as i128);
        if e_next_i128 < (a.locked_sats as i128) {
            return Err(UtxoRefError::AccountingViolation(
                "post-batch equity falls below locked_sats",
            ));
        }
        let e_next = e_next_i128 as u64;
        post_equities.insert(a.id.clone(), e_next);
        direct_payouts.insert(a.id.clone(), a.payout_sats);
        let entry = vault_retained_demand.get_mut(&a.vault_id).unwrap();
        *entry = entry
            .checked_add(e_next)
            .ok_or(UtxoRefError::AccountingViolation("vault liability overflow"))?;
    }

    // 6. Build Edmonds-Karp capacitated flow network:
    // Nodes:
    //   0 = SuperSource
    //   1 ..= V = src_vault(v_idx)
    //   V + 1 ..= 2V = dst_vault(v_idx)
    //   2V + 1 ..= 2V + A = dst_payout(a_idx)
    //   2V + A + 1 = SuperSink
    let v_len = snapshot.vaults.len();
    let a_len = snapshot.accounts.len();
    let source = 0usize;
    let sink = 2 * v_len + a_len + 1;
    let mut graph = MaxFlowGraph::new(sink + 1);

    for (v_idx, v) in snapshot.vaults.iter().enumerate() {
        let avail = v.total_input_sats()? - v.fee_sats;
        let src_node = 1 + v_idx;
        let dst_v_node = 1 + v_len + v_idx;
        graph.add_edge(source, src_node, avail, None);
        // Self-retention: a vault can always retain its own funds in its change output.
        graph.add_edge(
            src_node,
            dst_v_node,
            avail,
            Some((v.id.clone(), RouteTarget::Vault(v.id.clone()))),
        );
    }

    // Add permitted cross-vault & payout routes (enforcing netting-set domain isolation).
    for route in &snapshot.routes {
        let Some(&(from_idx, from_v)) = vault_map.get(&route.from_vault_id) else {
            return Err(UtxoRefError::DomainSubstitution(
                "route from unknown vault_id",
            ));
        };
        let src_node = 1 + from_idx;
        match &route.to_target {
            RouteTarget::Vault(dest_v_id) => {
                let Some(&(to_idx, to_v)) = vault_map.get(dest_v_id) else {
                    return Err(UtxoRefError::DomainSubstitution(
                        "route to unknown dest vault_id",
                    ));
                };
                if from_v.netting_set_id != to_v.netting_set_id {
                    return Err(UtxoRefError::DomainSubstitution(
                        "cross-domain vault route forbidden",
                    ));
                }
                if from_idx != to_idx {
                    graph.add_edge(
                        src_node,
                        1 + v_len + to_idx,
                        route.capacity_sats,
                        Some((route.from_vault_id.clone(), route.to_target.clone())),
                    );
                }
            }
            RouteTarget::Payout(acct_id) => {
                let Some(&(a_idx, acct)) = acct_map.get(acct_id) else {
                    return Err(UtxoRefError::DomainSubstitution(
                        "route to unknown payout account_id",
                    ));
                };
                if from_v.netting_set_id != acct.netting_set_id {
                    return Err(UtxoRefError::DomainSubstitution(
                        "cross-domain payout route forbidden",
                    ));
                }
                graph.add_edge(
                    src_node,
                    1 + 2 * v_len + a_idx,
                    route.capacity_sats,
                    Some((route.from_vault_id.clone(), route.to_target.clone())),
                );
            }
        }
    }

    let mut required_sink_flow = 0u64;
    for (v_idx, v) in snapshot.vaults.iter().enumerate() {
        let req = vault_retained_demand[&v.id];
        required_sink_flow = required_sink_flow
            .checked_add(req)
            .ok_or(UtxoRefError::AccountingViolation("sink demand overflow"))?;
        graph.add_edge(1 + v_len + v_idx, sink, req, None);
    }
    for (a_idx, a) in snapshot.accounts.iter().enumerate() {
        if a.payout_sats > 0 {
            required_sink_flow = required_sink_flow
                .checked_add(a.payout_sats)
                .ok_or(UtxoRefError::AccountingViolation("sink demand overflow"))?;
            graph.add_edge(1 + 2 * v_len + a_idx, sink, a.payout_sats, None);
        }
    }

    let achieved = graph.edmonds_karp(source, sink);
    if achieved < required_sink_flow {
        return Err(UtxoRefError::CapacitatedFlowDeficit {
            deficit_sats: required_sink_flow - achieved,
        });
    }

    // 7. Reconstruct exact vault residuals (required flow + any unspent local reserve) & route flows.
    let mut vault_residuals = BTreeMap::new();
    let mut route_allocations = Vec::new();

    for (v_idx, v) in snapshot.vaults.iter().enumerate() {
        let src_node = 1 + v_idx;
        let avail = v.total_input_sats()? - v.fee_sats;
        let mut used_from_src = 0u64;
        for e in &graph.adj[src_node] {
            if let Some((ref from_id, ref target)) = e.route_meta {
                let net_flow = e.initial_cap - e.res_cap;
                if net_flow > 0 {
                    used_from_src += net_flow;
                    route_allocations.push((from_id.clone(), target.clone(), net_flow));
                }
            }
        }
        let unallocated_local_surplus = avail - used_from_src;
        let residual = vault_retained_demand[&v.id] + unallocated_local_surplus;
        vault_residuals.insert(v.id.clone(), residual);
    }

    // Verify global satoshi conservation: inputs == fees + payouts + residuals!
    let sum_payouts: u64 = direct_payouts.values().sum();
    let sum_residuals: u64 = vault_residuals.values().sum();
    debug_assert_eq!(total_input_sats, total_fee_sats + sum_payouts + sum_residuals);

    let mut next_root_payload = borsh::to_vec(&(
        snapshot.epoch_id,
        &post_equities,
        &vault_residuals,
        &snapshot.obligations,
    ))
    .unwrap();
    next_root_payload.extend_from_slice(&actual_hash);
    let next_accounting_state_root =
        tagged_hash(b"SatsHedgeZero/UTXORef/NextAccountingRoot/v1", &next_root_payload);

    Ok(VerifiedPnlSettlementBatch {
        epoch_id: snapshot.epoch_id,
        snapshot_hash: actual_hash,
        net_account_deltas: net_deltas,
        post_account_equities: post_equities,
        direct_payouts_sats: direct_payouts,
        vault_residuals_sats: vault_residuals,
        route_allocations,
        total_input_sats,
        total_fee_sats,
        next_accounting_state_root,
        evidence_flags: BatchEvidenceFlags::REFERENCE_ACCOUNTING,
    })
}

/// Durable authorization progression (`PNL_BATCH_EXECUTION.md`: Ready -> Reserved -> Signed -> Confirmed | Frozen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BookAuthState {
    Ready,
    ReservedBeforeSigning {
        epoch_id: u64,
        snapshot_hash: [u8; 32],
        verified_batch: Box<VerifiedPnlSettlementBatch>,
    },
    Signed {
        epoch_id: u64,
        txid_hex: String,
        raw_signed_tx: Vec<u8>,
        verified_batch: Box<VerifiedPnlSettlementBatch>,
    },
    Frozen {
        reason: String,
    },
}

/// Persistent ledger & compare-and-swap reservation book preventing double-signing and reorg replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurablePnlBatchBook {
    pub book_id: String,
    pub last_settled_epoch: u64,
    pub ledger_state_root: [u8; 32],
    pub head_hash: [u8; 32],
    pub consumed_obligation_ids: BTreeSet<String>,
    pub spent_outpoints: Vec<BtcOutPoint>,
    pub state: BookAuthState,
}

impl DurablePnlBatchBook {
    pub fn new_genesis(book_id: &str, genesis_ledger_root: [u8; 32]) -> Self {
        let mut init_buf = Vec::new();
        init_buf.extend_from_slice(book_id.as_bytes());
        init_buf.extend_from_slice(&genesis_ledger_root);
        let head_hash = tagged_hash(b"SatsHedgeZero/UTXORef/BookHead/v1", &init_buf);
        Self {
            book_id: book_id.to_string(),
            last_settled_epoch: 0,
            ledger_state_root: genesis_ledger_root,
            head_hash,
            consumed_obligation_ids: BTreeSet::new(),
            spent_outpoints: Vec::new(),
            state: BookAuthState::Ready,
        }
    }

    fn bump_head(&mut self, tag: &[u8], extra: &[u8]) {
        let mut buf = Vec::with_capacity(64 + extra.len());
        buf.extend_from_slice(&self.head_hash);
        buf.extend_from_slice(tag);
        buf.extend_from_slice(extra);
        self.head_hash = tagged_hash(b"SatsHedgeZero/UTXORef/BookHead/v1", &buf);
    }

    /// Step 1 (`Ready -> ReservedBeforeSigning`): Verifies prior-ledger continuity (`epoch + 1`,
    /// `previous_state_root`), solves the batch, and locks the reservation BEFORE invoking any signer.
    pub fn reserve_before_signing(
        &mut self,
        expected_head_hash: &[u8; 32],
        snapshot: &PnlBatchSnapshotV1,
    ) -> Result<[u8; 32], UtxoRefError> {
        if &self.head_hash != expected_head_hash {
            return Err(UtxoRefError::HeadHashMismatch);
        }
        match &self.state {
            BookAuthState::Ready => {}
            BookAuthState::Frozen { .. } => return Err(UtxoRefError::BookFrozen),
            _ => return Err(UtxoRefError::ReservationActive),
        }
        if snapshot.epoch_id != self.last_settled_epoch + 1
            || snapshot.previous_state_root != self.ledger_state_root
        {
            return Err(UtxoRefError::PriorLedgerMismatch);
        }
        // Replay protection against the book's own durable state, independent of the
        // replay sets the caller put in the snapshot.
        for ob in &snapshot.obligations {
            if self.consumed_obligation_ids.contains(&ob.id) {
                return Err(UtxoRefError::ReplayDetected("obligation already settled in book"));
            }
        }
        let book_spent: BTreeSet<(&[u8; 32], u32)> =
            self.spent_outpoints.iter().map(|o| (&o.txid, o.vout)).collect();
        for v in &snapshot.vaults {
            for u in &v.utxos {
                if book_spent.contains(&(&u.outpoint.txid, u.outpoint.vout)) {
                    return Err(UtxoRefError::ReplayDetected("vault UTXO already spent in book"));
                }
            }
        }
        // The snapshot's replay sets must carry the book's whole settled history, so the
        // snapshot hash (and the next accounting root) commits to it.
        let snap_spent: BTreeSet<(&[u8; 32], u32)> =
            snapshot.spent_outpoints.iter().map(|o| (&o.txid, o.vout)).collect();
        let snap_consumed: BTreeSet<&str> =
            snapshot.consumed_obligation_ids.iter().map(String::as_str).collect();
        if !book_spent.is_subset(&snap_spent)
            || !self.consumed_obligation_ids.iter().all(|id| snap_consumed.contains(id.as_str()))
        {
            return Err(UtxoRefError::ReplayDetected(
                "snapshot replay sets omit the book's settled history",
            ));
        }

        let snap_hash = snapshot.snapshot_hash();
        let batch = solve_and_verify_pnl_batch(snapshot, &snap_hash)?;
        self.state = BookAuthState::ReservedBeforeSigning {
            epoch_id: snapshot.epoch_id,
            snapshot_hash: snap_hash,
            verified_batch: Box::new(batch),
        };
        self.bump_head(b"reserve", &snap_hash);
        Ok(self.head_hash)
    }

    /// Step 2 (`ReservedBeforeSigning -> Signed | Frozen`): Records exact signed bytes once.
    /// Ambiguity or signer error freezes the book rather than releasing the reservation!
    pub fn record_signed_outcome(
        &mut self,
        expected_head_hash: &[u8; 32],
        signer_result: Result<(String, Vec<u8>), &str>,
    ) -> Result<[u8; 32], UtxoRefError> {
        if &self.head_hash != expected_head_hash {
            return Err(UtxoRefError::HeadHashMismatch);
        }
        let BookAuthState::ReservedBeforeSigning {
            epoch_id,
            verified_batch,
            ..
        } = self.state.clone()
        else {
            return Err(UtxoRefError::InvalidBookTransition);
        };

        match signer_result {
            Ok((txid_hex, raw_signed_tx)) => {
                self.bump_head(b"signed", txid_hex.as_bytes());
                self.state = BookAuthState::Signed {
                    epoch_id,
                    txid_hex,
                    raw_signed_tx,
                    verified_batch,
                };
                Ok(self.head_hash)
            }
            Err(err_msg) => {
                // CRITICAL UTXORef rule: never release reservation after signer invocation!
                self.bump_head(b"freeze-ambiguous-sign", err_msg.as_bytes());
                self.state = BookAuthState::Frozen {
                    reason: format!("ambiguous signer failure: {err_msg}"),
                };
                Err(UtxoRefError::BookFrozen)
            }
        }
    }

    /// Step 3 (`Signed -> Ready` at `epoch + 1`): Commits the next ledger root after active-chain confirmation.
    pub fn confirm_active_chain(
        &mut self,
        expected_head_hash: &[u8; 32],
        confirmed_txid_hex: &str,
        settled_snapshot: &PnlBatchSnapshotV1,
    ) -> Result<[u8; 32], UtxoRefError> {
        if &self.head_hash != expected_head_hash {
            return Err(UtxoRefError::HeadHashMismatch);
        }
        let BookAuthState::Signed {
            epoch_id,
            mut verified_batch,
            txid_hex,
            ..
        } = self.state.clone()
        else {
            return Err(UtxoRefError::InvalidBookTransition);
        };
        // The replay sets below come from `settled_snapshot`: it must be the exact snapshot
        // the reservation verified. A different snapshot is rejected without mutation.
        if settled_snapshot.snapshot_hash() != verified_batch.snapshot_hash {
            return Err(UtxoRefError::SnapshotMismatch);
        }

        if txid_hex != confirmed_txid_hex {
            self.bump_head(b"freeze-txid-mismatch", confirmed_txid_hex.as_bytes());
            self.state = BookAuthState::Frozen {
                reason: "confirmed txid did not match signed reservation".into(),
            };
            return Err(UtxoRefError::BookFrozen);
        }

        verified_batch.evidence_flags.execution_verified = true;
        self.last_settled_epoch = epoch_id;
        self.ledger_state_root = verified_batch.next_accounting_state_root;
        for ob in &settled_snapshot.obligations {
            self.consumed_obligation_ids.insert(ob.id.clone());
        }
        for v in &settled_snapshot.vaults {
            for u in &v.utxos {
                if !self.spent_outpoints.contains(&u.outpoint) {
                    self.spent_outpoints.push(u.outpoint.clone());
                }
            }
        }
        self.state = BookAuthState::Ready;
        let next_root = self.ledger_state_root;
        self.bump_head(b"confirmed", &next_root);
        Ok(self.head_hash)
    }

    /// Freezes the book immediately if a watchtower detects a chain reorg of the last committed epoch.
    pub fn freeze_on_reorg(&mut self, reason: &str) {
        self.bump_head(b"freeze-reorg", reason.as_bytes());
        self.state = BookAuthState::Frozen {
            reason: reason.to_string(),
        };
    }
}
