//! Experimental (CBM-CACHE-03): seeded synthetic clearing workloads for the flow-certificate
//! cache. Every window is a batch-growth episode: obligations arrive one at a time, each
//! candidate (accepted obligations plus the new one) is screened, feasible candidates are
//! accepted, an infeasible full fill is retried as a half (partial) fill, and the final batch
//! settles through the unchanged canonical solver, whose residuals fund the next window.
//! Between windows routes, fees, protected collateral and vault UTXOs mutate by regime.
//! Synthetic outpoints and scripts only; nothing here is a live vault.
use std::collections::BTreeMap;

use shz_dlc::BtcOutPoint;
use shz_margin::CollateralAsset;

use crate::flow_cert::{FlowProblem, Verdict, Work, cold_solve};
use crate::pnl_batch::*;
use crate::UtxoRefError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity { Sparse, Dense }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime { Stable, Rotating, HighChurn }

#[derive(Debug, Clone, Copy)]
pub struct GymConfig {
    pub accounts: usize,
    pub connectivity: Connectivity,
    pub regime: Regime,
    pub windows: usize,
    pub candidates: usize,
    pub seed: u64,
}

/// xorshift64*; deterministic across platforms.
#[derive(Debug, Clone)]
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self { Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1) }
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 { if n == 0 { 0 } else { self.next_u64() % n } }
    pub fn chance(&mut self, per_mille: u64) -> bool { self.below(1000) < per_mille }
}

/// Kind of candidate, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateKind { Trade, PartialFill, Liquidation, Novation, Payout, Stress }

/// One screened candidate of the reference (cold) run.
#[derive(Debug, Clone)]
pub struct Query {
    pub window: usize,
    pub kind: CandidateKind,
    pub problem: FlowProblem,
    pub verdict: Verdict,
    /// Wall time of validation plus network construction (`FlowProblem::from_snapshot`), shared by every arm.
    pub build_ns: u64,
    /// Work of the cold solve (the saving a cache hit avoids, before its own check cost).
    pub cold_work: Work,
}

/// The reference trace: every candidate with its cold verdict, plus the canonical settlement
/// root of each window (from `solve_and_verify_pnl_batch`).
#[derive(Debug, Clone)]
pub struct Trace {
    pub queries: Vec<Query>,
    pub window_roots: Vec<[u8; 32]>,
    /// Wall time of each window's canonical `solve_and_verify_pnl_batch`, shared by every arm.
    pub canonical_ns: Vec<u64>,
    pub accepted_obligations: usize,
    /// Candidates whose cold verdict was compared against the canonical solver.
    pub canonical_checked: usize,
    /// Per window: the base snapshot (no obligations) and the accepted-batch history, so a
    /// prefix of the candidate stream can be settled (Phase 5: batch size within a budget).
    pub windows_detail: Vec<WindowDetail>,
}

/// Change to the accepted batch, at the query index where it happened.
#[derive(Debug, Clone)]
pub enum BatchEvent {
    /// Query `q` accepted these obligations.
    Accept { q: usize, added: Vec<RealizedObligation> },
    /// Before query `q`, the last accepted obligation was withdrawn (novation).
    Pop { q: usize },
}

#[derive(Debug, Clone)]
pub struct WindowDetail {
    pub base: PnlBatchSnapshotV1,
    pub events: Vec<BatchEvent>,
}
impl WindowDetail {
    /// The accepted batch after every query with index `<= q` was processed.
    pub fn accepted_through(&self, q: usize) -> Vec<RealizedObligation> {
        let mut obs: Vec<RealizedObligation> = Vec::new();
        for e in &self.events {
            match e {
                BatchEvent::Accept { q: at, added } if *at <= q => obs.extend(added.iter().cloned()),
                BatchEvent::Pop { q: at } if *at <= q => { obs.pop(); }
                _ => {}
            }
        }
        obs
    }
}

struct Market {
    vaults: Vec<(String, u64, u64, u64, BtcOutPoint)>, // id, sats, fee, protected, utxo
    accounts: Vec<(String, usize, u64)>,                // id, vault index, equity
    routes: BTreeMap<(String, RouteTarget), u64>,
    next_utxo: u64,
    next_ob: u64,
}

fn outpoint(n: u64) -> BtcOutPoint {
    let mut txid = [0u8; 32];
    txid[..8].copy_from_slice(&n.to_le_bytes());
    txid[31] = 0xC3;
    BtcOutPoint { txid, vout: (n % 4) as u32 }
}

impl Market {
    fn new(cfg: &GymConfig, r: &mut Rng) -> Self {
        let n_v = (cfg.accounts / 4).max(2);
        let mut accounts = Vec::new();
        let mut per_vault = vec![0u64; n_v];
        for i in 0..cfg.accounts {
            let v = i % n_v;
            let e = 20_000 + r.below(80_000);
            per_vault[v] += e;
            accounts.push((format!("a{i:05}"), v, e));
        }
        let mut m = Market { vaults: Vec::new(), accounts, routes: BTreeMap::new(), next_utxo: 1, next_ob: 1 };
        for (v, eq) in per_vault.iter().enumerate() {
            let fee = 300 + r.below(700);
            let protected = 1_000 + r.below(4_000);
            let slack = r.below(20_000);
            let u = m.utxo();
            m.vaults.push((format!("v{v:04}"), eq + protected + fee + slack, fee, protected, u));
        }
        let fan = match cfg.connectivity { Connectivity::Sparse => 2, Connectivity::Dense => 6 }.min(n_v - 1).max(1);
        for v in 0..n_v {
            for j in 0..fan {
                let to = (v + 1 + (r.below(n_v as u64 - 1) as usize + j) % (n_v - 1)) % n_v;
                if to != v { m.routes.insert((m.vaults[v].0.clone(), RouteTarget::Vault(m.vaults[to].0.clone())), 5_000 + r.below(60_000)); }
            }
        }
        for (id, v, _) in m.accounts.clone() {
            m.routes.insert((m.vaults[v].0.clone(), RouteTarget::Payout(id.clone())), 2_000 + r.below(30_000));
        }
        m
    }
    fn utxo(&mut self) -> BtcOutPoint { self.next_utxo += 1; outpoint(self.next_utxo) }
    fn snapshot(&self, obligations: &[RealizedObligation], payouts: &BTreeMap<String, u64>) -> PnlBatchSnapshotV1 {
        PnlBatchSnapshotV1 {
            network: "gym".into(), epoch_id: 1, previous_state_root: [0; 32],
            netting_sets: vec![NettingSetSpec { id: "ns".into(), collateral: CollateralAsset::VanillaBtc }],
            vaults: self.vaults.iter().map(|(id, sats, fee, protected, u)| VaultRecord {
                id: id.clone(), netting_set_id: "ns".into(), change_script_pubkey: vec![0x51, 0x20], fee_sats: *fee, protected_sats: *protected,
                utxos: vec![FundedVaultUtxo { outpoint: u.clone(), sats: *sats, script_pubkey: vec![0x51, 0x20] }],
            }).collect(),
            accounts: self.accounts.iter().map(|(id, v, e)| {
                let p = payouts.get(id).copied().unwrap_or(0);
                AccountRecord { id: id.clone(), netting_set_id: "ns".into(), vault_id: self.vaults[*v].0.clone(), equity_sats: *e, locked_sats: 0,
                    payout_sats: p, payout_script_pubkey: (p > 0).then(|| vec![0x00, 0x14]) }
            }).collect(),
            obligations: obligations.to_vec(), consumed_obligation_ids: vec![], spent_outpoints: vec![],
            routes: self.routes.iter().map(|((f, t), c)| PermittedRoute { from_vault_id: f.clone(), to_target: t.clone(), capacity_sats: *c }).collect(),
        }
    }
    fn mutate(&mut self, regime: Regime, r: &mut Rng) {
        let (route_pm, fee_pm, prot_pm, rotate_pm, churn_pm) = match regime {
            Regime::Stable => (20, 5, 5, 0, 0),
            Regime::Rotating => (100, 100, 50, 300, 20),
            Regime::HighChurn => (300, 300, 200, 800, 100),
        };
        let keys: Vec<_> = self.routes.keys().cloned().collect();
        for k in keys {
            if r.chance(route_pm) {
                let c = self.routes[&k];
                self.routes.insert(k.clone(), (c / 2 + r.below(c.max(2))).max(1));
            }
            if r.chance(churn_pm) { self.routes.remove(&k); }
        }
        let n_v = self.vaults.len();
        if n_v > 1 {
            for _ in 0..(n_v as u64 * churn_pm / 1000) {
                let (a, b) = (r.below(n_v as u64) as usize, r.below(n_v as u64) as usize);
                if a != b { self.routes.insert((self.vaults[a].0.clone(), RouteTarget::Vault(self.vaults[b].0.clone())), 5_000 + r.below(60_000)); }
            }
        }
        let mut fresh = Vec::new();
        for i in 0..n_v {
            if r.chance(fee_pm) { self.vaults[i].2 = 300 + r.below(700); self.vaults[i].1 += self.vaults[i].2; }
            if r.chance(prot_pm) { self.vaults[i].3 = 1_000 + r.below(4_000); self.vaults[i].1 += 4_000; }
            if r.chance(rotate_pm) { fresh.push(i); }
        }
        for i in fresh { self.vaults[i].4 = self.utxo(); }
    }
}

/// Run the reference (cold) episode and record every candidate with its verdict.
/// `check_canonical_every`: compare the cold verdict against `solve_and_verify_pnl_batch` on
/// every n-th candidate (1 = all) and on every window's final batch; any disagreement panics.
pub fn reference_trace(cfg: &GymConfig, check_canonical_every: usize) -> Result<Trace, UtxoRefError> {
    let mut r = Rng::new(cfg.seed);
    let mut m = Market::new(cfg, &mut r);
    let mut queries = Vec::new();
    let mut roots = Vec::new();
    let mut canonical_ns = Vec::new();
    let mut details = Vec::new();
    let (mut accepted_total, mut checked) = (0usize, 0usize);
    for w in 0..cfg.windows {
        let mut accepted: Vec<RealizedObligation> = Vec::new();
        let mut events: Vec<BatchEvent> = Vec::new();
        let base = m.snapshot(&[], &BTreeMap::new());
        let mut delta: BTreeMap<String, i128> = BTreeMap::new();
        let n_a = m.accounts.len() as u64;
        let mut c = 0;
        let screen = |m: &Market, obs: &[RealizedObligation], payouts: &BTreeMap<String, u64>, kind: CandidateKind, queries: &mut Vec<Query>, checked: &mut usize| -> Result<bool, UtxoRefError> {
            let snap = m.snapshot(obs, payouts);
            let t0 = std::time::Instant::now();
            let problem = FlowProblem::from_snapshot(&snap)?;
            let build_ns = t0.elapsed().as_nanos() as u64;
            let s = cold_solve(&problem);
            let verdict = if s.feasible(&problem) { Verdict::Feasible } else { Verdict::Infeasible { deficit_at_least: problem.demand - s.value } };
            if check_canonical_every > 0 && queries.len().is_multiple_of(check_canonical_every) {
                *checked += 1;
                match (solve_and_verify_pnl_batch(&snap, &snap.snapshot_hash()), verdict) {
                    (Ok(_), Verdict::Feasible) => {}
                    (Err(UtxoRefError::CapacitatedFlowDeficit { deficit_sats }), Verdict::Infeasible { deficit_at_least }) => {
                        assert_eq!(deficit_sats, deficit_at_least, "deficit differs from the canonical solver");
                    }
                    (got, want) => panic!("canonical solver disagrees: {got:?} vs {want:?}"),
                }
            }
            queries.push(Query { window: w, kind, problem, verdict, build_ns, cold_work: s.work });
            Ok(verdict == Verdict::Feasible)
        };
        while c < cfg.candidates {
            let kind = match r.below(20) { 0 => CandidateKind::Liquidation, 1 => CandidateKind::Novation, 2 => CandidateKind::Stress, _ => CandidateKind::Trade };
            let pick = |r: &mut Rng| r.below(n_a) as usize;
            let room = |m: &Market, d: &BTreeMap<String, i128>, i: usize| -> u64 {
                let (id, _, e) = &m.accounts[i];
                (*e as i128 + d.get(id).copied().unwrap_or(0)).max(0) as u64
            };
            let mut news: Vec<(usize, usize, u64)> = Vec::new();
            match kind {
                CandidateKind::Liquidation => {
                    let from = pick(&mut r);
                    let k = 2 + r.below(6);
                    let total = room(&m, &delta, from) * (500 + r.below(500)) / 1000;
                    for _ in 0..k { let to = pick(&mut r); if to != from { news.push((from, to, (total / k).max(1))); } }
                }
                CandidateKind::Novation if !accepted.is_empty() => {
                    // Reassign the creditor of the last accepted obligation.
                    let last = accepted.pop().unwrap();
                    events.push(BatchEvent::Pop { q: queries.len() });
                    *delta.get_mut(&last.from_account_id).unwrap() += last.sats as i128;
                    *delta.get_mut(&last.to_account_id).unwrap() -= last.sats as i128;
                    let from = m.accounts.iter().position(|a| a.0 == last.from_account_id).unwrap();
                    let to = pick(&mut r);
                    if to != from { news.push((from, to, last.sats)); }
                }
                CandidateKind::Stress => {
                    let from = pick(&mut r);
                    let to = pick(&mut r);
                    if to != from { news.push((from, to, room(&m, &delta, from))); }
                }
                _ => {
                    let from = pick(&mut r);
                    let to = pick(&mut r);
                    let x = room(&m, &delta, from) * (50 + r.below(300)) / 1000;
                    if to != from && x > 0 { news.push((from, to, x)); }
                }
            }
            news.retain(|n| n.2 > 0 && n.2 <= room(&m, &delta, n.0));
            if news.is_empty() { continue; }
            let mut tries = vec![(news.clone(), kind)];
            if kind == CandidateKind::Trade { tries.push((news.iter().map(|&(a, b, x)| (a, b, x / 2)).filter(|n| n.2 > 0).collect(), CandidateKind::PartialFill)); }
            for (batch, kind) in tries {
                if batch.is_empty() || c >= cfg.candidates { break; }
                let mut obs = accepted.clone();
                for &(a, b, x) in &batch {
                    m.next_ob += 1;
                    obs.push(RealizedObligation { id: format!("o{}", m.next_ob), netting_set_id: "ns".into(),
                        from_account_id: m.accounts[a].0.clone(), to_account_id: m.accounts[b].0.clone(), sats: x });
                }
                // Debtor room was checked one obligation at a time; a liquidation must also fit in total.
                let mut d2 = delta.clone();
                let mut ok = true;
                for o in &obs[accepted.len()..] {
                    *d2.entry(o.from_account_id.clone()).or_insert(0) -= o.sats as i128;
                    *d2.entry(o.to_account_id.clone()).or_insert(0) += o.sats as i128;
                }
                for (id, _, e) in &m.accounts { if (*e as i128) + d2.get(id).copied().unwrap_or(0) < 0 { ok = false; } }
                if !ok { continue; }
                c += 1;
                if screen(&m, &obs, &BTreeMap::new(), kind, &mut queries, &mut checked)? {
                    events.push(BatchEvent::Accept { q: queries.len() - 1, added: obs[accepted.len()..].to_vec() });
                    accepted = obs;
                    delta = d2;
                    break;
                }
            }
        }
        // Winners withdraw part of their gain as a direct payout, as a last candidate.
        let mut payouts = BTreeMap::new();
        for (id, d) in &delta { if *d > 0 && r.chance(300) { payouts.insert(id.clone(), (*d as u64) / 2); } }
        let mut final_payouts = BTreeMap::new();
        if !payouts.is_empty() && screen(&m, &accepted, &payouts, CandidateKind::Payout, &mut queries, &mut checked)? {
            final_payouts = payouts;
        }
        // Canonical settlement of the accepted batch funds the next window.
        let snap = m.snapshot(&accepted, &final_payouts);
        let t0 = std::time::Instant::now();
        let batch = solve_and_verify_pnl_batch(&snap, &snap.snapshot_hash()).expect("accepted batch settles canonically");
        canonical_ns.push(t0.elapsed().as_nanos() as u64);
        checked += 1;
        roots.push(batch.next_accounting_state_root);
        details.push(WindowDetail { base, events });
        accepted_total += accepted.len();
        for (id, _, e) in m.accounts.iter_mut() { *e = batch.post_account_equities[id]; }
        for i in 0..m.vaults.len() {
            let res = batch.vault_residuals_sats[&m.vaults[i].0];
            m.vaults[i].1 = res + m.vaults[i].2; // top up the fee
            m.vaults[i].4 = m.utxo();
        }
        m.mutate(cfg.regime, &mut r);
    }
    Ok(Trace { queries, window_roots: roots, canonical_ns, accepted_obligations: accepted_total, canonical_checked: checked, windows_detail: details })
}
