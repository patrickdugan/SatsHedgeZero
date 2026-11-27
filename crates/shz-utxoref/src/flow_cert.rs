//! Experimental (CBM-CACHE-03): flow and cut certificates for the `UTXORef` vault-funding
//! network, exact transport checks across mutations, residual repair from an old flow, and a
//! byte-budgeted certificate cache. Math: `research/utxoref_verification_cache/CBM_CACHE_03_MATH.md`.
//!
//! Not wired into [`crate::pnl_batch::solve_and_verify_pnl_batch`]: the canonical settlement
//! (route allocations, residuals, next accounting root) still comes from that solver. This
//! module only decides *feasibility* of candidate snapshots. A transported or repaired flow is
//! a feasibility witness, not the settlement. Every certificate is re-verified in full against
//! the candidate before use; cache policy can change cost, never a verdict.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use shz_dlc::tagged_hash;

use crate::UtxoRefError;
use crate::pnl_batch::{PnlBatchSnapshotV1, RouteTarget};

/// Stable node identity, so certificates survive insertion and deletion of vaults and accounts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKey {
    Source,
    Src(String),
    Dst(String),
    Pay(String),
    Sink,
}
impl NodeKey {
    fn heap_bytes(&self) -> usize {
        match self {
            NodeKey::Src(s) | NodeKey::Dst(s) | NodeKey::Pay(s) => s.len(),
            _ => 0,
        }
    }
    fn put(&self, b: &mut Vec<u8>) {
        let (tag, s) = match self {
            NodeKey::Source => (0u8, ""),
            NodeKey::Src(s) => (1, s.as_str()),
            NodeKey::Dst(s) => (2, s.as_str()),
            NodeKey::Pay(s) => (3, s.as_str()),
            NodeKey::Sink => (4, ""),
        };
        b.push(tag);
        b.extend((s.len() as u32).to_le_bytes());
        b.extend(s.as_bytes());
    }
}

/// The ordered node list of a problem and its commitment. Certificates carry it, so they
/// translate by index when a later problem has the same node set (the common case: route,
/// capacity and demand changes do not change nodes) and by key otherwise.
#[derive(Debug)]
pub struct Frame {
    pub node_set: [u8; 32],
    pub nodes: Vec<NodeKey>,
}
impl Frame {
    /// Bytes held by the node list.
    pub fn bytes(&self) -> usize { self.nodes.iter().map(|k| std::mem::size_of::<NodeKey>() + k.heap_bytes()).sum::<usize>() + 32 }
}

/// The funding network of one candidate snapshot, with parallel edges merged (summed
/// capacity: every cut capacity and the max-flow value are unchanged).
#[derive(Debug, Clone)]
pub struct FlowProblem {
    pub nodes: Vec<NodeKey>,
    pub frame: Arc<Frame>,
    index: BTreeMap<NodeKey, usize>,
    /// `(from, to, capacity)`, sorted by `(from, to)`.
    pub edges: Vec<(usize, usize, u64)>,
    out: Vec<Vec<usize>>,
    inc: Vec<Vec<usize>>,
    sink_edges: Vec<usize>,
    pub source: usize,
    pub sink: usize,
    /// Total sink capacity `D`: the batch is feasible iff max flow equals it.
    pub demand: u64,
    /// Canonical commitment to nodes, edges, capacities and demands.
    pub commitment: [u8; 32],
}

fn ns_err(m: &'static str) -> UtxoRefError { UtxoRefError::DomainSubstitution(m) }
fn acct_err(m: &'static str) -> UtxoRefError { UtxoRefError::AccountingViolation(m) }

impl FlowProblem {
    /// Validate `snapshot` exactly as steps 1-5 of `solve_and_verify_pnl_batch` do (same
    /// checks, same order, same errors) and build its step-6 network. Replay, domain and
    /// equity checks are re-run on every call; they are never cached.
    pub fn from_snapshot(snapshot: &PnlBatchSnapshotV1) -> Result<Self, UtxoRefError> {
        let mut set_map = BTreeMap::new();
        for ns in &snapshot.netting_sets {
            ns.collateral.validate_v0_funding().map_err(|_| acct_err("non-BTC netting set disabled in v0"))?;
            if set_map.insert(ns.id.clone(), ns).is_some() {
                return Err(acct_err("duplicate netting_set_id"));
            }
        }
        let prior_spent: BTreeSet<(Vec<u8>, u32)> =
            snapshot.spent_outpoints.iter().map(|o| (o.txid.to_vec(), o.vout)).collect();
        let mut seen_outpoints = BTreeSet::new();
        let mut vault_map = BTreeMap::new();
        let mut avail = BTreeMap::new();
        for v in &snapshot.vaults {
            if !set_map.contains_key(&v.netting_set_id) {
                return Err(ns_err("vault references unknown netting_set_id"));
            }
            for u in &v.utxos {
                let key = (u.outpoint.txid.to_vec(), u.outpoint.vout);
                if prior_spent.contains(&key) || !seen_outpoints.insert(key) {
                    return Err(UtxoRefError::ReplayDetected("duplicate or previously spent vault UTXO"));
                }
            }
            let v_in = v.total_input_sats()?;
            if v_in < v.fee_sats {
                return Err(acct_err("vault inputs cannot cover vault fee_sats"));
            }
            avail.insert(v.id.clone(), v_in - v.fee_sats);
            if vault_map.insert(v.id.clone(), v).is_some() {
                return Err(acct_err("duplicate vault_id"));
            }
        }
        let mut total_in = 0u64;
        for v in &snapshot.vaults {
            total_in = total_in.checked_add(v.total_input_sats()?).ok_or(acct_err("total input overflow"))?;
        }
        let mut acct_map = BTreeMap::new();
        let mut net: BTreeMap<String, i128> = BTreeMap::new();
        for a in &snapshot.accounts {
            let Some(home) = vault_map.get(&a.vault_id) else {
                return Err(ns_err("account references unknown vault_id"));
            };
            if home.netting_set_id != a.netting_set_id {
                return Err(ns_err("account netting_set_id does not match vault netting_set_id"));
            }
            if a.payout_sats > 0 && a.payout_script_pubkey.is_none() {
                return Err(acct_err("payout_sats > 0 requires authorized payout_script_pubkey"));
            }
            if acct_map.insert(a.id.clone(), a).is_some() {
                return Err(acct_err("duplicate account_id"));
            }
            net.insert(a.id.clone(), 0);
        }
        let consumed: BTreeSet<&str> = snapshot.consumed_obligation_ids.iter().map(String::as_str).collect();
        let mut seen_obs = BTreeSet::new();
        for ob in &snapshot.obligations {
            if consumed.contains(ob.id.as_str()) || !seen_obs.insert(ob.id.as_str()) {
                return Err(UtxoRefError::ReplayDetected("duplicate or already-consumed obligation_id"));
            }
            let Some(debtor) = acct_map.get(&ob.from_account_id) else { return Err(acct_err("unknown debtor account")) };
            let Some(creditor) = acct_map.get(&ob.to_account_id) else { return Err(acct_err("unknown creditor account")) };
            if debtor.netting_set_id != ob.netting_set_id || creditor.netting_set_id != ob.netting_set_id {
                return Err(ns_err("cross-domain obligation forbidden"));
            }
            *net.get_mut(&ob.from_account_id).unwrap() -= ob.sats as i128;
            *net.get_mut(&ob.to_account_id).unwrap() += ob.sats as i128;
        }
        let mut req: BTreeMap<String, u64> = snapshot.vaults.iter().map(|v| (v.id.clone(), v.protected_sats)).collect();
        for a in &snapshot.accounts {
            let b = net[&a.id];
            if a.payout_sats > b.max(0) as u64 {
                return Err(acct_err("payout_sats exceeds positive net PnL in current batch"));
            }
            let e_next = (a.equity_sats as i128) + b - (a.payout_sats as i128);
            if e_next < a.locked_sats as i128 {
                return Err(acct_err("post-batch equity falls below locked_sats"));
            }
            let entry = req.get_mut(&a.vault_id).unwrap();
            *entry = entry.checked_add(e_next as u64).ok_or(acct_err("vault liability overflow"))?;
        }
        // Network (step 6), merged by endpoint pair.
        let mut caps: BTreeMap<(NodeKey, NodeKey), u64> = BTreeMap::new();
        let add = |caps: &mut BTreeMap<(NodeKey, NodeKey), u64>, a: NodeKey, b: NodeKey, c: u64| -> Result<(), UtxoRefError> {
            let e = caps.entry((a, b)).or_insert(0);
            *e = e.checked_add(c).ok_or(acct_err("route capacity overflow"))?;
            Ok(())
        };
        for v in &snapshot.vaults {
            let a = avail[&v.id];
            add(&mut caps, NodeKey::Source, NodeKey::Src(v.id.clone()), a)?;
            add(&mut caps, NodeKey::Src(v.id.clone()), NodeKey::Dst(v.id.clone()), a)?;
        }
        for r in &snapshot.routes {
            let Some(from_v) = vault_map.get(&r.from_vault_id) else { return Err(ns_err("route from unknown vault_id")) };
            match &r.to_target {
                RouteTarget::Vault(d) => {
                    let Some(to_v) = vault_map.get(d) else { return Err(ns_err("route to unknown dest vault_id")) };
                    if from_v.netting_set_id != to_v.netting_set_id {
                        return Err(ns_err("cross-domain vault route forbidden"));
                    }
                    if r.from_vault_id != *d {
                        add(&mut caps, NodeKey::Src(r.from_vault_id.clone()), NodeKey::Dst(d.clone()), r.capacity_sats)?;
                    }
                }
                RouteTarget::Payout(a) => {
                    let Some(acct) = acct_map.get(a) else { return Err(ns_err("route to unknown payout account_id")) };
                    if from_v.netting_set_id != acct.netting_set_id {
                        return Err(ns_err("cross-domain payout route forbidden"));
                    }
                    add(&mut caps, NodeKey::Src(r.from_vault_id.clone()), NodeKey::Pay(a.clone()), r.capacity_sats)?;
                }
            }
        }
        let mut demand = 0u64;
        for v in &snapshot.vaults {
            demand = demand.checked_add(req[&v.id]).ok_or(acct_err("sink demand overflow"))?;
            add(&mut caps, NodeKey::Dst(v.id.clone()), NodeKey::Sink, req[&v.id])?;
        }
        for a in &snapshot.accounts {
            if a.payout_sats > 0 {
                demand = demand.checked_add(a.payout_sats).ok_or(acct_err("sink demand overflow"))?;
                add(&mut caps, NodeKey::Pay(a.id.clone()), NodeKey::Sink, a.payout_sats)?;
            }
        }
        let _ = total_in;
        Ok(Self::from_caps(caps, demand))
    }

    /// Build from an explicit capacity map (merged edges). `demand` must equal the sum of the
    /// capacities into `Sink`.
    pub fn from_caps(caps: BTreeMap<(NodeKey, NodeKey), u64>, demand: u64) -> Self {
        let mut keys: BTreeSet<NodeKey> = BTreeSet::new();
        keys.insert(NodeKey::Source);
        keys.insert(NodeKey::Sink);
        for (a, b) in caps.keys() {
            keys.insert(a.clone());
            keys.insert(b.clone());
        }
        let nodes: Vec<NodeKey> = keys.into_iter().collect();
        let index: BTreeMap<NodeKey, usize> = nodes.iter().cloned().enumerate().map(|(i, k)| (k, i)).collect();
        let mut edges: Vec<(usize, usize, u64)> = caps.iter().map(|((a, b), c)| (index[a], index[b], *c)).collect();
        edges.sort_unstable_by_key(|e| (e.0, e.1));
        let (source, sink) = (index[&NodeKey::Source], index[&NodeKey::Sink]);
        let mut out = vec![Vec::new(); nodes.len()];
        let mut inc = vec![Vec::new(); nodes.len()];
        let mut sink_edges = Vec::new();
        let mut b = Vec::new();
        b.extend((nodes.len() as u64).to_le_bytes());
        for k in &nodes {
            k.put(&mut b);
        }
        let node_set = tagged_hash(b"SatsHedgeZero/UTXORef/FlowNodes/v1", &b);
        b.extend((edges.len() as u64).to_le_bytes());
        for (i, &(u, v, c)) in edges.iter().enumerate() {
            out[u].push(i);
            inc[v].push(i);
            if v == sink {
                sink_edges.push(i);
            }
            b.extend((u as u64).to_le_bytes());
            b.extend((v as u64).to_le_bytes());
            b.extend(c.to_le_bytes());
        }
        b.extend(demand.to_le_bytes());
        let commitment = tagged_hash(b"SatsHedgeZero/UTXORef/FlowProblem/v1", &b);
        let frame = Arc::new(Frame { node_set, nodes: nodes.clone() });
        Self { nodes, frame, index, edges, out, inc, sink_edges, source, sink, demand, commitment }
    }

    pub fn node(&self, k: &NodeKey) -> Option<usize> { self.index.get(k).copied() }
    /// Edge index of `(u, v)`: `out[u]` is sorted by head because edges are sorted.
    pub fn edge(&self, u: usize, v: usize) -> Option<usize> {
        let o = self.out.get(u)?;
        o.binary_search_by_key(&v, |&e| self.edges[e].1).ok().map(|i| o[i])
    }
    /// Map a certificate frame's node indices to this problem's (identity when the node set
    /// is the same).
    fn translate(&self, f: &Frame, w: &mut Work) -> Option<Vec<Option<usize>>> {
        if f.node_set == self.frame.node_set { return None; }
        w.edge_inspections += f.nodes.len() as u64;
        Some(f.nodes.iter().map(|k| self.node(k)).collect())
    }
    /// Capacity map by node keys (for diffs and mutation in tests and the gym).
    pub fn caps(&self) -> BTreeMap<(NodeKey, NodeKey), u64> {
        self.edges.iter().map(|&(u, v, c)| ((self.nodes[u].clone(), self.nodes[v].clone()), c)).collect()
    }
}

/// Work counters: the deterministic cost measures reported next to wall time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Work {
    pub augmenting_paths: u64,
    pub edge_inspections: u64,
    pub cancellations: u64,
}
impl Work {
    pub fn add(&mut self, o: &Work) {
        self.augmenting_paths += o.augmenting_paths;
        self.edge_inspections += o.edge_inspections;
        self.cancellations += o.cancellations;
    }
}

/// A maximum flow of one problem, with its minimum cut when it falls short of demand.
#[derive(Debug, Clone)]
pub struct Solve {
    pub value: u64,
    pub flow: Vec<u64>,
    pub min_cut: Option<Vec<usize>>,
    pub work: Work,
}
impl Solve {
    pub fn feasible(&self, p: &FlowProblem) -> bool { self.value == p.demand }
}

/// Edmonds-Karp from `flow` (zero for a cold solve) until the value reaches `demand` or no
/// augmenting path exists. Deterministic: arcs are scanned in edge order.
fn augment(p: &FlowProblem, mut flow: Vec<u64>, w: &mut Work) -> Solve {
    let n = p.nodes.len();
    let mut value: u64 = p.out[p.source].iter().map(|&e| flow[e]).sum::<u64>() - p.inc[p.source].iter().map(|&e| flow[e]).sum::<u64>();
    let mut parent: Vec<Option<(usize, bool)>> = vec![None; n];
    let mut seen = vec![false; n];
    loop {
        if value >= p.demand {
            return Solve { value, flow, min_cut: None, work: *w };
        }
        parent.iter_mut().for_each(|x| *x = None);
        seen.iter_mut().for_each(|x| *x = false);
        seen[p.source] = true;
        let mut q = VecDeque::from([p.source]);
        'bfs: while let Some(u) = q.pop_front() {
            for &e in &p.out[u] {
                w.edge_inspections += 1;
                let (_, v, c) = p.edges[e];
                if !seen[v] && flow[e] < c {
                    seen[v] = true;
                    parent[v] = Some((e, true));
                    if v == p.sink { break 'bfs; }
                    q.push_back(v);
                }
            }
            for &e in &p.inc[u] {
                w.edge_inspections += 1;
                let (v, _, _) = p.edges[e];
                if !seen[v] && flow[e] > 0 {
                    seen[v] = true;
                    parent[v] = Some((e, false));
                    q.push_back(v);
                }
            }
        }
        if !seen[p.sink] {
            let cut = (0..n).filter(|&i| seen[i]).collect();
            return Solve { value, flow, min_cut: Some(cut), work: *w };
        }
        let mut push = p.demand - value;
        let mut v = p.sink;
        while let Some((e, fwd)) = parent[v] {
            let (a, b, c) = p.edges[e];
            push = push.min(if fwd { c - flow[e] } else { flow[e] });
            v = if fwd { a } else { b };
        }
        let mut v = p.sink;
        while let Some((e, fwd)) = parent[v] {
            let (a, b, _) = p.edges[e];
            if fwd { flow[e] += push; v = a; } else { flow[e] -= push; v = b; }
        }
        value += push;
        w.augmenting_paths += 1;
    }
}

/// Cold solve from the zero flow.
pub fn cold_solve(p: &FlowProblem) -> Solve {
    let mut w = Work::default();
    augment(p, vec![0; p.edges.len()], &mut w)
}

/// A reusable certificate: node indices into its `frame` (stable node identities).
#[derive(Debug, Clone)]
pub struct Certificate {
    pub frame: Arc<Frame>,
    pub kind: CertKind,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertKind {
    /// Sparse feasible flow: `(from, to, flow)` for nonzero edges only.
    Flow(Vec<(u32, u32, u64)>),
    /// Source side of a cut proving infeasibility.
    Cut(Vec<u32>),
}
impl Certificate {
    pub fn from_solve(p: &FlowProblem, s: &Solve) -> Self {
        let kind = match &s.min_cut {
            Some(cut) => CertKind::Cut(cut.iter().map(|&i| i as u32).collect()),
            None => CertKind::Flow(p.edges.iter().zip(&s.flow).filter(|(_, f)| **f > 0).map(|(&(u, v, _), &f)| (u as u32, v as u32, f)).collect()),
        };
        Certificate { frame: p.frame.clone(), kind }
    }
    pub fn is_flow(&self) -> bool { matches!(self.kind, CertKind::Flow(_)) }
    /// Bytes of the index payload (the shared frame is accounted separately by the cache).
    pub fn bytes(&self) -> usize {
        match &self.kind {
            CertKind::Flow(es) => es.len() * std::mem::size_of::<(u32, u32, u64)>(),
            CertKind::Cut(ns) => ns.len() * 4,
        }
    }
}

/// Exact check (T1): does the flow certificate prove `p` feasible? Every flow edge must
/// exist in `p` within capacity, conservation must hold at every inner node, and every sink
/// edge must be saturated.
pub fn check_flow(p: &FlowProblem, cert: &Certificate, w: &mut Work) -> bool {
    let CertKind::Flow(flow) = &cert.kind else { return false };
    let map = p.translate(&cert.frame, w);
    let at = |i: u32| -> Option<usize> { match &map { None => Some(i as usize).filter(|&x| x < p.nodes.len()), Some(m) => m.get(i as usize).copied().flatten() } };
    let mut bal = vec![0i128; p.nodes.len()];
    let mut on_sink = 0u64;
    let mut sink_flow: BTreeMap<usize, u64> = BTreeMap::new();
    for &(a, b, f) in flow {
        w.edge_inspections += 1;
        let (Some(u), Some(v)) = (at(a), at(b)) else { return false };
        let Some(e) = p.edge(u, v) else { return false };
        if f > p.edges[e].2 { return false; }
        bal[u] -= f as i128;
        bal[v] += f as i128;
        if v == p.sink {
            if sink_flow.insert(e, f).is_some() { return false; }
            on_sink += f;
        }
    }
    for &e in &p.sink_edges {
        w.edge_inspections += 1;
        if sink_flow.get(&e).copied().unwrap_or(0) != p.edges[e].2 { return false; }
    }
    on_sink == p.demand && bal.iter().enumerate().all(|(i, &x)| x == 0 || i == p.source || i == p.sink)
}

/// Sound check (T2): capacity in `p` of the certificate's cut (nodes it does not place on the
/// source side go to the sink side; any assignment is a valid cut). The candidate is proven
/// infeasible when the result is below `p.demand`.
pub fn cut_capacity(p: &FlowProblem, cert: &Certificate, w: &mut Work) -> u64 {
    let CertKind::Cut(s_side) = &cert.kind else { return u64::MAX };
    let map = p.translate(&cert.frame, w);
    let mut in_s = vec![false; p.nodes.len()];
    in_s[p.source] = true;
    for &k in s_side {
        let i = match &map { None => Some(k as usize).filter(|&x| x < p.nodes.len()), Some(m) => m.get(k as usize).copied().flatten() };
        if let Some(i) = i && i != p.sink { in_s[i] = true; }
    }
    let mut u = 0u64;
    for &(a, b, c) in &p.edges {
        w.edge_inspections += 1;
        if in_s[a] && !in_s[b] { u = u.saturating_add(c); }
    }
    u
}

/// Residual repair (T4): clip an old flow witness to `p`, cancel the resulting excesses back
/// toward the source and deficits forward toward the sink, then augment. The result is a
/// maximum flow of `p` (with its minimum cut when short), exactly as a cold solve decides.
pub fn repair(p: &FlowProblem, old: &Certificate) -> Solve {
    let mut w = Work::default();
    let mut flow = vec![0u64; p.edges.len()];
    if let CertKind::Flow(fl) = &old.kind {
        let map = p.translate(&old.frame, &mut w);
        let at = |i: u32| -> Option<usize> { match &map { None => Some(i as usize).filter(|&x| x < p.nodes.len()), Some(m) => m.get(i as usize).copied().flatten() } };
        for &(a, b, f) in fl {
            w.edge_inspections += 1;
            if let (Some(u), Some(v)) = (at(a), at(b)) && let Some(e) = p.edge(u, v) {
                flow[e] = f.min(p.edges[e].2);
            }
        }
    }
    let n = p.nodes.len();
    let mut bal = vec![0i128; n];
    for (e, &(u, v, _)) in p.edges.iter().enumerate() {
        bal[u] -= flow[e] as i128;
        bal[v] += flow[e] as i128;
    }
    // Excess at a node: reduce its inflow, moving the excess upstream; deficit: reduce its
    // outflow, moving the deficit downstream. Total flow strictly drops at every step.
    let mut work: VecDeque<usize> = (0..n).filter(|&i| i != p.source && i != p.sink && bal[i] != 0).collect();
    while let Some(x) = work.pop_front() {
        if x == p.source || x == p.sink { continue; }
        while bal[x] > 0 {
            let Some(&e) = p.inc[x].iter().find(|&&e| flow[e] > 0) else { break };
            w.edge_inspections += 1;
            let d = (bal[x] as u128).min(flow[e] as u128) as u64;
            flow[e] -= d;
            bal[x] -= d as i128;
            let m = p.edges[e].0;
            bal[m] += d as i128;
            w.cancellations += 1;
            if m != p.source && m != p.sink { work.push_back(m); }
        }
        while bal[x] < 0 {
            let Some(&e) = p.out[x].iter().find(|&&e| flow[e] > 0) else { break };
            w.edge_inspections += 1;
            let d = ((-bal[x]) as u128).min(flow[e] as u128) as u64;
            flow[e] -= d;
            bal[x] += d as i128;
            let m = p.edges[e].1;
            bal[m] -= d as i128;
            w.cancellations += 1;
            if m != p.source && m != p.sink { work.push_back(m); }
        }
    }
    debug_assert!(bal.iter().enumerate().all(|(i, &x)| x == 0 || i == p.source || i == p.sink));
    augment(p, flow, &mut w)
}

/// Feasibility verdict of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Feasible,
    /// Infeasible; `deficit_at_least` is exact when the path was a solve or repair.
    Infeasible { deficit_at_least: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Path {
    ExactMemo,
    TransportFlow,
    TransportCut,
    Repair,
    Cold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// No cache: every candidate is a cold solve.
    Cold,
    /// Reuse only on an identical problem commitment.
    ExactMemo,
    /// Structural retrieval, LRU eviction by bytes.
    Lru,
    /// Structural retrieval, evict lowest use count (oldest first on ties).
    Frequency,
    /// Structural retrieval, priority = aging + uses * saved cost / bytes (GDSF-style),
    /// with bypass when a newcomer ranks below every resident.
    Utility,
    /// Causal online score: priority = (hits + 1) / (age + 2) * saved / bytes; bypass as Utility.
    Causal,
}

/// One reuse of a cached certificate: it was resident from `from` (creation or previous
/// use, in screen-call time) to `to`, held `bytes`, and saved `saved` edge inspections
/// against a cold solve of the query it served. Input to the offline admission bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reuse { pub from: u64, pub to: u64, pub bytes: usize, pub saved: u64 }

#[derive(Debug, Clone)]
struct Entry {
    commitment: [u8; 32],
    cert: Certificate,
    feasible: bool,
    bytes: usize,
    saved: u64,
    last_use: u64,
    hits: u64,
    born: u64,
}

/// Outcome of screening one candidate.
#[derive(Debug, Clone)]
pub struct Screen {
    pub verdict: Verdict,
    pub path: Path,
    pub work: Work,
}

/// Byte-budgeted certificate cache. `repair` warm-starts misses from the most recent flow
/// certificate instead of a cold solve. Every hit is a full re-verification.
pub struct CertCache {
    pub policy: Policy,
    pub budget_bytes: usize,
    pub repair: bool,
    /// Structural retrieval tries at most this many residents per kind, most recent first.
    pub retrieval: usize,
    /// Keep only the node-set commitment of each frame (32 bytes), not its key list. A
    /// certificate is then reusable only for problems with the identical node set; on any
    /// other node set it maps nothing and fails its check (repair starts from zero flow).
    pub compact_frames: bool,
    entries: Vec<Entry>,
    used: usize,
    clock: u64,
    aging: u64,
    pub peak_bytes: usize,
    pub bypasses: u64,
    pub evictions: u64,
    /// When set, every hit is logged (offline admission analysis).
    pub reuse_log: Option<Vec<Reuse>>,
    /// Resident frames: node-set commitment -> (referencing entries, bytes), counted once.
    frames: BTreeMap<[u8; 32], (usize, usize)>,
    /// Cold edge inspections of the current query, when the caller knows them (for `Reuse::saved`).
    pub cold_hint: u64,
}

impl CertCache {
    pub fn new(policy: Policy, budget_bytes: usize, repair: bool, retrieval: usize) -> Self {
        Self { policy, budget_bytes, repair, retrieval, entries: Vec::new(), used: 0, clock: 0, aging: 0, peak_bytes: 0, bypasses: 0, evictions: 0, compact_frames: false, reuse_log: None, cold_hint: 0, frames: BTreeMap::new() }
    }
    pub fn used_bytes(&self) -> usize { self.used }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    fn priority(&self, e: &Entry) -> u128 {
        let density = (e.saved as u128) * 1_000_000 / e.bytes.max(1) as u128;
        match self.policy {
            Policy::Utility => self.aging as u128 + density * (e.hits as u128 + 1),
            Policy::Causal => density * (e.hits as u128 + 1) / ((self.clock - e.born) as u128 + 2),
            Policy::Frequency => ((e.hits as u128) << 64) | e.last_use as u128,
            _ => e.last_use as u128,
        }
    }

    /// Decide feasibility of `p`. Never returns a verdict that a cold solve would not.
    pub fn screen(&mut self, p: &FlowProblem) -> Screen {
        self.clock += 1;
        let mut w = Work::default();
        if self.policy != Policy::Cold
            && let Some(i) = self.entries.iter().position(|e| e.commitment == p.commitment) {
                // Identical problem: the stored certificate verifies by identity.
                let e = &mut self.entries[i];
                if let Some(log) = self.reuse_log.as_mut() {
                    log.push(Reuse { from: e.last_use, to: self.clock, bytes: e.bytes, saved: self.cold_hint });
                }
                e.hits += 1;
                e.last_use = self.clock;
                let verdict = if e.feasible { Verdict::Feasible } else {
                    let u = cut_capacity(p, &e.cert, &mut w);
                    Verdict::Infeasible { deficit_at_least: p.demand - u }
                };
                return Screen { verdict, path: Path::ExactMemo, work: w };
        }
        if !matches!(self.policy, Policy::Cold | Policy::ExactMemo) {
            let mut order: Vec<usize> = (0..self.entries.len()).collect();
            order.sort_unstable_by_key(|&i| std::cmp::Reverse(self.entries[i].last_use));
            let (mut tried_f, mut tried_c) = (0, 0);
            for i in order {
                let e = &self.entries[i];
                let ok = match &e.cert.kind {
                    CertKind::Flow(_) => {
                        if tried_f >= self.retrieval { continue; }
                        tried_f += 1;
                        check_flow(p, &e.cert, &mut w).then_some(Verdict::Feasible)
                    }
                    CertKind::Cut(_) => {
                        if tried_c >= self.retrieval { continue; }
                        tried_c += 1;
                        let u = cut_capacity(p, &e.cert, &mut w);
                        (u < p.demand).then(|| Verdict::Infeasible { deficit_at_least: p.demand - u })
                    }
                };
                if let Some(verdict) = ok {
                    let e = &mut self.entries[i];
                    if let Some(log) = self.reuse_log.as_mut() {
                        log.push(Reuse { from: e.last_use, to: self.clock, bytes: e.bytes, saved: self.cold_hint.saturating_sub(w.edge_inspections) });
                    }
                    e.hits += 1;
                    e.last_use = self.clock;
                    let path = if verdict == Verdict::Feasible { Path::TransportFlow } else { Path::TransportCut };
                    return Screen { verdict, path, work: w };
                }
            }
        }
        // Miss: repair from the most recent flow certificate, or solve cold.
        let warm = if self.repair && self.policy != Policy::Cold {
            self.entries.iter().filter(|e| e.feasible).max_by_key(|e| e.last_use).map(|e| e.cert.clone())
        } else { None };
        let (solve, path) = match warm {
            Some(c) => (repair(p, &c), Path::Repair),
            None => (cold_solve(p), Path::Cold),
        };
        w.add(&solve.work);
        let verdict = if solve.feasible(p) { Verdict::Feasible } else { Verdict::Infeasible { deficit_at_least: p.demand - solve.value } };
        if self.policy != Policy::Cold {
            let cert = Certificate::from_solve(p, &solve);
            self.admit(p.commitment, cert, solve.feasible(p), solve.work.edge_inspections.max(1));
        }
        Screen { verdict, path, work: w }
    }

    fn admit(&mut self, commitment: [u8; 32], mut cert: Certificate, feasible: bool, saved: u64) {
        if self.compact_frames {
            cert.frame = Arc::new(Frame { node_set: cert.frame.node_set, nodes: Vec::new() });
        }
        let bytes = cert.bytes() + std::mem::size_of::<Entry>();
        let node_set = cert.frame.node_set;
        let frame_bytes = cert.frame.bytes();
        if bytes + frame_bytes > self.budget_bytes { self.bypasses += 1; return; }
        let e = Entry { commitment, cert, feasible, bytes, saved, last_use: self.clock, hits: 0, born: self.clock };
        let bypassable = matches!(self.policy, Policy::Utility | Policy::Causal);
        loop {
            let extra = if self.frames.contains_key(&node_set) { 0 } else { frame_bytes };
            if self.used + bytes + extra <= self.budget_bytes { self.used += extra; break; }
            let (i, pr) = self.entries.iter().enumerate().map(|(i, x)| (i, self.priority(x))).min_by_key(|&(i, pr)| (pr, i)).unwrap();
            if bypassable && self.priority(&e) < pr { self.bypasses += 1; return; }
            if self.policy == Policy::Utility { self.aging = self.aging.max(pr as u64); }
            let gone = self.entries.swap_remove(i);
            self.used -= gone.bytes;
            let f = self.frames.get_mut(&gone.cert.frame.node_set).unwrap();
            f.0 -= 1;
            if f.0 == 0 { self.used -= f.1; self.frames.remove(&gone.cert.frame.node_set); }
            self.evictions += 1;
        }
        self.frames.entry(node_set).or_insert((0, frame_bytes)).0 += 1;
        self.used += bytes;
        self.peak_bytes = self.peak_bytes.max(self.used);
        self.entries.push(e);
    }
}

/// Offline admission bounds over a logged reuse structure (`CertCache::reuse_log` from an
/// unbounded run). Assumes a miss would regenerate the evicted certificate, as caching oracles do.
pub mod oracle {
    use super::Reuse;

    /// Exact optimum of the fractional relaxation of byte-budgeted optional admission (the
    /// LP of unsplittable flow on a path), solved as a min-cost flow of `budget` units along
    /// the time line. An upper bound on the inspections any admission policy can save with
    /// this reuse structure. Per-byte savings are rounded up, so the bound stays an upper bound.
    pub fn fractional_bound(reuses: &[Reuse], budget: usize) -> u64 {
        const SCALE: u128 = 1 << 20;
        let mut times: Vec<u64> = reuses.iter().flat_map(|r| [r.from, r.to]).collect();
        times.sort_unstable();
        times.dedup();
        if times.len() < 2 || budget == 0 { return 0; }
        let at = |t: u64| times.binary_search(&t).unwrap();
        let n = times.len();
        // Arcs: (to, capacity, cost, reverse index).
        let mut g: Vec<Vec<(usize, u64, i128, usize)>> = vec![Vec::new(); n];
        let add = |g: &mut Vec<Vec<(usize, u64, i128, usize)>>, a: usize, b: usize, cap: u64, cost: i128| {
            let (ra, rb) = (g[b].len(), g[a].len());
            g[a].push((b, cap, cost, ra));
            g[b].push((a, 0, -cost, rb));
        };
        for i in 0..n - 1 { add(&mut g, i, i + 1, budget as u64, 0); }
        for r in reuses {
            if r.saved == 0 || r.bytes == 0 || r.bytes > budget || r.from >= r.to { continue; }
            let per_byte = ((r.saved as u128) * SCALE).div_ceil(r.bytes as u128) as i128;
            add(&mut g, at(r.from), at(r.to), r.bytes as u64, -per_byte);
        }
        // Successive shortest paths with Bellman-Ford (costs negative, no negative cycles).
        let (src, dst) = (0, n - 1);
        let mut left = budget as u64;
        let mut total: i128 = 0;
        while left > 0 {
            let mut dist = vec![i128::MAX; n];
            let mut prev: Vec<Option<(usize, usize)>> = vec![None; n];
            dist[src] = 0;
            for _ in 0..n {
                let mut changed = false;
                for u in 0..n {
                    if dist[u] == i128::MAX { continue; }
                    for (k, &(v, cap, cost, _)) in g[u].iter().enumerate() {
                        if cap > 0 && dist[u] + cost < dist[v] { dist[v] = dist[u] + cost; prev[v] = Some((u, k)); changed = true; }
                    }
                }
                if !changed { break; }
            }
            if dist[dst] == i128::MAX || dist[dst] >= 0 { break; }
            let mut push = left;
            let mut v = dst;
            while let Some((u, k)) = prev[v] { push = push.min(g[u][k].1); v = u; }
            let mut v = dst;
            while let Some((u, k)) = prev[v] {
                let (to, _, _, r) = g[u][k];
                g[u][k].1 -= push;
                g[to][r].1 += push;
                v = u;
            }
            left -= push;
            total += dist[dst] * push as i128;
        }
        ((-total) as u128).div_ceil(SCALE) as u64
    }

    /// Integral schedule: admit reuse intervals by savings per byte, keeping occupancy within
    /// `budget` at every time. A lower bound on the offline optimum.
    pub fn greedy_schedule(reuses: &[Reuse], budget: usize) -> u64 {
        let mut times: Vec<u64> = reuses.iter().flat_map(|r| [r.from, r.to]).collect();
        times.sort_unstable();
        times.dedup();
        let at = |t: u64| times.binary_search(&t).unwrap();
        let mut occ = vec![0usize; times.len()];
        let mut order: Vec<&Reuse> = reuses.iter().filter(|r| r.saved > 0 && r.bytes <= budget && r.from < r.to).collect();
        order.sort_by(|a, b| ((b.saved as u128) * a.bytes as u128).cmp(&((a.saved as u128) * b.bytes as u128)));
        let mut saved = 0;
        for r in order {
            let (a, b) = (at(r.from), at(r.to));
            if occ[a..b].iter().all(|&o| o + r.bytes <= budget) {
                occ[a..b].iter_mut().for_each(|o| *o += r.bytes);
                saved += r.saved;
            }
        }
        saved
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn bounds_bracket_brute_force() {
            let mut x = 7u64;
            let mut rnd = |n: u64| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x % n };
            for _ in 0..300 {
                let k = 1 + rnd(7) as usize;
                let rs: Vec<Reuse> = (0..k).map(|_| { let a = rnd(8); Reuse { from: a, to: a + 1 + rnd(5), bytes: 1 + rnd(6) as usize, saved: rnd(50) } }).collect();
                let budget = 1 + rnd(10) as usize;
                let mut best = 0;
                for mask in 0u32..(1 << k) {
                    let pick: Vec<&Reuse> = (0..k).filter(|i| mask >> i & 1 == 1).map(|i| &rs[i]).collect();
                    let ok = (0..20u64).all(|t| pick.iter().filter(|r| r.from <= t && t < r.to).map(|r| r.bytes).sum::<usize>() <= budget);
                    if ok { best = best.max(pick.iter().map(|r| r.saved).sum::<u64>()); }
                }
                let (lo, hi) = (greedy_schedule(&rs, budget), fractional_bound(&rs, budget));
                assert!(lo <= best && best <= hi, "{lo} <= {best} <= {hi} failed for {rs:?} budget {budget}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> NodeKey {
        match s {
            "s" => NodeKey::Source,
            "t" => NodeKey::Sink,
            x => NodeKey::Src(x.into()),
        }
    }
    fn problem(edges: &[(&str, &str, u64)]) -> FlowProblem {
        let caps: BTreeMap<_, _> = edges.iter().map(|&(a, b, c)| ((k(a), k(b)), c)).collect();
        let d = edges.iter().filter(|e| e.1 == "t").map(|e| e.2).sum();
        FlowProblem::from_caps(caps, d)
    }

    #[test]
    fn cold_flow_cut_and_transport() {
        let p = problem(&[("s", "a", 5), ("s", "b", 5), ("a", "c", 4), ("b", "c", 4), ("a", "t", 1), ("c", "t", 8)]);
        let s = cold_solve(&p);
        assert!(s.feasible(&p));
        let f = Certificate::from_solve(&p, &s);
        assert!(f.is_flow());
        let mut w = Work::default();
        assert!(check_flow(&p, &f, &mut w));
        // Capacity up anywhere: flow transports. Demand up: it cannot.
        let up = problem(&[("s", "a", 9), ("s", "b", 5), ("a", "c", 4), ("b", "c", 4), ("a", "t", 1), ("c", "t", 8)]);
        assert!(check_flow(&up, &f, &mut w));
        let more = problem(&[("s", "a", 5), ("s", "b", 5), ("a", "c", 4), ("b", "c", 4), ("a", "t", 2), ("c", "t", 8)]);
        assert!(!check_flow(&more, &f, &mut w));
        let r = repair(&more, &f);
        assert_eq!(r.value, cold_solve(&more).value);
        // Route cut: infeasible, min cut transports to a further cut.
        let tight = problem(&[("s", "a", 5), ("s", "b", 5), ("a", "c", 4), ("b", "c", 3), ("a", "t", 1), ("c", "t", 8)]);
        let r = repair(&tight, &f);
        assert_eq!(r.value, 8);
        let cut = Certificate::from_solve(&tight, &r);
        assert!(!cut.is_flow());
        assert_eq!(cut_capacity(&tight, &cut, &mut w), 8);
        let tighter = problem(&[("s", "a", 5), ("s", "b", 5), ("a", "c", 4), ("b", "c", 2), ("a", "t", 1), ("c", "t", 8)]);
        assert!(cut_capacity(&tighter, &cut, &mut w) < tighter.demand);
        assert_eq!(cold_solve(&tighter).value, 7);
    }

    #[test]
    fn random_transport_is_sound_and_repair_is_exact() {
        // Random layered graphs; random mutations; every certificate verdict agrees with cold.
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = |n: u64| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x % n };
        let names = ["a", "b", "c", "d", "e", "f"];
        for _ in 0..400 {
            let mut edges = Vec::new();
            for n in &names[..3] { edges.push(("s", *n, 1 + rnd(20))); }
            for a in &names[..3] { for b in &names[3..] { if rnd(3) > 0 { edges.push((*a, *b, rnd(15))); } } }
            for n in &names[3..] { edges.push((*n, "t", rnd(18))); }
            let p = problem(&edges);
            let s = cold_solve(&p);
            let cert = Certificate::from_solve(&p, &s);
            for e in edges.iter_mut() { if rnd(3) == 0 { e.2 = rnd(22); } }
            // Node-set changes: drop a middle node's edges, or add a new node, so translation by key runs.
            match rnd(4) {
                0 => edges.retain(|e| e.0 != "d" && e.1 != "d"),
                1 => { edges.push(("a", "g", rnd(9))); edges.push(("g", "t", rnd(9))); }
                _ => {}
            }
            let q = problem(&edges);
            let truth = cold_solve(&q);
            let mut w = Work::default();
            match &cert.kind {
                CertKind::Flow(_) => {
                    if check_flow(&q, &cert, &mut w) { assert!(truth.feasible(&q)); }
                    let r = repair(&q, &cert);
                    assert_eq!(r.value, truth.value, "repair finds the max flow");
                }
                CertKind::Cut(_) => {
                    let u = cut_capacity(&q, &cert, &mut w);
                    assert!(truth.value <= u, "weak duality");
                    if u < q.demand { assert!(!truth.feasible(&q)); }
                }
            }
        }
    }
}
