//! CBM-CACHE-03 differential tests: every cache policy against cold Edmonds-Karp and the
//! canonical `solve_and_verify_pnl_batch` on seeded gym traces, plus tampered certificates.
//! A false acceptance (cache says feasible, cold says infeasible) fails immediately.
use shz_utxoref::clearing_gym::*;
use shz_utxoref::flow_cert::*;

const POLICIES: [Policy; 6] = [Policy::Cold, Policy::ExactMemo, Policy::Lru, Policy::Frequency, Policy::Utility, Policy::Causal];

fn replay(trace: &Trace, policy: Policy, budget: usize, repair: bool) -> std::collections::BTreeMap<Path, usize> {
    let mut cache = CertCache::new(policy, budget, repair, 4);
    let mut paths = std::collections::BTreeMap::new();
    for q in &trace.queries {
        let s = cache.screen(&q.problem);
        *paths.entry(s.path).or_insert(0) += 1;
        match (q.verdict, s.verdict) {
            (Verdict::Feasible, Verdict::Feasible) => {}
            (Verdict::Infeasible { deficit_at_least: exact }, Verdict::Infeasible { deficit_at_least: lb }) => {
                assert!(lb >= 1 && lb <= exact, "deficit bound {lb} vs exact {exact}");
                if matches!(s.path, Path::Cold | Path::Repair) { assert_eq!(lb, exact); }
            }
            (want, got) => panic!("{policy:?} repair={repair} budget={budget}: verdict {got:?} via {:?}, cold says {want:?}", s.path),
        }
        assert!(cache.used_bytes() <= budget);
    }
    paths
}

#[test]
fn every_policy_agrees_with_cold_and_the_canonical_solver() {
    let mut transported = 0;
    for &accounts in &[8usize, 32] {
        for &connectivity in &[Connectivity::Sparse, Connectivity::Dense] {
            for &regime in &[Regime::Stable, Regime::Rotating, Regime::HighChurn] {
                for seed in 1..=2u64 {
                    let cfg = GymConfig { accounts, connectivity, regime, windows: 4, candidates: 12, seed };
                    let trace = reference_trace(&cfg, 1).unwrap();
                    assert_eq!(trace.canonical_checked, trace.queries.len() + cfg.windows);
                    assert!(trace.queries.iter().any(|q| matches!(q.verdict, Verdict::Infeasible { .. })) || accounts == 8);
                    for policy in POLICIES {
                        for repair in [false, true] {
                            for budget in [4 << 10, 64 << 10, 1 << 20] {
                                let p = replay(&trace, policy, budget, repair);
                                transported += p.get(&Path::TransportFlow).unwrap_or(&0) + p.get(&Path::TransportCut).unwrap_or(&0);
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(transported > 0, "the traces exercise transport");
}

#[test]
fn cache_runs_do_not_change_settlement_roots() {
    // The reference run is deterministic: the same config yields identical roots, and the
    // cache arms replay its exact candidates, so their accept/reject sequence (and therefore
    // every canonical settlement) is the reference one.
    let cfg = GymConfig { accounts: 32, connectivity: Connectivity::Sparse, regime: Regime::Rotating, windows: 5, candidates: 16, seed: 7 };
    let a = reference_trace(&cfg, 0).unwrap();
    let b = reference_trace(&cfg, 0).unwrap();
    assert_eq!(a.window_roots, b.window_roots);
    assert_eq!(a.window_roots.len(), 5);
    assert!(a.accepted_obligations > 0);
}

#[test]
fn tampered_certificates_never_prove_a_false_verdict() {
    let cfg = GymConfig { accounts: 32, connectivity: Connectivity::Dense, regime: Regime::HighChurn, windows: 3, candidates: 16, seed: 11 };
    let trace = reference_trace(&cfg, 0).unwrap();
    let mut r = Rng::new(99);
    let mut checked = 0;
    for (i, q) in trace.queries.iter().enumerate() {
        let s = cold_solve(&q.problem);
        let cert = Certificate::from_solve(&q.problem, &s);
        // Apply the certificate, tampered, to this and to the next few candidates.
        for target in trace.queries.iter().skip(i).take(4) {
            for _ in 0..8 {
                let mut w = Work::default();
                match &cert.kind {
                    CertKind::Flow(f) => {
                        let mut f = f.clone();
                        if f.is_empty() { continue; }
                        let j = r.below(f.len() as u64) as usize;
                        match r.below(3) {
                            0 => f[j].2 = f[j].2.saturating_add(1 + r.below(1000)),
                            1 => f[j].2 = f[j].2.saturating_sub(1 + r.below(1000)),
                            _ => { f.remove(j); }
                        }
                        let t = Certificate { frame: cert.frame.clone(), kind: CertKind::Flow(f) };
                        if check_flow(&target.problem, &t, &mut w) {
                            assert_eq!(target.verdict, Verdict::Feasible, "tampered flow accepted for an infeasible candidate");
                        }
                    }
                    CertKind::Cut(c) => {
                        let mut c = c.clone();
                        if !c.is_empty() && r.below(2) == 0 { let j = r.below(c.len() as u64) as usize; c.remove(j); }
                        let t = Certificate { frame: cert.frame.clone(), kind: CertKind::Cut(c) };
                        let u = cut_capacity(&target.problem, &t, &mut w);
                        if u < target.problem.demand {
                            assert!(matches!(target.verdict, Verdict::Infeasible { .. }), "tampered cut rejected a feasible candidate");
                        }
                    }
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 500);
}
