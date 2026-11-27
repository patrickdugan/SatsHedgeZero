//! Differential tests of the clearing step against the real `shz_dex::routing::clearing`.
//!
//! Every batch of every trace is cleared by the real router; the step is synthesized on
//! the batch's real pre-state and inputs and must (a) satisfy every constraint and (b)
//! output exactly the real post-state and the chain over the real `BatchClearing::digest()`.
//! Tampered witnesses and tampered inputs must be rejected.
use halo2curves::bn256::Fr as F;
use lightninger_bitvm3_clearing::{
    clearing_step::{chain_next, check_step, steps_of, ClearingStep, PoolState, Tamper},
    gadgets::{prorata, prorata_native, W},
    trace::{self, Trace},
};
use nova_snark::frontend::{test_cs::TestConstraintSystem, ConstraintSystem};
use shz_dex::routing::clearing::Waterfall;

const A: usize = 6;
const R: usize = 4;

fn check_trace(t: &Trace) {
    assert!(t.max_rows() <= R, "{}: {} rows", t.name, t.max_rows());
    let (steps, _, _) = steps_of(A, R, &t.batches);
    let mut chain = [0u8; 32];
    for (s, b) in steps.iter().zip(&t.batches) {
        assert_eq!(s.pre.identity(), 0, "{} seq {}: pre identity", t.name, b.seq);
        let (ok, which, out, n) = check_step(s, &s.pre.to_z());
        assert!(ok, "{} seq {} ({:?}): unsatisfied at {which:?}", t.name, b.seq, b.report.layer);
        chain = chain_next(&chain, b.seq, &b.digest);
        let mut post = b.post.clone();
        post.chain = chain;
        assert_eq!(out, post.to_z(), "{} seq {} ({:?}): output differs from the real post-state", t.name, b.seq, b.report.layer);
        eprintln!("{} seq {} {:?} rows {} claim_haircuts {}: ok ({n} constraints)", t.name, b.seq, b.report.layer, b.rows.len(), b.report.claim_haircuts.len());
    }
}

fn traces() -> Vec<Trace> {
    vec![
        trace::liquidation_drill(1_000_000, A),
        trace::liquidation_drill(0, A),
        trace::own_claim(A),
        trace::legacy_deficit(A),
        trace::random_walk(6, A, 200_000, 14, 7),
        trace::random_walk(6, A, 0, 14, 11),
        trace::random_walk(6, A, 200_000, 160, 7),
    ]
}

#[test]
fn real_batches_satisfy_and_match_the_router() {
    let ts = traces();
    let mut layers = std::collections::BTreeSet::new();
    let mut with_claim_haircuts = 0;
    let mut negative_cash = 0;
    for t in &ts {
        check_trace(t);
        for b in &t.batches {
            layers.insert(b.report.layer);
            with_claim_haircuts += (!b.report.claim_haircuts.is_empty()) as usize;
            negative_cash += (b.report.cash_before < 0) as usize;
        }
    }
    eprintln!("layers {layers:?}, batches with claim haircuts {with_claim_haircuts}, with negative cash {negative_cash}");
    for l in [Waterfall::None, Waterfall::Margin, Waterfall::OwnClaim, Waterfall::Fund, Waterfall::Haircut, Waterfall::Carried] {
        assert!(layers.contains(&l), "no batch reached {l:?}");
    }
    assert!(negative_cash > 0, "no batch with negative pool cash");
}

#[test]
fn prorata_gadget_matches_clearing_prorata() {
    let cases: &[(u64, &[u64])] = &[(7, &[3, 3, 3]), (10, &[1, 2, 3, 4]), (1, &[5, 0, 5]), (9, &[4, 5]), (0, &[1]), (0, &[0, 0]), (5, &[0, 0, 5]), (1_000_003, &[999_999, 1, 7, 333_333])];
    for &(t, a) in cases {
        let mut cs = TestConstraintSystem::<F>::new();
        let total = lightninger_bitvm3_clearing::gadgets::alloc(cs.namespace(|| "t"), t as i128).unwrap();
        let amounts: Vec<W> = a.iter().enumerate().map(|(i, &x)| lightninger_bitvm3_clearing::gadgets::alloc(cs.namespace(|| format!("a{i}")), x as i128).unwrap()).collect();
        let out = prorata(cs.namespace(|| "p"), &total, &amounts, &|_, x| x).unwrap();
        assert!(cs.is_satisfied(), "{t} {a:?}");
        let got: Vec<u64> = out.iter().map(|w| w.v as u64).collect();
        assert_eq!(got, prorata_native(t, a), "{t} {a:?}");
    }
}

/// The richest batches for tampering: one per waterfall layer that moves the fund, the
/// haircut, the carry and the claim-haircut list.
fn pick(ts: &[Trace], f: impl Fn(&trace::BatchRecord) -> bool) -> (ClearingStep, PoolState) {
    for t in ts {
        let (steps, _, _) = steps_of(A, R, &t.batches);
        for (s, b) in steps.into_iter().zip(&t.batches) {
            if f(b) {
                let mut post = b.post.clone();
                post.chain = chain_next(&s.pre.chain, b.seq, &b.digest);
                return (s, post);
            }
        }
    }
    panic!("no such batch");
}

fn rejects(s: &ClearingStep, tampers: Vec<Tamper>, what: &str) {
    let mut s = s.clone();
    s.tampers = tampers;
    let (ok, which, _, _) = check_step(&s, &s.pre.to_z());
    assert!(!ok, "{what}: tampered witness accepted");
    eprintln!("{what}: rejected at {}", which.unwrap_or_default());
}

#[test]
fn tampered_witnesses_are_rejected() {
    let ts = vec![trace::liquidation_drill(1_000_000, A), trace::liquidation_drill(0, A), trace::own_claim(A)];
    // Fund layer with a shortfall and two loser rows.
    let (fund, _) = pick(&ts, |b| b.report.layer == Waterfall::Fund && b.rows.len() >= 2);
    let k = fund.rows.iter().position(|r| r.pnl < 0).unwrap();
    rejects(&fund, vec![Tamper::add("net", k, 1)], "net +1");
    rejects(&fund, vec![Tamper::add("collected", k, -1), Tamper::add("shortfall", k, 1)], "collect 1 sat less margin, 1 more shortfall");
    rejects(&fund, vec![Tamper::add("fund_absorbed", 0, -1), Tamper::add("fund_after", 0, 1), Tamper::add("carry_after", 0, 1)], "carry 1 sat the fund could absorb");
    rejects(&fund, vec![Tamper::add("cash_after", 0, 1)], "cash_after +1");
    rejects(&fund, vec![Tamper::add("claims_after", 0, 1)], "claims_after +1 (identity)");
    rejects(&fund, vec![Tamper::set("layer", 0, Waterfall::Haircut as i128)], "layer Fund -> Haircut");
    rejects(&fund, vec![Tamper::set("digest_bit", 0, 0)], "different digest");
    rejects(&fund, vec![Tamper::add("claim_before", k, 1)], "claim_before +1");
    // OwnClaim: the loss must take released margin before the account's own claim.
    let (own, _) = pick(&ts, |b| b.report.layer == Waterfall::OwnClaim);
    let k = own.rows.iter().position(|r| r.pnl < 0).unwrap();
    let r = &own.rows[k];
    let need = r.pnl.unsigned_abs() as i128;
    let claim = own.pre.claims[r.slot] as i128;
    let own_first = need.min(claim);
    rejects(
        &own,
        vec![Tamper::set("own_claim_used", k, own_first), Tamper::set("collected", k, (need - own_first).min(r.released as i128))],
        "own claim before margin (reordered waterfall)",
    );
    // Haircut: shares must follow prorata's floors and remainder order.
    let (hc, _) = pick(&ts, |b| b.report.haircut > 1 && b.report.layer >= Waterfall::Haircut);
    let first = (0..A + R).find(|&i| i < A && hc.pre.claims[i] > 0 || i >= A && hc.rows.get(i - A).is_some_and(|r| r.pnl > 0)).unwrap();
    rejects(&hc, vec![Tamper::add("cut_rem", first, 1)], "haircut remainder +1 on the first claim");
    rejects(&hc, vec![Tamper::add("haircut", 0, -1)], "haircut 1 sat short");
    // Payment: the pool pays everything it can, pro rata; it cannot keep cash and defer.
    let (pay, _) = pick(&ts, |b| b.report.rows.iter().any(|r| r.paid > 0));
    let k = pay.rows.iter().zip(&pay.rows).position(|_| true).unwrap();
    let kp = (0..pay.rows.len()).find(|&i| pay.rows[i].pnl > 0).unwrap_or(k);
    rejects(&pay, vec![Tamper::add("paid", kp, -1), Tamper::add("claim_after", kp, 1), Tamper::add("net", kp, -1), Tamper::add("cash_after", 0, 1)], "pay 1 sat less and defer it");
    rejects(&pay, vec![Tamper::add("claim3", 0, 1), Tamper::add("claim3", 1, -1)], "move 1 sat of deferred claim between accounts");
    // A batch input (pnl) is the prover's choice: the step clears it, and the digest, so
    // the chain, is no longer the one the lanes signed.
    let (pay, real) = pick(&ts, |b| b.report.rows.iter().any(|r| r.paid > 0));
    let mut m = pay.clone();
    m.tampers = vec![Tamper::add("pnl", 0, 1)];
    let (ok, _, out, _) = check_step(&m, &m.pre.to_z());
    assert!(!ok || out != real.to_z(), "row pnl +1 reached the real post-state");
    eprintln!("row pnl +1: satisfied={ok}, output differs from the router's");
}

#[test]
fn broken_identity_and_wrong_inputs_are_rejected() {
    let t = trace::liquidation_drill(0, A);
    let (steps, _, _) = steps_of(A, R, &t.batches);
    // identity: a z0 whose book is off by one
    let s = &steps[2];
    let mut z = s.pre.to_z();
    z[4] += F::from(1u64);
    let mut s2 = s.clone();
    s2.pre.book += 1;
    let (ok, which, _, _) = check_step(&s2, &z);
    assert!(!ok);
    eprintln!("book +1 in z: rejected at {}", which.unwrap_or_default());
    // unsorted account table
    let mut s3 = s.clone();
    s3.pre.keys.swap(0, 1);
    s3.pre.claims.swap(0, 1);
    for r in &mut s3.rows {
        r.slot = match r.slot {
            0 => 1,
            1 => 0,
            x => x,
        };
    }
    let (ok, which, _, _) = check_step(&s3, &s3.pre.to_z());
    assert!(!ok);
    eprintln!("unsorted table: rejected at {}", which.unwrap_or_default());
    // z0 that disagrees with the witness's pre-state (claims moved)
    let mut z = s.pre.to_z();
    z[5] += F::from(1u64);
    z[6] -= F::from(1u64);
    let (ok, which, _, _) = check_step(s, &z);
    assert!(!ok);
    eprintln!("claims moved in z: rejected at {}", which.unwrap_or_default());
}

#[test]
fn skipped_and_reordered_batches_do_not_reach_the_real_chain() {
    let t = trace::liquidation_drill(1_000_000, A);
    let (steps, _, _) = steps_of(A, R, &t.batches);
    // Skip batch 2: fold batch 3's rows on the state after batch 1. The step is a function,
    // so it computes something, but neither the state nor the chain is the router's.
    let mut skip = steps[3].clone();
    skip.pre = steps[2].pre.clone();
    let (ok, _, out, _) = check_step(&skip, &skip.pre.to_z());
    let mut real = t.batches[3].post.clone();
    real.chain = chain_next(&steps[3].pre.chain, t.batches[3].seq, &t.batches[3].digest);
    assert!(!ok || out != real.to_z(), "skipped batch reached the real post-state");
    let real_after_2 = {
        let mut p = t.batches[2].post.clone();
        p.chain = chain_next(&steps[2].pre.chain, t.batches[2].seq, &t.batches[2].digest);
        p
    };
    assert!(!ok || out != real_after_2.to_z(), "skipped batch reached the real state after the skipped one");
    eprintln!("skipped batch: satisfied={ok}, output differs from both real states");
    // Reorder the rows of a multi-row batch: the digest (and so the chain) changes.
    let (i, s) = steps.iter().enumerate().find(|(_, s)| s.rows.len() >= 2).unwrap();
    let mut swapped = s.clone();
    swapped.rows.swap(0, 1);
    let (ok, _, out, _) = check_step(&swapped, &swapped.pre.to_z());
    let mut real = t.batches[i].post.clone();
    real.chain = chain_next(&s.pre.chain, t.batches[i].seq, &t.batches[i].digest);
    assert!(ok, "row order is the batch's choice; the step clears any order");
    assert_ne!(out[out.len() - 2..], real.to_z()[real.to_z().len() - 2..], "reordered rows produced the real chain");
    eprintln!("reordered rows: chain differs from the real one");
}
