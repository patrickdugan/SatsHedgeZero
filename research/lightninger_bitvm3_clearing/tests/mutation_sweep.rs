//! Field-level mutation sweep: every named witness field of the clearing step, every row
//! input, every `z_in` element, perturbed by +1 and by -1 one at a time, plus compensating
//! pairs that preserve the conservation sums. A mutation of a derived field must leave the
//! system unsatisfied; a mutation of a batch input (pnl, released, slot) or a reordering may
//! satisfy the step, but then its output must differ from the router's post-state and chain.
//! Writes `artifacts/mutation_sweep.json`.
use halo2curves::bn256::Fr as F;
use lightninger_bitvm3_clearing::{
    audit::record,
    clearing_step::{chain_next, steps_of, ClearingStep, PoolState, Tamper},
    trace,
};
use serde_json::json;

const A: usize = 6;
const R: usize = 4;

fn outcome(s: &ClearingStep, z: &[F], real: &PoolState) -> &'static str {
    let (cs, public) = record(s, z);
    if cs.satisfied().is_some() {
        return "unsatisfied";
    }
    let out: Vec<F> = public[z.len()..].iter().map(|&v| cs.values[v as usize]).collect();
    if out == real.to_z() {
        "ACCEPTED"
    } else {
        "output differs"
    }
}

#[test]
fn every_field_mutation_is_rejected() {
    let mut picked = Vec::new();
    for t in [trace::liquidation_drill(1_000_000, A), trace::liquidation_drill(0, A), trace::own_claim(A), trace::legacy_deficit(A), trace::random_walk(6, A, 0, 14, 11)] {
        let (steps, _, _) = steps_of(A, R, &t.batches);
        for (s, b) in steps.into_iter().zip(&t.batches) {
            let new_layer = b.rows.len() >= 2 && (b.report.layer as u8 >= 1) && !picked.iter().any(|(_, x): &(ClearingStep, trace::BatchRecord)| x.report.layer == b.report.layer);
            let first_claim_haircut = !b.report.claim_haircuts.is_empty() && !picked.iter().any(|(_, x): &(ClearingStep, trace::BatchRecord)| !x.report.claim_haircuts.is_empty());
            if new_layer || first_claim_haircut {
                picked.push((s, b.clone()));
            }
        }
    }
    let mut results = Vec::new();
    let (mut total, mut rejected) = (0, 0);
    for (s, b) in &picked {
        let mut real = b.post.clone();
        real.chain = chain_next(&s.pre.chain, b.seq, &b.digest);
        let n = s.rows.len();
        let mut muts: Vec<(String, ClearingStep, Vec<F>)> = Vec::new();
        let z = s.pre.to_z();
        let per_row = ["pnl", "claim_before", "collected", "own_claim_used", "shortfall", "row_haircut", "paid", "claim_after", "net"];
        let scalars = ["shortfall_total", "fund_absorbed", "fund_after", "haircut", "carry_after", "cash_after", "claims_after", "layer"];
        for d in [1i128, -1] {
            for name in per_row {
                for k in 0..n {
                    let mut m = s.clone();
                    m.tampers = vec![Tamper::add(name, k, d)];
                    muts.push((format!("{name}[{k}]{d:+}"), m, z.clone()));
                }
            }
            for name in scalars {
                let mut m = s.clone();
                m.tampers = vec![Tamper::add(name, 0, d)];
                muts.push((format!("{name}{d:+}"), m, z.clone()));
            }
            for j in 0..A {
                let mut m = s.clone();
                m.tampers = vec![Tamper::add("claim3", j, d)];
                muts.push((format!("claim3[{j}]{d:+}"), m, z.clone()));
            }
            for h in 0..A {
                let mut m = s.clone();
                m.tampers = vec![Tamper::add("claim_haircut", h, d)];
                muts.push((format!("claim_haircut[{h}]{d:+}"), m, z.clone()));
            }
            for i in 0..A + R {
                let mut m = s.clone();
                m.tampers = vec![Tamper::add("cut_rem", i, d)];
                muts.push((format!("cut_rem[{i}]{d:+}"), m, z.clone()));
            }
            for i in 0..R {
                let mut m = s.clone();
                m.tampers = vec![Tamper::add("pay_rem", i, d)];
                muts.push((format!("pay_rem[{i}]{d:+}"), m, z.clone()));
            }
            for i in 0..z.len() {
                let mut zz = z.clone();
                zz[i] += if d > 0 { F::from(1u64) } else { -F::from(1u64) };
                muts.push((format!("z_in[{i}]{d:+}"), s.clone(), zz));
            }
            // batch inputs
            for k in 0..n {
                // released is unsigned: -1 on a row that released nothing is not a mutation
                if s.rows[k].released as i128 + d >= 0 {
                    let mut m = s.clone();
                    m.rows[k].released = (m.rows[k].released as i128 + d) as u64;
                    muts.push((format!("input released[{k}]{d:+}"), m, z.clone()));
                }
                let mut m = s.clone();
                m.rows[k].pnl += d as i64;
                muts.push((format!("input pnl[{k}]{d:+}"), m, z.clone()));
            }
        }
        for k in 0..n {
            let mut m = s.clone();
            m.rows[k].slot = (0..A).find(|j| !s.rows.iter().any(|r| r.slot == *j)).unwrap_or((m.rows[k].slot + 1) % A);
            muts.push((format!("input slot[{k}] -> unused slot"), m, z.clone()));
        }
        let mut m = s.clone();
        m.rows.swap(0, 1);
        muts.push(("input rows 0,1 swapped".into(), m, z.clone()));
        let mut m = s.clone();
        m.rows.pop();
        muts.push(("input last row dropped".into(), m, z.clone()));
        m = s.clone();
        m.tampers = vec![Tamper::set("digest_bit", 0, 0)];
        muts.push(("digest replaced".into(), m, z.clone()));
        // compensating pairs (keep every sum the draft circuit checked)
        let pairs: Vec<(&str, Vec<Tamper>)> = vec![
            ("collected-1, shortfall+1", (0..n).flat_map(|k| [Tamper::add("collected", k, -1), Tamper::add("shortfall", k, 1)]).take(2).collect()),
            ("own_claim_used-1, shortfall+1", vec![Tamper::add("own_claim_used", 0, -1), Tamper::add("shortfall", 0, 1)]),
            ("fund_absorbed-1, carry_after+1", vec![Tamper::add("fund_absorbed", 0, -1), Tamper::add("fund_after", 0, 1), Tamper::add("carry_after", 0, 1)]),
            ("haircut+1, carry_after-1", vec![Tamper::add("haircut", 0, 1), Tamper::add("carry_after", 0, -1)]),
            ("paid-1, claim_after+1", vec![Tamper::add("paid", 0, -1), Tamper::add("claim_after", 0, 1)]),
            ("paid[0]-1, paid[1]+1", vec![Tamper::add("paid", 0, -1), Tamper::add("paid", 1, 1), Tamper::add("claim_after", 0, 1), Tamper::add("claim_after", 1, -1)]),
            ("claim3 moved 1 sat between slots 0,1", vec![Tamper::add("claim3", 0, 1), Tamper::add("claim3", 1, -1)]),
            ("cut_rem moved first->second", vec![Tamper::add("cut_rem", 0, -1), Tamper::add("cut_rem", 1, 1)]),
            ("pay_rem moved first->second", vec![Tamper::add("pay_rem", 0, -1), Tamper::add("pay_rem", 1, 1)]),
        ];
        for (name, t) in pairs {
            let mut m = s.clone();
            m.tampers = t;
            muts.push((format!("pair: {name}"), m, z.clone()));
        }
        for (name, m, zz) in &muts {
            let o = outcome(m, zz, &real);
            total += 1;
            if o != "ACCEPTED" {
                rejected += 1;
            }
            results.push(json!({"batch": b.seq, "layer": format!("{:?}", b.report.layer), "mutation": name, "outcome": o}));
        }
        eprintln!("{:?} seq {}: {} mutations", b.report.layer, b.seq, muts.len());
    }
    let accepted: Vec<_> = results.iter().filter(|r| r["outcome"] == "ACCEPTED").cloned().collect();
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/mutation_sweep.json");
    std::fs::write(&p, serde_json::to_string_pretty(&json!({"total": total, "rejected": rejected, "accepted": accepted, "results": results})).unwrap()).unwrap();
    eprintln!("{rejected}/{total} mutations rejected");
    assert!(accepted.is_empty(), "accepted mutations: {accepted:?}");
}
