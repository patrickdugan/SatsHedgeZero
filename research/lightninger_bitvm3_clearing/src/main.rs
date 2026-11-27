//! `lightninger-bitvm3-clearing` CLI.
//!
//! - `shape` — primary constraint counts of the clearing step for several `(A, R)` and of
//!   the TapSighash step for the vector and Core shapes.
//! - `prove-clearing <scenario> <K> [A] [R]` — fold the first `K` real batches of a router
//!   trace (`drill_fund`, `drill_nofund`, `own_claim`, `legacy`, `walk`, `walk_nofund`,
//!   `walk:<windows>`), compress, verify,
//!   and write `artifacts/clearing_<scenario>_k<K>.json` with the BitVM3 statement.
//! - `prove-cet [scenario] [K]` — the joint statement: M17 folds of the CET and refund inputs
//!   (`artifacts/core_cet_txs.json`, from `tests/core_cet.rs`), bind-mode TapSighash and Secq
//!   folds of their signatures, the binding check (and its negative cases), a clearing fold of
//!   `K` batches, and the 304-byte statement over all of them (`artifacts/cet_joint_statement.json`).
//! - `trace-stats <scenario> [A]` — batch count, largest batch, layers of a trace.
//! - `prove-tapsighash <vector|core:LABEL>` — fold every signature slot of one transaction,
//!   fold the same slots through `Mnr05SecqBip340Step` (Secq256k1), check both end in the
//!   same accumulator, write `artifacts/tapsighash_<source>.json`.
use ff::{Field, PrimeField};
use halo2curves::{bn256::Fr as F, secq256k1::Fq as SecqScalar};
use lightninger_bitvm3_clearing::{
    clearing_step::{commitment_hash, program_hash, steps_of, ClearingStep, PoolState, RELATION_CLEARING_V1},
    fold::{self, shape_constraints, FoldReceipt},
    gadgets::{le_halves, sha256_native},
    tapsighash_step::{bound_steps, sighash_steps, spent_commitment, tap_z, BoundSlot, SigSlot, SighashStep, Tx, TxShape, RELATION_TAPSIGHASH_V1},
    trace,
};
use nova_snark::{
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc::EvaluationEngine, Secp256k1Engine, Secq256k1Engine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shz_mnr05_bitvm3_ln_dlc::secq_schnorr_circuit::{secq_from_u128, Bip340StepSlot, Mnr05SecqBip340Step};
use shz_nova_bitvm::bitvm3::{split_statement_digest_be_u128, BitcoinNetworkCode, UtxoRefL2SettlementStatementV0};
use std::{path::PathBuf, time::Instant};

fn artifacts() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn log(s: &str) {
    eprintln!("[{}] {s}", chrono_like());
}
fn chrono_like() -> String {
    format!("{:.1}s", START.with(|t| t.elapsed().as_secs_f64()))
}
thread_local! { static START: Instant = Instant::now(); }

fn scenario(name: &str, a: usize) -> trace::Trace {
    match name {
        "drill_fund" => trace::liquidation_drill(1_000_000, a),
        "drill_nofund" => trace::liquidation_drill(0, a),
        "own_claim" => trace::own_claim(a),
        "legacy" => trace::legacy_deficit(a),
        "walk" => trace::random_walk(6, a, 200_000, 40, 7),
        "walk_nofund" => trace::random_walk(6, a, 0, 14, 11),
        _ => match (name.strip_prefix("walk:"), name.strip_prefix("journal:")) {
            // walk:N — the seeded random walk with N windows, for long folds
            (Some(n), _) => trace::random_walk(6, a, 200_000, n.parse().expect("walk:<windows>"), 7),
            // journal:PATH — committed live-venue batches (artifacts/testnet4_demo/venue_fill.json)
            (_, Some(p)) => {
                let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{p}: {e}"))).expect("venue json");
                trace::from_venue(&v, a).unwrap_or_else(|e| panic!("{p}: {e}"))
            }
            _ => panic!("unknown scenario {name}"),
        },
    }
}

fn shape() {
    let mut rows = Vec::new();
    for (a, r) in [(4, 2), (6, 4), (8, 4), (16, 8)] {
        let t = Instant::now();
        let (c, v) = shape_constraints(&ClearingStep::blank(a, r));
        rows.push(json!({"step": "clearing", "A": a, "R": r, "arity": PoolState::arity(a), "constraints": c, "aux_variables": v, "synth_seconds": t.elapsed().as_secs_f64()}));
        log(&format!("clearing A={a} R={r}: {c} constraints"));
    }
    let v: Value = serde_json::from_str(include_str!("../tests/vectors/bip341-wallet-test-vectors.json")).unwrap();
    let k = &v["keyPathSpending"][0];
    let tx = Tx::parse(&hex::decode(k["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap());
    let spks: Vec<Vec<u8>> = k["given"]["utxosSpent"].as_array().unwrap().iter().map(|u| hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap()).collect();
    let mut shapes = vec![("bip341_vector_9in_2out", TxShape::of(&tx, &spks, 0))];
    shapes.push(("p2tr_3in_3out_annex40", TxShape { script_sig_lens: vec![0; 3], prevout_spk_lens: vec![34; 3], out_spk_lens: vec![34; 3], annex_max: 40, bind: false }));
    shapes.push(("p2tr_3in_3out", TxShape { script_sig_lens: vec![0; 3], prevout_spk_lens: vec![34; 3], out_spk_lens: vec![34; 3], annex_max: 0, bind: false }));
    for (name, s) in shapes {
        let (c, v) = shape_constraints(&SighashStep::blank(&s));
        rows.push(json!({"step": "tapsighash", "shape": name, "constraints": c, "aux_variables": v}));
        log(&format!("tapsighash {name}: {c} constraints"));
    }
    let p = artifacts().join("shape_constraints.json");
    std::fs::write(&p, serde_json::to_string_pretty(&rows).unwrap()).unwrap();
    log(&format!("wrote {}", p.display()));
}

#[derive(Serialize)]
struct ClearingRun {
    scenario: String,
    accounts_table: usize,
    rows_capacity: usize,
    batches: Vec<Value>,
    fold: FoldReceipt,
    bitvm3_statement_hex: String,
    bitvm3_statement_sha256: String,
    bitvm3_public_limbs_be: [String; 2],
}

fn prove_clearing(name: &str, k: usize, a: usize, r: usize) {
    let t = scenario(name, a);
    let live = name.starts_with("journal:");
    assert!(t.batches.len() >= k, "{name} has {} batches, asked for {k}", t.batches.len());
    let batches = &t.batches[..k];
    assert!(batches.iter().all(|b| b.rows.len() <= r));
    let (steps, z0, zk) = steps_of(a, r, batches);
    log(&format!("{name}: {k} batches, layers {:?}", batches.iter().map(|b| format!("{:?}", b.report.layer)).collect::<Vec<_>>()));
    let (receipt, proof) = fold::prove(RELATION_CLEARING_V1, &ClearingStep::blank(a, r), &steps, &z0.to_z(), &zk.to_z(), &mut |s| log(s)).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(std::env::temp_dir().join(format!("clearing_{name}_k{k}.proof")), &proof).ok();
    let stmt = UtxoRefL2SettlementStatementV0 {
        network_code: if live { BitcoinNetworkCode::Testnet4 } else { BitcoinNetworkCode::Regtest },
        chain_genesis_hash: [0; 32],
        contract_id: sha256_native(if live { b"lightninger/venue/testnet4".as_slice() } else { b"lightninger/venue/regtest-drill".as_slice() }),
        commitment_hash: commitment_hash(&zk.to_z()),
        assertion_txid: [0; 32],
        settlement_txid: [0; 32],
        program_hash: program_hash(a, r),
        verifying_key_hash: hex::decode(&receipt.vk_sha256).unwrap().try_into().unwrap(),
        policy_hash: [0; 32],
        epoch_id: zk.seq,
        assertion_vout: 0,
    };
    let enc = stmt.encode();
    let d = sha256_native(&enc);
    let limbs = split_statement_digest_be_u128(&d);
    let run = ClearingRun {
        scenario: t.name.clone(),
        accounts_table: a,
        rows_capacity: r,
        batches: batches
            .iter()
            .map(|b| json!({"seq": b.seq, "layer": format!("{:?}", b.report.layer), "rows": b.rows.len(), "claim_haircuts": b.report.claim_haircuts.len(), "digest": hex::encode(b.digest), "cash_before": b.report.cash_before, "cash_after": b.report.cash_after}))
            .collect(),
        fold: receipt,
        bitvm3_statement_hex: hex::encode(enc),
        bitvm3_statement_sha256: hex::encode(d),
        bitvm3_public_limbs_be: [limbs[0].to_string(), limbs[1].to_string()],
    };
    let p = artifacts().join(format!("clearing_{}_k{k}_A{a}_R{r}.json", if live { format!("journal_{}", t.name) } else { name.replace(':', "") }));
    std::fs::write(&p, serde_json::to_string_pretty(&run).unwrap()).unwrap();
    log(&format!("wrote {}", p.display()));
}

#[derive(Deserialize)]
struct CoreTx {
    label: String,
    signed_hex: String,
    amounts: Vec<u64>,
    spks: Vec<String>,
    /// `script_path: null | {key, tapleaf, codesep}` per slot (absent = key path).
    slots: Vec<BoundSlot>,
}

type SE1 = Secq256k1Engine;
type SE2 = Secp256k1Engine;
type SS1 = RelaxedR1CSSNARK<SE1, EvaluationEngine<SE1>>;
type SS2 = RelaxedR1CSSNARK<SE2, EvaluationEngine<SE2>>;

/// Fold the BIP-340 slots through the MNR-05 Secq256k1 step (unchanged, by path dependency).
fn prove_secq(slots: &[Bip340StepSlot]) -> Value {
    let mut acc = [0u8; 32];
    let mut steps = Vec::new();
    for s in slots {
        steps.push(Mnr05SecqBip340Step::from_valid_slot(acc, s.clone()).unwrap());
        acc = s.next_accumulator(&acc);
    }
    let t = Instant::now();
    let pp = PublicParams::<SE1, SE2, Mnr05SecqBip340Step>::setup(&Mnr05SecqBip340Step::blank(), &*SS1::ck_floor(), &*SS2::ck_floor()).unwrap();
    let (pk, vk) = CompressedSNARK::<SE1, SE2, Mnr05SecqBip340Step, SS1, SS2>::setup(&pp).unwrap();
    let setup = t.elapsed().as_secs_f64();
    let z0 = vec![SecqScalar::ZERO; 3];
    let (lo, hi) = le_halves(&acc);
    let want = vec![SecqScalar::from(slots.len() as u64), secq_from_u128(lo), secq_from_u128(hi)];
    let t = Instant::now();
    let mut rec = RecursiveSNARK::new(&pp, &steps[0], &z0).unwrap();
    for s in &steps {
        rec.prove_step(&pp, s).unwrap();
    }
    let zn = rec.verify(&pp, steps.len(), &z0).unwrap();
    assert_eq!(zn, want, "Secq accumulator");
    let fold_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let proof = CompressedSNARK::<SE1, SE2, Mnr05SecqBip340Step, SS1, SS2>::prove(&pp, &pk, &rec).unwrap();
    let comp = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let out = proof.verify(&vk, steps.len(), &z0).unwrap();
    let ver = t.elapsed().as_secs_f64();
    assert_eq!(out, want);
    let mut bad = z0.clone();
    bad[1] += SecqScalar::ONE;
    let rejected = proof.verify(&vk, steps.len(), &bad).is_err();
    assert!(rejected);
    let (c1, c2) = pp.num_constraints();
    let bytes = bincode::serialize(&proof).unwrap();
    json!({"relation": "shz/mnr05-secq256k1-bip340-batch-auth/v1 (Mnr05SecqBip340Step, unchanged)", "steps": steps.len(), "primary_constraints": c1, "secondary_constraints": c2,
        "setup_seconds": setup, "fold_seconds": fold_s, "compress_seconds": comp, "verify_seconds": ver, "proof_bytes": bytes.len(),
        "auth_accumulator": hex::encode(acc), "mutated_z0_rejected": rejected, "output": out.iter().map(|e| hex::encode(e.to_repr().as_ref())).collect::<Vec<_>>()})
}

fn prove_tapsighash(source: &str) {
    let (label, tx, amounts, spks, slots, annex_max) = if source == "vector" {
        let v: Value = serde_json::from_str(include_str!("../tests/vectors/bip341-wallet-test-vectors.json")).unwrap();
        let k = &v["keyPathSpending"][0];
        let tx = Tx::parse(&hex::decode(k["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap());
        let u = k["given"]["utxosSpent"].as_array().unwrap();
        let amounts: Vec<u64> = u.iter().map(|x| x["amountSats"].as_u64().unwrap()).collect();
        let spks: Vec<Vec<u8>> = u.iter().map(|x| hex::decode(x["scriptPubKey"].as_str().unwrap()).unwrap()).collect();
        let slots = k["inputSpending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let w = hex::decode(s["expected"]["witness"][0].as_str().unwrap()).unwrap();
                SigSlot { input: s["given"]["txinIndex"].as_u64().unwrap() as usize, hash_type: s["given"]["hashType"].as_u64().unwrap() as u8, annex: None, sig_rx: w[..32].try_into().unwrap(), sig_s: w[32..64].try_into().unwrap() }
            })
            .collect::<Vec<SigSlot>>();
        ("bip341_vector".to_string(), tx, amounts, spks, slots.into_iter().map(|s| (s, None)).collect::<Vec<_>>(), 0)
    } else {
        // <source>:<label> from a signed-transaction file in the core_sighash_txs.json shape
        let (src, want) = source.split_once(':').expect("vector | core:LABEL | corescript:LABEL | testnet4:LABEL");
        let (file, annex_max) = match src {
            "core" => ("core_sighash_txs.json", Some(40)),
            "corescript" => ("core_scriptpath_txs.json", None),
            "testnet4" => ("testnet4_demo/txs.json", None),
            _ => panic!("unknown source {src}"),
        };
        let all: Vec<CoreTx> = serde_json::from_str(&std::fs::read_to_string(artifacts().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"))).unwrap();
        let c = all.into_iter().find(|c| c.label == want).unwrap_or_else(|| panic!("no label {want} in {file}"));
        let tx = Tx::parse(&hex::decode(&c.signed_hex).unwrap());
        let amax = annex_max.unwrap_or_else(|| c.slots.iter().filter_map(|s| s.slot.annex.as_ref().map(|a| a.len())).max().unwrap_or(0));
        (format!("{src}_{}", c.label), tx, c.amounts, c.spks.iter().map(|s| hex::decode(s).unwrap()).collect(), c.slots.into_iter().map(|s| (s.slot, s.script_path)).collect::<Vec<_>>(), amax)
    };
    let mut shape = TxShape::of(&tx, &spks, annex_max);
    // bind mode when any signature is a script-path one
    shape.bind = slots.iter().any(|s| s.1.is_some());
    let spent = spent_commitment(&amounts, &spks);
    let (steps, b, acc, mask, par) = if shape.bind {
        bound_steps(&shape, &tx, &amounts, &spks, &slots)
    } else {
        let plain: Vec<SigSlot> = slots.iter().map(|s| s.0.clone()).collect();
        let (st, b, acc, mask) = sighash_steps(&shape, &tx, &amounts, &spks, &plain);
        (st, b, acc, mask, [0; 32])
    };
    let mut z0 = tap_z(0, &[0; 32], &tx.txid(), &spent, 0);
    let mut zk = tap_z(steps.len() as u64, &acc, &tx.txid(), &spent, mask);
    if shape.bind {
        let (p0, p1) = le_halves(&par);
        z0.extend([F::ZERO, F::ZERO]);
        zk.extend([F::from_u128(p0), F::from_u128(p1)]);
    }
    log(&format!("{label}: {} signature steps ({} script path), txid {}", steps.len(), slots.iter().filter(|s| s.1.is_some()).count(), hex::encode(tx.txid())));
    let (receipt, _) = fold::prove(RELATION_TAPSIGHASH_V1, &SighashStep::blank(&shape), &steps, &z0, &zk, &mut |s| log(s)).unwrap_or_else(|e| panic!("{e}"));
    log("folding the same slots through Mnr05SecqBip340Step");
    let secq = prove_secq(&b);
    let (lo, hi) = le_halves(&acc);
    let same = receipt.zk[1] == hex_be(lo) && receipt.zk[2] == hex_be(hi);
    assert!(same, "TapSighash and Secq accumulators differ");
    let out = json!({
        "source": label, "txid": hex::encode(tx.txid()), "shape": shape,
        "slots": slots.iter().map(|(s, e)| json!({"input": s.input, "hash_type": format!("{:#04x}", s.hash_type), "annex_len": s.annex.as_ref().map(|a| a.len()), "script_path": e})).collect::<Vec<_>>(),
        "sighashes": b.iter().map(|s| hex::encode(s.sighash32)).collect::<Vec<_>>(),
        "auth_accumulator": hex::encode(acc), "signed_mask": format!("{mask:#b}"),
        "params_accumulator": if shape.bind { Some(hex::encode(par)) } else { None },
        "tapsighash_fold": receipt, "secq_fold": secq, "accumulators_equal": same,
    });
    let p = artifacts().join(format!("tapsighash_{label}.json"));
    std::fs::write(&p, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    log(&format!("wrote {}", p.display()));
}

fn audit_one(name: &str, cs: &lightninger_bitvm3_clearing::audit::AuditCS, public: &[u32], pairs: usize, export: bool) -> Value {
    let t = Instant::now();
    let r = cs.audit(public, pairs);
    log(&format!("{name}: {} constraints, single {}/{} rejected, pairs {}/{} rejected, free {:?} {:?} ({:.0}s)", r.constraints, r.single_rejected, r.single_mutations, r.pair_rejected, r.pair_mutations, r.single_free, r.pair_free, t.elapsed().as_secs_f64()));
    if export {
        let p = std::env::temp_dir().join(format!("{name}.r1cs"));
        cs.write_r1cs(&p, public).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        log(&format!("exported {} ({} bytes, sha256 {})", p.display(), bytes.len(), hex::encode(sha256_native(&bytes))));
        return json!({"name": name, "report": r, "r1cs_bytes": bytes.len(), "r1cs_sha256": hex::encode(sha256_native(&bytes)), "r1cs_path_at_run": p.display().to_string()});
    }
    json!({"name": name, "report": r})
}

/// Variable-level audit of real steps (and small instances exported as .r1cs).
fn audit_all(pairs: usize) {
    let pairs_budget = pairs;
    use lightninger_bitvm3_clearing::audit::record;
    let mut out = Vec::new();
    let traces: Vec<(&str, trace::Trace)> = ["drill_fund", "drill_nofund", "own_claim", "legacy", "walk", "walk_nofund"].iter().map(|n| (*n, scenario(n, 6))).collect();
    for layer in ["None", "Margin", "OwnClaim", "Fund", "Haircut", "Carried"] {
        let mut best: Option<(&str, ClearingStep, &trace::BatchRecord)> = None;
        for (sc, t) in &traces {
            let (steps, _, _) = steps_of(6, 4, &t.batches);
            for (s, b) in steps.into_iter().zip(&t.batches) {
                let score = |b: &trace::BatchRecord| b.rows.len() + 4 * b.report.claim_haircuts.len() + 2 * (b.report.cash_before < 0) as usize;
                if format!("{:?}", b.report.layer) == layer && best.as_ref().is_none_or(|x| score(b) > score(x.2)) {
                    best = Some((*sc, s, b));
                }
            }
        }
        let (sc, s, b) = best.expect("layer present in the traces");
        let (cs, public) = record(&s, &s.pre.to_z());
        out.push(audit_one(&format!("clearing_A6_R4_{sc}_seq{}_{layer}_rows{}_ch{}", b.seq, b.rows.len(), b.report.claim_haircuts.len()), &cs, &public, pairs, false));
    }
    // the batch with the most claim haircuts (deferred claims of accounts outside the batch)
    let (sc, s, b) = traces.iter().flat_map(|(sc, t)| { let (st, _, _) = steps_of(6, 4, &t.batches); st.into_iter().zip(t.batches.iter()).map(move |(s, b)| (*sc, s, b)) }).max_by_key(|(_, _, b)| b.report.claim_haircuts.len()).unwrap();
    let (cs, public) = record(&s, &s.pre.to_z());
    out.push(audit_one(&format!("clearing_A6_R4_{sc}_seq{}_{:?}_rows{}_ch{}", b.seq, b.report.layer, b.rows.len(), b.report.claim_haircuts.len()), &cs, &public, pairs, false));
    // small instance for external tools: 2 accounts, 1 row
    let t = trace::own_claim(4);
    let small: Vec<_> = t.batches.iter().filter(|b| b.rows.len() <= 2).cloned().collect();
    let (steps, _, _) = steps_of(4, 2, &small);
    let s = &steps[steps.len() / 2];
    let (cs, public) = record(s, &s.pre.to_z());
    out.push(audit_one("clearing_A4_R2_small", &cs, &public, pairs, true));
    let v: Value = serde_json::from_str(include_str!("../tests/vectors/bip341-wallet-test-vectors.json")).unwrap();
    let k = &v["keyPathSpending"][0];
    let tx = Tx::parse(&hex::decode(k["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap());
    let u = k["given"]["utxosSpent"].as_array().unwrap();
    let amounts: Vec<u64> = u.iter().map(|x| x["amountSats"].as_u64().unwrap()).collect();
    let spks: Vec<Vec<u8>> = u.iter().map(|x| hex::decode(x["scriptPubKey"].as_str().unwrap()).unwrap()).collect();
    let slots: Vec<SigSlot> = k["inputSpending"].as_array().unwrap().iter().map(|s| {
        let w = hex::decode(s["expected"]["witness"][0].as_str().unwrap()).unwrap();
        SigSlot { input: s["given"]["txinIndex"].as_u64().unwrap() as usize, hash_type: s["given"]["hashType"].as_u64().unwrap() as u8, annex: None, sig_rx: w[..32].try_into().unwrap(), sig_s: w[32..64].try_into().unwrap() }
    }).collect();
    let shape = TxShape::of(&tx, &spks, 0);
    let (steps, _, _, _) = sighash_steps(&shape, &tx, &amounts, &spks, &slots);
    for st in [&steps[0], &steps[1], &steps[3]] {
        let (cs, public) = record(st, &st.z_in());
        out.push(audit_one(&format!("tapsighash_vector_input{}_{:#04x}", st.slot.input, st.slot.hash_type), &cs, &public, pairs, false));
    }
    // annex shape, annex present, from the Core run if available
    if let Ok(txt) = std::fs::read_to_string(artifacts().join("core_sighash_txs.json")) {
        let all: Vec<CoreTx> = serde_json::from_str(&txt).unwrap();
        if let Some(c) = all.iter().find(|c| c.label == "annex") {
            let tx = Tx::parse(&hex::decode(&c.signed_hex).unwrap());
            let spks: Vec<Vec<u8>> = c.spks.iter().map(|s| hex::decode(s).unwrap()).collect();
            let shape = TxShape::of(&tx, &spks, 40);
            let plain: Vec<SigSlot> = c.slots.iter().map(|s| s.slot.clone()).collect();
            let (steps, _, _, _) = sighash_steps(&shape, &tx, &c.amounts, &spks, &plain);
            let (cs, public) = record(&steps[0], &steps[0].z_in());
            out.push(audit_one("tapsighash_core_annex_input0", &cs, &public, pairs, false));
        }
    }
    // bind mode (script path), from the Core script-path run
    if let Ok(txt) = std::fs::read_to_string(artifacts().join("core_scriptpath_txs.json")) {
        let all: Vec<CoreTx> = serde_json::from_str(&txt).unwrap();
        let c = &all[0];
        let tx = Tx::parse(&hex::decode(&c.signed_hex).unwrap());
        let spks: Vec<Vec<u8>> = c.spks.iter().map(|s| hex::decode(s).unwrap()).collect();
        let mut shape = TxShape::of(&tx, &spks, 0);
        shape.bind = true;
        let pairs: Vec<_> = c.slots.iter().map(|s| (s.slot.clone(), s.script_path.clone())).collect();
        let (steps, _, _, _, _) = bound_steps(&shape, &tx, &c.amounts, &spks, &pairs);
        for i in [1, 3] {
            let (cs, public) = record(&steps[i], &steps[i].z_in());
            out.push(audit_one(&format!("tapsighash_bind_core_slot{i}_{}", if steps[i].ext.is_some() { "scriptpath" } else { "keypath" }), &cs, &public, pairs_budget, false));
        }
    }
    // smallest TapSighash relation: 1 P2TR input, 1 P2TR output
    let shape1 = TxShape { script_sig_lens: vec![0], prevout_spk_lens: vec![34], out_spk_lens: vec![34], annex_max: 0, bind: false };
    let st = SighashStep::blank(&shape1);
    let (cs, public) = record(&st, &st.z_in());
    out.push(audit_one("tapsighash_1in_1out_small", &cs, &public, pairs, true));
    let p = artifacts().join("audit_r1cs.json");
    std::fs::write(&p, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    log(&format!("wrote {}", p.display()));
}

#[derive(Deserialize)]
struct CetTx {
    label: String,
    signed_hex: String,
    amounts: Vec<u64>,
    spks: Vec<String>,
    slots: Vec<BoundSlot>,
    m17_flags: u32,
}

fn prove_cet(clearing_scenario: &str, k: usize) {
    use lightninger_bitvm3_clearing::cet::{expected_slots, joint_commitment, params_of, verify_binding};
    use m17_nova_script::{circuit as m17c, Case};
    let txs: Vec<CetTx> = serde_json::from_str(&std::fs::read_to_string(artifacts().join("core_cet_txs.json")).expect("run tests/core_cet.rs first")).unwrap();
    let t = Instant::now();
    let m17_pp = m17c::setup();
    log(&format!("M17 setup {:.1}s", t.elapsed().as_secs_f64()));
    let mut parts = Vec::new();
    let mut cet_txid = [0u8; 32];
    let mut m17_folds = Vec::new();
    let mut tap_zks = Vec::new();
    let mut secq_zks = Vec::new();
    for c in &txs {
        let tx = Tx::parse(&hex::decode(&c.signed_hex).unwrap());
        let spks: Vec<Vec<u8>> = c.spks.iter().map(|s| hex::decode(s).unwrap()).collect();
        if c.label == "cet" {
            cet_txid = tx.txid();
        }
        // 1. M17 per input
        let mut folded = Vec::new();
        for i in 0..tx.inputs.len() {
            let case = Case {
                id: format!("{}/{i}", c.label),
                category: "cet".into(),
                flags: String::new(),
                flag_bits: c.m17_flags,
                expect_valid: true,
                description: c.label.clone(),
                tx: c.signed_hex.clone(),
                prevouts: c.amounts.iter().zip(&c.spks).map(|(a, s)| (*a as i64, s.clone())).collect(),
                index: i,
            };
            let f = m17c::fold_case(&m17_pp, &case).unwrap_or_else(|e| panic!("M17 {}: {e}", c.label));
            log(&format!("{} input {i}: M17 {} steps folded {:.1}s, verified {:.2}s, {} deferred signatures", c.label, f.steps, f.prove_seconds, f.verify_seconds, f.deferred.len()));
            folded.push((i, f));
        }
        // 2. TapSighash (bind) and Secq folds of the signatures M17 relies on
        let mut slots = Vec::new();
        for (i, f) in &folded {
            slots.extend(expected_slots(*i, f).unwrap());
        }
        let signed: Vec<_> = c.slots.iter().map(|s| (s.slot.clone(), s.script_path.clone())).collect();
        assert_eq!(slots, signed, "{}: M17's deferred signatures are not the signed slots", c.label);
        let mut shape = TxShape::of(&tx, &spks, 0);
        shape.bind = true;
        let (steps, b, acc, mask, par) = bound_steps(&shape, &tx, &c.amounts, &spks, &slots);
        let spent = spent_commitment(&c.amounts, &spks);
        let mut z0 = tap_z(0, &[0; 32], &tx.txid(), &spent, 0);
        z0.extend([F::ZERO, F::ZERO]);
        let mut zk = tap_z(steps.len() as u64, &acc, &tx.txid(), &spent, mask);
        let (p0, p1) = le_halves(&par);
        zk.extend([F::from_u128(p0), F::from_u128(p1)]);
        let (tap, _) = fold::prove(RELATION_TAPSIGHASH_V1, &SighashStep::blank(&shape), &steps, &z0, &zk, &mut |s| log(s)).unwrap_or_else(|e| panic!("{e}"));
        let secq = prove_secq(&b);
        let (lo, hi) = le_halves(&acc);
        let secq_zk = vec![SecqScalar::from(b.len() as u64), secq_from_u128(lo), secq_from_u128(hi)];
        // 3. the binding, and what it must reject
        let refs: Vec<(usize, &m17c::Folded)> = folded.iter().map(|(i, f)| (*i, f)).collect();
        verify_binding(&tx, &c.amounts, &spks, &refs, &zk, &acc).unwrap_or_else(|e| panic!("binding {}: {e}", c.label));
        let key0: [u8; 32] = spks[0][2..34].try_into().unwrap();
        let par_with = |sl: &[(SigSlot, Option<lightninger_bitvm3_clearing::tapsighash_step::ScriptPath>)]| {
            let mut z = zk.clone();
            let p = params_of(sl, |_| key0);
            let (a, b) = le_halves(&p);
            z[8] = F::from_u128(a);
            z[9] = F::from_u128(b);
            z
        };
        let mut negatives = Vec::new();
        let mut neg = |name: &str, z: Vec<F>, acc2: [u8; 32]| {
            let r = verify_binding(&tx, &c.amounts, &spks, &refs, &z, &acc2);
            assert!(r.is_err(), "{name}: binding accepted");
            negatives.push(json!({"case": name, "rejected": r.unwrap_err()}));
        };
        let mut sw = slots.clone();
        sw.swap(0, 1);
        neg("signatures in another order", par_with(&sw), acc);
        let mut dropped = slots.clone();
        dropped.pop();
        let mut z = par_with(&dropped);
        z[0] = F::from(dropped.len() as u64);
        neg("one signature dropped", z, acc);
        let mut other_leaf = slots.clone();
        other_leaf[0].1.as_mut().unwrap().tapleaf[0] ^= 1;
        neg("signature checked for another tapleaf", par_with(&other_leaf), acc);
        let mut other_cs = slots.clone();
        other_cs[0].1.as_mut().unwrap().codesep = 0;
        neg("signature checked for another codeseparator position", par_with(&other_cs), acc);
        let mut z = zk.clone();
        z[3] += F::ONE;
        neg("TapSighash fold over another transaction", z, acc);
        let mut bad = acc;
        bad[0] ^= 1;
        neg("Secq fold ending in another accumulator", zk.clone(), bad);
        log(&format!("{}: binding verified; {} negative cases rejected", c.label, negatives.len()));
        parts.push(json!({
            "label": c.label, "txid": hex::encode(tx.txid()), "shape": shape,
            "m17": folded.iter().map(|(i, f)| json!({"input": i, "steps": f.steps, "claims": f.claims.len(), "deferred_signatures": f.deferred.len(), "prove_seconds": f.prove_seconds, "verify_seconds": f.verify_seconds,
                "z0": f.z0.iter().map(|e| hex::encode(e.to_repr().as_ref())).collect::<Vec<_>>(), "zn": f.zn.iter().map(|e| hex::encode(e.to_repr().as_ref())).collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "slots": slots.iter().map(|(s, e)| json!({"input": s.input, "hash_type": s.hash_type, "script_path": e})).collect::<Vec<_>>(),
            "params_accumulator": hex::encode(par), "auth_accumulator": hex::encode(acc),
            "tapsighash_fold": tap, "secq_fold": secq, "binding_negatives": negatives,
        }));
        m17_folds.push(folded);
        tap_zks.push(zk);
        secq_zks.push(secq_zk);
    }
    // 4. the clearing chain
    let tr = scenario(clearing_scenario, 6);
    let batches = &tr.batches[..k];
    let (steps, cz0, czk) = steps_of(6, 4, batches);
    let (clear, _) = fold::prove(RELATION_CLEARING_V1, &ClearingStep::blank(6, 4), &steps, &cz0.to_z(), &czk.to_z(), &mut |s| log(s)).unwrap_or_else(|e| panic!("{e}"));
    // 5. the joint statement: every fold's public IO under one commitment
    let mut commits = Vec::new();
    for (j, folded) in m17_folds.iter().enumerate() {
        let refs: Vec<(usize, &m17c::Folded)> = folded.iter().map(|(i, f)| (*i, f)).collect();
        commits.push(joint_commitment(&cz0.to_z(), &czk.to_z(), &tap_zks[j], &secq_zks[j], &refs));
    }
    let mut cb = lightninger_bitvm3_clearing::cet::JOINT_TAG.to_vec();
    for c in &commits {
        cb.extend(c);
    }
    let commitment = sha256_native(&cb);
    let stmt = UtxoRefL2SettlementStatementV0 {
        network_code: BitcoinNetworkCode::Regtest,
        chain_genesis_hash: [0; 32],
        contract_id: sha256_native(b"lightninger/dlc/regtest-cet-demo"),
        commitment_hash: commitment,
        assertion_txid: [0; 32],
        settlement_txid: cet_txid,
        program_hash: sha256_native(format!("{RELATION_CLEARING_V1}+{RELATION_TAPSIGHASH_V1}+bind+shz/mnr05-secq256k1-bip340-batch-auth/v1+m17-nova-script@f80c364").as_bytes()),
        verifying_key_hash: sha256_native(&[hex::decode(&clear.vk_sha256).unwrap()].concat()),
        policy_hash: [0; 32],
        epoch_id: czk.seq,
        assertion_vout: 0,
    };
    let enc = stmt.encode();
    let d = sha256_native(&enc);
    let limbs = split_statement_digest_be_u128(&d);
    let out = json!({
        "spends": parts,
        "clearing": {"scenario": tr.name, "batches": k, "layers": batches.iter().map(|b| format!("{:?}", b.report.layer)).collect::<Vec<_>>(), "fold": clear},
        "per_transaction_commitments": commits.iter().map(hex::encode).collect::<Vec<_>>(),
        "commitment_hash": hex::encode(commitment),
        "bitvm3_statement_hex": hex::encode(enc), "bitvm3_statement_sha256": hex::encode(d),
        "bitvm3_public_limbs_be": [limbs[0].to_string(), limbs[1].to_string()],
    });
    let p = artifacts().join("cet_joint_statement.json");
    std::fs::write(&p, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    log(&format!("wrote {}", p.display()));
}

fn hex_be(v: u128) -> String {
    let e = F::from_u128(v);
    let mut b = e.to_repr().as_ref().to_vec();
    b.reverse();
    hex::encode(b)
}

fn main() {
    START.with(|_| ());
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("shape") => shape(),
        Some("prove-clearing") => {
            let k = a[3].parse().unwrap();
            let acc = a.get(4).map_or(6, |x| x.parse().unwrap());
            let r = a.get(5).map_or(4, |x| x.parse().unwrap());
            prove_clearing(&a[2], k, acc, r)
        }
        Some("prove-tapsighash") => prove_tapsighash(&a[2]),
        Some("trace-stats") => {
            let t = scenario(&a[2], a.get(3).map_or(6, |x| x.parse().unwrap()));
            println!("{}: {} batches, max rows {}, layers {:?}, batches with claim haircuts {}", t.name, t.batches.len(), t.max_rows(), t.layers(), t.batches.iter().filter(|b| !b.report.claim_haircuts.is_empty()).count());
        }
        Some("prove-cet") => prove_cet(a.get(2).map_or("drill_fund", String::as_str), a.get(3).map_or(4, |x| x.parse().unwrap())),
        Some("audit") => audit_all(a.get(2).map_or(2_000_000, |x| x.parse().unwrap())),
        _ => eprintln!("usage: shape | trace-stats <scenario> [A] | prove-clearing <scenario> <K> [A] [R] | prove-tapsighash <vector|core:LABEL> | audit [pair_budget]"),
    }
}
