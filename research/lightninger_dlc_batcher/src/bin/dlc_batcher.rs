//! `dlc-batcher`: proofs, statement and BitVM3 claim graph of one DLC batch epoch.
//!
//! - `prove <dir> [A] [R]` — `<dir>` holds `txs.json` (the signed settlement), `manifest.json` and
//!   `batches.json` from `tests/core_batch.rs` (or the testnet4 builder); `artifacts/venue_batches.json`
//!   is the venue trace. Folds the clearing of every batch (`trace::from_venue`, table `A`, `R` rows
//!   per batch), M17 over every settlement input, the bind-mode TapSighash and Secq folds over every
//!   signature, checks the binding and the settlement relation (and their negative cases), and writes
//!   `<dir>/joint_statement.json` with the 304-byte statement, plus the SP1 guest's input
//!   (`<dir>/guest_input.json`; the clearing key and proof go to `$LIGHTNINGER_DLC_BATCH_GUEST_DIR`).
//! - `wrong-statement <dir>` — the statement an operator would claim for the tampered settlement
//!   (account 3 paid one sat less, from `receipt.json`): `<dir>/wrong_statement.json`.
//! - `claim-graph <dir> <gc_honest.json> <gc_wrong.json>` — phase B on the regtest chain phase A left:
//!   two pool vaults, an honest claim that pays the operator after the window and a claim of the wrong
//!   statement that the challenger disproves with the garbled verifier's reject label.
use ff::{Field, PrimeField};
use halo2curves::{bn256::Fr as F, secq256k1::Fq as SecqScalar};
use lightninger_bitvm3_clearing::{
    cet::{expected_slots, params_of, verify_binding},
    clearing_step::{steps_of, ClearingStep, RELATION_CLEARING_V1},
    fold::{self, E1, E2, S1, S2},
    gadgets::{le_halves, sha256_native},
    tapsighash_step::{bound_steps, spent_commitment, tap_z, BoundSlot, SigSlot, SighashStep, Tx, TxShape, RELATION_TAPSIGHASH_V1},
    trace,
};
use lightninger_dlc_batch_relation as rel;
use lightninger_dlc_batcher::*;
use m17_nova_script::{circuit as m17c, Case};
use nova_snark::{
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc::EvaluationEngine, Secp256k1Engine, Secq256k1Engine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait,
};
use serde::Deserialize;
use serde_json::{json, Value};
use shz_mnr05_bitvm3_ln_dlc::secq_schnorr_circuit::{secq_from_u128, Bip340StepSlot, Mnr05SecqBip340Step};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

type SE1 = Secq256k1Engine;
type SE2 = Secp256k1Engine;
type SS1 = RelaxedR1CSSNARK<SE1, EvaluationEngine<SE1>>;
type SS2 = RelaxedR1CSSNARK<SE2, EvaluationEngine<SE2>>;

thread_local! { static START: Instant = Instant::now(); }
fn log(s: &str) {
    eprintln!("[{:.1}s] {s}", START.with(|t| t.elapsed().as_secs_f64()));
}

fn artifacts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts")
}

fn read<T: for<'a> Deserialize<'a>>(p: &Path) -> T {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn write(p: &Path, v: &Value) {
    std::fs::write(p, serde_json::to_string_pretty(v).unwrap()).unwrap();
    log(&format!("wrote {}", p.display()));
}

#[derive(Deserialize)]
struct SignedTx {
    label: String,
    signed_hex: String,
    amounts: Vec<u64>,
    spks: Vec<String>,
    slots: Vec<BoundSlot>,
    m17_flags: u32,
}

fn reprs<P: PrimeField>(z: &[P]) -> Vec<[u8; 32]> {
    z.iter().map(|e| e.to_repr().as_ref().try_into().unwrap()).collect()
}

fn regtest_genesis() -> [u8; 32] {
    hex::decode(shz_nova_bitvm::bitvm3::BITCOIN_REGTEST_GENESIS_HASH_HEX).unwrap().try_into().unwrap()
}
fn testnet4_genesis() -> [u8; 32] {
    hex::decode(shz_nova_bitvm::bitvm3::BITCOIN_TESTNET4_GENESIS_HASH_HEX).unwrap().try_into().unwrap()
}

use rel::PROGRAM;

fn prove_secq(slots: &[Bip340StepSlot]) -> (Value, Vec<SecqScalar>) {
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
    assert_eq!(rec.verify(&pp, steps.len(), &z0).unwrap(), want, "Secq accumulator");
    let fold_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let proof = CompressedSNARK::<SE1, SE2, Mnr05SecqBip340Step, SS1, SS2>::prove(&pp, &pk, &rec).unwrap();
    let comp = t.elapsed().as_secs_f64();
    let out = proof.verify(&vk, steps.len(), &z0).unwrap();
    assert_eq!(out, want);
    let mut bad = z0.clone();
    bad[1] += SecqScalar::ONE;
    let rejected = proof.verify(&vk, steps.len(), &bad).is_err();
    assert!(rejected);
    let (c1, c2) = pp.num_constraints();
    let r = json!({"relation": "shz/mnr05-secq256k1-bip340-batch-auth/v1", "steps": steps.len(), "primary_constraints": c1, "secondary_constraints": c2,
        "setup_seconds": setup, "fold_seconds": fold_s, "compress_seconds": comp, "proof_bytes": bincode::serialize(&proof).unwrap().len(),
        "auth_accumulator": hex::encode(acc), "mutated_z0_rejected": rejected});
    (r, want)
}

/// The clearing fold's verifier key, rebuilt (setup is deterministic) and checked against the receipt.
fn clearing_vk_bytes(a: usize, r: usize, vk_sha: &str) -> Vec<u8> {
    use bincode::Options;
    let blank = ClearingStep::blank(a, r);
    let pp = PublicParams::<E1, E2, ClearingStep>::setup(&blank, &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
    let (_, vk) = CompressedSNARK::<E1, E2, ClearingStep, S1, S2>::setup(&pp).unwrap();
    let b = bincode::DefaultOptions::new().with_fixint_encoding().serialize(&vk).unwrap();
    assert_eq!(hex::encode(sha256_native(&b)), vk_sha, "rebuilt clearing key differs from the proved one");
    b
}

fn prove(dir: &Path, a: usize, r: usize) {
    let txs: Vec<SignedTx> = read(&dir.join("txs.json"));
    let manifest: rel::Manifest = read(&dir.join("manifest.json"));
    let batches: Vec<rel::Batch> = read(&dir.join("batches.json"));
    // the venue trace of the epoch: `$LIGHTNINGER_DLC_BATCH_VENUE` (one settlement daemon segment) or the research epoch
    let venue: Value = read(&std::env::var("LIGHTNINGER_DLC_BATCH_VENUE").map(PathBuf::from).unwrap_or_else(|_| artifacts().join("venue_batches.json")));
    let c = txs.iter().find(|c| c.label == "settlement").expect("settlement");
    let raw = hex::decode(&c.signed_hex).unwrap();
    let tx = Tx::parse(&raw);
    let spks: Vec<Vec<u8>> = c.spks.iter().map(|s| hex::decode(s).unwrap()).collect();
    let (m_amounts, m_spks) = manifest.spent();
    assert_eq!((m_amounts.clone(), m_spks.clone()), (c.amounts.clone(), spks.clone()), "txs.json prevouts differ from the manifest");

    // 0. the settlement relation, natively, and what it must reject
    let settled = rel::check_settlement(&raw, &manifest, &batches).unwrap();
    assert_eq!(settled.txid, tx.txid());
    let mut rel_neg = Vec::new();
    let mut neg_rel = |name: &str, raw2: &[u8], m2: &rel::Manifest, b2: &[rel::Batch]| {
        let e = rel::check_settlement(raw2, m2, b2).expect_err(name);
        rel_neg.push(json!({"case": name, "rejected": e}));
    };
    let paid = |r: &rel::Row| manifest.accounts.iter().any(|a| (a.channel_txid, a.channel_vout) == (r.channel_txid, r.channel_vout));
    let mut b2 = batches.clone();
    if let Some(k) = b2.iter().position(|b| b.rows.iter().any(|r| r.net != 0 && paid(r))) {
        let ri = b2[k].rows.iter().position(|r| r.net != 0 && paid(r)).unwrap();
        b2[k].rows[ri].net += 1;
        neg_rel("one batch row's net changed by 1 (payout no longer matches)", &raw, &manifest, &b2);
    }
    if manifest.accounts.len() >= 2 {
        let mut m2 = manifest.clone();
        m2.accounts.swap(0, 1);
        neg_rel("manifest accounts in another order", &raw, &m2, &batches);
    }
    let mut m3 = manifest.clone();
    m3.accounts.pop();
    neg_rel("one account left out of the manifest", &raw, &m3, &batches);
    let mut m4 = manifest.clone();
    let j = 2.min(manifest.accounts.len() - 1);
    m4.accounts[j].payout_spk[5] ^= 1;
    neg_rel(&format!("account {j}'s payout key changed"), &raw, &m4, &batches);
    if let Some(c) = manifest.carried.first() {
        let mut m5 = manifest.clone();
        m5.carried[0].net = c.net + 1;
        neg_rel("a carried channel's net stated 1 sat off", &raw, &m5, &batches);
    }
    log(&format!("settlement relation holds; {} negative cases rejected", rel_neg.len()));

    // 1. M17 per input
    let t = Instant::now();
    let m17_pp = m17c::setup();
    log(&format!("M17 setup {:.1}s", t.elapsed().as_secs_f64()));
    let mut folded = Vec::new();
    for i in 0..tx.inputs.len() {
        let case = Case {
            id: format!("settlement/{i}"),
            category: "dlc-batch".into(),
            flags: String::new(),
            flag_bits: c.m17_flags,
            expect_valid: true,
            description: "DLC batch settlement".into(),
            tx: c.signed_hex.clone(),
            prevouts: c.amounts.iter().zip(&c.spks).map(|(a, s)| (*a as i64, s.clone())).collect(),
            index: i,
        };
        let f = m17c::fold_case(&m17_pp, &case).unwrap_or_else(|e| panic!("M17 input {i}: {e}"));
        log(&format!("input {i}: M17 {} steps folded {:.1}s, {} deferred signatures", f.steps, f.prove_seconds, f.deferred.len()));
        folded.push((i, f));
    }
    // 2. TapSighash (bind) and Secq folds
    let mut slots = Vec::new();
    for (i, f) in &folded {
        slots.extend(expected_slots(*i, f).unwrap());
    }
    let signed: Vec<_> = c.slots.iter().map(|s| (s.slot.clone(), s.script_path.clone())).collect();
    assert_eq!(slots, signed, "M17's deferred signatures are not the signed slots");
    let mut shape = TxShape::of(&tx, &spks, 0);
    shape.bind = true;
    let (steps, b, acc, mask, par) = bound_steps(&shape, &tx, &c.amounts, &spks, &slots);
    let spent = spent_commitment(&c.amounts, &spks);
    assert_eq!(spent, rel::spent_commitment(&m_amounts, &m_spks));
    let mut z0 = tap_z(0, &[0; 32], &tx.txid(), &spent, 0);
    z0.extend([F::ZERO, F::ZERO]);
    let mut tap_zk = tap_z(steps.len() as u64, &acc, &tx.txid(), &spent, mask);
    let (p0, p1) = le_halves(&par);
    tap_zk.extend([F::from_u128(p0), F::from_u128(p1)]);
    let (tap, _) = fold::prove(RELATION_TAPSIGHASH_V1, &SighashStep::blank(&shape), &steps, &z0, &tap_zk, &mut |s| log(s)).unwrap_or_else(|e| panic!("{e}"));
    let (secq, secq_zk) = prove_secq(&b);
    // 3. the binding and its negative cases
    let refs: Vec<(usize, &m17c::Folded)> = folded.iter().map(|(i, f)| (*i, f)).collect();
    verify_binding(&tx, &c.amounts, &spks, &refs, &tap_zk, &acc).unwrap_or_else(|e| panic!("binding: {e}"));
    let par_with = |sl: &[(SigSlot, Option<lightninger_bitvm3_clearing::tapsighash_step::ScriptPath>)]| {
        let mut z = tap_zk.clone();
        let p = params_of(sl, |i| spks[i][2..34].try_into().unwrap());
        let (x, y) = le_halves(&p);
        z[8] = F::from_u128(x);
        z[9] = F::from_u128(y);
        z
    };
    let mut bind_neg = Vec::new();
    let mut neg = |name: &str, z: Vec<F>, acc2: [u8; 32]| {
        let e = verify_binding(&tx, &c.amounts, &spks, &refs, &z, &acc2).expect_err(name);
        bind_neg.push(json!({"case": name, "rejected": e}));
    };
    let mut sw = slots.clone();
    sw.swap(0, 1);
    neg("trader and batcher signatures of input 0 swapped", par_with(&sw), acc);
    let mut dropped = slots.clone();
    dropped.pop();
    let mut z = par_with(&dropped);
    z[0] = F::from(dropped.len() as u64);
    neg("operator's signature dropped", z, acc);
    let mut ht = slots.clone();
    ht[0].0.hash_type = 0x00;
    neg("trader 0's SINGLE|ACP signature claimed as SIGHASH_DEFAULT", par_with(&ht), acc);
    let mut other_leaf = slots.clone();
    match other_leaf[2].1.as_mut() {
        // variant A: script-path signatures
        Some(sp) => {
            sp.tapleaf[0] ^= 1;
            neg("signature 2 checked for another tapleaf (the refund leaf's)", par_with(&other_leaf), acc);
        }
        // variant B: MuSig2 key-path signatures
        None => {
            other_leaf[2].1 = Some(lightninger_bitvm3_clearing::tapsighash_step::ScriptPath { key: spks[other_leaf[2].0.input][2..34].try_into().unwrap(), tapleaf: [0; 32], codesep: u32::MAX });
            neg("key-path signature 2 claimed as a script-path signature", par_with(&other_leaf), acc);
        }
    }
    let mut z = tap_zk.clone();
    z[3] += F::ONE;
    neg("TapSighash fold over another transaction", z, acc);
    let mut z = tap_zk.clone();
    z[5] += F::ONE;
    neg("TapSighash fold over other spent outputs (collateral)", z, acc);
    let mut bad = acc;
    bad[0] ^= 1;
    neg("Secq fold ending in another accumulator", tap_zk.clone(), bad);
    log(&format!("binding verified; {} negative cases rejected", bind_neg.len()));

    // 4. the clearing chain of the epoch's venue batches
    let tr = venue_trace(&venue, a);
    let kk = tr.batches.len();
    assert_eq!(kk, batches.len());
    assert!(tr.max_rows() <= r, "a batch has {} rows, R = {r}", tr.max_rows());
    for (x, y) in tr.batches.iter().zip(&batches) {
        assert_eq!((x.seq, x.digest), (y.seq, y.digest()), "venue trace and batches.json differ");
    }
    let (csteps, cz0, czk) = steps_of(a, r, &tr.batches);
    assert_eq!(czk.chain, rel::chain_of(&batches).unwrap(), "relation chain differs from the fold's");
    let (clear, cproof) = fold::prove(RELATION_CLEARING_V1, &ClearingStep::blank(a, r), &csteps, &cz0.to_z(), &czk.to_z(), &mut |s| log(s)).unwrap_or_else(|e| panic!("{e}"));
    let vk_bytes = clearing_vk_bytes(a, r, &clear.vk_sha256);

    // 5. the joint statement
    let m17io: Vec<rel::M17Io> = folded.iter().map(|(i, f)| rel::M17Io { input: *i as u32, z0_sha256: rel::hz(&reprs(&f.z0)), zn_sha256: rel::hz(&reprs(&f.zn)) }).collect();
    let (cz0r, czkr, tapr) = (reprs(&cz0.to_z()), reprs(&czk.to_z()), reprs(&tap_zk));
    let commitment = rel::joint_commitment(&rel::hz(&cz0r), &rel::hz(&czkr), &rel::hz(&tapr), &rel::hz(&reprs(&secq_zk)), &m17io);
    // cross-check against the clearing crate's own joint commitment
    let lib_inner = lightninger_bitvm3_clearing::cet::joint_commitment(&cz0.to_z(), &czk.to_z(), &tap_zk, &secq_zk, &refs);
    assert_eq!(commitment, sha256_native(&[lightninger_bitvm3_clearing::cet::JOINT_TAG, &lib_inner[..]].concat()));
    let testnet4 = manifest.network_code == 1;
    let stmt = rel::Statement {
        network_code: manifest.network_code,
        chain_genesis_hash: if testnet4 { testnet4_genesis() } else { regtest_genesis() },
        contract_id: rel::contract_id(&manifest),
        commitment_hash: commitment,
        assertion_txid: [0; 32],
        settlement_txid: settled.txid,
        program_hash: rel::sha256(PROGRAM.as_bytes()),
        verifying_key_hash: rel::sha256(&vk_bytes),
        policy_hash: manifest.hash(),
        epoch_id: manifest.epoch_id,
        assertion_vout: 0,
    };
    let enc = stmt.encode();
    let d = rel::sha256(&enc);
    let limbs = rel::public_limbs(&d);
    let shz = shz_nova_bitvm::bitvm3::UtxoRefL2SettlementStatementV0::decode(&enc).expect("shz-nova-bitvm decodes the statement");
    assert_eq!(shz.encode(), enc);
    let gdir = PathBuf::from(std::env::var("LIGHTNINGER_DLC_BATCH_GUEST_DIR").unwrap_or_else(|_| format!("D:/shz/tmp/dlc-batch/guest-{}", if testnet4 { "testnet4" } else { "regtest" })));
    std::fs::create_dir_all(&gdir).unwrap();
    std::fs::write(gdir.join("clearing_vk.bin"), &vk_bytes).unwrap();
    std::fs::write(gdir.join("clearing_proof.bin"), &cproof).unwrap();
    // the guest's own check, natively, must give the same statement
    let gin = rel::GuestIn {
        steps: kk as u32,
        table: a as u32,
        z0: cz0r.clone(),
        tap_zk: tapr.clone(),
        secq_zk_sha256: rel::hz(&reprs(&secq_zk)),
        m17: m17io.clone(),
        manifest: manifest.clone(),
        batches: batches.clone(),
        settlement: raw.clone(),
    };
    assert_eq!(rel::guest_statement(&gin, &czkr, &rel::sha256(&vk_bytes)).unwrap(), enc, "guest relation gives another statement");
    std::fs::write(gdir.join("guest_in.bin"), bincode::serialize(&gin).unwrap()).unwrap();
    std::fs::write(gdir.join("expected_statement.bin"), enc).unwrap();
    write(
        &dir.join("guest_input.json"),
        &json!({
            "clearing_vk_file": "clearing_vk.bin", "clearing_vk_sha256": clear.vk_sha256, "clearing_vk_bytes": vk_bytes.len(),
            "clearing_proof_file": "clearing_proof.bin", "guest_in_file": "guest_in.bin (bincode of relation::GuestIn)", "guest_dir": gdir.display().to_string().replace('\\', "/"), "clearing_proof_sha256": clear.proof_sha256, "clearing_proof_bytes": cproof.len(),
            "table": a, "rows": r, "steps": kk,
            "z0": cz0r.iter().map(hex::encode).collect::<Vec<_>>(),
            "tap_zk": tapr.iter().map(hex::encode).collect::<Vec<_>>(),
            "secq_zk_sha256": hex::encode(rel::hz(&reprs(&secq_zk))),
            "m17": m17io, "manifest": manifest, "batches": batches, "settlement_hex": c.signed_hex,
            "network_code": stmt.network_code, "chain_genesis_hash": hex::encode(stmt.chain_genesis_hash), "program": PROGRAM,
            "expected_statement_hex": hex::encode(enc),
        }),
    );
    write(
        &dir.join("joint_statement.json"),
        &json!({
            "settlement": {"txid": hex::encode(settled.txid), "inputs": tx.inputs.len(), "outputs": tx.outputs.len(), "payouts": settled.payouts, "net": settled.net, "fronted": settled.fronted,
                "shape": shape, "slots": slots.iter().map(|(s, e)| json!({"input": s.input, "hash_type": s.hash_type, "script_path": e})).collect::<Vec<_>>()},
            "relation_negatives": rel_neg,
            "m17": folded.iter().map(|(i, f)| json!({"input": i, "steps": f.steps, "claims": f.claims.len(), "deferred_signatures": f.deferred.len(), "prove_seconds": f.prove_seconds, "verify_seconds": f.verify_seconds})).collect::<Vec<_>>(),
            "params_accumulator": hex::encode(par), "auth_accumulator": hex::encode(acc),
            "tapsighash_fold": tap, "secq_fold": secq, "binding_negatives": bind_neg,
            "clearing": {"trace": tr.name, "accounts": tr.accounts, "table": a, "rows": r, "batches": kk, "layers": tr.layers(), "fold": clear},
            "statement": {
                "network": if testnet4 { "testnet4" } else { "regtest" },
                "contract_id": hex::encode(stmt.contract_id), "commitment_hash": hex::encode(commitment), "settlement_txid": hex::encode(stmt.settlement_txid),
                "program": PROGRAM, "program_hash": hex::encode(stmt.program_hash), "verifying_key_hash": hex::encode(stmt.verifying_key_hash),
                "policy_hash (manifest)": hex::encode(stmt.policy_hash), "epoch_id": stmt.epoch_id, "event_id": manifest.event_id,
            },
            "bitvm3_statement_hex": hex::encode(enc), "bitvm3_statement_sha256": hex::encode(d),
            "bitvm3_public_limbs_be": [limbs[0].to_string(), limbs[1].to_string()],
        }),
    );
}

/// `trace::from_venue` with the account table sorted by key, as the clearing circuit requires
/// (`sorted{j}_lt`); `from_venue` keeps first-appearance order. Row order inside each batch (and so
/// every digest) is unchanged; only table slots move.
fn venue_trace(venue: &Value, a: usize) -> trace::Trace {
    let mut tr = trace::from_venue(venue, a).unwrap_or_else(|e| panic!("from_venue: {e}"));
    let old = tr.batches[0].pre.keys.clone();
    let mut sorted = old.clone();
    sorted.sort_by(|x, y| lightninger_bitvm3_clearing::clearing_step::key_limbs(x).cmp(&lightninger_bitvm3_clearing::clearing_step::key_limbs(y)));
    let slot = |j: usize| sorted.iter().position(|k| *k == old[j]).unwrap();
    let perm = |v: &[u64]| {
        let mut o = vec![0u64; v.len()];
        for (j, x) in v.iter().enumerate() {
            o[slot(j)] = *x;
        }
        o
    };
    for b in &mut tr.batches {
        assert_eq!(b.pre.keys, old);
        b.pre.keys = sorted.clone();
        b.post.keys = sorted.clone();
        b.pre.claims = perm(&b.pre.claims);
        b.post.claims = perm(&b.post.claims);
        for r in &mut b.rows {
            r.slot = slot(r.slot);
        }
    }
    tr
}

/// Every clearing step of the venue trace on a test constraint system: which batch, which constraint.
fn check_clearing(a: usize, r: usize) {
    use lightninger_bitvm3_clearing::clearing_step::check_step;
    let venue: Value = read(&artifacts().join("venue_batches.json"));
    let tr = venue_trace(&venue, a);
    let (steps, z0, _) = steps_of(a, r, &tr.batches);
    let mut z = z0.to_z();
    for (i, st) in steps.iter().enumerate() {
        let want = {
            let mut p = tr.batches[i].post.clone();
            p.chain = lightninger_bitvm3_clearing::clearing_step::chain_next(&steps[i].pre.chain, tr.batches[i].seq, &tr.batches[i].digest);
            p
        };
        let (ok, which, out, n) = check_step(st, &z);
        log(&format!("batch {} ({} rows, layer {:?}): satisfied {ok}, {n} constraints, first unsatisfied {which:?}, output matches {}", tr.batches[i].seq, tr.batches[i].rows.len(), tr.batches[i].report.layer, out == want.to_z()));
        z = out;
    }
}

/// The clearing fold's verifier key for table `a` and `r` rows (setup is deterministic).
fn clearing_vk(a: usize, r: usize, out: &Path) {
    use bincode::Options;
    let blank = ClearingStep::blank(a, r);
    let pp = PublicParams::<E1, E2, ClearingStep>::setup(&blank, &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
    let (_, vk) = CompressedSNARK::<E1, E2, ClearingStep, S1, S2>::setup(&pp).unwrap();
    let b = bincode::DefaultOptions::new().with_fixint_encoding().serialize(&vk).unwrap();
    std::fs::write(out, &b).unwrap();
    println!("{} {}", hex::encode(sha256_native(&b)), b.len());
}

/// Re-encode `<dir>/guest/guest_in.bin` (bincode of `relation::GuestIn`, current field layout) from
/// `<dir>/guest_input.json`, and check the guest relation still gives `expected_statement.bin`.
fn guest_in(dir: &Path) {
    let gi: Value = read(&dir.join("guest_input.json"));
    let h = |v: &Value| -> [u8; 32] { hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap() };
    let g = rel::GuestIn {
        steps: gi["steps"].as_u64().unwrap() as u32,
        table: gi["table"].as_u64().unwrap() as u32,
        z0: gi["z0"].as_array().unwrap().iter().map(h).collect(),
        tap_zk: gi["tap_zk"].as_array().unwrap().iter().map(h).collect(),
        secq_zk_sha256: h(&gi["secq_zk_sha256"]),
        m17: serde_json::from_value(gi["m17"].clone()).unwrap(),
        manifest: serde_json::from_value(gi["manifest"].clone()).unwrap(),
        batches: serde_json::from_value(gi["batches"].clone()).unwrap(),
        settlement: hex::decode(gi["settlement_hex"].as_str().unwrap()).unwrap(),
    };
    let want = hex::decode(gi["expected_statement_hex"].as_str().unwrap()).unwrap();
    let gdir = dir.join("guest");
    assert_eq!(std::fs::read(gdir.join("expected_statement.bin")).unwrap(), want);
    // the relation part of the guest, on the statement's own z_K is not available here; check the
    // settlement relation and the manifest hash the statement names instead
    let st = rel::check_settlement(&g.settlement, &g.manifest, &g.batches).unwrap();
    assert_eq!(&want[164..196], &st.txid[..], "settlement txid");
    assert_eq!(&want[260..292], &g.manifest.hash()[..], "manifest hash");
    std::fs::write(gdir.join("guest_in.bin"), bincode::serialize(&g).unwrap()).unwrap();
    log(&format!("wrote {} ({} bytes)", gdir.join("guest_in.bin").display(), bincode::serialize(&g).unwrap().len()));
}

fn wrong_statement(dir: &Path) {
    let js: Value = read(&dir.join("joint_statement.json"));
    let rc: Value = read(&dir.join("receipt.json"));
    let mut enc = hex::decode(js["bitvm3_statement_hex"].as_str().unwrap()).unwrap();
    let t = rel::parse_tx(&hex::decode(rc["tampered_settlement_hex"].as_str().expect("receipt has the tampered settlement")).unwrap()).unwrap();
    enc[164..196].copy_from_slice(&t.txid);
    let d = rel::sha256(&enc);
    write(
        &dir.join("wrong_statement.json"),
        &json!({"what": "the joint statement with settlement_txid replaced by the tampered settlement (account 3 paid 1 sat less, the operator keeps it)",
            "tampered_settlement_txid": hex::encode(t.txid), "bitvm3_statement_hex": hex::encode(&enc), "bitvm3_statement_sha256": hex::encode(d)}),
    );
}

// ---------------------------------------------------------------------------------------------
// BitVM3 claim graph (phase B)
// ---------------------------------------------------------------------------------------------

/// Regtest-only keys: pool committee (presigns claim and payout), operator (claimant), watcher.
const POOL_SK: [u8; 32] = [0xd0; 32];
const OPERATOR_SK: [u8; 32] = [0x0b; 32];
const WATCH_SK: [u8; 32] = [0xee; 32];
const RECLAIM_BLOCKS: u32 = 144;
const WINDOW_BLOCKS: u32 = 6;

fn vault_output(d: &[u8; 32], c: &[u8; 32]) -> TapOutput {
    let claim = [push32(d), vec![OP_CHECKSIGVERIFY], push32(c), vec![OP_CHECKSIG]].concat();
    let reclaim = [num(RECLAIM_BLOCKS), vec![OP_CSV, OP_DROP], push32(d), vec![OP_CHECKSIG]].concat();
    TapOutput::new(vec![claim, reclaim])
}

fn claim_output(d: &[u8; 32], w: &[u8; 32], reject_sha: &[u8; 32]) -> TapOutput {
    let payout = [num(WINDOW_BLOCKS), vec![OP_CSV, OP_DROP], push32(d), vec![OP_CHECKSIG]].concat();
    let disprove = [vec![OP_SHA256], push32(reject_sha), vec![OP_EQUALVERIFY], push32(w), vec![OP_CHECKSIG]].concat();
    TapOutput::new(vec![payout, disprove])
}

fn claim_id(stmt_sha: &[u8; 32], gc: &Value, payout_spk: &[u8]) -> [u8; 32] {
    let mut b = b"LIGHTNINGER/DLC-BATCH/BITVM3-CLAIM/V1".to_vec();
    b.extend(stmt_sha);
    for k in ["vk_sha256", "ciphertext_commitment_blake3", "accept_label_sha256", "reject_label_sha256"] {
        b.extend(hex::decode(gc[k].as_str().unwrap()).unwrap());
    }
    b.extend(payout_spk);
    rel::sha256(&b)
}

struct Graph {
    v: TapOutput,
    k: TapOutput,
    vault: (String, u32, u64),
    claim: Tx,
    payout: Tx,
    disprove: Tx,
}

fn h32(v: &Value, k: &str) -> [u8; 32] {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("{k}"))).unwrap().try_into().unwrap()
}

fn build_graph(node: &Node, sink: &str, value: u64, stmt_sha: &[u8; 32], gc: &Value, payout_spk: &[u8], pool_spk: &[u8]) -> (Graph, Value) {
    let (d, c, w) = (xonly(&POOL_SK), xonly(&OPERATOR_SK), xonly(&WATCH_SK));
    let v = vault_output(&d, &c);
    let k = claim_output(&d, &w, &h32(gc, "reject_label_sha256"));
    let txid = node.cli(&["sendtoaddress", &address(node, &v.output_key), &format!("{:.8}", value as f64 / 1e8)]);
    node.cli(&["generatetoaddress", "1", sink]);
    let dj = node.json(&["getrawtransaction", &txid, "true"]);
    let vout = dj["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == hex::encode(v.spk()).as_str()).unwrap()["n"].as_u64().unwrap() as u32;
    let cid = claim_id(stmt_sha, gc, payout_spk);
    let fee = 400;
    let k_value = value - fee;
    let mut claim = Tx { version: 2, inputs: vec![input(&txid, vout, 0xffff_ffff)], outputs: vec![out(k_value, k.spk()), out(0, [vec![0x6a, 36], b"SHZC".to_vec(), cid.to_vec()].concat())], locktime: 0, witness: vec![] };
    // the committee presigns its half of the claim at setup; the operator signs to start the window
    let (sd, _) = sign_leaf(&claim, &[value], &[v.spk()], 0, &v, 0, &POOL_SK, 0);
    let (sc, _) = sign_leaf(&claim, &[value], &[v.spk()], 0, &v, 0, &OPERATOR_SK, 0);
    claim.witness = vec![vec![sc, sd, v.leaves[0].clone(), v.control(0)]];
    let claim_txid = hex::encode(claim.txid());
    let mut payout = Tx { version: 2, inputs: vec![input(&claim_txid, 0, WINDOW_BLOCKS)], outputs: vec![out(k_value - fee, payout_spk.to_vec())], locktime: 0, witness: vec![] };
    let (sp, _) = sign_leaf(&payout, &[k_value], &[k.spk()], 0, &k, 0, &POOL_SK, 0);
    payout.witness = vec![vec![sp, k.leaves[0].clone(), k.control(0)]];
    let disprove = Tx { version: 2, inputs: vec![input(&claim_txid, 0, 0xffff_fffd)], outputs: vec![out(k_value - fee, pool_spk.to_vec())], locktime: 0, witness: vec![] };
    let desc = json!({"vault": {"outpoint": format!("{txid}:{vout}"), "sats": value, "spk": hex::encode(v.spk()), "leaves": v.leaves.iter().map(hex::encode).collect::<Vec<_>>()},
        "claim": {"txid": claim_txid, "claim_id": hex::encode(cid), "k_sats": k_value, "k_spk": hex::encode(k.spk()), "leaves": k.leaves.iter().map(hex::encode).collect::<Vec<_>>()},
        "payout": {"txid": hex::encode(payout.txid()), "to_spk": hex::encode(payout_spk), "sequence": WINDOW_BLOCKS},
        "disprove": {"to_spk": hex::encode(pool_spk)}, "window_blocks": WINDOW_BLOCKS, "reclaim_blocks": RECLAIM_BLOCKS,
        "statement_sha256": hex::encode(stmt_sha), "garbled_instance": gc});
    (Graph { v, k, vault: (txid, vout, value), claim, payout, disprove }, desc)
}

fn signed_disprove(g: &Graph, label: &[u8]) -> Vec<u8> {
    let mut t = g.disprove.clone();
    let (sw, _) = sign_leaf(&t, &[g.claim.outputs[0].value], &[g.k.spk()], 0, &g.k, 1, &WATCH_SK, 0);
    t.witness = vec![vec![sw, label.to_vec(), g.k.leaves[1].clone(), g.k.control(1)]];
    serialize_signed(&t)
}

fn claim_graph(dir: &Path, honest_path: &Path, wrong_path: &Path) {
    let rc: Value = read(&dir.join("receipt.json"));
    let js: Value = read(&dir.join("joint_statement.json"));
    let ws: Value = read(&dir.join("wrong_statement.json"));
    let gh: Value = read(honest_path);
    let gw: Value = read(wrong_path);
    let stmt = h32(&js, "bitvm3_statement_sha256");
    let wrong = h32(&ws, "bitvm3_statement_sha256");
    assert_eq!(gh["claimed_statement_sha256"].as_str().unwrap(), hex::encode(stmt));
    assert_eq!(gw["claimed_statement_sha256"].as_str().unwrap(), hex::encode(wrong));
    assert_eq!(gh["evaluated_label_is_accept"], true, "honest instance did not evaluate to accept");
    assert_eq!(gw["evaluated_label_is_reject"], true, "wrong-statement instance did not evaluate to reject");
    let datadir = PathBuf::from(rc["datadir"].as_str().unwrap());
    let node = Node::regtest(&PathBuf::from(std::env::var("LIGHTNINGER_BITCOIND").expect("LIGHTNINGER_BITCOIND")), &datadir);
    let _ = node.try_cli(&["loadwallet", "w"]);
    let sink = node.cli(&["getnewaddress", "", "bech32m"]);
    let s_txid = rc["settlement"]["txid"].as_str().unwrap();
    let s_conf = node.json(&["getrawtransaction", s_txid, "true"])["confirmations"].as_u64().unwrap_or(0);
    assert!(s_conf > 0, "settlement is not confirmed on this chain");
    let fronted = rc["settlement"]["fronted"].as_i64().unwrap();
    let fee = rc["settlement"]["fee"].as_u64().unwrap();
    // the pool reimburses what the operator paid beyond the accounts' collateral, plus the settlement fee
    let reimburse = (fronted.max(0) as u64 + fee).max(2_000) + 800;
    let operator_spk = key_output(&xonly(&OPERATOR_SK)).spk();
    let pool_spk = key_output(&xonly(&POOL_SK)).spk();
    let mut events = Vec::new();
    let mut ev = |name: &str, r: Value| {
        log(&format!("{name}: {r}"));
        events.push(json!({"step": name, "result": r}));
    };

    // honest claim: the statement of the mined settlement, accept label
    let (g, gdesc) = build_graph(&node, &sink, reimburse, &stmt, &gh, &operator_spk, &pool_spk);
    let claim_raw = serialize_signed(&g.claim);
    ev("honest: claim testmempoolaccept", node.accept(&[&claim_raw])[0].clone());
    node.cli(&["sendrawtransaction", &hex::encode(&claim_raw)]);
    node.cli(&["generatetoaddress", "1", &sink]);
    let label_accept = hex::decode(gh["evaluated_label_hex"].as_str().unwrap()).unwrap();
    let r = node.accept(&[&signed_disprove(&g, &label_accept)]);
    assert_eq!(r[0]["allowed"], false);
    ev("honest: challenger's disprove with the evaluated (accept) label", r[0].clone());
    let pay_raw = serialize_signed(&g.payout);
    let r = node.accept(&[&pay_raw]);
    assert_eq!(r[0]["allowed"], false);
    ev("honest: payout one block after the claim", r[0].clone());
    node.cli(&["generatetoaddress", &(WINDOW_BLOCKS - 1).to_string(), &sink]);
    let r = node.accept(&[&pay_raw]);
    assert_eq!(r[0]["allowed"], true, "{r}");
    ev("honest: payout after the window", r[0].clone());
    let pay_txid = node.cli(&["sendrawtransaction", &hex::encode(&pay_raw)]);
    node.cli(&["generatetoaddress", "1", &sink]);
    ev("honest: payout mined", json!({"txid": pay_txid, "height": node.height(), "to": "operator"}));

    // wrong statement: the operator claims the tampered settlement; the reject label disproves it
    let (gx, wdesc) = build_graph(&node, &sink, reimburse, &wrong, &gw, &operator_spk, &pool_spk);
    let claimx = serialize_signed(&gx.claim);
    node.cli(&["sendrawtransaction", &hex::encode(&claimx)]);
    node.cli(&["generatetoaddress", "1", &sink]);
    ev("wrong: claim mined", json!({"txid": hex::encode(gx.claim.txid()), "height": node.height()}));
    let mut forged = hex::decode(gw["evaluated_label_hex"].as_str().unwrap()).unwrap();
    forged[0] ^= 1;
    let r = node.accept(&[&signed_disprove(&gx, &forged)]);
    assert_eq!(r[0]["allowed"], false);
    ev("wrong: disprove with a label one bit off the reject label", r[0].clone());
    let label_reject = hex::decode(gw["evaluated_label_hex"].as_str().unwrap()).unwrap();
    let dis = signed_disprove(&gx, &label_reject);
    let r = node.accept(&[&dis]);
    assert_eq!(r[0]["allowed"], true, "{r}");
    ev("wrong: disprove with the evaluated reject label", r[0].clone());
    let dis_txid = node.cli(&["sendrawtransaction", &hex::encode(&dis)]);
    node.cli(&["generatetoaddress", &WINDOW_BLOCKS.to_string(), &sink]);
    ev("wrong: disprove mined, funds back to the pool", json!({"txid": dis_txid, "height": node.height()}));
    let r = node.accept(&[&serialize_signed(&gx.payout)]);
    assert_eq!(r[0]["allowed"], false);
    ev("wrong: operator's payout after the window", r[0].clone());
    let _ = (&g.v, &g.vault, &gx.v, &gx.vault);
    write(
        &dir.join("claim_graph.json"),
        &json!({"node": node.json(&["getnetworkinfo"])["subversion"], "settlement_txid": s_txid, "settlement_confirmations_at_start": s_conf,
            "reimbursement_sats": reimburse, "honest_graph": gdesc, "wrong_statement_graph": wdesc, "events": events,
            "keys": {"pool_committee": hex::encode(xonly(&POOL_SK)), "operator": hex::encode(xonly(&OPERATOR_SK)), "watcher": hex::encode(xonly(&WATCH_SK)), "note": "regtest-only fixed keys"}}),
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dir = |i: usize| -> PathBuf {
        let p = PathBuf::from(&a[i]);
        if p.is_absolute() { p } else { artifacts().join(p) }
    };
    match a.get(1).map(String::as_str) {
        Some("prove") if a.len() >= 3 => prove(&dir(2), a.get(3).map_or(8, |x| x.parse().unwrap()), a.get(4).map_or(2, |x| x.parse().unwrap())),
        Some("check-clearing") => check_clearing(a.get(2).map_or(8, |x| x.parse().unwrap()), a.get(3).map_or(2, |x| x.parse().unwrap())),
        Some("clearing-vk") if a.len() == 5 => clearing_vk(a[2].parse().unwrap(), a[3].parse().unwrap(), &PathBuf::from(&a[4])),
        Some("guest-in") if a.len() == 3 => guest_in(&dir(2)),
        Some("wrong-statement") if a.len() == 3 => wrong_statement(&dir(2)),
        Some("claim-graph") if a.len() == 5 => claim_graph(&dir(2), &PathBuf::from(&a[3]), &PathBuf::from(&a[4])),
        _ => {
            eprintln!("usage: dlc-batcher prove <dir> [A] [R] | wrong-statement <dir> | claim-graph <dir> <gc_honest.json> <gc_wrong.json>");
            std::process::exit(2);
        }
    }
}
