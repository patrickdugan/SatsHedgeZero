//! The TapSighash step against the BIP-341 wallet test vectors (`keyPathSpending`: a
//! 9-input transaction with P2TR, P2PKH and P2WPKH prevouts, two non-P2TR outputs, and
//! all seven hash types across its seven taproot inputs).
use halo2curves::bn256::Fr as F;
use lightninger_bitvm3_clearing::{
    clearing_step::check_step,
    gadgets::sha256_native,
    tapsighash_step::{sig_msg, sighash_steps, spent_commitment, tap_sighash, tap_z, SigSlot, SighashStep, Tx, TxShape},
};
use serde_json::Value;
use shz_dlc::{bip340_verify, Bip340Signature};

pub struct Vector {
    pub tx: Tx,
    pub amounts: Vec<u64>,
    pub spks: Vec<Vec<u8>>,
    pub slots: Vec<SigSlot>,
    pub sig_msgs: Vec<Vec<u8>>,
    pub sighashes: Vec<[u8; 32]>,
}

pub fn vector() -> Vector {
    let v: Value = serde_json::from_str(include_str!("vectors/bip341-wallet-test-vectors.json")).unwrap();
    let k = &v["keyPathSpending"][0];
    let tx = Tx::parse(&hex::decode(k["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap());
    let utxos = k["given"]["utxosSpent"].as_array().unwrap();
    let amounts = utxos.iter().map(|u| u["amountSats"].as_u64().unwrap()).collect();
    let spks = utxos.iter().map(|u| hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap()).collect();
    let mut slots = Vec::new();
    let mut sig_msgs = Vec::new();
    let mut sighashes = Vec::new();
    for s in k["inputSpending"].as_array().unwrap() {
        let input = s["given"]["txinIndex"].as_u64().unwrap() as usize;
        let hash_type = s["given"]["hashType"].as_u64().unwrap() as u8;
        let w = hex::decode(s["expected"]["witness"][0].as_str().unwrap()).unwrap();
        assert!(w.len() == 64 || (w.len() == 65 && w[64] == hash_type));
        slots.push(SigSlot { input, hash_type, annex: None, sig_rx: w[..32].try_into().unwrap(), sig_s: w[32..64].try_into().unwrap() });
        sig_msgs.push(hex::decode(s["intermediary"]["sigMsg"].as_str().unwrap()).unwrap());
        sighashes.push(hex::decode(s["intermediary"]["sigHash"].as_str().unwrap()).unwrap().try_into().unwrap());
    }
    Vector { tx, amounts, spks, slots, sig_msgs, sighashes }
}

#[test]
fn native_sighash_matches_bip341_vectors() {
    let v = vector();
    let mut types = std::collections::BTreeSet::new();
    for (i, s) in v.slots.iter().enumerate() {
        let m = sig_msg(&v.tx, &v.amounts, &v.spks, s.input, s.hash_type, None).unwrap();
        assert_eq!(m, v.sig_msgs[i], "sigMsg of input {}", s.input);
        let h = tap_sighash(&v.tx, &v.amounts, &v.spks, s.input, s.hash_type, None).unwrap();
        assert_eq!(h, v.sighashes[i], "sigHash of input {}", s.input);
        let px: [u8; 32] = v.spks[s.input][2..34].try_into().unwrap();
        assert!(bip340_verify(&px, &h, &Bip340Signature { r_x: s.sig_rx, s: s.sig_s }).is_ok(), "vector signature of input {}", s.input);
        types.insert(s.hash_type);
    }
    assert_eq!(types.len(), 7, "{types:?}");
}

#[test]
fn circuit_folds_every_vector_input() {
    let v = vector();
    let shape = TxShape::of(&v.tx, &v.spks, 0);
    let (steps, slots, acc, mask) = sighash_steps(&shape, &v.tx, &v.amounts, &v.spks, &v.slots);
    let txid = v.tx.txid();
    let spent = spent_commitment(&v.amounts, &v.spks);
    let mut n = 0;
    for (i, s) in steps.iter().enumerate() {
        let (ok, which, out, c) = check_step(s, &s.z_in());
        assert!(ok, "input {} type {:#04x}: unsatisfied at {which:?}", s.slot.input, s.slot.hash_type);
        let next = slots[i].next_accumulator(&s.prev_acc);
        assert_eq!(out, tap_z(i as u64 + 1, &next, &txid, &spent, s.mask | 1 << s.slot.input));
        assert_eq!(slots[i].sighash32, v.sighashes[i]);
        n = c;
    }
    eprintln!("vector relation: {n} constraints per step, final accumulator {}, mask {mask:#b}", hex::encode(acc));
    let _ = sha256_native(&[]);
}

fn rejects(s: &SighashStep, what: &str) {
    let (ok, which, _, _) = check_step(s, &s.z_in());
    assert!(!ok, "{what}: accepted");
    eprintln!("{what}: rejected at {}", which.unwrap_or_default());
}

#[test]
fn invalid_slots_are_rejected() {
    let v = vector();
    let shape = TxShape::of(&v.tx, &v.spks, 0);
    let (steps, _, _, _) = sighash_steps(&shape, &v.tx, &v.amounts, &v.spks, &v.slots);
    let base = &steps[3]; // input 4, SIGHASH_DEFAULT
    let mut s = base.clone();
    s.slot.hash_type = 0x04;
    rejects(&s, "hash type 0x04");
    let mut s = base.clone();
    s.slot.hash_type = 0x80;
    rejects(&s, "hash type 0x80");
    let mut s = base.clone();
    s.mask |= 1 << s.slot.input;
    rejects(&s, "input already signed");
    // SIGHASH_SINGLE on input 3 of a 2-output transaction has no output to commit to
    let mut s = steps.iter().find(|s| s.slot.input == 3).unwrap().clone();
    s.slot.hash_type = 0x03;
    rejects(&s, "SINGLE without a matching output");
    // a z whose txid is another transaction's
    let s = base.clone();
    let mut z = s.z_in();
    z[3] += F::from(1u64);
    let (ok, _, _, _) = check_step(&s, &z);
    assert!(!ok, "foreign txid accepted");
    // the witness's spent outputs disagree with the committed ones
    let mut s = base.clone();
    let z = s.z_in();
    s.amounts[0] += 1;
    let (ok, _, _, _) = check_step(&s, &z);
    assert!(!ok, "changed prevout amount accepted");
}
