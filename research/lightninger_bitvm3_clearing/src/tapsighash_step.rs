//! Uniform Nova step: one BIP-341 key-path signature message, computed in R1CS from the
//! transaction, chained into the MNR-05 authorization accumulator.
//!
//! The relation is fixed by a transaction shape ([`TxShape`]: input count, scriptSig and
//! prevout scriptPubKey lengths, output script lengths, maximum annex length). One shape
//! covers every input and all seven valid hash types (`0x00 0x01 0x02 0x03 0x81 0x82 0x83`),
//! with or without an annex; the input index, the hash type and the annex are witnesses.
//!
//! Folded state `z` (arity 8):
//! `[step, acc_lo, acc_hi, txid_lo, txid_hi, spent_lo, spent_hi, signed_mask]` where
//! `acc` is `Bip340StepSlot::next_accumulator`'s chain (`SHZ/MNR05/AUTH_ACC/V1`, byte for byte),
//! `txid` is the transaction id in display byte order (`reverse(SHA256d(stripped tx))`),
//! `spent = SHA256(sha_amounts || sha_scriptpubkeys)` commits to the spent outputs, and
//! `signed_mask` has bit `i` set once input `i` is signed (each input at most once).
//!
//! Per step the circuit: rebuilds `txid` from the transaction bytes (count and length bytes
//! are shape constants); builds `sha_prevouts`, `sha_amounts`, `sha_scriptpubkeys`,
//! `sha_sequences`, `sha_outputs`, `sha_single_output` and `sha_annex`; selects the input's
//! outpoint, amount, scriptPubKey and sequence; requires that scriptPubKey to be P2TR
//! (`OP_1 0x20 <x>`) and takes `x` as the signing key (key path: the output key signs, so
//! `ext_flag = 0` and no BIP-342 extension); requires `SINGLE` to have a matching output and
//! an annex to start with `0x50`; assembles `SigMsg` for the hash type's layout and hashes it
//! as the `TapSighash` tagged hash; and appends
//! `(step, hash_type, x, sighash, sig.r_x, sig.s)` to the accumulator.
//! The Secq256k1 step (`Mnr05SecqBip340Step`) folds the same slots and checks each BIP-340
//! signature; equal final accumulators bind the two proofs.
use crate::gadgets::*;
use ff::Field;
use halo2curves::bn256::Fr as F;
use nova_snark::{
    frontend::{gadgets::boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError},
    traits::circuit::StepCircuit,
};
use serde::{Deserialize, Serialize};
use shz_mnr05_bitvm3_ln_dlc::secq_schnorr_circuit::{Bip340StepSlot, AUTH_ACC_DOMAIN};

pub const RELATION_TAPSIGHASH_V1: &str = "lightninger/bip341-keypath-tapsighash-fold/v1";
pub const HASH_TYPES: [u8; 7] = [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIn {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u64,
    pub spk: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
    /// Witness stacks (empty for an unsigned transaction).
    pub witness: Vec<Vec<Vec<u8>>>,
}

fn read_compact(b: &[u8], i: &mut usize) -> u64 {
    let x = b[*i];
    *i += 1;
    let n = match x {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        _ => return x as u64,
    };
    let mut v = 0u64;
    for k in 0..n {
        v |= (b[*i + k] as u64) << (8 * k);
    }
    *i += n;
    v
}

fn compact(n: usize) -> Vec<u8> {
    assert!(n < 0xfd, "compact sizes >= 253 are not in any shape here");
    vec![n as u8]
}

impl Tx {
    pub fn parse(b: &[u8]) -> Tx {
        let mut i = 0;
        let rd = |i: &mut usize, n: usize| -> Vec<u8> {
            let v = b[*i..*i + n].to_vec();
            *i += n;
            v
        };
        let version = u32::from_le_bytes(rd(&mut i, 4).try_into().unwrap());
        let segwit = b[i] == 0 && b[i + 1] == 1;
        if segwit {
            i += 2;
        }
        let n_in = read_compact(b, &mut i) as usize;
        let mut inputs = Vec::new();
        for _ in 0..n_in {
            let txid: [u8; 32] = rd(&mut i, 32).try_into().unwrap();
            let vout = u32::from_le_bytes(rd(&mut i, 4).try_into().unwrap());
            let l = read_compact(b, &mut i) as usize;
            let script_sig = rd(&mut i, l);
            let sequence = u32::from_le_bytes(rd(&mut i, 4).try_into().unwrap());
            inputs.push(TxIn { txid, vout, script_sig, sequence });
        }
        let n_out = read_compact(b, &mut i) as usize;
        let mut outputs = Vec::new();
        for _ in 0..n_out {
            let value = u64::from_le_bytes(rd(&mut i, 8).try_into().unwrap());
            let l = read_compact(b, &mut i) as usize;
            outputs.push(TxOut { value, spk: rd(&mut i, l) });
        }
        let mut witness = Vec::new();
        if segwit {
            for _ in 0..n_in {
                let items = read_compact(b, &mut i) as usize;
                let mut st = Vec::new();
                for _ in 0..items {
                    let l = read_compact(b, &mut i) as usize;
                    st.push(rd(&mut i, l));
                }
                witness.push(st);
            }
        }
        let locktime = u32::from_le_bytes(rd(&mut i, 4).try_into().unwrap());
        assert_eq!(i, b.len(), "trailing bytes");
        Tx { version, inputs, outputs, locktime, witness }
    }

    pub fn out_bytes(o: &TxOut) -> Vec<u8> {
        let mut v = o.value.to_le_bytes().to_vec();
        v.extend(compact(o.spk.len()));
        v.extend(&o.spk);
        v
    }

    /// Serialization without witness (the txid preimage).
    pub fn stripped(&self) -> Vec<u8> {
        let mut v = self.version.to_le_bytes().to_vec();
        v.extend(compact(self.inputs.len()));
        for x in &self.inputs {
            v.extend(x.txid);
            v.extend(x.vout.to_le_bytes());
            v.extend(compact(x.script_sig.len()));
            v.extend(&x.script_sig);
            v.extend(x.sequence.to_le_bytes());
        }
        v.extend(compact(self.outputs.len()));
        for o in &self.outputs {
            v.extend(Self::out_bytes(o));
        }
        v.extend(self.locktime.to_le_bytes());
        v
    }

    /// Display-order txid.
    pub fn txid(&self) -> [u8; 32] {
        let mut d = sha256_native(&sha256_native(&self.stripped()));
        d.reverse();
        d
    }
}

/// BIP-341 `SigMsg` for a key-path spend (`ext_flag = 0`), natively.
pub fn sig_msg(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], input: usize, hash_type: u8, annex: Option<&[u8]>) -> Result<Vec<u8>, String> {
    sig_msg_ext(tx, amounts, spks, input, hash_type, annex, None)
}

/// BIP-341 `SigMsg` with the BIP-342 extension when `ext` is `Some(script path)`.
pub fn sig_msg_ext(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], input: usize, hash_type: u8, annex: Option<&[u8]>, ext: Option<&ScriptPath>) -> Result<Vec<u8>, String> {
    if !HASH_TYPES.contains(&hash_type) {
        return Err(format!("invalid hash type {hash_type:#04x}"));
    }
    let acp = hash_type & 0x80 != 0;
    let out_type = if hash_type == 0 { 1 } else { hash_type & 3 };
    let mut m = vec![0x00, hash_type];
    m.extend(tx.version.to_le_bytes());
    m.extend(tx.locktime.to_le_bytes());
    if !acp {
        let mut p = Vec::new();
        let mut a = Vec::new();
        let mut s = Vec::new();
        let mut q = Vec::new();
        for (i, x) in tx.inputs.iter().enumerate() {
            p.extend(x.txid);
            p.extend(x.vout.to_le_bytes());
            a.extend(amounts[i].to_le_bytes());
            s.extend(compact(spks[i].len()));
            s.extend(&spks[i]);
            q.extend(x.sequence.to_le_bytes());
        }
        for d in [p, a, s, q] {
            m.extend(sha256_native(&d));
        }
    }
    if out_type == 1 {
        let o: Vec<u8> = tx.outputs.iter().flat_map(Tx::out_bytes).collect();
        m.extend(sha256_native(&o));
    }
    m.push(2 * ext.is_some() as u8 + annex.is_some() as u8);
    if acp {
        let x = &tx.inputs[input];
        m.extend(x.txid);
        m.extend(x.vout.to_le_bytes());
        m.extend(amounts[input].to_le_bytes());
        m.extend(compact(spks[input].len()));
        m.extend(&spks[input]);
        m.extend(x.sequence.to_le_bytes());
    } else {
        m.extend((input as u32).to_le_bytes());
    }
    if let Some(an) = annex {
        let mut v = compact(an.len());
        v.extend(an);
        m.extend(sha256_native(&v));
    }
    if out_type == 3 {
        let o = tx.outputs.get(input).ok_or("SIGHASH_SINGLE without a matching output")?;
        m.extend(sha256_native(&Tx::out_bytes(o)));
    }
    if let Some(e) = ext {
        m.extend(e.tapleaf);
        m.push(0x00);
        m.extend(e.codesep.to_le_bytes());
    }
    Ok(m)
}

pub fn tap_sighash(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], input: usize, hash_type: u8, annex: Option<&[u8]>) -> Result<[u8; 32], String> {
    Ok(tagged_hash(b"TapSighash", &sig_msg(tx, amounts, spks, input, hash_type, annex)?))
}

pub fn tap_sighash_ext(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], input: usize, hash_type: u8, annex: Option<&[u8]>, ext: Option<&ScriptPath>) -> Result<[u8; 32], String> {
    Ok(tagged_hash(b"TapSighash", &sig_msg_ext(tx, amounts, spks, input, hash_type, annex, ext)?))
}

/// A tapscript signature: the key it is checked against (from the script, not the output),
/// the tapleaf hash of the executed script and the codeseparator position (`u32::MAX` for none).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptPath {
    pub key: [u8; 32],
    pub tapleaf: [u8; 32],
    pub codesep: u32,
}

pub const PARAMS_TAG: &[u8] = b"LIGHTNINGER/TAPSIG/PARAMS/V1";

/// The parameter accumulator of the bind mode: what each signature is checked as, in terms a
/// verifier holding the spend's script claims recomputes without any curve or sighash work.
/// `SHA256(PARAMS_TAG || par || input || hash_type || ext || tapleaf || codesep_le32 || key ||
/// r_x || s || annex_present || sha_annex)` (zeros for absent fields).
pub fn params_next(par: &[u8; 32], slot: &SigSlot, ext: Option<&ScriptPath>, key: &[u8; 32]) -> [u8; 32] {
    let mut b = PARAMS_TAG.to_vec();
    b.extend(par);
    b.push(slot.input as u8);
    b.push(slot.hash_type);
    b.push(ext.is_some() as u8);
    b.extend(ext.map_or([0; 32], |e| e.tapleaf));
    b.extend(ext.map_or(0, |e| e.codesep).to_le_bytes());
    b.extend(key);
    b.extend(slot.sig_rx);
    b.extend(slot.sig_s);
    b.push(slot.annex.is_some() as u8);
    b.extend(slot.annex.as_ref().map_or([0; 32], |a| sha256_native(&[compact(a.len()), a.clone()].concat())));
    sha256_native(&b)
}

/// `SHA256(sha_amounts || sha_scriptpubkeys)`.
pub fn spent_commitment(amounts: &[u64], spks: &[Vec<u8>]) -> [u8; 32] {
    let a: Vec<u8> = amounts.iter().flat_map(|x| x.to_le_bytes()).collect();
    let s: Vec<u8> = spks.iter().flat_map(|k| [compact(k.len()), k.clone()].concat()).collect();
    sha256_native(&[sha256_native(&a), sha256_native(&s)].concat())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxShape {
    pub script_sig_lens: Vec<usize>,
    pub prevout_spk_lens: Vec<usize>,
    pub out_spk_lens: Vec<usize>,
    pub annex_max: usize,
    /// Bind mode: script-path (tapscript) signatures allowed, and `z` carries the parameter
    /// accumulator (arity 10). Off: the key-path relation of arity 8.
    #[serde(default)]
    pub bind: bool,
}

impl TxShape {
    pub fn of(tx: &Tx, spks: &[Vec<u8>], annex_max: usize) -> Self {
        Self {
            script_sig_lens: tx.inputs.iter().map(|x| x.script_sig.len()).collect(),
            prevout_spk_lens: spks.iter().map(|s| s.len()).collect(),
            out_spk_lens: tx.outputs.iter().map(|o| o.spk.len()).collect(),
            annex_max,
            bind: false,
        }
    }
    pub fn n_in(&self) -> usize {
        self.script_sig_lens.len()
    }
    pub fn n_out(&self) -> usize {
        self.out_spk_lens.len()
    }
    /// Inputs a key-path signature can be proven for (34-byte prevout scripts).
    pub fn taproot_inputs(&self) -> Vec<usize> {
        (0..self.n_in()).filter(|&i| self.prevout_spk_lens[i] == 34).collect()
    }
}

/// One signature slot: everything the step needs besides the folded state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigSlot {
    pub input: usize,
    pub hash_type: u8,
    pub annex: Option<Vec<u8>>,
    pub sig_rx: [u8; 32],
    pub sig_s: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct SighashStep {
    pub shape: TxShape,
    pub tx: Tx,
    pub amounts: Vec<u64>,
    pub spks: Vec<Vec<u8>>,
    pub slot: SigSlot,
    pub step: u8,
    pub prev_acc: [u8; 32],
    pub mask: u64,
    /// Bind mode only: a script-path signature, and the parameter accumulator before this step.
    pub ext: Option<ScriptPath>,
    pub par: [u8; 32],
}

impl SighashStep {
    pub fn pubkey_x(&self) -> [u8; 32] {
        match &self.ext {
            Some(e) => e.key,
            None => self.spks[self.slot.input][2..34].try_into().unwrap(),
        }
    }
    pub fn sighash(&self) -> [u8; 32] {
        tap_sighash_ext(&self.tx, &self.amounts, &self.spks, self.slot.input, self.slot.hash_type, self.slot.annex.as_deref(), self.ext.as_ref()).expect("valid slot")
    }
    /// The MNR-05 slot this step accumulates (the Secq step checks its signature).
    pub fn bip340_slot(&self) -> Bip340StepSlot {
        Bip340StepSlot { step_idx: self.step, sighash_flag: self.slot.hash_type, pubkey_x: self.pubkey_x(), sighash32: self.sighash(), sig_rx: self.slot.sig_rx, sig_s: self.slot.sig_s }
    }
    pub fn z_in(&self) -> Vec<F> {
        let mut z = tap_z(self.step as u64, &self.prev_acc, &self.tx.txid(), &spent_commitment(&self.amounts, &self.spks), self.mask);
        if self.shape.bind {
            let (p0, p1) = le_halves(&self.par);
            z.extend([fu(p0), fu(p1)]);
        }
        z
    }
    /// A setup witness of the same shape: zero bytes, the first taproot input, `SIGHASH_DEFAULT`.
    pub fn blank(shape: &TxShape) -> Self {
        let tx = Tx {
            version: 2,
            inputs: shape.script_sig_lens.iter().map(|&l| TxIn { txid: [0; 32], vout: 0, script_sig: vec![0; l], sequence: 0 }).collect(),
            outputs: shape.out_spk_lens.iter().map(|&l| TxOut { value: 0, spk: vec![0; l] }).collect(),
            locktime: 0,
            witness: vec![],
        };
        let spks = shape.prevout_spk_lens.iter().map(|&l| if l == 34 { [vec![0x51, 0x20], vec![0; 32]].concat() } else { vec![0; l] }).collect();
        let input = shape.taproot_inputs()[0];
        Self {
            shape: shape.clone(),
            tx,
            amounts: vec![0; shape.n_in()],
            spks,
            slot: SigSlot { input, hash_type: 0, annex: None, sig_rx: [0; 32], sig_s: [0; 32] },
            step: 0,
            prev_acc: [0; 32],
            mask: 0,
            ext: None,
            par: [0; 32],
        }
    }
}

pub fn tap_z(step: u64, acc: &[u8; 32], txid: &[u8; 32], spent: &[u8; 32], mask: u64) -> Vec<F> {
    let (a0, a1) = le_halves(acc);
    let (t0, t1) = le_halves(txid);
    let (s0, s1) = le_halves(spent);
    vec![F::from(step), fu(a0), fu(a1), fu(t0), fu(t1), fu(s0), fu(s1), F::from(mask)]
}

/// Steps for `slots` over one transaction, with the accumulator and mask threaded through.
pub fn sighash_steps(shape: &TxShape, tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], slots: &[SigSlot]) -> (Vec<SighashStep>, Vec<Bip340StepSlot>, [u8; 32], u64) {
    let mut acc = [0u8; 32];
    let mut mask = 0u64;
    let mut steps = Vec::new();
    let mut b = Vec::new();
    for (i, s) in slots.iter().enumerate() {
        let st = SighashStep { shape: shape.clone(), tx: tx.clone(), amounts: amounts.to_vec(), spks: spks.to_vec(), slot: s.clone(), step: i as u8, prev_acc: acc, mask, ext: None, par: [0; 32] };
        let bs = st.bip340_slot();
        acc = bs.next_accumulator(&acc);
        mask |= 1 << s.input;
        b.push(bs);
        steps.push(st);
    }
    (steps, b, acc, mask)
}

/// Bind-mode steps: key-path (`None`) and script-path signatures over one transaction, with the
/// authorization accumulator, the key-path mask and the parameter accumulator threaded through.
pub fn bound_steps(shape: &TxShape, tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], slots: &[(SigSlot, Option<ScriptPath>)]) -> (Vec<SighashStep>, Vec<Bip340StepSlot>, [u8; 32], u64, [u8; 32]) {
    assert!(shape.bind);
    let (mut acc, mut mask, mut par) = ([0u8; 32], 0u64, [0u8; 32]);
    let (mut steps, mut b) = (Vec::new(), Vec::new());
    for (i, (s, e)) in slots.iter().enumerate() {
        let st = SighashStep { shape: shape.clone(), tx: tx.clone(), amounts: amounts.to_vec(), spks: spks.to_vec(), slot: s.clone(), step: i as u8, prev_acc: acc, mask, ext: e.clone(), par };
        let bs = st.bip340_slot();
        acc = bs.next_accumulator(&acc);
        par = params_next(&par, s, e.as_ref(), &st.pubkey_x());
        if e.is_none() {
            mask |= 1 << s.input;
        }
        b.push(bs);
        steps.push(st);
    }
    (steps, b, acc, mask, par)
}

impl StepCircuit<F> for SighashStep {
    fn arity(&self) -> usize {
        if self.shape.bind {
            10
        } else {
            8
        }
    }

    fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let sh = &self.shape;
        let (n_in, n_out) = (sh.n_in(), sh.n_out());
        assert!(n_in <= 32);
        let one = W::konst::<CS>(1);
        let tx = &self.tx;
        assert_eq!(TxShape { bind: sh.bind, ..TxShape::of(tx, &self.spks, sh.annex_max) }, *sh, "witness does not have the relation's shape");

        // ------------------------------------------------ transaction bytes and txid
        let mut tx_bits: Vec<Boolean> = Vec::new();
        let version = alloc_bytes(cs.namespace(|| "version"), &tx.version.to_le_bytes())?;
        tx_bits.extend(version.iter().cloned());
        tx_bits.extend(const_bits(&compact(n_in)));
        let mut outpoints = Vec::new();
        let mut seqs = Vec::new();
        for (i, x) in tx.inputs.iter().enumerate() {
            let mut b = x.txid.to_vec();
            b.extend(x.vout.to_le_bytes());
            let op = alloc_bytes(cs.namespace(|| format!("outpoint{i}")), &b)?;
            tx_bits.extend(op.iter().cloned());
            tx_bits.extend(const_bits(&compact(x.script_sig.len())));
            tx_bits.extend(alloc_bytes(cs.namespace(|| format!("script_sig{i}")), &x.script_sig)?);
            let sq = alloc_bytes(cs.namespace(|| format!("seq{i}")), &x.sequence.to_le_bytes())?;
            tx_bits.extend(sq.iter().cloned());
            outpoints.push(op);
            seqs.push(sq);
        }
        tx_bits.extend(const_bits(&compact(n_out)));
        let mut outs = Vec::new();
        for (k, o) in tx.outputs.iter().enumerate() {
            let mut b = alloc_bytes(cs.namespace(|| format!("value{k}")), &o.value.to_le_bytes())?;
            b.extend(const_bits(&compact(o.spk.len())));
            b.extend(alloc_bytes(cs.namespace(|| format!("spk_out{k}")), &o.spk)?);
            tx_bits.extend(b.iter().cloned());
            outs.push(b);
        }
        let locktime = alloc_bytes(cs.namespace(|| "locktime"), &tx.locktime.to_le_bytes())?;
        tx_bits.extend(locktime.iter().cloned());
        let h1 = sha256_fixed(cs.namespace(|| "txid1"), &tx_bits)?;
        let h2 = sha256_fixed(cs.namespace(|| "txid2"), &h1)?;
        let txid_display: Vec<Boolean> = h2.chunks(8).rev().flat_map(|c| c.to_vec()).collect();
        bind_halves(cs, "txid", &txid_display, &z[3], &z[4]);

        // ------------------------------------------------ spent outputs
        let mut amounts = Vec::new();
        let mut spks = Vec::new();
        for i in 0..n_in {
            amounts.push(alloc_bytes(cs.namespace(|| format!("amount{i}")), &self.amounts[i].to_le_bytes())?);
            let mut s = const_bits(&compact(self.spks[i].len()));
            s.extend(alloc_bytes(cs.namespace(|| format!("spk{i}")), &self.spks[i])?);
            spks.push(s);
        }
        let cat = |v: &[Vec<Boolean>]| -> Vec<Boolean> { v.iter().flatten().cloned().collect() };
        let sha_prevouts = sha256_fixed(cs.namespace(|| "sha_prevouts"), &cat(&outpoints))?;
        let sha_amounts = sha256_fixed(cs.namespace(|| "sha_amounts"), &cat(&amounts))?;
        let sha_spks = sha256_fixed(cs.namespace(|| "sha_spks"), &cat(&spks))?;
        let sha_seqs = sha256_fixed(cs.namespace(|| "sha_seqs"), &cat(&seqs))?;
        let sha_outputs = sha256_fixed(cs.namespace(|| "sha_outputs"), &cat(&outs))?;
        let spent = sha256_fixed(cs.namespace(|| "spent"), &[sha_amounts.clone(), sha_spks.clone()].concat())?;
        bind_halves(cs, "spent", &spent, &z[5], &z[6]);

        // ------------------------------------------------ input selection
        let taproot = sh.taproot_inputs();
        let mut sel: Vec<W> = vec![W::zero(); n_in];
        for &i in &taproot {
            sel[i] = alloc_bit(cs.namespace(|| format!("in{i}")), self.slot.input == i)?;
        }
        enforce_eq(cs, "one_input", &W::sum(&sel), &one);
        let idx = W::sum(&sel.iter().enumerate().map(|(i, s)| s.scale(i as i128)).collect::<Vec<_>>());
        // each input signed at most once: bit `input` of the mask is clear
        let mask = W::num(&z[7], self.mask as i128);
        let mask_bits = range(cs.namespace(|| "mask"), &mask, n_in)?;
        let mut hit = W::zero();
        for &i in &taproot {
            hit = hit.add(&mul(cs.namespace(|| format!("hit{i}")), &sel[i], &W::bit(&mask_bits[i], CS::one()))?);
        }
        // bind mode: a script-path signature (ext = 1) leaves the key-path mask alone
        let ext = if sh.bind { alloc_bit(cs.namespace(|| "ext"), self.ext.is_some())? } else { W::zero() };
        let keypath = ext.not::<CS>();
        let hit = if sh.bind { mul(cs.namespace(|| "hit_kp"), &hit, &keypath)? } else { hit };
        enforce_eq(cs, "not_signed_yet", &hit, &W::zero());
        let added = W::sum(&sel.iter().enumerate().map(|(i, s)| s.scale(1i128 << i)).collect::<Vec<_>>());
        let added = if sh.bind { mul(cs.namespace(|| "mask_kp"), &added, &keypath)? } else { added };
        let mask_out = mask.add(&added);
        let tsel: Vec<W> = taproot.iter().map(|&i| sel[i].clone()).collect();
        let pick = |cs: &mut CS, name: &str, v: &[Vec<Boolean>]| mux_bits(cs.namespace(|| name.to_string()), &tsel, &taproot.iter().map(|&i| v[i].clone()).collect::<Vec<_>>());
        let my_outpoint = pick(cs, "my_outpoint", &outpoints)?;
        let my_amount = pick(cs, "my_amount", &amounts)?;
        let my_spk = pick(cs, "my_spk", &spks)?;
        let my_seq = pick(cs, "my_seq", &seqs)?;
        // P2TR: 0x22 0x51 0x20 <x>; the output key x signs a key-path spend
        let p2tr = const_bits(&[0x22, 0x51, 0x20]);
        for (i, (x, y)) in my_spk[..24].iter().zip(&p2tr).enumerate() {
            cs.enforce(|| format!("p2tr{i}"), |_| x.lc(CS::one(), F::ONE) - &y.lc(CS::one(), F::ONE), |l| l + CS::one(), |l| l);
        }
        let spk_x = my_spk[24..].to_vec();
        // bind mode: the script-path fields (zero on a key-path step) and the signing key
        let e = self.ext.clone().unwrap_or(ScriptPath { key: [0; 32], tapleaf: [0; 32], codesep: 0 });
        let (px, leaf_bits, csep_bits) = if sh.bind {
            let key = alloc_bytes(cs.namespace(|| "script_key"), &e.key)?;
            let leaf = alloc_bytes(cs.namespace(|| "tapleaf"), &e.tapleaf)?;
            let csep = alloc_bytes(cs.namespace(|| "codesep"), &e.codesep.to_le_bytes())?;
            for (name, bytes) in [("key", &key), ("leaf", &leaf), ("csep", &csep)] {
                for (i, byte) in bytes.chunks(8).enumerate() {
                    let v = W { lc: lc_bytes_be::<CS>(byte), v: bits_value(byte)[0] as i128 };
                    enforce_mul(cs, &format!("kp_zero_{name}{i}"), &keypath, &v, &W::zero());
                }
            }
            let px = mux_bits(cs.namespace(|| "px"), &[keypath.clone(), ext.clone()], &[spk_x, key])?;
            (px, leaf, csep)
        } else {
            (spk_x, vec![], vec![])
        };

        // ------------------------------------------------ hash type
        let ht = self.slot.hash_type;
        let ht_bits_le = alloc_bits_le(cs.namespace(|| "ht"), ht as i128, 8)?;
        let ht_w = W { lc: lc_bits_le::<CS>(&ht_bits_le), v: ht as i128 };
        let mut o = Vec::new();
        for (k, &t) in HASH_TYPES.iter().enumerate() {
            o.push(alloc_bit(cs.namespace(|| format!("ht_is{k}")), ht == t)?);
        }
        enforce_eq(cs, "ht_one", &W::sum(&o), &one);
        let ht_val = W::sum(&o.iter().zip(HASH_TYPES).map(|(b, t)| b.scale(t as i128)).collect::<Vec<_>>());
        enforce_eq(cs, "ht_valid", &ht_val, &ht_w);
        let ht_byte = le_bits_to_bytes(&ht_bits_le);
        // layout classes (acp, outputs): ALL, NONE, SINGLE x (no ACP, ACP)
        let classes = [o[0].add(&o[1]), o[2].clone(), o[3].clone(), o[4].clone(), o[5].clone(), o[6].clone()];
        let single = o[3].add(&o[6]);
        let mut bad_single = W::zero();
        for i in n_out..n_in {
            bad_single = bad_single.add(&sel[i]);
        }
        enforce_mul(cs, "single_has_output", &single, &bad_single, &W::zero());
        let single_cfgs: Vec<(W, Vec<Boolean>)> = (0..n_out.min(n_in)).map(|k| (sel[k].clone(), outs[k].clone())).collect();
        let sha_single = if single_cfgs.is_empty() { vec![Boolean::constant(false); 256] } else { sha256_var(cs.namespace(|| "sha_single"), &SHA256_IV, 0, &single_cfgs)? };

        // ------------------------------------------------ annex
        let annex = self.slot.annex.clone().unwrap_or_default();
        assert!(annex.len() <= sh.annex_max, "annex longer than the shape allows");
        let (present, sha_annex) = if sh.annex_max == 0 {
            (W::zero(), vec![Boolean::constant(false); 256])
        } else {
            let mut buf = annex.clone();
            buf.resize(sh.annex_max, 0);
            let ab = alloc_bytes(cs.namespace(|| "annex"), &buf)?;
            let mut lsel = Vec::new();
            for l in 1..=sh.annex_max {
                lsel.push(alloc_bit(cs.namespace(|| format!("annex_len{l}")), annex.len() == l)?);
            }
            let present = W::sum(&lsel);
            // bytes past the annex length are zero, so the witness is unique
            for i in 0..sh.annex_max {
                let longer = W::sum(&lsel[i..]);
                let byte = W { lc: lc_bytes_be::<CS>(&ab[8 * i..8 * i + 8]), v: buf[i] as i128 };
                enforce_mul(cs, &format!("annex_pad{i}"), &longer.not::<CS>(), &byte, &W::zero());
            }
            enforce_mul(cs, "annex_present_bit", &present, &present.not::<CS>(), &W::zero());
            let first = W { lc: lc_bytes_be::<CS>(&ab[..8]), v: buf[0] as i128 };
            enforce_mul(cs, "annex_0x50", &present, &first.sub(&W::konst::<CS>(0x50)), &W::zero());
            let cfgs: Vec<(W, Vec<Boolean>)> = (1..=sh.annex_max)
                .map(|l| {
                    let mut m = const_bits(&compact(l));
                    m.extend(ab[..8 * l].iter().cloned());
                    (lsel[l - 1].clone(), m)
                })
                .collect();
            (present.clone(), sha256_var(cs.namespace(|| "sha_annex"), &SHA256_IV, 0, &cfgs)?)
        };
        let present_b = Boolean::from(nova_snark::frontend::gadgets::boolean::AllocatedBit::alloc(cs.namespace(|| "spend_type"), Some(present.v == 1))?);
        enforce_eq(cs, "spend_type_bit", &W::bit(&present_b, CS::one()), &present);
        let mut spend_type = vec![Boolean::constant(false); 6];
        let ext_b = if sh.bind {
            let b = Boolean::from(nova_snark::frontend::gadgets::boolean::AllocatedBit::alloc(cs.namespace(|| "ext_bit"), Some(self.ext.is_some()))?);
            enforce_eq(cs, "ext_bit_eq", &W::bit(&b, CS::one()), &ext);
            b
        } else {
            Boolean::constant(false)
        };
        spend_type.push(ext_b.clone());
        spend_type.push(present_b.clone());

        // ------------------------------------------------ input index (non-ACP)
        let idx_bits = alloc_bits_le(cs.namespace(|| "idx"), idx.v, 8)?;
        enforce_eq(cs, "idx_bits", &W { lc: lc_bits_le::<CS>(&idx_bits), v: idx.v }, &idx);
        let mut idx4 = le_bits_to_bytes(&idx_bits);
        idx4.extend(const_bits(&[0, 0, 0]));

        // ------------------------------------------------ SigMsg, by layout
        let mut head = const_bits(&[0x00]);
        head.extend(ht_byte);
        head.extend(version);
        head.extend(locktime);
        let four = [sha_prevouts, sha_amounts, sha_spks, sha_seqs].concat();
        let mut acp_data = my_outpoint;
        acp_data.extend(my_amount);
        acp_data.extend(my_spk);
        acp_data.extend(my_seq);
        let mut ext_tail = leaf_bits.clone();
        ext_tail.extend(const_bits(&[0x00]));
        ext_tail.extend(csep_bits.clone());
        let mut configs = Vec::new();
        for (c, class) in classes.iter().enumerate() {
            let (acp, all, sgl) = (c >= 3, c % 3 == 0, c % 3 == 2);
            for (an, xt) in [(false, false), (true, false), (false, true), (true, true)] {
                if (an && sh.annex_max == 0) || (xt && !sh.bind) {
                    continue;
                }
                let s = if sh.annex_max == 0 { class.clone() } else { mul(cs.namespace(|| format!("cfg{c}_{an}_{xt}")), class, &if an { present.clone() } else { present.not::<CS>() })? };
                let s = if sh.bind { mul(cs.namespace(|| format!("cfgx{c}_{an}_{xt}")), &s, &if xt { ext.clone() } else { keypath.clone() })? } else { s };
                let mut m = head.clone();
                if !acp {
                    m.extend(four.iter().cloned());
                }
                if all {
                    m.extend(sha_outputs.iter().cloned());
                }
                m.extend(spend_type.iter().cloned());
                m.extend(if acp { acp_data.clone() } else { idx4.clone() });
                if an {
                    m.extend(sha_annex.iter().cloned());
                }
                if sgl {
                    m.extend(sha_single.iter().cloned());
                }
                if xt {
                    m.extend(ext_tail.iter().cloned());
                }
                configs.push((s, m));
            }
        }
        let th = sha256_native(b"TapSighash");
        let iv = midstate(&[th, th].concat());
        let sighash = sha256_var(cs.namespace(|| "tapsighash"), &iv, 64, &configs)?;

        // ------------------------------------------------ accumulator
        let prev = alloc_bytes(cs.namespace(|| "prev_acc"), &self.prev_acc)?;
        bind_halves(cs, "prev_acc", &prev, &z[1], &z[2]);
        let step_bits = alloc_bytes(cs.namespace(|| "step"), &[self.step])?;
        cs.enforce(|| "step_bind", |_| lc_bytes_be::<CS>(&step_bits) - z[0].get_variable(), |l| l + CS::one(), |l| l);
        let rx = alloc_bytes(cs.namespace(|| "rx"), &self.slot.sig_rx)?;
        let s = alloc_bytes(cs.namespace(|| "s"), &self.slot.sig_s)?;
        let mut pre = const_bits(AUTH_ACC_DOMAIN);
        pre.extend(prev);
        pre.extend(step_bits);
        pre.extend(le_bits_to_bytes(&ht_bits_le));
        pre.extend(px.iter().cloned());
        pre.extend(sighash);
        pre.extend(rx.iter().cloned());
        pre.extend(s.iter().cloned());
        let acc = sha256_fixed(cs.namespace(|| "acc"), &pre)?;
        let (acc_lo, acc_hi) = digest_to_halves(cs.namespace(|| "acc_out"), &acc)?;
        let par_out = if sh.bind {
            let par_in = alloc_bytes(cs.namespace(|| "par_in"), &self.par)?;
            bind_halves(cs, "par_in", &par_in, &z[8], &z[9]);
            let annex_hash = mux_bits(cs.namespace(|| "annex_hash"), &[present.not::<CS>(), present.clone()], &[vec![Boolean::constant(false); 256], sha_annex.clone()])?;
            let mut q = const_bits(PARAMS_TAG);
            q.extend(par_in);
            q.extend(le_bits_to_bytes(&idx_bits));
            q.extend(le_bits_to_bytes(&ht_bits_le));
            q.extend(vec![Boolean::constant(false); 7]);
            q.push(ext_b.clone());
            q.extend(leaf_bits);
            q.extend(csep_bits);
            q.extend(px);
            q.extend(rx);
            q.extend(s);
            q.extend(vec![Boolean::constant(false); 7]);
            q.push(present_b);
            q.extend(annex_hash);
            let par = sha256_fixed(cs.namespace(|| "par"), &q)?;
            Some(digest_to_halves(cs.namespace(|| "par_out"), &par)?)
        } else {
            None
        };

        let step_out = alloc_num(cs.namespace(|| "step_out"), F::from(self.step as u64 + 1))?;
        cs.enforce(|| "step_inc", |l| l + z[0].get_variable() + CS::one() - step_out.get_variable(), |l| l + CS::one(), |l| l);
        let mask_n = alloc_num(cs.namespace(|| "mask_out"), fi(mask_out.v))?;
        enforce_eq(cs, "mask_bind", &W::num(&mask_n, mask_out.v), &mask_out);
        let mut out = vec![step_out, acc_lo, acc_hi, z[3].clone(), z[4].clone(), z[5].clone(), z[6].clone(), mask_n];
        if let Some((lo, hi)) = par_out {
            out.extend([lo, hi]);
        }
        Ok(out)
    }
}


/// A signature slot as exchanged in JSON (`artifacts/*txs.json`): the key-path fields plus an
/// optional script path (`null` for a key-path signature).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundSlot {
    #[serde(flatten)]
    pub slot: SigSlot,
    #[serde(default)]
    pub script_path: Option<ScriptPath>,
}
