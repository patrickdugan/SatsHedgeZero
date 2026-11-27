//! Uniform Nova step: one committed V3 batch through `clearing::clear`, exactly.
//!
//! Folded state `z` (arity `7 + 4A` for an account table of `A` slots):
//!
//! | index | value |
//! |---|---|
//! | 0 | `seq` of the next batch |
//! | 1 | pool `cash` (i64) |
//! | 2 | `fund` |
//! | 3 | `carry` |
//! | 4 | `book` (i128, signed entry value of every open lot) |
//! | 5 .. 5+A | deferred claim of each table slot |
//! | 5+A .. 5+4A | table keys, 3 limbs per slot: txid[0..12], txid[12..24], txid[24..32] ‖ vout (big-endian) |
//! | 5+4A, 6+4A | digest chain, little-endian 128-bit halves |
//!
//! The account table lists every account that can hold a claim or appear in a batch, in
//! strictly ascending `(txid, vout)` order (checked in every step), so table order is the
//! `BTreeMap` key order `clear` uses for deferred claims. Unused slots carry keys that never
//! appear in a batch and a zero claim.
//!
//! Per step the witness is the batch input only: up to `R` rows `(slot, pnl, released)` in
//! batch order (what `positions::settle` produced). The step recomputes, in R1CS:
//! 1. losses: `collected = min(loss, released)`, `own_claim_used = min(rest, claim)`,
//!    `shortfall = rest - own_claim_used`, for rows with `pnl < 0`;
//! 2. `fund_absorbed = min(shortfall, fund)`;
//! 3. `haircut = min(shortfall - fund_absorbed + carry, base)` split by `prorata` over every
//!    deferred claim (key order) then every gain (batch order), `carry' = owed - haircut`;
//! 4. `paid = prorata(min(due, max(cash, 0)), dues)`, `claim_after = due - paid`,
//!    `net = paid - collected`, `cash' = cash + collected - paid`;
//! 5. the `layer` (`max` of Margin/OwnClaim/Fund/Haircut/Carried), the `claim_haircuts` list
//!    of non-batch accounts, `claims_after`, and the exact `BatchClearing::digest()`
//!    preimage (variable number of rows and of claim haircuts) hashed as the
//!    `SHZ/HFT/CLEARING/V1` tagged hash;
//! 6. `chain' = SHA256("LIGHTNINGER/V3CLEAR/CHAIN/V1" || chain || seq_le64 || digest)`,
//!    `seq' = seq + 1`, `book' = book - sum(pnl)`, and the identity
//!    `cash - claims - fund + carry == book` on the input and output state.
use crate::gadgets::*;
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr as F;
use nova_snark::{
    frontend::{gadgets::boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError},
    traits::circuit::StepCircuit,
};
use serde::{Deserialize, Serialize};

pub const CLEARING_TAG: &[u8] = b"SHZ/HFT/CLEARING/V1";
pub const CHAIN_TAG: &[u8] = b"LIGHTNINGER/V3CLEAR/CHAIN/V1";
pub const RELATION_CLEARING_V1: &str = "lightninger/v3-clearing-batch-fold/v1";

pub type Key = ([u8; 32], u32);

/// Folded pool state before a batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolState {
    pub seq: u64,
    pub cash: i64,
    pub fund: u64,
    pub carry: u64,
    pub book: i128,
    pub claims: Vec<u64>,
    pub keys: Vec<Key>,
    pub chain: [u8; 32],
}

/// One batch account's clearing input, in batch order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowIn {
    pub slot: usize,
    pub pnl: i64,
    pub released: u64,
}

/// Replace a named witness value: `name`, row/slot/item index, and the change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tamper {
    pub name: String,
    pub idx: usize,
    pub op: TamperOp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TamperOp {
    Add(i128),
    Set(i128),
}

impl Tamper {
    pub fn add(name: &str, idx: usize, d: i128) -> Self {
        Self { name: name.into(), idx, op: TamperOp::Add(d) }
    }
    pub fn set(name: &str, idx: usize, v: i128) -> Self {
        Self { name: name.into(), idx, op: TamperOp::Set(v) }
    }
}

pub fn key_limbs(k: &Key) -> [u128; 3] {
    let t = &k.0;
    let l0 = u128::from_be_bytes([[0u8; 4].as_slice(), &t[0..12]].concat().try_into().unwrap());
    let l1 = u128::from_be_bytes([[0u8; 4].as_slice(), &t[12..24]].concat().try_into().unwrap());
    let l2 = (u64::from_be_bytes(t[24..32].try_into().unwrap()) as u128) << 32 | k.1 as u128;
    [l0, l1, l2]
}

impl PoolState {
    pub fn arity(a: usize) -> usize {
        7 + 4 * a
    }
    pub fn to_z(&self) -> Vec<F> {
        let mut z = vec![fi(self.seq as i128), fi(self.cash as i128), fi(self.fund as i128), fi(self.carry as i128), fi(self.book)];
        z.extend(self.claims.iter().map(|&c| fi(c as i128)));
        for k in &self.keys {
            z.extend(key_limbs(k).iter().map(|&l| fu(l)));
        }
        let (lo, hi) = le_halves(&self.chain);
        z.push(fu(lo));
        z.push(fu(hi));
        z
    }
    /// `cash - claims - fund + carry - book`.
    pub fn identity(&self) -> i128 {
        self.cash as i128 - self.claims.iter().map(|&c| c as i128).sum::<i128>() - self.fund as i128 + self.carry as i128 - self.book
    }
}

/// `chain' = SHA256(CHAIN_TAG || chain || seq_le64 || digest)`.
pub fn chain_next(chain: &[u8; 32], seq: u64, digest: &[u8; 32]) -> [u8; 32] {
    let mut b = CHAIN_TAG.to_vec();
    b.extend_from_slice(chain);
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(digest);
    sha256_native(&b)
}

#[derive(Clone, Debug)]
pub struct ClearingStep {
    /// Account table slots.
    pub a: usize,
    /// Maximum rows per batch.
    pub r: usize,
    pub pre: PoolState,
    pub rows: Vec<RowIn>,
    pub tampers: Vec<Tamper>,
}

impl ClearingStep {
    pub fn new(a: usize, r: usize, pre: PoolState, rows: Vec<RowIn>) -> Self {
        assert_eq!(pre.claims.len(), a);
        assert_eq!(pre.keys.len(), a);
        assert!(rows.len() <= r, "batch has {} rows, step capacity {r}", rows.len());
        Self { a, r, pre, rows, tampers: Vec::new() }
    }
    /// Setup witness: an empty batch over a table of distinct ascending keys.
    pub fn blank(a: usize, r: usize) -> Self {
        let keys = (0..a).map(|i| ([i as u8 + 1; 32], 0u32)).collect();
        let pre = PoolState { seq: 0, cash: 0, fund: 0, carry: 0, book: 0, claims: vec![0; a], keys, chain: [0; 32] };
        Self::new(a, r, pre, Vec::new())
    }
    fn t(&self, name: &str, idx: usize, honest: i128) -> i128 {
        let mut v = honest;
        for t in self.tampers.iter().filter(|t| t.name == name && t.idx == idx) {
            v = match t.op {
                TamperOp::Add(d) => v + d,
                TamperOp::Set(s) => s,
            };
        }
        v
    }
}

struct RowW {
    key_bytes: Vec<Boolean>,
    pnl_bits: Vec<Boolean>,
    pnl: W,
    released_bits: Vec<Boolean>,
    collected: W,
    collected_bits: Vec<Boolean>,
    own: W,
    own_bits: Vec<Boolean>,
    shortfall: W,
    shortfall_bits: Vec<Boolean>,
    claim_before_bits: Vec<Boolean>,
    gain: W,
    neg: W,
    sel: Vec<W>,
    haircut_bits: Vec<Boolean>,
    claim_after_bits: Vec<Boolean>,
    paid_bits: Vec<Boolean>,
    net_bits: Vec<Boolean>,
}

impl RowW {
    fn bytes(&self) -> Vec<Boolean> {
        let mut b = self.key_bytes.clone();
        b.extend(le_bits_to_bytes(&self.pnl_bits));
        for x in [
            &self.released_bits,
            &self.collected_bits,
            &self.own_bits,
            &self.shortfall_bits,
            &self.haircut_bits,
            &self.claim_before_bits,
            &self.claim_after_bits,
            &self.paid_bits,
        ] {
            b.extend(le_bits_to_bytes(x));
        }
        b.extend(le_bits_to_bytes(&self.net_bits));
        assert_eq!(b.len(), 116 * 8);
        b
    }
}

/// Allocate a key's `put_op` bytes (txid ‖ vout LE) and bind them to three z limbs.
fn key_bytes<CS: ConstraintSystem<F>>(mut cs: CS, k: &Key, limbs: [&W; 3]) -> Res<Vec<Boolean>> {
    let mut bytes = k.0.to_vec();
    bytes.extend(k.1.to_le_bytes());
    let bits = alloc_bytes(cs.namespace(|| "bytes"), &bytes)?;
    let vout_le = lc_bytes_le::<CS>(&bits[256..288]);
    let l0 = lc_bytes_be::<CS>(&bits[0..96]);
    let l1 = lc_bytes_be::<CS>(&bits[96..192]);
    let l2 = lc_bytes_be::<CS>(&bits[192..256]);
    let shift = fu(1u128 << 32);
    let mut l2s = nova_snark::frontend::LinearCombination::zero();
    for (var, c) in l2.iter() {
        l2s = l2s + (*c * shift, var);
    }
    let l2s = l2s + &vout_le;
    cs.enforce(|| "l0", |_| l0 - &limbs[0].lc, |x| x + CS::one(), |x| x);
    cs.enforce(|| "l1", |_| l1 - &limbs[1].lc, |x| x + CS::one(), |x| x);
    cs.enforce(|| "l2", |_| l2s - &limbs[2].lc, |x| x + CS::one(), |x| x);
    Ok(bits)
}

/// Bit `a < b` for keys given as 3 limbs of at most 96 bits, compared lexicographically.
fn key_lt<CS: ConstraintSystem<F>>(mut cs: CS, a: [&W; 3], b: [&W; 3]) -> Res<W> {
    let one = W::konst::<CS>(1);
    let lt = |cs: &mut CS, i: usize| le(cs.namespace(|| format!("lt{i}")), &a[i].add(&one), b[i], 97);
    let lt0 = lt(&mut cs, 0)?;
    let lt1 = lt(&mut cs, 1)?;
    let lt2 = lt(&mut cs, 2)?;
    let eq0 = nonzero(cs.namespace(|| "ne0"), &a[0].sub(b[0]))?.not::<CS>();
    let eq1 = nonzero(cs.namespace(|| "ne1"), &a[1].sub(b[1]))?.not::<CS>();
    let t1 = mul(cs.namespace(|| "eq1lt2"), &eq1, &lt2)?;
    let t0 = mul(cs.namespace(|| "eq0rest"), &eq0, &lt1.add(&t1))?;
    Ok(lt0.add(&t0))
}

impl StepCircuit<F> for ClearingStep {
    fn arity(&self) -> usize {
        PoolState::arity(self.a)
    }

    fn synthesize<CS: ConstraintSystem<F>>(&self, cs: &mut CS, z: &[AllocatedNum<F>]) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let (a_n, r_n) = (self.a, self.r);
        assert_eq!(z.len(), self.arity());
        let p = &self.pre;
        let one = W::konst::<CS>(1);

        // ---------------------------------------------------------------- input state
        let seq = W::num(&z[0], p.seq as i128);
        let seq_bits = range(cs.namespace(|| "seq"), &seq, 64)?;
        let cash0 = W::num(&z[1], p.cash as i128);
        let cash0_bits = range_i64(cs.namespace(|| "cash0"), &cash0)?;
        let fund0 = W::num(&z[2], p.fund as i128);
        range(cs.namespace(|| "fund0"), &fund0, 64)?;
        let carry0 = W::num(&z[3], p.carry as i128);
        range(cs.namespace(|| "carry0"), &carry0, 64)?;
        let book0 = W::num(&z[4], p.book);
        let claims0: Vec<W> = (0..a_n).map(|j| W::num(&z[5 + j], p.claims[j] as i128)).collect();
        for (j, c) in claims0.iter().enumerate() {
            range(cs.namespace(|| format!("claim0_{j}")), c, 64)?;
        }
        let limbs: Vec<[W; 3]> = (0..a_n)
            .map(|j| {
                let l = key_limbs(&p.keys[j]);
                [0, 1, 2].map(|i| W::num(&z[5 + a_n + 3 * j + i], l[i] as i128))
            })
            .collect();
        let mut key_bits = Vec::with_capacity(a_n);
        for j in 0..a_n {
            key_bits.push(key_bytes(cs.namespace(|| format!("key{j}")), &p.keys[j], [&limbs[j][0], &limbs[j][1], &limbs[j][2]])?);
        }
        for j in 1..a_n {
            let lt = key_lt(
                cs.namespace(|| format!("sorted{j}")),
                [&limbs[j - 1][0], &limbs[j - 1][1], &limbs[j - 1][2]],
                [&limbs[j][0], &limbs[j][1], &limbs[j][2]],
            )?;
            enforce_eq(cs, &format!("sorted{j}_lt"), &lt, &one);
        }
        let claims0_sum = W::sum(&claims0);
        let id0 = cash0.sub(&claims0_sum).sub(&fund0).add(&carry0).sub(&book0);
        enforce_eq(cs, "identity_in", &id0, &W::zero());
        let chain_in_bits = alloc_bytes(cs.namespace(|| "chain_in"), &p.chain)?;
        bind_halves(cs, "chain_in", &chain_in_bits, &z[5 + 4 * a_n], &z[6 + 4 * a_n]);

        // ---------------------------------------------------------------- rows, step 1
        let mut rows: Vec<RowW> = Vec::with_capacity(r_n);
        let mut acts: Vec<W> = Vec::with_capacity(r_n);
        for k in 0..r_n {
            let mut cs = cs.namespace(|| format!("row{k}"));
            let input = self.rows.get(k);
            let act = alloc_bit(cs.namespace(|| "act"), input.is_some())?;
            if k > 0 {
                let prev = &acts[k - 1];
                enforce_mul(&mut cs, "prefix", &act, &prev.not::<CS>(), &W::zero());
            }
            let slot = input.map(|r| r.slot);
            let mut sel = Vec::with_capacity(a_n);
            for j in 0..a_n {
                sel.push(alloc_bit(cs.namespace(|| format!("sel{j}")), slot == Some(j))?);
            }
            enforce_eq(&mut cs, "one_slot", &W::sum(&sel), &act);
            let pnl_v = self.t("pnl", k, input.map_or(0, |r| r.pnl as i128));
            let pnl = alloc(cs.namespace(|| "pnl"), pnl_v)?;
            let pnl_bits = range_i64(cs.namespace(|| "pnl_bits"), &pnl)?;
            enforce_mul(&mut cs, "idle_pnl", &act.not::<CS>(), &pnl, &W::zero());
            let rel = alloc(cs.namespace(|| "released"), input.map_or(0, |r| r.released as i128))?;
            let released_bits = range(cs.namespace(|| "released_bits"), &rel, 64)?;
            enforce_mul(&mut cs, "idle_rel", &act.not::<CS>(), &rel, &W::zero());
            let neg = W::bit(&pnl_bits[63], CS::one());
            // gain = pnl if pnl >= 0 else 0; loss = gain - pnl (= |pnl| for a loser)
            let gain = alloc(cs.namespace(|| "gain"), if neg.v == 1 { 0 } else { pnl.v })?;
            enforce_mul(&mut cs, "gain_c", &neg.not::<CS>(), &pnl, &gain);
            let loss = gain.sub(&pnl);
            // channel bytes and claim_before from the selected slot
            let mut lim = [W::zero(), W::zero(), W::zero()];
            let mut cb = W::zero();
            for j in 0..a_n {
                for i in 0..3 {
                    let t = mul(cs.namespace(|| format!("k{j}_{i}")), &sel[j], &limbs[j][i])?;
                    lim[i] = lim[i].add(&t);
                }
                let t = mul(cs.namespace(|| format!("c{j}")), &sel[j], &claims0[j])?;
                cb = cb.add(&t);
            }
            let key = slot.map(|s| p.keys[s]).unwrap_or(([0; 32], 0));
            let kb = key_bytes(cs.namespace(|| "chan"), &key, [&lim[0], &lim[1], &lim[2]])?;
            let (cb, claim_before_bits) = claim_u64(cs.namespace(|| "cb"), &cb, self.t("claim_before", k, cb.v))?;
            // 1. collected = min(loss, released); own = min(rest, claim); shortfall = rest - own
            let collected = min_claimed(cs.namespace(|| "collected"), &loss, &rel, 66, |h| self.t("collected", k, h))?;
            let collected_bits = range(cs.namespace(|| "collected_bits"), &collected, 64)?;
            let rest = loss.sub(&collected);
            let own = min_claimed(cs.namespace(|| "own"), &rest, &cb, 66, |h| self.t("own_claim_used", k, h))?;
            let own_bits = range(cs.namespace(|| "own_bits"), &own, 64)?;
            let sf = rest.sub(&own);
            let (shortfall, shortfall_bits) = claim_u64(cs.namespace(|| "shortfall"), &sf, self.t("shortfall", k, sf.v))?;
            rows.push(RowW {
                key_bytes: kb,
                pnl_bits,
                pnl,
                released_bits,
                collected,
                collected_bits,
                own,
                own_bits,
                shortfall,
                shortfall_bits,
                claim_before_bits,
                gain,
                neg,
                sel,
                haircut_bits: vec![],
                claim_after_bits: vec![],
                paid_bits: vec![],
                net_bits: vec![],
            });
            acts.push(act);
        }
        // each slot is in at most one row
        let mut in_batch = Vec::with_capacity(a_n);
        for j in 0..a_n {
            let u = W::sum(rows.iter().map(|r| &r.sel[j]));
            enforce_mul(cs, &format!("distinct{j}"), &u, &u.not::<CS>(), &W::zero());
            in_batch.push(u);
        }
        // claims after step 1: a loser's own claim is cancelled by own_claim_used
        let mut claims1 = Vec::with_capacity(a_n);
        for j in 0..a_n {
            let mut c = claims0[j].clone();
            for (k, r) in rows.iter().enumerate() {
                let t = mul(cs.namespace(|| format!("own{k}_{j}")), &r.sel[j], &r.own)?;
                c = c.sub(&t);
            }
            claims1.push(c);
        }
        let collected_total = W::sum(rows.iter().map(|r| &r.collected));
        range(cs.namespace(|| "collected_total"), &collected_total, 64)?;
        let sft = W::sum(rows.iter().map(|r| &r.shortfall));
        let (shortfall_total, shortfall_total_bits) = claim_u64(cs.namespace(|| "shortfall_total"), &sft, self.t("shortfall_total", 0, sft.v))?;
        let cash1 = cash0.add(&collected_total);
        let cash1_bits = range_i64(cs.namespace(|| "cash1"), &cash1)?;

        // ---------------------------------------------------------------- 2. fund
        let fa = min_claimed(cs.namespace(|| "fund_absorbed"), &shortfall_total, &fund0, 66, |h| self.t("fund_absorbed", 0, h))?;
        let fa_bits = range(cs.namespace(|| "fa_bits"), &fa, 64)?;
        let fd = fund0.sub(&fa);
        let (fund_after, fund_after_bits) = claim_u64(cs.namespace(|| "fund_after"), &fd, self.t("fund_after", 0, fd.v))?;

        // ---------------------------------------------------------------- 3. haircut
        let owed = shortfall_total.sub(&fa).add(&carry0);
        range(cs.namespace(|| "owed"), &owed, 64)?;
        let mut amounts: Vec<W> = claims1.clone();
        amounts.extend(rows.iter().map(|r| r.gain.clone()));
        let base = W::sum(&amounts);
        range(cs.namespace(|| "base"), &base, 64)?;
        let hc = min_claimed(cs.namespace(|| "haircut"), &owed, &base, 66, |h| self.t("haircut", 0, h))?;
        let hc_bits = range(cs.namespace(|| "hc_bits"), &hc, 64)?;
        let cut = prorata(cs.namespace(|| "cut"), &hc, &amounts, &|i, x| self.t("cut_rem", i, x))?;
        let co = owed.sub(&hc);
        let (carry_after, carry_after_bits) = claim_u64(cs.namespace(|| "carry_after"), &co, self.t("carry_after", 0, co.v))?;
        let claims2: Vec<W> = (0..a_n).map(|j| claims1[j].sub(&cut[j])).collect();

        // ---------------------------------------------------------------- 4. payment
        let mut dues = Vec::with_capacity(r_n);
        for k in 0..r_n {
            let mut cs = cs.namespace(|| format!("due{k}"));
            let cutg = &cut[a_n + k];
            let mut h = cutg.clone();
            let mut c2 = W::zero();
            for j in 0..a_n {
                let t = mul(cs.namespace(|| format!("h{j}")), &rows[k].sel[j], &cut[j])?;
                h = h.add(&t);
                let t = mul(cs.namespace(|| format!("c{j}")), &rows[k].sel[j], &claims2[j])?;
                c2 = c2.add(&t);
            }
            let (_, hb) = claim_u64(cs.namespace(|| "haircut"), &h, self.t("row_haircut", k, h.v))?;
            rows[k].haircut_bits = hb;
            let due = rows[k].gain.sub(cutg).add(&c2);
            range(cs.namespace(|| "due"), &due, 64)?;
            dues.push(due);
        }
        let due = W::sum(&dues);
        range(cs.namespace(|| "due_total"), &due, 64)?;
        let cash1_neg = W::bit(&cash1_bits[63], CS::one());
        let available = mul(cs.namespace(|| "available"), &cash1_neg.not::<CS>(), &cash1)?;
        let tpay = min_claimed(cs.namespace(|| "tpay"), &due, &available, 66, |h| h)?;
        let paid = prorata(cs.namespace(|| "pay"), &tpay, &dues, &|i, x| self.t("pay_rem", i, x))?;
        let mut claim_after = Vec::with_capacity(r_n);
        for k in 0..r_n {
            let mut cs = cs.namespace(|| format!("pay{k}"));
            let (pw, pb) = claim_u64(cs.namespace(|| "paid"), &paid[k], self.t("paid", k, paid[k].v))?;
            rows[k].paid_bits = pb;
            let ca = dues[k].sub(&pw);
            let (ca, cab) = claim_u64(cs.namespace(|| "claim_after"), &ca, self.t("claim_after", k, ca.v))?;
            rows[k].claim_after_bits = cab;
            let nt = pw.sub(&rows[k].collected);
            let (_, nb) = claim_i64(cs.namespace(|| "net"), &nt, self.t("net", k, nt.v))?;
            rows[k].net_bits = nb;
            claim_after.push(ca);
        }
        let out = W::sum(&paid);
        let ca_cash = cash1.sub(&out);
        let (cash_after, cash_after_bits) = claim_i64(cs.namespace(|| "cash_after"), &ca_cash, self.t("cash_after", 0, ca_cash.v))?;
        // never below its starting value if that was negative, never below zero otherwise
        let cash0_neg = W::bit(&cash0_bits[63], CS::one());
        let floor = mul(cs.namespace(|| "cash_floor"), &cash0_neg, &cash0)?;
        range(cs.namespace(|| "cash_ge_floor"), &cash_after.sub(&floor), 64)?;
        let mut claims3 = Vec::with_capacity(a_n);
        for j in 0..a_n {
            let mut cs = cs.namespace(|| format!("claim3_{j}"));
            let mut c = mul(cs.namespace(|| "keep"), &in_batch[j].not::<CS>(), &claims2[j])?;
            for k in 0..r_n {
                let t = mul(cs.namespace(|| format!("r{k}")), &rows[k].sel[j], &claim_after[k])?;
                c = c.add(&t);
            }
            let c = W { v: self.t("claim3", j, c.v), ..c };
            range(cs.namespace(|| "rng"), &c, 64)?;
            claims3.push(c);
        }
        let cl = W::sum(&claims3);
        let (claims_after, claims_after_bits) = claim_u64(cs.namespace(|| "claims_after"), &cl, self.t("claims_after", 0, cl.v))?;

        // ---------------------------------------------------------------- claim haircuts
        let mut include = Vec::with_capacity(a_n);
        for j in 0..a_n {
            let nz = nonzero(cs.namespace(|| format!("cut_nz{j}")), &cut[j])?;
            include.push(mul(cs.namespace(|| format!("incl{j}")), &nz, &in_batch[j].not::<CS>())?);
        }
        // entry h of the list is the slot j with include_j and h earlier includes
        let mut m = vec![vec![W::zero(); a_n]; a_n];
        let mut prefix = W::zero();
        for j in 0..a_n {
            let e = one_hot(cs.namespace(|| format!("pos{j}")), &prefix, j + 1)?;
            for (h, eh) in e.iter().enumerate() {
                m[h][j] = mul(cs.namespace(|| format!("m{h}_{j}")), &include[j], eh)?;
            }
            prefix = prefix.add(&include[j]);
        }
        let h_count = prefix;
        let mut entries = Vec::with_capacity(a_n);
        for h in 0..a_n {
            let mut cs = cs.namespace(|| format!("ch{h}"));
            let mut lim = [W::zero(), W::zero(), W::zero()];
            let mut amt = W::zero();
            let mut key = ([0u8; 32], 0u32);
            for j in h..a_n {
                for i in 0..3 {
                    let t = mul(cs.namespace(|| format!("k{j}_{i}")), &m[h][j], &limbs[j][i])?;
                    lim[i] = lim[i].add(&t);
                }
                let t = mul(cs.namespace(|| format!("a{j}")), &m[h][j], &cut[j])?;
                amt = amt.add(&t);
                if m[h][j].v == 1 {
                    key = p.keys[j];
                }
            }
            let mut b = key_bytes(cs.namespace(|| "key"), &key, [&lim[0], &lim[1], &lim[2]])?;
            let (_, ab) = claim_u64(cs.namespace(|| "amt"), &amt, self.t("claim_haircut", h, amt.v))?;
            b.extend(le_bits_to_bytes(&ab));
            entries.push(b);
        }

        // ---------------------------------------------------------------- layer
        let any_loss = nonzero(cs.namespace(|| "any_loss"), &W::sum(rows.iter().map(|r| &r.neg)))?;
        let any_own = nonzero(cs.namespace(|| "any_own"), &W::sum(rows.iter().map(|r| &r.own)))?;
        let nz_fund = nonzero(cs.namespace(|| "nz_fund"), &fa)?;
        let nz_hc = nonzero(cs.namespace(|| "nz_hc"), &hc)?;
        let nz_carry = nonzero(cs.namespace(|| "nz_carry"), &carry_after)?;
        let l5 = nz_carry.clone();
        let n5 = l5.not::<CS>();
        let l4 = mul(cs.namespace(|| "l4"), &nz_hc, &n5)?;
        let n4 = n5.sub(&l4);
        let l3 = mul(cs.namespace(|| "l3"), &nz_fund, &n4)?;
        let n3 = n4.sub(&l3);
        let l2 = mul(cs.namespace(|| "l2"), &any_own, &n3)?;
        let n2 = n3.sub(&l2);
        let l1 = mul(cs.namespace(|| "l1"), &any_loss, &n2)?;
        let layer_honest = l1.v + 2 * l2.v + 3 * l3.v + 4 * l4.v + 5 * l5.v;
        let layer_v = self.t("layer", 0, layer_honest);
        let lb = alloc_bits_le(cs.namespace(|| "layer_bits"), layer_v, 3)?;
        enforce_eq(cs, "layer_b0", &W::bit(&lb[0], CS::one()), &l1.add(&l3).add(&l5));
        enforce_eq(cs, "layer_b1", &W::bit(&lb[1], CS::one()), &l2.add(&l3));
        enforce_eq(cs, "layer_b2", &W::bit(&lb[2], CS::one()), &l4.add(&l5));
        let mut layer_byte = vec![Boolean::constant(false); 5];
        layer_byte.extend([lb[2].clone(), lb[1].clone(), lb[0].clone()]);

        // ---------------------------------------------------------------- digest preimage
        let mut tail = Vec::new();
        for x in [&shortfall_total_bits, &fa_bits, &hc_bits] {
            tail.extend(le_bits_to_bytes(x));
        }
        tail.extend(layer_byte);
        tail.extend(le_bits_to_bytes(&cash0_bits));
        tail.extend(le_bits_to_bytes(&cash_after_bits));
        for x in [&fund_after_bits, &carry_after_bits, &claims_after_bits] {
            tail.extend(le_bits_to_bytes(x));
        }
        assert_eq!(tail.len(), 65 * 8);
        // stage A: claim-haircut count, the first h entries, the tail
        let sel_h = one_hot(cs.namespace(|| "sel_h"), &h_count, a_n + 1)?;
        let t_cands: Vec<Vec<Boolean>> = (0..=a_n)
            .map(|h| {
                let mut v = const_bits(&(h as u64).to_le_bytes());
                for e in &entries[..h] {
                    v.extend(e.iter().cloned());
                }
                v.extend(tail.iter().cloned());
                v
            })
            .collect();
        let t_bits = mux_bits(cs.namespace(|| "stage_a"), &sel_h, &t_cands)?;
        // stage B: row count, the first r rows, then stage A
        let mut sel_r = Vec::with_capacity(r_n + 1);
        for r in 0..=r_n {
            let hi = if r == 0 { one.clone() } else { acts[r - 1].clone() };
            let lo = if r == r_n { W::zero() } else { acts[r].clone() };
            sel_r.push(hi.sub(&lo));
        }
        let row_bytes: Vec<Vec<Boolean>> = rows.iter().map(|r| r.bytes()).collect();
        let m_cands: Vec<Vec<Boolean>> = (0..=r_n)
            .map(|r| {
                let mut v = const_bits(&(r as u64).to_le_bytes());
                for rb in &row_bytes[..r] {
                    v.extend(rb.iter().cloned());
                }
                v.extend(t_bits.iter().cloned());
                v
            })
            .collect();
        let m_bits = mux_bits(cs.namespace(|| "stage_b"), &sel_r, &m_cands)?;
        // stage C: padding for the exact length, SHA-256 after the constant tag block
        let th = sha256_native(CLEARING_TAG);
        let iv = midstate(&[th, th].concat());
        let mut configs = Vec::with_capacity((r_n + 1) * (a_n + 1));
        for r in 0..=r_n {
            for h in 0..=a_n {
                let s = mul(cs.namespace(|| format!("sel_rh{r}_{h}")), &sel_r[r], &sel_h[h])?;
                let len = 81 + 116 * r + 44 * h;
                configs.push((s, m_bits[..len * 8].to_vec()));
            }
        }
        let digest_bits = sha256_var(cs.namespace(|| "digest"), &iv, 64, &configs)?;
        let digest_bits: Vec<Boolean> = if self.tampers.iter().any(|t| t.name == "digest_bit") {
            // a prover that substitutes another digest must allocate it; bind it to the computed one
            let mut d: [u8; 32] = bits_value(&digest_bits).try_into().unwrap();
            d[0] ^= 1;
            let alt = alloc_bytes(cs.namespace(|| "alt_digest"), &d)?;
            for (i, (x, y)) in alt.iter().zip(&digest_bits).enumerate() {
                cs.enforce(
                    || format!("alt{i}"),
                    |_| x.lc(CS::one(), F::ONE) - &y.lc(CS::one(), F::ONE),
                    |l| l + CS::one(),
                    |l| l,
                );
            }
            alt
        } else {
            digest_bits
        };

        // ---------------------------------------------------------------- chain, outputs
        let mut cpre = const_bits(CHAIN_TAG);
        cpre.extend(chain_in_bits);
        cpre.extend(le_bits_to_bytes(&seq_bits));
        cpre.extend(digest_bits);
        let chain_out = sha256_fixed(cs.namespace(|| "chain"), &cpre)?;
        let (chain_lo, chain_hi) = digest_to_halves(cs.namespace(|| "chain_out"), &chain_out)?;

        let pnl_sum = W::sum(rows.iter().map(|r| &r.pnl));
        let book1 = book0.sub(&pnl_sum);
        let id1 = cash_after.sub(&claims_after).sub(&fund_after).add(&carry_after).sub(&book1);
        enforce_eq(cs, "identity_out", &id1, &W::zero());

        let mut outs = Vec::with_capacity(self.arity());
        let mut emit = |cs: &mut CS, name: &str, w: &W| -> Res<()> {
            let n = alloc_num(cs.namespace(|| format!("out_{name}")), fi(w.v))?;
            enforce_eq(cs, &format!("bind_{name}"), &W::num(&n, w.v), w);
            outs.push(n);
            Ok(())
        };
        emit(cs, "seq", &seq.add(&one))?;
        emit(cs, "cash", &cash_after)?;
        emit(cs, "fund", &fund_after)?;
        emit(cs, "carry", &carry_after)?;
        emit(cs, "book", &book1)?;
        for (j, c) in claims3.iter().enumerate() {
            emit(cs, &format!("claim{j}"), c)?;
        }
        for zi in &z[5 + a_n..5 + 4 * a_n] {
            outs.push(zi.clone());
        }
        outs.push(chain_lo);
        outs.push(chain_hi);
        Ok(outs)
    }
}

/// `z` after the batch, from the real post-state and the real digest.
pub fn expected_z_after(pre: &PoolState, post_claims: &[u64], cash: i64, fund: u64, carry: u64, book: i128, digest: &[u8; 32]) -> PoolState {
    PoolState {
        seq: pre.seq + 1,
        cash,
        fund,
        carry,
        book,
        claims: post_claims.to_vec(),
        keys: pre.keys.clone(),
        chain: chain_next(&pre.chain, pre.seq, digest),
    }
}

pub fn program_hash(a: usize, r: usize) -> [u8; 32] {
    sha256_native(format!("{RELATION_CLEARING_V1}/A{a}/R{r}").as_bytes())
}

/// `commitment_hash` of the 304-byte BitVM3 statement: the proven final `z`, each element
/// as its 32-byte little-endian field representation, under a tag.
pub fn commitment_hash(z: &[F]) -> [u8; 32] {
    let mut b = b"LIGHTNINGER/V3CLEAR/COMMIT/V1".to_vec();
    for e in z {
        b.extend_from_slice(e.to_repr().as_ref());
    }
    sha256_native(&b)
}

/// Synthesize one step on a [`TestConstraintSystem`] with input state `z`: returns whether
/// every constraint holds, the first unsatisfied constraint, the outputs, and the count.
pub fn check_step<C: StepCircuit<F>>(step: &C, z: &[F]) -> (bool, Option<String>, Vec<F>, usize) {
    use nova_snark::frontend::test_cs::TestConstraintSystem;
    let mut cs = TestConstraintSystem::<F>::new();
    let zin: Vec<AllocatedNum<F>> = z
        .iter()
        .enumerate()
        .map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(*v)).unwrap())
        .collect();
    let out = step.synthesize(&mut cs, &zin).expect("synthesize");
    let ok = cs.is_satisfied();
    let which = if ok { None } else { cs.which_is_unsatisfied().map(|s| s.to_string()) };
    (ok, which, out.iter().map(|n| n.get_value().unwrap_or(F::ZERO)).collect(), cs.num_constraints())
}

/// Build the fold steps of a trace: each batch's real pre-state with the running chain.
pub fn steps_of(a: usize, r: usize, batches: &[crate::trace::BatchRecord]) -> (Vec<ClearingStep>, PoolState, PoolState) {
    let mut chain = [0u8; 32];
    let mut steps = Vec::with_capacity(batches.len());
    let mut z0 = None;
    let mut last = None;
    for b in batches {
        let mut pre = b.pre.clone();
        pre.chain = chain;
        if z0.is_none() {
            z0 = Some(pre.clone());
        }
        chain = chain_next(&chain, b.seq, &b.digest);
        let mut post = b.post.clone();
        post.chain = chain;
        last = Some(post);
        steps.push(ClearingStep::new(a, r, pre, b.rows.clone()));
    }
    (steps, z0.expect("non-empty"), last.unwrap())
}
