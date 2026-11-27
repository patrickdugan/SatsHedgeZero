//! R1CS gadgets over `bn256::Fr` shared by the clearing and TapSighash steps.
//!
//! Every gadget computes its own witness from the input values and never branches on them,
//! so the constraint shape is identical for the blank setup witness and for any real one.
//! Values are carried next to their linear combinations as exact integers ([`W`]); a value
//! that does not satisfy a gadget's relation (a tampered witness) leaves the system
//! unsatisfied instead of panicking.
#![allow(deprecated)] // sha2 0.10 re-exports generic-array 0.14 (pinned with nova-snark 0.76)
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr as F;
use nova_snark::frontend::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::AllocatedNum,
        sha256::sha256_compression_function,
        uint32::UInt32,
    },
    ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use sha2::digest::generic_array::GenericArray;

pub type Res<T> = Result<T, SynthesisError>;

pub const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Field element of a signed integer.
pub fn fi(v: i128) -> F {
    if v >= 0 {
        F::from_u128(v as u128)
    } else {
        -F::from_u128(v.unsigned_abs())
    }
}

pub fn fu(v: u128) -> F {
    F::from_u128(v)
}

/// A linear combination together with its exact integer value.
#[derive(Clone)]
pub struct W {
    pub lc: LinearCombination<F>,
    pub v: i128,
}

impl W {
    pub fn zero() -> W {
        W { lc: LinearCombination::zero(), v: 0 }
    }
    pub fn konst<CS: ConstraintSystem<F>>(v: i128) -> W {
        W { lc: LinearCombination::zero() + (fi(v), CS::one()), v }
    }
    pub fn var(var: Variable, v: i128) -> W {
        W { lc: LinearCombination::zero() + var, v }
    }
    pub fn num(n: &AllocatedNum<F>, v: i128) -> W {
        Self::var(n.get_variable(), v)
    }
    pub fn add(&self, o: &W) -> W {
        W { lc: self.lc.clone() + &o.lc, v: self.v + o.v }
    }
    pub fn sub(&self, o: &W) -> W {
        W { lc: self.lc.clone() - &o.lc, v: self.v - o.v }
    }
    pub fn scale(&self, k: i128) -> W {
        let c = fi(k);
        let mut lc = LinearCombination::zero();
        for (var, coeff) in self.lc.iter() {
            lc = lc + (*coeff * c, var);
        }
        W { lc, v: self.v * k }
    }
    pub fn bit(b: &Boolean, one: Variable) -> W {
        W { lc: b.lc(one, F::ONE), v: b.get_value().unwrap_or(false) as i128 }
    }
    pub fn sum<'a>(it: impl IntoIterator<Item = &'a W>) -> W {
        it.into_iter().fold(W::zero(), |a, b| a.add(b))
    }
    /// `1 - self`, for a bit.
    pub fn not<CS: ConstraintSystem<F>>(&self) -> W {
        W::konst::<CS>(1).sub(self)
    }
}

pub fn alloc<CS: ConstraintSystem<F>>(mut cs: CS, v: i128) -> Res<W> {
    let n = AllocatedNum::alloc(cs.namespace(|| "n"), || Ok(fi(v)))?;
    Ok(W::num(&n, v))
}

/// Allocate `v` as a field element and return the [`AllocatedNum`].
pub fn alloc_num<CS: ConstraintSystem<F>>(mut cs: CS, v: F) -> Res<AllocatedNum<F>> {
    AllocatedNum::alloc(cs.namespace(|| "n"), || Ok(v))
}

/// `a == b`.
pub fn enforce_eq<CS: ConstraintSystem<F>>(cs: &mut CS, name: &str, a: &W, b: &W) {
    cs.enforce(|| name.to_string(), |_| a.lc.clone() - &b.lc, |l| l + CS::one(), |l| l);
}

/// `a * b == c`.
pub fn enforce_mul<CS: ConstraintSystem<F>>(cs: &mut CS, name: &str, a: &W, b: &W, c: &W) {
    cs.enforce(|| name.to_string(), |_| a.lc.clone(), |_| b.lc.clone(), |_| c.lc.clone());
}

/// `a * b` as a fresh variable.
pub fn mul<CS: ConstraintSystem<F>>(mut cs: CS, a: &W, b: &W) -> Res<W> {
    let v = a.v.checked_mul(b.v).expect("product fits i128");
    let c = alloc(cs.namespace(|| "c"), v)?;
    enforce_mul(&mut cs, "mul", a, b, &c);
    Ok(c)
}

/// Allocate `n` bits (little-endian) of `v mod 2^n`.
pub fn alloc_bits_le<CS: ConstraintSystem<F>>(mut cs: CS, v: i128, n: usize) -> Res<Vec<Boolean>> {
    assert!(n <= 126);
    let u = v.rem_euclid(1i128 << n) as u128;
    (0..n)
        .map(|i| {
            Ok(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("b{i}")),
                Some((u >> i) & 1 == 1),
            )?))
        })
        .collect()
}

pub fn lc_bits_le<CS: ConstraintSystem<F>>(bits: &[Boolean]) -> LinearCombination<F> {
    let mut lc = LinearCombination::zero();
    let mut w = F::ONE;
    for b in bits {
        lc = lc + &b.lc(CS::one(), w);
        w = w.double();
    }
    lc
}

/// Range check `0 <= w < 2^n`; returns the little-endian bits.
pub fn range<CS: ConstraintSystem<F>>(mut cs: CS, w: &W, n: usize) -> Res<Vec<Boolean>> {
    let bits = alloc_bits_le(cs.namespace(|| "bits"), w.v, n)?;
    let lc = lc_bits_le::<CS>(&bits);
    cs.enforce(|| "pack", |_| lc - &w.lc, |l| l + CS::one(), |l| l);
    Ok(bits)
}

/// Two's-complement 64-bit decomposition of a signed `w` (`-2^63 <= w < 2^63`).
pub fn range_i64<CS: ConstraintSystem<F>>(mut cs: CS, w: &W) -> Res<Vec<Boolean>> {
    let bits = alloc_bits_le(cs.namespace(|| "bits"), w.v, 64)?;
    let mut lc = lc_bits_le::<CS>(&bits[..63]);
    lc = lc - &bits[63].lc(CS::one(), fu(1u128 << 63));
    cs.enforce(|| "pack_i64", |_| lc - &w.lc, |l| l + CS::one(), |l| l);
    Ok(bits)
}

/// A value derived as a linear combination that is published (a digest field): allocate
/// the claimed value's bits and bind them to the derivation. `claimed != w.v` is unsatisfiable.
pub fn claim_u64<CS: ConstraintSystem<F>>(cs: CS, w: &W, claimed: i128) -> Res<(W, Vec<Boolean>)> {
    let c = W { lc: w.lc.clone(), v: claimed };
    let bits = range(cs, &c, 64)?;
    Ok((W { lc: w.lc.clone(), v: claimed }, bits))
}

pub fn claim_i64<CS: ConstraintSystem<F>>(cs: CS, w: &W, claimed: i128) -> Res<(W, Vec<Boolean>)> {
    let c = W { lc: w.lc.clone(), v: claimed };
    let bits = range_i64(cs, &c)?;
    Ok((W { lc: w.lc.clone(), v: claimed }, bits))
}

/// Bit `x != 0`.
pub fn nonzero<CS: ConstraintSystem<F>>(mut cs: CS, x: &W) -> Res<W> {
    let xf = fi(x.v);
    let inv: F = Option::from(xf.invert()).unwrap_or(F::ZERO);
    let b = (x.v != 0) as i128;
    let inv_n = alloc_num(cs.namespace(|| "inv"), inv)?;
    let b_w = alloc(cs.namespace(|| "b"), b)?;
    cs.enforce(|| "x*inv=b", |_| x.lc.clone(), |l| l + inv_n.get_variable(), |_| b_w.lc.clone());
    let nb = b_w.not::<CS>();
    cs.enforce(|| "x*(1-b)=0", |_| x.lc.clone(), |_| nb.lc.clone(), |l| l);
    // inv is 0 when x is 0, so the witness is unique
    cs.enforce(|| "inv*(1-b)=0", |l| l + inv_n.get_variable(), |_| nb.lc.clone(), |l| l);
    Ok(b_w)
}

/// Bit `a <= b`, for `|b - a| < 2^n`.
pub fn le<CS: ConstraintSystem<F>>(mut cs: CS, a: &W, b: &W, n: usize) -> Res<W> {
    let t = b.sub(a).add(&W::konst::<CS>(1i128 << n));
    let bits = range(cs.namespace(|| "t"), &t, n + 1)?;
    Ok(W::bit(&bits[n], CS::one()))
}

/// `c ? a : b` with the claimed result `v` (honest: the selected value).
pub fn select<CS: ConstraintSystem<F>>(mut cs: CS, c: &W, a: &W, b: &W, v: i128) -> Res<W> {
    let m = alloc(cs.namespace(|| "m"), v)?;
    let amb = a.sub(b);
    let mmb = m.sub(b);
    enforce_mul(&mut cs, "sel", c, &amb, &mmb);
    Ok(m)
}

pub fn select_honest(c: &W, a: &W, b: &W) -> i128 {
    if c.v == 1 {
        a.v
    } else {
        b.v
    }
}

/// `min(a, b)` with claimed result `v`. Comparison width `n`.
pub fn min_claimed<CS: ConstraintSystem<F>>(mut cs: CS, a: &W, b: &W, n: usize, v: impl FnOnce(i128) -> i128) -> Res<W> {
    let c = le(cs.namespace(|| "le"), a, b, n)?;
    let honest = select_honest(&c, a, b);
    select(cs.namespace(|| "sel"), &c, a, b, v(honest))
}

/// `clearing::prorata`: split `total` over `amounts`, floors `total * a_i / sum` first,
/// then the remainder one unit at a time in order, each share capped at its amount.
/// Requires `total <= sum(amounts)` (both callers guarantee it). `tamper(i, x)` may replace
/// the remainder increment of item `i`.
pub fn prorata<CS: ConstraintSystem<F>>(
    mut cs: CS,
    total: &W,
    amounts: &[W],
    tamper: &dyn Fn(usize, i128) -> i128,
) -> Res<Vec<W>> {
    let s = W::sum(amounts);
    let nz = nonzero(cs.namespace(|| "s_nz"), &s)?;
    // s' = s, or 1 when s == 0 (then every amount is 0 and so is every share).
    let sp = s.add(&nz.not::<CS>());
    let mut qs = Vec::with_capacity(amounts.len());
    for (i, a) in amounts.iter().enumerate() {
        let mut ns = cs.namespace(|| format!("q{i}"));
        let prod = total.v.checked_mul(a.v).expect("total*amount fits i128");
        let (q, r) = (prod.div_euclid(sp.v.max(1)), prod.rem_euclid(sp.v.max(1)));
        let q_w = alloc(ns.namespace(|| "q"), q)?;
        range(ns.namespace(|| "q_rng"), &q_w, 64)?;
        let r_w = alloc(ns.namespace(|| "r"), r)?;
        range(ns.namespace(|| "r_rng"), &r_w, 72)?;
        // r < s'
        let slack = sp.sub(&W::konst::<CS>(1)).sub(&r_w);
        range(ns.namespace(|| "r_lt_s"), &slack, 72)?;
        let qsp = mul(ns.namespace(|| "q*s"), &q_w, &sp)?;
        // total * a == q * s' + r
        let rhs = qsp.add(&r_w);
        enforce_mul(&mut ns, "t*a", total, a, &rhs);
        qs.push(q_w);
    }
    let mut rest = total.sub(&W::sum(&qs));
    let mut out = Vec::with_capacity(amounts.len());
    for (i, (a, q)) in amounts.iter().zip(&qs).enumerate() {
        let mut ns = cs.namespace(|| format!("rem{i}"));
        let d = a.sub(q);
        let c = le(ns.namespace(|| "le"), &rest, &d, 72)?;
        let honest = select_honest(&c, &rest, &d);
        let x = select(ns.namespace(|| "x"), &c, &rest, &d, tamper(i, honest))?;
        rest = rest.sub(&x);
        out.push(q.add(&x));
    }
    Ok(out)
}

/// Native `clearing::prorata`, used to cross-check the gadget.
pub fn prorata_native(total: u64, amounts: &[u64]) -> Vec<u64> {
    let sum: u128 = amounts.iter().map(|&a| a as u128).sum();
    if sum == 0 || total == 0 {
        return vec![0; amounts.len()];
    }
    let mut out: Vec<u64> = amounts.iter().map(|&a| (total as u128 * a as u128 / sum) as u64).collect();
    let mut rest = total - out.iter().sum::<u64>();
    for (o, &a) in out.iter_mut().zip(amounts) {
        let x = rest.min(a - *o);
        *o += x;
        rest -= x;
    }
    out
}

// ---------------------------------------------------------------- bytes and bits

/// Bytes as constant bits, each byte most-significant bit first (the SHA-256 gadget order).
pub fn const_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|v| (0..8).rev().map(move |j| Boolean::constant((v >> j) & 1 == 1)))
        .collect()
}

pub fn alloc_bytes<CS: ConstraintSystem<F>>(mut cs: CS, bytes: &[u8]) -> Res<Vec<Boolean>> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for (i, b) in bytes.iter().enumerate() {
        for j in (0..8).rev() {
            out.push(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("y{i}_{j}")),
                Some((b >> j) & 1 == 1),
            )?));
        }
    }
    Ok(out)
}

/// Little-endian value bits -> their `to_le_bytes()` byte string in SHA bit order.
pub fn le_bits_to_bytes(bits_le: &[Boolean]) -> Vec<Boolean> {
    assert_eq!(bits_le.len() % 8, 0);
    let mut out = Vec::with_capacity(bits_le.len());
    for byte in 0..bits_le.len() / 8 {
        for k in (0..8).rev() {
            out.push(bits_le[8 * byte + k].clone());
        }
    }
    out
}

/// Linear combination of a byte string (SHA bit order) read as a little-endian integer.
pub fn lc_bytes_le<CS: ConstraintSystem<F>>(bits: &[Boolean]) -> LinearCombination<F> {
    assert_eq!(bits.len() % 8, 0);
    let mut lc = LinearCombination::zero();
    for (i, b) in bits.iter().enumerate() {
        let (byte, j) = (i / 8, i % 8);
        let weight = fu(2).pow_vartime([(8 * byte + 7 - j) as u64]);
        lc = lc + &b.lc(CS::one(), weight);
    }
    lc
}

/// Linear combination of a byte string (SHA bit order) read as a big-endian integer.
pub fn lc_bytes_be<CS: ConstraintSystem<F>>(bits: &[Boolean]) -> LinearCombination<F> {
    let mut lc = LinearCombination::zero();
    let mut w = F::ONE;
    for b in bits.iter().rev() {
        lc = lc + &b.lc(CS::one(), w);
        w = w.double();
    }
    lc
}

pub fn bits_value(bits: &[Boolean]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | b.get_value().unwrap_or(false) as u8))
        .collect()
}

/// 32-byte digest -> its two little-endian 128-bit halves (the MNR-05 `z` convention).
pub fn le_halves(d: &[u8; 32]) -> (u128, u128) {
    (
        u128::from_le_bytes(d[0..16].try_into().unwrap()),
        u128::from_le_bytes(d[16..32].try_into().unwrap()),
    )
}

/// Bind a 256-bit digest (SHA bit order) to two fresh outputs `(lo, hi)` (LE halves).
pub fn digest_to_halves<CS: ConstraintSystem<F>>(mut cs: CS, bits: &[Boolean]) -> Res<(AllocatedNum<F>, AllocatedNum<F>)> {
    assert_eq!(bits.len(), 256);
    let d: [u8; 32] = bits_value(bits).try_into().unwrap();
    let (lo, hi) = le_halves(&d);
    let lo_n = alloc_num(cs.namespace(|| "lo"), fu(lo))?;
    let hi_n = alloc_num(cs.namespace(|| "hi"), fu(hi))?;
    let l = lc_bytes_le::<CS>(&bits[..128]);
    let h = lc_bytes_le::<CS>(&bits[128..]);
    cs.enforce(|| "lo_c", |_| l - lo_n.get_variable(), |x| x + CS::one(), |x| x);
    cs.enforce(|| "hi_c", |_| h - hi_n.get_variable(), |x| x + CS::one(), |x| x);
    Ok((lo_n, hi_n))
}

/// Bind a 256-bit digest (SHA bit order) to existing `(lo, hi)` variables.
pub fn bind_halves<CS: ConstraintSystem<F>>(cs: &mut CS, name: &str, bits: &[Boolean], lo: &AllocatedNum<F>, hi: &AllocatedNum<F>) {
    let l = lc_bytes_le::<CS>(&bits[..128]);
    let h = lc_bytes_le::<CS>(&bits[128..]);
    cs.enforce(|| format!("{name}_lo"), |_| l - lo.get_variable(), |x| x + CS::one(), |x| x);
    cs.enforce(|| format!("{name}_hi"), |_| h - hi.get_variable(), |x| x + CS::one(), |x| x);
}

// ---------------------------------------------------------------- selection and SHA-256

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Src {
    Var(Variable, bool),
    Const(bool),
}

fn src(b: &Boolean) -> Src {
    match b {
        Boolean::Is(a) => Src::Var(a.get_variable(), false),
        Boolean::Not(a) => Src::Var(a.get_variable(), true),
        Boolean::Constant(c) => Src::Const(*c),
    }
}

/// Bitwise selection among candidate bit strings by one-hot selectors (the caller enforces
/// that exactly one selector is 1). Shorter candidates read as zero-padded. Positions where
/// every candidate carries the same source cost nothing; otherwise one constraint per
/// distinct non-constant source. The output equals the selected candidate bit, so it is
/// boolean without a booleanity constraint.
pub fn mux_bits<CS: ConstraintSystem<F>>(mut cs: CS, sels: &[W], cands: &[Vec<Boolean>]) -> Res<Vec<Boolean>> {
    assert_eq!(sels.len(), cands.len());
    let len = cands.iter().map(|c| c.len()).max().unwrap_or(0);
    let active = sels.iter().position(|s| s.v == 1);
    let f = Boolean::constant(false);
    let mut out = Vec::with_capacity(len);
    for p in 0..len {
        // groups: (source, a representative boolean, summed selector, number of candidates)
        let mut groups: Vec<(Src, Boolean, W, usize)> = Vec::new();
        for (sel, cand) in sels.iter().zip(cands) {
            let b = cand.get(p).unwrap_or(&f);
            let s = src(b);
            match groups.iter_mut().find(|g| g.0 == s) {
                Some(g) => {
                    g.2 = g.2.add(sel);
                    g.3 += 1;
                }
                None => groups.push((s, b.clone(), sel.clone(), 1)),
            }
        }
        if groups.len() == 1 {
            out.push(groups[0].1.clone());
            continue;
        }
        let value = active.map(|a| cands[a].get(p).unwrap_or(&f).get_value().unwrap_or(false)).unwrap_or(false);
        let mut ns = cs.namespace(|| format!("p{p}"));
        let o = AllocatedNum::alloc(ns.namespace(|| "o"), || Ok(if value { F::ONE } else { F::ZERO }))?;
        let vars: Vec<&(Src, Boolean, W, usize)> = groups.iter().filter(|g| matches!(g.0, Src::Var(..))).collect();
        let mut rhs = LinearCombination::zero() + o.get_variable();
        for g in groups.iter().filter(|g| g.0 == Src::Const(true)) {
            rhs = rhs - &g.2.lc;
        }
        if vars.is_empty() {
            ns.enforce(|| "const", |_| rhs, |l| l + CS::one(), |l| l);
        } else {
            for (k, g) in vars.iter().enumerate() {
                let src_lc = g.1.lc(CS::one(), F::ONE);
                if k + 1 == vars.len() {
                    ns.enforce(|| "last", |_| g.2.lc.clone(), |_| src_lc, |_| rhs.clone());
                } else {
                    let tv = g.2.v * g.1.get_value().unwrap_or(false) as i128;
                    let t = alloc(ns.namespace(|| format!("t{k}")), tv)?;
                    ns.enforce(|| format!("tc{k}"), |_| g.2.lc.clone(), |_| src_lc, |_| t.lc.clone());
                    rhs = rhs - &t.lc;
                }
            }
        }
        out.push(Boolean::Is(AllocatedBit::from_parts_unchecked(o.get_variable(), Some(value))));
    }
    Ok(out)
}

/// SHA-256 padding bits for a message of `total_bytes` bytes.
pub fn pad_bits(total_bytes: usize) -> Vec<Boolean> {
    let mut pad = vec![0x80u8];
    while (total_bytes + pad.len() + 8) % 64 != 0 {
        pad.push(0);
    }
    pad.extend(((total_bytes as u64) * 8).to_be_bytes());
    const_bits(&pad)
}

/// SHA-256 state after hashing `prefix` (a multiple of 64 bytes) natively.
pub fn midstate(prefix: &[u8]) -> [u32; 8] {
    assert_eq!(prefix.len() % 64, 0);
    let mut st = SHA256_IV;
    for block in prefix.chunks(64) {
        sha2::compress256(&mut st, &[*GenericArray::from_slice(block)]);
    }
    st
}

/// The state after each 512-bit block, as big-endian digest bits.
pub fn sha_blocks<CS: ConstraintSystem<F>>(mut cs: CS, iv: &[u32; 8], bits: &[Boolean]) -> Res<Vec<Vec<Boolean>>> {
    assert_eq!(bits.len() % 512, 0);
    let mut cur: Vec<UInt32> = iv.iter().map(|&v| UInt32::constant(v)).collect();
    let mut states = Vec::new();
    for (i, block) in bits.chunks(512).enumerate() {
        cur = sha256_compression_function(cs.namespace(|| format!("blk{i}")), block, &cur)?;
        states.push(cur.iter().cloned().flat_map(|u| u.into_bits_be()).collect());
    }
    Ok(states)
}

/// SHA-256 of `prefix || msg` where `prefix` (`prefix_bytes` long, already absorbed into
/// `iv`) is fixed and `msg` is one of several candidates of different lengths, chosen by
/// one-hot selectors. Pads each candidate for its own length, hashes the selected padded
/// string over the longest block count, and returns the state after the selected
/// candidate's last block.
pub fn sha256_var<CS: ConstraintSystem<F>>(
    mut cs: CS,
    iv: &[u32; 8],
    prefix_bytes: usize,
    configs: &[(W, Vec<Boolean>)],
) -> Res<Vec<Boolean>> {
    let mut padded = Vec::with_capacity(configs.len());
    let mut blocks = Vec::with_capacity(configs.len());
    for (_, m) in configs {
        assert_eq!(m.len() % 8, 0);
        let mut p = m.clone();
        p.extend(pad_bits(prefix_bytes + m.len() / 8));
        blocks.push(p.len() / 512);
        padded.push(p);
    }
    let nb = *blocks.iter().max().unwrap();
    let sels: Vec<W> = configs.iter().map(|c| c.0.clone()).collect();
    let mut msg = mux_bits(cs.namespace(|| "pad_mux"), &sels, &padded)?;
    msg.resize(nb * 512, Boolean::constant(false));
    let states = sha_blocks(cs.namespace(|| "sha"), iv, &msg)?;
    let mut counts: Vec<usize> = blocks.clone();
    counts.sort_unstable();
    counts.dedup();
    let group_sels: Vec<W> = counts
        .iter()
        .map(|&n| W::sum(configs.iter().zip(&blocks).filter(|(_, &b)| b == n).map(|(c, _)| &c.0)))
        .collect();
    let group_states: Vec<Vec<Boolean>> = counts.iter().map(|&n| states[n - 1].clone()).collect();
    mux_bits(cs.namespace(|| "out_mux"), &group_sels, &group_states)
}

/// Plain SHA-256 of a fixed-length bit string (wrapper over the library gadget).
pub fn sha256_fixed<CS: ConstraintSystem<F>>(cs: CS, bits: &[Boolean]) -> Res<Vec<Boolean>> {
    nova_snark::frontend::gadgets::sha256::sha256(cs, bits)
}

/// One-hot bits `e[0..n]` with `sum(e) == 1` and `sum(i * e[i]) == x`.
pub fn one_hot<CS: ConstraintSystem<F>>(mut cs: CS, x: &W, n: usize) -> Res<Vec<W>> {
    let mut e = Vec::with_capacity(n);
    for i in 0..n {
        let b = AllocatedBit::alloc(cs.namespace(|| format!("e{i}")), Some(x.v == i as i128))?;
        e.push(W::bit(&Boolean::from(b), CS::one()));
    }
    let total = W::sum(&e);
    enforce_eq(&mut cs, "sum1", &total, &W::konst::<CS>(1));
    let idx = W::sum(&e.iter().enumerate().map(|(i, b)| b.scale(i as i128)).collect::<Vec<_>>());
    enforce_eq(&mut cs, "idx", &idx, x);
    Ok(e)
}

/// Allocate a bit.
pub fn alloc_bit<CS: ConstraintSystem<F>>(mut cs: CS, v: bool) -> Res<W> {
    let b = AllocatedBit::alloc(cs.namespace(|| "bit"), Some(v))?;
    Ok(W::bit(&Boolean::from(b), CS::one()))
}

pub fn sha256_native(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let t = sha256_native(tag);
    let mut b = Vec::with_capacity(64 + msg.len());
    b.extend_from_slice(&t);
    b.extend_from_slice(&t);
    b.extend_from_slice(msg);
    sha256_native(&b)
}
