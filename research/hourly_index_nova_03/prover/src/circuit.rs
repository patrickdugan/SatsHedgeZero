//! Generic R1CS circuits for `SHZ-INDEX-03`:
//! 1. [`HourStepGeneric<F>`] (`shz/hourly-index-checkpoint-nova/v1`, arity 8):
//!    Exact `INDEX-02` checkpoint relation instantiated over ANY `PrimeFieldBits` scalar field
//!    (`PallasEngine` for Route A and `Bn256EngineIPA` for Route B/C) against the exact
//!    `INDEX-01` checkpoint root `c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5`.
//! 2. [`SourceBoundHourStep<F>`] (`shz/hourly-index-source-bound-nova/v2`, arity 10):
//!    Extends `INDEX-02` with an authenticated 8-hour source-candidate hash chain (`source_acc32`)
//!    and bidirectional `VALID` vs `HOLD` necessity constraints over the EXACT SAME allocated leaf
//!    wires so a malicious prover CANNOT fabricate `HOLD` when valid in-spread source candidates
//!    exist — even if recomputing the checkpoint root.
#![forbid(unsafe_code)]

use std::marker::PhantomData;

use ff::{PrimeField, PrimeFieldBits};
use nova_snark::frontend::gadgets::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    sha256::sha256,
};
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sources::{source_candidate_leaf_bytes, AuthenticatedHourSourceBundle};

pub const RELATION_V1: &str = "shz/hourly-index-checkpoint-nova/v1";
pub const RELATION_V2_SOURCE_BOUND: &str = "shz/hourly-index-source-bound-nova/v2";
pub const ARITY_V1: usize = 8;
pub const ARITY_V2: usize = 10;

pub const LEAF_DOMAIN: &[u8] = b"SHZ/HOUR/LEAF/V1";
pub const NODE_DOMAIN: &[u8] = b"SHZ/HOUR/NODE/V1";
pub const ROOT_DOMAIN: &[u8] = b"SHZ/8H/ROOT/V1";
pub const SOURCE_ACC_DOMAIN: &[u8] = b"SHZ/SOURCE/ACC/V1";

pub const MAX_PRICE: i128 = 10_000_000_000_000_000;
pub const HOUR_US: i128 = 3_600_000_000;
pub const MAX_AGE: i128 = 300_000_000;
pub const MAX_SKEW: i128 = 60_000_000;

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn f_from_le_bytes<F: PrimeField>(bytes: &[u8]) -> F {
    bytes
        .iter()
        .rev()
        .fold(F::ZERO, |acc, b| acc * F::from(256) + F::from(u64::from(*b)))
}

pub fn parse_canonical_u64(s: &str) -> Result<u64, String> {
    let v = s.parse::<u64>().map_err(|_| "invalid u64")?;
    if v.to_string() != s {
        return Err("noncanonical u64".into());
    }
    Ok(v)
}

pub fn parse_canonical_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err("noncanonical digest".into());
    }
    hex::decode(s)
        .map_err(|_| "digest hex")?
        .try_into()
        .map_err(|_| "digest length".into())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimV1 {
    pub genesis: String,
    pub policy_hash: String,
    pub start_hour: String,
    pub checkpoint_root: String,
}

impl ClaimV1 {
    pub fn state<F: PrimeField>(&self, count: u64) -> Result<Vec<F>, String> {
        let start = parse_canonical_u64(&self.start_hour)?;
        if start % 8 != 0 || start > 999_999_992 || (count != 0 && count != 8) {
            return Err("invalid public checkpoint range".into());
        }
        let mut out = vec![F::from(count), F::from(start)];
        for h in [&self.genesis, &self.policy_hash, &self.checkpoint_root] {
            let b = parse_canonical_hex32(h)?;
            out.push(f_from_le_bytes(&b[..16]));
            out.push(f_from_le_bytes(&b[16..]));
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimV2SourceBound {
    pub genesis: String,
    pub policy_hash: String,
    pub start_hour: String,
    pub checkpoint_root: String,
    pub source_accumulator_root: String,
}

impl ClaimV2SourceBound {
    pub fn state<F: PrimeField>(&self, count: u64) -> Result<Vec<F>, String> {
        let mut out = ClaimV1 {
            genesis: self.genesis.clone(),
            policy_hash: self.policy_hash.clone(),
            start_hour: self.start_hour.clone(),
            checkpoint_root: self.checkpoint_root.clone(),
        }
        .state::<F>(count)?;
        if count == 0 {
            out.push(F::ZERO);
            out.push(F::ZERO);
        } else {
            let acc = parse_canonical_hex32(&self.source_accumulator_root)?;
            out.push(f_from_le_bytes(&acc[..16]));
            out.push(f_from_le_bytes(&acc[16..]));
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordJson {
    pub genesis: String,
    pub policy_hash: String,
    pub hour_id: String,
    pub status: u8,
    pub hold_reason: u8,
    pub pyth_price_e8: String,
    pub chainlink_price_e8: String,
    pub index_price_e8: String,
    pub pyth_publish_us: String,
    pub chainlink_publish_us: String,
    pub pyth_report_hash: String,
    pub chainlink_report_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CheckpointJson {
    pub genesis: String,
    pub policy_hash: String,
    pub start_hour: String,
    pub checkpoint_root: String,
    pub inclusion: Vec<InclusionJson>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InclusionJson {
    pub hour_id: String,
    pub siblings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FixtureJson {
    pub records: Vec<RecordJson>,
    pub checkpoint: CheckpointJson,
}

#[derive(Clone, Debug)]
pub struct HourStepData {
    pub position: u8,
    pub start: u64,
    pub genesis: [u8; 32],
    pub policy: [u8; 32],
    pub hour: u64,
    pub status: u8,
    pub reason: u8,
    pub p: u64,
    pub c: u64,
    pub index: u64,
    pub pt: u64,
    pub ct: u64,
    pub p_hash: [u8; 32],
    pub c_hash: [u8; 32],
    pub siblings: [[u8; 32]; 3],
}

impl HourStepData {
    pub fn from_record(
        r: &RecordJson,
        start: u64,
        position: u8,
        siblings: &[String],
    ) -> Result<Self, String> {
        if siblings.len() != 3 {
            return Err("expected three siblings".into());
        }
        Ok(Self {
            position,
            start,
            genesis: parse_canonical_hex32(&r.genesis)?,
            policy: parse_canonical_hex32(&r.policy_hash)?,
            hour: parse_canonical_u64(&r.hour_id)?,
            status: r.status,
            reason: r.hold_reason,
            p: parse_canonical_u64(&r.pyth_price_e8)?,
            c: parse_canonical_u64(&r.chainlink_price_e8)?,
            index: parse_canonical_u64(&r.index_price_e8)?,
            pt: parse_canonical_u64(&r.pyth_publish_us)?,
            ct: parse_canonical_u64(&r.chainlink_publish_us)?,
            p_hash: parse_canonical_hex32(&r.pyth_report_hash)?,
            c_hash: parse_canonical_hex32(&r.chainlink_report_hash)?,
            siblings: [
                parse_canonical_hex32(&siblings[0])?,
                parse_canonical_hex32(&siblings[1])?,
                parse_canonical_hex32(&siblings[2])?,
            ],
        })
    }

    pub fn leaf_bytes(&self) -> Vec<u8> {
        let mut b = LEAF_DOMAIN.to_vec();
        b.extend(self.genesis);
        b.extend(self.policy);
        b.extend(self.hour.to_le_bytes());
        b.extend([self.status, self.reason]);
        for v in [self.p, self.c, self.index, self.pt, self.ct] {
            b.extend(v.to_le_bytes());
        }
        b.extend(self.p_hash);
        b.extend(self.c_hash);
        b
    }

    pub fn native_root(&self) -> [u8; 32] {
        let mut d = sha256_bytes(&self.leaf_bytes());
        for (i, s) in self.siblings.iter().enumerate() {
            let mut b = NODE_DOMAIN.to_vec();
            if (self.position >> i) & 1 == 0 {
                b.extend(d);
                b.extend(s);
            } else {
                b.extend(s);
                b.extend(d);
            }
            d = sha256_bytes(&b);
        }
        let mut b = ROOT_DOMAIN.to_vec();
        b.extend(self.genesis);
        b.extend(self.policy);
        b.extend(self.start.to_le_bytes());
        b.extend(d);
        sha256_bytes(&b)
    }
}

impl FixtureJson {
    pub fn claim_v1(&self) -> ClaimV1 {
        ClaimV1 {
            genesis: self.checkpoint.genesis.clone(),
            policy_hash: self.checkpoint.policy_hash.clone(),
            start_hour: self.checkpoint.start_hour.clone(),
            checkpoint_root: self.checkpoint.checkpoint_root.clone(),
        }
    }

    pub fn steps_data(&self) -> Result<Vec<HourStepData>, String> {
        if self.records.len() != 8 || self.checkpoint.inclusion.len() != 8 {
            return Err("exactly eight hourly openings required".into());
        }
        let start = parse_canonical_u64(&self.checkpoint.start_hour)?;
        self.records
            .iter()
            .zip(&self.checkpoint.inclusion)
            .enumerate()
            .map(|(i, (r, p))| {
                if p.hour_id != r.hour_id {
                    return Err("path hour differs".into());
                }
                HourStepData::from_record(r, start, i as u8, &p.siblings)
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct HourStepGeneric<F: PrimeField> {
    pub data: HourStepData,
    pub _marker: PhantomData<F>,
}

impl<F: PrimeField> HourStepGeneric<F> {
    pub fn new(data: HourStepData) -> Self {
        Self {
            data,
            _marker: PhantomData,
        }
    }
}

fn constant_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|v| (0..8).rev().map(move |j| Boolean::constant((v >> j) & 1 != 0)))
        .collect()
}

fn alloc_bytes_bits<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    bytes: &[u8],
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for (i, b) in bytes.iter().enumerate() {
        for j in (0..8).rev() {
            out.push(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("byte {i} bit {j}")),
                Some((b >> j) & 1 != 0),
            )?));
        }
    }
    Ok(out)
}

fn le_lc<F: PrimeField, CS: ConstraintSystem<F>>(b: &[Boolean]) -> LinearCombination<F> {
    assert_eq!(b.len() % 8, 0);
    let mut out = LinearCombination::zero();
    let mut weight = F::ONE;
    for byte in b.chunks_exact(8) {
        for x in byte.iter().rev() {
            out = out + &x.lc(CS::one(), weight);
            weight = weight.double();
        }
    }
    out
}

fn bit_sum<F: PrimeField, CS: ConstraintSystem<F>>(b: &[Boolean]) -> LinearCombination<F> {
    b.iter()
        .fold(LinearCombination::zero(), |lc, x| lc + &x.lc(CS::one(), F::ONE))
}

fn bind_le<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    label: &str,
    b: &[Boolean],
    n: &AllocatedNum<F>,
) {
    cs.enforce(
        || label.to_owned(),
        |_| le_lc::<F, CS>(b),
        |lc| lc + CS::one(),
        |lc| lc + n.get_variable(),
    );
}

fn eq_lc<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    label: &str,
    l: LinearCombination<F>,
    r: LinearCombination<F>,
) {
    cs.enforce(|| label.to_owned(), |_| l, |lc| lc + CS::one(), |_| r);
}

fn zero_if<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    label: &str,
    gate: &Boolean,
    v: LinearCombination<F>,
) {
    cs.enforce(|| label.to_owned(), |_| gate.lc(CS::one(), F::ONE), |_| v, |lc| lc);
}

fn slack<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    label: &str,
    gate: &Boolean,
    expr: LinearCombination<F>,
    value: i128,
    width: usize,
) -> Result<(), SynthesisError> {
    let mut ns = cs.namespace(|| label.to_owned());
    let witness = if gate.get_value() == Some(true) && value >= 0 {
        value as u128
    } else {
        0
    };
    let mut rhs = LinearCombination::zero();
    let mut w = F::ONE;
    for i in 0..width {
        let bit = Boolean::from(AllocatedBit::alloc(
            ns.namespace(|| format!("slack bit {i}")),
            Some((witness >> i) & 1 != 0),
        )?);
        rhs = rhs + &bit.lc(CS::one(), w);
        w = w.double();
    }
    ns.enforce(
        || "bounded gated difference",
        |_| gate.lc(CS::one(), F::ONE),
        |_| expr,
        |_| rhs,
    );
    Ok(())
}

fn pick_bits<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    selector: &Boolean,
    a: &[Boolean],
    b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    a.iter()
        .zip(b)
        .enumerate()
        .map(|(i, (x, y))| {
            let v = if selector.get_value() == Some(true) {
                y.get_value()
            } else {
                x.get_value()
            };
            let mut ns = cs.namespace(|| format!("select {i}"));
            let o = Boolean::from(AllocatedBit::alloc(ns.namespace(|| "result"), v)?);
            ns.enforce(
                || "conditional select",
                |_| selector.lc(CS::one(), F::ONE),
                |_| y.lc(CS::one(), F::ONE) - &x.lc(CS::one(), F::ONE),
                |_| o.lc(CS::one(), F::ONE) - &x.lc(CS::one(), F::ONE),
            );
            Ok(o)
        })
        .collect()
}

fn one_lc<F: PrimeField, CS: ConstraintSystem<F>>() -> LinearCombination<F> {
    LinearCombination::zero() + CS::one()
}

fn scaled_lc<F: PrimeField, CS: ConstraintSystem<F>>(
    b: &[Boolean],
    coefficient: i64,
) -> LinearCombination<F> {
    let mut out = LinearCombination::zero();
    let mut w = F::from(coefficient.unsigned_abs());
    if coefficient < 0 {
        w = -w;
    }
    for byte in b.chunks_exact(8) {
        for x in byte.iter().rev() {
            out = out + &x.lc(CS::one(), w);
            w = w.double();
        }
    }
    out
}

struct AllocatedLeafWires<F: PrimeField> {
    next_z_v1: Vec<AllocatedNum<F>>,
    hour: Vec<Boolean>,
    valid: Boolean,
    reason: Vec<Boolean>,
    p: Vec<Boolean>,
    c: Vec<Boolean>,
    pt: Vec<Boolean>,
    ct: Vec<Boolean>,
    ph: Vec<Boolean>,
    ch: Vec<Boolean>,
}

fn synthesize_base_with_wires<F: PrimeField, CS: ConstraintSystem<F>>(
    d: &HourStepData,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
) -> Result<AllocatedLeafWires<F>, SynthesisError> {
    assert_eq!(z.len(), ARITY_V1);
    let pos = alloc_bytes_bits(cs.namespace(|| "position"), &[d.position])?;
    bind_le(cs, "position equals fold count", &pos, &z[0]);
    eq_lc(
        cs,
        "position fits three bits",
        bit_sum::<F, CS>(&pos[..5]),
        LinearCombination::zero(),
    );

    let start = alloc_bytes_bits(cs.namespace(|| "start"), &d.start.to_le_bytes())?;
    bind_le(cs, "start is public", &start, &z[1]);
    eq_lc(
        cs,
        "eight hour alignment",
        bit_sum::<F, CS>(&start[5..8]),
        LinearCombination::zero(),
    );
    slack(
        cs,
        "bounded start",
        &Boolean::constant(true),
        LinearCombination::zero() + (F::from(999_999_992), CS::one()) - &le_lc::<F, CS>(&start),
        999_999_992 - i128::from(d.start),
        30,
    )?;

    let genesis = alloc_bytes_bits(cs.namespace(|| "genesis"), &d.genesis)?;
    let policy = alloc_bytes_bits(cs.namespace(|| "policy"), &d.policy)?;
    for (i, b) in [genesis.as_slice(), policy.as_slice()].into_iter().enumerate() {
        bind_le(cs, &format!("public header {i} low"), &b[..128], &z[2 + i * 2]);
        bind_le(cs, &format!("public header {i} high"), &b[128..], &z[3 + i * 2]);
    }

    let hour = alloc_bytes_bits(cs.namespace(|| "hour"), &d.hour.to_le_bytes())?;
    eq_lc(
        cs,
        "consecutive UTC hour",
        le_lc::<F, CS>(&hour),
        le_lc::<F, CS>(&start) + &le_lc::<F, CS>(&pos),
    );

    let status = alloc_bytes_bits(cs.namespace(|| "status"), &[d.status])?;
    let reason = alloc_bytes_bits(cs.namespace(|| "reason"), &[d.reason])?;
    let valid = Boolean::from(AllocatedBit::alloc(
        cs.namespace(|| "valid status flag"),
        Some(d.status == 1),
    )?);
    let hold = valid.not();
    eq_lc(
        cs,
        "exact status encoding",
        le_lc::<F, CS>(&status) + &valid.lc(CS::one(), F::ONE),
        LinearCombination::zero() + (F::from(2), CS::one()),
    );
    zero_if(cs, "valid reason zero", &valid, le_lc::<F, CS>(&reason));
    eq_lc(
        cs,
        "reason fits two bits",
        bit_sum::<F, CS>(&reason[..6]),
        LinearCombination::zero(),
    );
    slack(
        cs,
        "hold reason nonzero",
        &hold,
        le_lc::<F, CS>(&reason) - &one_lc::<F, CS>(),
        i128::from(d.reason) - 1,
        2,
    )?;

    let p = alloc_bytes_bits(cs.namespace(|| "pyth"), &d.p.to_le_bytes())?;
    let c = alloc_bytes_bits(cs.namespace(|| "chainlink"), &d.c.to_le_bytes())?;
    let index = alloc_bytes_bits(cs.namespace(|| "index"), &d.index.to_le_bytes())?;
    let pt = alloc_bytes_bits(cs.namespace(|| "pyth time"), &d.pt.to_le_bytes())?;
    let ct = alloc_bytes_bits(cs.namespace(|| "chainlink time"), &d.ct.to_le_bytes())?;
    let ph = alloc_bytes_bits(cs.namespace(|| "pyth report"), &d.p_hash)?;
    let ch = alloc_bytes_bits(cs.namespace(|| "chainlink report"), &d.c_hash)?;

    for (i, (b, v)) in [(&p, d.p), (&c, d.c), (&index, d.index)].into_iter().enumerate() {
        slack(
            cs,
            &format!("positive price {i}"),
            &valid,
            le_lc::<F, CS>(b) - &one_lc::<F, CS>(),
            i128::from(v) - 1,
            54,
        )?;
        slack(
            cs,
            &format!("bounded price {i}"),
            &valid,
            LinearCombination::zero() + (F::from(MAX_PRICE as u64), CS::one()) - &le_lc::<F, CS>(b),
            MAX_PRICE - i128::from(v),
            54,
        )?;
    }
    for (i, b) in [&p, &c, &index, &pt, &ct].into_iter().enumerate() {
        zero_if(cs, &format!("hold value {i}"), &hold, le_lc::<F, CS>(b));
    }
    for (i, (b, h)) in [(&ph, &d.p_hash), (&ch, &d.c_hash)].into_iter().enumerate() {
        zero_if(cs, &format!("hold digest {i}"), &hold, bit_sum::<F, CS>(b));
        slack(
            cs,
            &format!("nonzero report {i}"),
            &valid,
            bit_sum::<F, CS>(b) - &one_lc::<F, CS>(),
            i128::from(h.iter().map(|v| v.count_ones()).sum::<u32>()) - 1,
            8,
        )?;
    }

    let pv = i128::from(d.p);
    let cv = i128::from(d.c);
    let iv = i128::from(d.index);
    slack(
        cs,
        "midpoint floor",
        &Boolean::constant(true),
        le_lc::<F, CS>(&p) + &le_lc::<F, CS>(&c) + &scaled_lc::<F, CS>(&index, -2),
        pv + cv - 2 * iv,
        1,
    )?;
    slack(
        cs,
        "spread p-c",
        &valid,
        scaled_lc::<F, CS>(&p, -19_950) + &scaled_lc::<F, CS>(&c, 20_050),
        50 * (pv + cv) - 20_000 * (pv - cv),
        80,
    )?;
    slack(
        cs,
        "spread c-p",
        &valid,
        scaled_lc::<F, CS>(&c, -19_950) + &scaled_lc::<F, CS>(&p, 20_050),
        50 * (pv + cv) - 20_000 * (cv - pv),
        80,
    )?;

    let cutoff = (i128::from(d.hour) + 1) * HOUR_US;
    for (i, (t, v)) in [(&pt, d.pt), (&ct, d.ct)].into_iter().enumerate() {
        let diff = scaled_lc::<F, CS>(&hour, HOUR_US as i64)
            + (F::from(HOUR_US as u64), CS::one())
            - &le_lc::<F, CS>(t);
        slack(
            cs,
            &format!("nonfuture source {i}"),
            &valid,
            diff,
            cutoff - i128::from(v),
            64,
        )?;
        slack(
            cs,
            &format!("fresh source {i}"),
            &valid,
            le_lc::<F, CS>(t)
                + &scaled_lc::<F, CS>(&hour, -(HOUR_US as i64))
                + (-F::from((HOUR_US - MAX_AGE) as u64), CS::one()),
            i128::from(v) + MAX_AGE - cutoff,
            64,
        )?;
    }
    for (i, (a, b, va, vb)) in [(&pt, &ct, d.pt, d.ct), (&ct, &pt, d.ct, d.pt)]
        .into_iter()
        .enumerate()
    {
        slack(
            cs,
            &format!("source skew {i}"),
            &valid,
            le_lc::<F, CS>(a) - &le_lc::<F, CS>(b) + (F::from(MAX_SKEW as u64), CS::one()),
            i128::from(va) - i128::from(vb) + MAX_SKEW,
            64,
        )?;
    }

    let mut leaf = constant_bits(LEAF_DOMAIN);
    for b in [
        &genesis, &policy, &hour, &status, &reason, &p, &c, &index, &pt, &ct, &ph, &ch,
    ] {
        leaf.extend(b.iter().cloned());
    }
    let mut digest = sha256(cs.namespace(|| "exact leaf sha256"), &leaf)?;
    for i in 0..3 {
        let s = alloc_bytes_bits(cs.namespace(|| format!("sibling {i}")), &d.siblings[i])?;
        let selector = &pos[7 - i];
        let l = pick_bits(cs.namespace(|| format!("left {i}")), selector, &digest, &s)?;
        let r = pick_bits(cs.namespace(|| format!("right {i}")), selector, &s, &digest)?;
        let mut data = constant_bits(NODE_DOMAIN);
        data.extend(l);
        data.extend(r);
        digest = sha256(cs.namespace(|| format!("node sha256 {i}")), &data)?;
    }
    let mut root = constant_bits(ROOT_DOMAIN);
    root.extend(genesis);
    root.extend(policy);
    root.extend(start);
    root.extend(digest);
    let root = sha256(cs.namespace(|| "exact checkpoint sha256"), &root)?;
    bind_le(cs, "checkpoint low", &root[..128], &z[6]);
    bind_le(cs, "checkpoint high", &root[128..], &z[7]);

    let count = AllocatedNum::alloc_infallible(cs.namespace(|| "next count"), || {
        F::from(u64::from(d.position) + 1)
    });
    eq_lc(
        cs,
        "literal next count",
        LinearCombination::zero() + z[0].get_variable() + CS::one(),
        LinearCombination::zero() + count.get_variable(),
    );
    let mut next_z_v1 = vec![count];
    next_z_v1.extend_from_slice(&z[1..]);

    Ok(AllocatedLeafWires {
        next_z_v1,
        hour,
        valid,
        reason,
        p,
        c,
        pt,
        ct,
        ph,
        ch,
    })
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for HourStepGeneric<F> {
    fn arity(&self) -> usize {
        ARITY_V1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        Ok(synthesize_base_with_wires(&self.data, cs, z)?.next_z_v1)
    }
}

/// Source-candidate witness bound into each hourly transition of [`SourceBoundHourStep`].
#[derive(Clone, Debug)]
pub struct SourceCandidateWitness {
    pub prev_acc: [u8; 32],
    pub pyth_present: bool,
    pub chainlink_present: bool,
    pub cand_p: u64,
    pub cand_c: u64,
    pub cand_pt: u64,
    pub cand_ct: u64,
    pub cand_p_hash: [u8; 32],
    pub cand_c_hash: [u8; 32],
}

impl SourceCandidateWitness {
    pub fn next_accumulator(&self, hour_id: u64) -> [u8; 32] {
        let cand_bytes = source_candidate_leaf_bytes(
            hour_id,
            self.pyth_present,
            self.chainlink_present,
            self.cand_p,
            self.cand_c,
            self.cand_pt,
            self.cand_ct,
            &self.cand_p_hash,
            &self.cand_c_hash,
        );
        let mut pre = Vec::with_capacity(SOURCE_ACC_DOMAIN.len() + 32 + cand_bytes.len());
        pre.extend_from_slice(SOURCE_ACC_DOMAIN);
        pre.extend_from_slice(&self.prev_acc);
        pre.extend_from_slice(&cand_bytes);
        sha256_bytes(&pre)
    }
}

pub fn compute_source_accumulator_chain(
    bundles: &[AuthenticatedHourSourceBundle],
) -> ([u8; 32], Vec<SourceCandidateWitness>) {
    assert_eq!(bundles.len(), 8);
    let mut acc = [0u8; 32];
    let mut witnesses = Vec::with_capacity(8);
    for b in bundles {
        let w = SourceCandidateWitness {
            prev_acc: acc,
            pyth_present: b.pyth_present,
            chainlink_present: b.chainlink_present,
            cand_p: b.candidate_pyth_price_e8,
            cand_c: b.candidate_chainlink_price_e8,
            cand_pt: b.candidate_pyth_publish_us,
            cand_ct: b.candidate_chainlink_publish_us,
            cand_p_hash: parse_canonical_hex32(&b.candidate_pyth_report_sha256_hex).unwrap(),
            cand_c_hash: parse_canonical_hex32(&b.candidate_chainlink_report_sha256_hex).unwrap(),
        };
        acc = w.next_accumulator(b.hour_id);
        witnesses.push(w);
    }
    (acc, witnesses)
}

#[derive(Clone, Debug)]
pub struct SourceBoundHourStep<F: PrimeField> {
    pub data: HourStepData,
    pub cand: SourceCandidateWitness,
    pub _marker: PhantomData<F>,
}

impl<F: PrimeField> SourceBoundHourStep<F> {
    pub fn new(data: HourStepData, cand: SourceCandidateWitness) -> Self {
        Self {
            data,
            cand,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for SourceBoundHourStep<F> {
    fn arity(&self) -> usize {
        ARITY_V2
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(z.len(), ARITY_V2);
        // 1. Run exact INDEX-02 leaf + Merkle + checkpoint_root constraints and retain exact leaf wires!
        let wires = synthesize_base_with_wires(&self.data, &mut cs.namespace(|| "index02_base"), &z[0..8])?;
        let d = &self.data;
        let cand = &self.cand;

        // 2. Bind prev_acc to z[8..10] and allocate source-candidate wires
        let prev_acc = alloc_bytes_bits(cs.namespace(|| "prev_acc"), &cand.prev_acc)?;
        bind_le(cs, "prev_acc low", &prev_acc[..128], &z[8]);
        bind_le(cs, "prev_acc high", &prev_acc[128..], &z[9]);

        let p_pres_byte =
            alloc_bytes_bits(cs.namespace(|| "cand_p_pres"), &[u8::from(cand.pyth_present)])?;
        let c_pres_byte = alloc_bytes_bits(
            cs.namespace(|| "cand_c_pres"),
            &[u8::from(cand.chainlink_present)],
        )?;
        eq_lc(
            cs,
            "p_pres boolean byte",
            bit_sum::<F, CS>(&p_pres_byte[..7]),
            LinearCombination::zero(),
        );
        eq_lc(
            cs,
            "c_pres boolean byte",
            bit_sum::<F, CS>(&c_pres_byte[..7]),
            LinearCombination::zero(),
        );
        let p_pres = &p_pres_byte[7];
        let c_pres = &c_pres_byte[7];

        let both_pres = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "both_sources_present"),
            Some(cand.pyth_present && cand.chainlink_present),
        )?);
        cs.enforce(
            || "both_pres = p_pres * c_pres",
            |_| p_pres.lc(CS::one(), F::ONE),
            |_| c_pres.lc(CS::one(), F::ONE),
            |_| both_pres.lc(CS::one(), F::ONE),
        );

        let cp = alloc_bytes_bits(cs.namespace(|| "cand_p"), &cand.cand_p.to_le_bytes())?;
        let cc = alloc_bytes_bits(cs.namespace(|| "cand_c"), &cand.cand_c.to_le_bytes())?;
        let cpt = alloc_bytes_bits(cs.namespace(|| "cand_pt"), &cand.cand_pt.to_le_bytes())?;
        let cct = alloc_bytes_bits(cs.namespace(|| "cand_ct"), &cand.cand_ct.to_le_bytes())?;
        let cph = alloc_bytes_bits(cs.namespace(|| "cand_ph"), &cand.cand_p_hash)?;
        let cch = alloc_bytes_bits(cs.namespace(|| "cand_ch"), &cand.cand_c_hash)?;

        // 3. Mode partition bound directly to `wires.valid` and `wires.reason` (ZERO duplicate wires!)
        let is_r1 = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_r1"),
            Some(d.status == 2 && d.reason == 1),
        )?);
        let is_r2 = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_r2"),
            Some(d.status == 2 && d.reason == 2),
        )?);
        let is_r3 = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_r3"),
            Some(d.status == 2 && d.reason == 3),
        )?);
        eq_lc(
            cs,
            "mode partition",
            wires.valid.lc(CS::one(), F::ONE)
                + &is_r1.lc(CS::one(), F::ONE)
                + &is_r2.lc(CS::one(), F::ONE)
                + &is_r3.lc(CS::one(), F::ONE),
            one_lc::<F, CS>(),
        );
        eq_lc(
            cs,
            "reason bound to mode",
            le_lc::<F, CS>(&wires.reason),
            is_r1.lc(CS::one(), F::ONE)
                + &is_r2.lc(CS::one(), F::from(2))
                + &is_r3.lc(CS::one(), F::from(3)),
        );

        // 4. When VALID: leaf wires MUST equal candidate wires bit-for-bit / limb-for-limb!
        zero_if(
            cs,
            "valid requires both_pres",
            &wires.valid,
            one_lc::<F, CS>() - &both_pres.lc(CS::one(), F::ONE),
        );
        zero_if(cs, "valid p == cand_p", &wires.valid, le_lc::<F, CS>(&wires.p) - &le_lc::<F, CS>(&cp));
        zero_if(cs, "valid c == cand_c", &wires.valid, le_lc::<F, CS>(&wires.c) - &le_lc::<F, CS>(&cc));
        zero_if(cs, "valid pt == cand_pt", &wires.valid, le_lc::<F, CS>(&wires.pt) - &le_lc::<F, CS>(&cpt));
        zero_if(cs, "valid ct == cand_ct", &wires.valid, le_lc::<F, CS>(&wires.ct) - &le_lc::<F, CS>(&cct));
        zero_if(
            cs,
            "valid ph_lo == cand_ph_lo",
            &wires.valid,
            le_lc::<F, CS>(&wires.ph[..128]) - &le_lc::<F, CS>(&cph[..128]),
        );
        zero_if(
            cs,
            "valid ph_hi == cand_ph_hi",
            &wires.valid,
            le_lc::<F, CS>(&wires.ph[128..]) - &le_lc::<F, CS>(&cph[128..]),
        );
        zero_if(
            cs,
            "valid ch_lo == cand_ch_lo",
            &wires.valid,
            le_lc::<F, CS>(&wires.ch[..128]) - &le_lc::<F, CS>(&cch[..128]),
        );
        zero_if(
            cs,
            "valid ch_hi == cand_ch_hi",
            &wires.valid,
            le_lc::<F, CS>(&wires.ch[128..]) - &le_lc::<F, CS>(&cch[128..]),
        );

        // 5. HOLD necessity constraints:
        // Reason 1: missing source (`both_pres == 0`)
        zero_if(cs, "r1 requires missing source", &is_r1, both_pres.lc(CS::one(), F::ONE));

        // Reason 2: both present AND strict spread > 50 bps (`20,000 * |cp - cc| >= 50 * (cp + cc) + 1`)
        zero_if(
            cs,
            "r2 requires both_pres",
            &is_r2,
            one_lc::<F, CS>() - &both_pres.lc(CS::one(), F::ONE),
        );
        for (i, (b, v)) in [(&cp, cand.cand_p), (&cc, cand.cand_c)].into_iter().enumerate() {
            slack(
                cs,
                &format!("r2 pos price {i}"),
                &is_r2,
                le_lc::<F, CS>(b) - &one_lc::<F, CS>(),
                i128::from(v) - 1,
                54,
            )?;
            slack(
                cs,
                &format!("r2 max price {i}"),
                &is_r2,
                LinearCombination::zero() + (F::from(MAX_PRICE as u64), CS::one()) - &le_lc::<F, CS>(b),
                MAX_PRICE - i128::from(v),
                54,
            )?;
        }
        let cpv = i128::from(cand.cand_p);
        let ccv = i128::from(cand.cand_c);
        let r2_p_gt_c = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "r2_p_gt_c"),
            Some(d.status == 2 && d.reason == 2 && cpv > ccv),
        )?);
        let r2_c_gt_p = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "r2_c_gt_p"),
            Some(d.status == 2 && d.reason == 2 && ccv > cpv),
        )?);
        eq_lc(
            cs,
            "r2 direction partition",
            r2_p_gt_c.lc(CS::one(), F::ONE) + &r2_c_gt_p.lc(CS::one(), F::ONE),
            is_r2.lc(CS::one(), F::ONE),
        );
        slack(
            cs,
            "r2 strict spread p>c",
            &r2_p_gt_c,
            scaled_lc::<F, CS>(&cp, 19_950) + &scaled_lc::<F, CS>(&cc, -20_050) - &one_lc::<F, CS>(),
            19_950 * cpv - 20_050 * ccv - 1,
            80,
        )?;
        slack(
            cs,
            "r2 strict spread c>p",
            &r2_c_gt_p,
            scaled_lc::<F, CS>(&cc, 19_950) + &scaled_lc::<F, CS>(&cp, -20_050) - &one_lc::<F, CS>(),
            19_950 * ccv - 20_050 * cpv - 1,
            80,
        )?;

        // Reason 3: both present AND strict timestamp freshness/future/skew violation
        zero_if(
            cs,
            "r3 requires both_pres",
            &is_r3,
            one_lc::<F, CS>() - &both_pres.lc(CS::one(), F::ONE),
        );
        let cutoff = (i128::from(d.hour) + 1) * HOUR_US;
        let cptv = i128::from(cand.cand_pt);
        let cctv = i128::from(cand.cand_ct);
        let raw_viols = [
            cutoff - cptv - MAX_AGE - 1,
            cptv - cutoff - 1,
            cutoff - cctv - MAX_AGE - 1,
            cctv - cutoff - 1,
            cptv - cctv - MAX_SKEW - 1,
            cctv - cptv - MAX_SKEW - 1,
        ];
        let chosen_v = if d.status == 2 && d.reason == 3 {
            raw_viols.iter().position(|&x| x >= 0)
        } else {
            None
        };
        let mut v_flags = Vec::with_capacity(6);
        for k in 0..6 {
            v_flags.push(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("r3_viol_{k}")),
                Some(chosen_v == Some(k)),
            )?));
        }
        eq_lc(
            cs,
            "r3 violation partition",
            bit_sum::<F, CS>(&v_flags),
            is_r3.lc(CS::one(), F::ONE),
        );
        let cutoff_lc =
            scaled_lc::<F, CS>(&wires.hour, HOUR_US as i64) + (F::from(HOUR_US as u64), CS::one());
        slack(
            cs,
            "r3_v0_pyth_stale",
            &v_flags[0],
            cutoff_lc.clone()
                - &le_lc::<F, CS>(&cpt)
                - &(LinearCombination::zero() + (F::from((MAX_AGE + 1) as u64), CS::one())),
            raw_viols[0],
            64,
        )?;
        slack(
            cs,
            "r3_v1_pyth_future",
            &v_flags[1],
            le_lc::<F, CS>(&cpt) - &cutoff_lc - &one_lc::<F, CS>(),
            raw_viols[1],
            64,
        )?;
        slack(
            cs,
            "r3_v2_cl_stale",
            &v_flags[2],
            cutoff_lc.clone()
                - &le_lc::<F, CS>(&cct)
                - &(LinearCombination::zero() + (F::from((MAX_AGE + 1) as u64), CS::one())),
            raw_viols[2],
            64,
        )?;
        slack(
            cs,
            "r3_v3_cl_future",
            &v_flags[3],
            le_lc::<F, CS>(&cct) - &cutoff_lc - &one_lc::<F, CS>(),
            raw_viols[3],
            64,
        )?;
        slack(
            cs,
            "r3_v4_skew_p_c",
            &v_flags[4],
            le_lc::<F, CS>(&cpt)
                - &le_lc::<F, CS>(&cct)
                - &(LinearCombination::zero() + (F::from((MAX_SKEW + 1) as u64), CS::one())),
            raw_viols[4],
            64,
        )?;
        slack(
            cs,
            "r3_v5_skew_c_p",
            &v_flags[5],
            le_lc::<F, CS>(&cct)
                - &le_lc::<F, CS>(&cpt)
                - &(LinearCombination::zero() + (F::from((MAX_SKEW + 1) as u64), CS::one())),
            raw_viols[5],
            64,
        )?;

        // 6. Compute running SHA-256 over `SOURCE_ACC_DOMAIN || prev_acc || SOURCE_CANDIDATE_DOMAIN || cand_tuple`
        let mut cand_bits = constant_bits(crate::sources::SOURCE_CANDIDATE_DOMAIN);
        for b in [
            &wires.hour,
            &p_pres_byte,
            &c_pres_byte,
            &cp,
            &cc,
            &cpt,
            &cct,
            &cph,
            &cch,
        ] {
            cand_bits.extend(b.iter().cloned());
        }
        let mut acc_preimage = constant_bits(SOURCE_ACC_DOMAIN);
        acc_preimage.extend(prev_acc);
        acc_preimage.extend(cand_bits);
        let next_acc_bits = sha256(cs.namespace(|| "next_source_acc_sha256"), &acc_preimage)?;

        let expected_next_acc = cand.next_accumulator(d.hour);
        let next_acc_lo = AllocatedNum::alloc_infallible(cs.namespace(|| "next_acc_lo"), || {
            f_from_le_bytes(&expected_next_acc[..16])
        });
        let next_acc_hi = AllocatedNum::alloc_infallible(cs.namespace(|| "next_acc_hi"), || {
            f_from_le_bytes(&expected_next_acc[16..])
        });
        bind_le(cs, "bind next_acc_lo", &next_acc_bits[..128], &next_acc_lo);
        bind_le(cs, "bind next_acc_hi", &next_acc_bits[128..], &next_acc_hi);

        let mut out = wires.next_z_v1;
        out.push(next_acc_lo);
        out.push(next_acc_hi);
        Ok(out)
    }
}
