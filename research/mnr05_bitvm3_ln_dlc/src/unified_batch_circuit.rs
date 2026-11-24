//! `Gate 1a + Gate 2b`: Unified Transparent Nova Batch-Clearing Circuit
//! (`shz/mnr05-unified-bitvm3-batch-clearing/v1`, 3 folds over `Bn256EngineIPA` / `GrumpkinEngine`).
//!
//! Across 3 uniform folds (`k = 0, 1, 2` for `U_AB`, `U_BC`, `U_CA`), constrains in R1CS:
//! 1. Exact `348`-byte stripped 3-input, 5-output Bitcoin clearing transaction `SHA256d` `txid`,
//!    all 5 little-endian 64-bit output amounts (offsets `129, 172, 215, 258, 301`), and exact
//!    funding-to-payout+fee conservation (`sum(inputs) == sum(outputs) + miner_fee`).
//! 2. Per-vault outpoint nullifier non-membership (`EMPTY`) -> insertion (`CONSUMED`) in a
//!    domain-separated 8-slot Sparse Nullifier Tree, reading `vin[k]`'s 36-byte outpoint directly
//!    from the allocated `348`-byte transaction wires so no vault can be double-consumed or skipped.
//! 3. Authenticated `INDEX-03` `VALID` hourly oracle record (`midpoint = floor((p + c)/2)`,
//!    `<= 50 bps` relative spread) + 3-level Merkle inclusion to `oracle_checkpoint_root32`.
//! 4. Canonical `304`-byte `UtxoRefL2SettlementStatementV0` (`UTXOREF_L2_SETTLEMENT_GROTH16_V0\0`)
//!    binding `final_nullifier_root32` (at `k = 2`), `assertion_txid`, `settlement_txid`,
//!    `auth_accumulator_root32` (from [`crate::secq_schnorr_circuit`]), and `oracle_checkpoint_root32`
//!    into the exact big-endian 128-bit public input limbs `[stmt_hi128_be, stmt_lo128_be]`.
#![forbid(unsafe_code)]

use bincode::Options;
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr as BnScalar;
use nova_snark::{
    frontend::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            num::AllocatedNum,
            sha256::sha256,
        },
        ConstraintSystem, LinearCombination, SynthesisError,
    },
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc::EvaluationEngine, Bn256EngineIPA, GrumpkinEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_nova_bitvm::bitvm3::{
    split_statement_digest_be_u128, BitcoinNetworkCode, UtxoRefL2SettlementStatementV0,
    BITVM3_STATEMENT_LEN, BITVM3_STATEMENT_MAGIC,
};

pub const RELATION_UNIFIED_BATCH_V1: &str = "shz/mnr05-unified-bitvm3-batch-clearing/v1";
pub const UNIFIED_ARITY: usize = 11;
pub const UNIFIED_FOLDS: usize = 3;

pub const NULL_LEAF_DOMAIN: &[u8] = b"SHZ/MNR05/NULL/V1";
pub const NULL_NODE_DOMAIN: &[u8] = b"SHZ/MNR05/NULL_NODE/V1";
pub const NULL_TREE_DEPTH: usize = 3; // 8 vault slots per batch epoch

pub const IDX_LEAF_DOMAIN: &[u8] = b"SHZ/HOUR/LEAF/V1";
pub const IDX_NODE_DOMAIN: &[u8] = b"SHZ/HOUR/NODE/V1";
pub const IDX_ROOT_DOMAIN: &[u8] = b"SHZ/8H/ROOT/V1";

pub type B1 = Bn256EngineIPA;
pub type B2 = GrumpkinEngine;
type BE1 = EvaluationEngine<B1>;
type BE2 = EvaluationEngine<B2>;
type BS1 = RelaxedR1CSSNARK<B1, BE1>;
type BS2 = RelaxedR1CSSNARK<B2, BE2>;

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn double_sha256_bytes(data: &[u8]) -> [u8; 32] {
    sha256_bytes(&sha256_bytes(data))
}

pub fn reverse32(mut b: [u8; 32]) -> [u8; 32] {
    b.reverse();
    b
}

pub fn bn_from_u128(v: u128) -> BnScalar {
    let mut le = [0u8; 32];
    le[0..16].copy_from_slice(&v.to_le_bytes());
    BnScalar::from_repr(le.into()).unwrap()
}

pub fn le_u128_halves(d: &[u8; 32]) -> (u128, u128) {
    (
        u128::from_le_bytes(d[0..16].try_into().unwrap()),
        u128::from_le_bytes(d[16..32].try_into().unwrap()),
    )
}

/// Domain-separated 8-leaf (`NULL_TREE_DEPTH = 3`) Sparse Nullifier Tree for vault outpoints.
#[derive(Clone, Debug)]
pub struct BatchVaultNullifierTree {
    pub leaves: [[u8; 32]; 8],
}

impl Default for BatchVaultNullifierTree {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchVaultNullifierTree {
    pub fn new() -> Self {
        Self {
            leaves: [[0u8; 32]; 8],
        }
    }

    pub fn nullifier_for_outpoint(outpoint_36b: &[u8; 36]) -> [u8; 32] {
        let mut pre = Vec::with_capacity(NULL_LEAF_DOMAIN.len() + 36);
        pre.extend_from_slice(NULL_LEAF_DOMAIN);
        pre.extend_from_slice(outpoint_36b);
        sha256_bytes(&pre)
    }

    fn hash_pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let mut b = Vec::with_capacity(NULL_NODE_DOMAIN.len() + 64);
        b.extend_from_slice(NULL_NODE_DOMAIN);
        b.extend_from_slice(l);
        b.extend_from_slice(r);
        sha256_bytes(&b)
    }

    pub fn root(&self) -> [u8; 32] {
        let l1: Vec<[u8; 32]> = (0..4)
            .map(|i| Self::hash_pair(&self.leaves[2 * i], &self.leaves[2 * i + 1]))
            .collect();
        let l2: Vec<[u8; 32]> = (0..2)
            .map(|i| Self::hash_pair(&l1[2 * i], &l1[2 * i + 1]))
            .collect();
        Self::hash_pair(&l2[0], &l2[1])
    }

    pub fn siblings(&self, slot: u8) -> [[u8; 32]; 3] {
        let idx = slot as usize;
        assert!(idx < 8);
        let l1: Vec<[u8; 32]> = (0..4)
            .map(|i| Self::hash_pair(&self.leaves[2 * i], &self.leaves[2 * i + 1]))
            .collect();
        let l2: Vec<[u8; 32]> = (0..2)
            .map(|i| Self::hash_pair(&l1[2 * i], &l1[2 * i + 1]))
            .collect();
        [
            self.leaves[idx ^ 1],
            l1[(idx >> 1) ^ 1],
            l2[(idx >> 2) ^ 1],
        ]
    }

    /// Consumes `slot` (`0..8`) for `outpoint_36b`, returning `(old_root, siblings, new_root)`.
    /// Fails if `slot` is already non-empty!
    #[allow(clippy::type_complexity)]
    pub fn consume_vault_slot(
        &mut self,
        slot: u8,
        outpoint_36b: &[u8; 36],
    ) -> Result<([u8; 32], [[u8; 32]; 3], [u8; 32]), String> {
        if slot >= 8 {
            return Err("vault nullifier slot >= 8".into());
        }
        if self.leaves[slot as usize] != [0u8; 32] {
            return Err(format!("vault nullifier slot {slot} already consumed"));
        }
        let old_root = self.root();
        let sibs = self.siblings(slot);
        let nullifier = Self::nullifier_for_outpoint(outpoint_36b);
        self.leaves[slot as usize] = nullifier;
        let new_root = self.root();
        Ok((old_root, sibs, new_root))
    }
}

/// Authenticated `INDEX-03` hourly oracle opening witness embedded inside the batch proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleOpeningWitness {
    pub position: u8,
    pub start_hour: u64,
    pub genesis: [u8; 32],
    pub policy_hash: [u8; 32],
    pub hour_id: u64,
    pub pyth_price_e8: u64,
    pub chainlink_price_e8: u64,
    pub index_price_e8: u64,
    pub pyth_publish_us: u64,
    pub chainlink_publish_us: u64,
    pub pyth_report_hash: [u8; 32],
    pub chainlink_report_hash: [u8; 32],
    pub merkle_siblings: [[u8; 32]; 3],
}

impl OracleOpeningWitness {
    pub fn checkpoint_root(&self) -> [u8; 32] {
        let mut leaf = IDX_LEAF_DOMAIN.to_vec();
        leaf.extend_from_slice(&self.genesis);
        leaf.extend_from_slice(&self.policy_hash);
        leaf.extend_from_slice(&self.hour_id.to_le_bytes());
        leaf.extend_from_slice(&[1u8, 0u8]); // VALID = 1, reason = 0
        for v in [
            self.pyth_price_e8,
            self.chainlink_price_e8,
            self.index_price_e8,
            self.pyth_publish_us,
            self.chainlink_publish_us,
        ] {
            leaf.extend_from_slice(&v.to_le_bytes());
        }
        leaf.extend_from_slice(&self.pyth_report_hash);
        leaf.extend_from_slice(&self.chainlink_report_hash);

        let mut d = sha256_bytes(&leaf);
        for (i, s) in self.merkle_siblings.iter().enumerate() {
            let mut n = IDX_NODE_DOMAIN.to_vec();
            if ((self.position >> i) & 1) == 0 {
                n.extend_from_slice(&d);
                n.extend_from_slice(s);
            } else {
                n.extend_from_slice(s);
                n.extend_from_slice(&d);
            }
            d = sha256_bytes(&n);
        }
        let mut r = IDX_ROOT_DOMAIN.to_vec();
        r.extend_from_slice(&self.genesis);
        r.extend_from_slice(&self.policy_hash);
        r.extend_from_slice(&self.start_hour.to_le_bytes());
        r.extend_from_slice(&d);
        sha256_bytes(&r)
    }
}

/// Public claim pinned independently by the verifier & BitVM3 L1 Tapscript tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedBatchPublicClaim {
    pub initial_nullifier_root: [u8; 32],
    pub final_nullifier_root: [u8; 32],
    pub oracle_checkpoint_root: [u8; 32],
    pub settlement_txid_be: [u8; 32],
    pub auth_accumulator_root: [u8; 32],
    pub bitvm3_statement_304b_sha256: [u8; 32],
    pub bitvm3_public_limbs_be: [u128; 2],
}

impl UnifiedBatchPublicClaim {
    pub fn state(&self, fold_count: u64) -> Vec<BnScalar> {
        let null_root = if fold_count == 0 {
            &self.initial_nullifier_root
        } else {
            &self.final_nullifier_root
        };
        let (n_lo, n_hi) = le_u128_halves(null_root);
        let (c_lo, c_hi) = le_u128_halves(&self.oracle_checkpoint_root);
        let (t_lo, t_hi) = le_u128_halves(&self.settlement_txid_be);
        let (a_lo, a_hi) = le_u128_halves(&self.auth_accumulator_root);
        vec![
            BnScalar::from(fold_count),
            bn_from_u128(n_lo),
            bn_from_u128(n_hi),
            bn_from_u128(c_lo),
            bn_from_u128(c_hi),
            bn_from_u128(t_lo),
            bn_from_u128(t_hi),
            bn_from_u128(a_lo),
            bn_from_u128(a_hi),
            bn_from_u128(self.bitvm3_public_limbs_be[0]),
            bn_from_u128(self.bitvm3_public_limbs_be[1]),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct Mnr05UnifiedBatchStep {
    pub fold_idx: u8,
    pub vault_slot: u8,
    pub cur_nullifier_root: [u8; 32],
    pub next_nullifier_root: [u8; 32],
    pub nullifier_siblings: [[u8; 32]; 3],
    pub stripped_tx_348b: [u8; 348],
    pub input_amounts_sats: [u64; 3],
    pub miner_fee_sats: u64,
    pub oracle: OracleOpeningWitness,
    pub statement_304b: [u8; BITVM3_STATEMENT_LEN],
}

impl Mnr05UnifiedBatchStep {
    pub fn blank() -> Self {
        let mut tx = [0u8; 348];
        tx[0..4].copy_from_slice(&2i32.to_le_bytes());
        tx[4] = 3;
        tx[5..37].copy_from_slice(&[0x11; 32]);
        tx[42..46].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        tx[46..78].copy_from_slice(&[0x22; 32]);
        tx[83..87].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        tx[87..119].copy_from_slice(&[0x33; 32]);
        tx[124..128].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        tx[128] = 5;
        let outs = [55_000_000u64, 35_000_000, 71_498_500, 82_498_500, 330];
        let offsets = [129usize, 172, 215, 258, 301];
        for (&amt, &off) in outs.iter().zip(offsets.iter()) {
            tx[off..off + 8].copy_from_slice(&amt.to_le_bytes());
            tx[off + 8] = 0x22;
            tx[off + 9] = 0x51;
            tx[off + 10] = 0x20;
        }
        tx[344..348].copy_from_slice(&150u32.to_le_bytes());

        let mut tree = BatchVaultNullifierTree::new();
        let out0: [u8; 36] = tx[5..41].try_into().unwrap();
        let (old_r, sibs, new_r) = tree.consume_vault_slot(0, &out0).unwrap();

        let oracle = OracleOpeningWitness {
            position: 0,
            start_hour: 498_000,
            genesis: [0x01; 32],
            policy_hash: [0x02; 32],
            hour_id: 498_000,
            pyth_price_e8: 6_000_000_000_000,
            chainlink_price_e8: 6_000_000_000_000,
            index_price_e8: 6_000_000_000_000,
            pyth_publish_us: 1_792_803_590_000_000,
            chainlink_publish_us: 1_792_803_590_000_000,
            pyth_report_hash: [0xaa; 32],
            chainlink_report_hash: [0xbb; 32],
            merkle_siblings: [[0xcc; 32]; 3],
        };
        let ckpt = oracle.checkpoint_root();
        let txid_be = reverse32(double_sha256_bytes(&tx));
        let stmt = UtxoRefL2SettlementStatementV0 {
            network_code: BitcoinNetworkCode::Regtest,
            chain_genesis_hash: [0x01; 32],
            contract_id: [0x03; 32],
            commitment_hash: new_r,
            assertion_txid: [0x04; 32],
            settlement_txid: txid_be,
            program_hash: [0x05; 32],
            verifying_key_hash: [0x06; 32],
            policy_hash: ckpt,
            epoch_id: 498_000,
            assertion_vout: 0,
        };
        Self {
            fold_idx: 0,
            vault_slot: 0,
            cur_nullifier_root: old_r,
            next_nullifier_root: new_r,
            nullifier_siblings: sibs,
            stripped_tx_348b: tx,
            input_amounts_sats: [99_000_000, 90_000_000, 55_000_000],
            miner_fee_sats: 2_670,
            oracle,
            statement_304b: stmt.encode(),
        }
    }
}

fn constant_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|v| (0..8).rev().map(move |j| Boolean::constant((v >> j) & 1 != 0)))
        .collect()
}

fn alloc_bytes_bits<CS: ConstraintSystem<BnScalar>>(
    mut cs: CS,
    bytes: &[u8],
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for (i, b) in bytes.iter().enumerate() {
        for j in (0..8).rev() {
            out.push(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("b{i}_{j}")),
                Some((b >> j) & 1 != 0),
            )?));
        }
    }
    Ok(out)
}

fn le_lc<CS: ConstraintSystem<BnScalar>>(bits: &[Boolean]) -> LinearCombination<BnScalar> {
    assert_eq!(bits.len() % 8, 0);
    let mut lc = LinearCombination::zero();
    let mut w = BnScalar::ONE;
    for byte in bits.as_chunks::<8>().0 {
        for b in byte.iter().rev() {
            lc = lc + &b.lc(CS::one(), w);
            w = w.double();
        }
    }
    lc
}

fn be_lc<CS: ConstraintSystem<BnScalar>>(bits: &[Boolean]) -> LinearCombination<BnScalar> {
    let mut lc = LinearCombination::zero();
    let mut w = BnScalar::ONE;
    for b in bits.iter().rev() {
        lc = lc + &b.lc(CS::one(), w);
        w = w.double();
    }
    lc
}

fn reverse_digest_bits(bits256: &[Boolean]) -> Vec<Boolean> {
    assert_eq!(bits256.len(), 256);
    let mut out = Vec::with_capacity(256);
    for byte in bits256.as_chunks::<8>().0.iter().rev() {
        out.extend_from_slice(byte);
    }
    out
}

fn pick_bits<CS: ConstraintSystem<BnScalar>>(
    mut cs: CS,
    sel: &Boolean,
    a: &[Boolean],
    b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    a.iter()
        .zip(b)
        .enumerate()
        .map(|(i, (x, y))| {
            let v = if sel.get_value() == Some(true) {
                y.get_value()
            } else {
                x.get_value()
            };
            let mut ns = cs.namespace(|| format!("sel_{i}"));
            let o = Boolean::from(AllocatedBit::alloc(ns.namespace(|| "o"), v)?);
            ns.enforce(
                || "mux",
                |_| sel.lc(CS::one(), BnScalar::ONE),
                |_| y.lc(CS::one(), BnScalar::ONE) - &x.lc(CS::one(), BnScalar::ONE),
                |_| o.lc(CS::one(), BnScalar::ONE) - &x.lc(CS::one(), BnScalar::ONE),
            );
            Ok(o)
        })
        .collect()
}

fn slack_nonneg<CS: ConstraintSystem<BnScalar>>(
    mut cs: CS,
    gate: &Boolean,
    expr: LinearCombination<BnScalar>,
    val: i128,
    width: usize,
) -> Result<(), SynthesisError> {
    let wv = if gate.get_value() == Some(true) && val >= 0 {
        val as u128
    } else {
        0
    };
    let mut rhs = LinearCombination::zero();
    let mut w = BnScalar::ONE;
    for i in 0..width {
        let bit = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("slk_{i}")),
            Some((wv >> i) & 1 != 0),
        )?);
        rhs = rhs + &bit.lc(CS::one(), w);
        w = w.double();
    }
    cs.enforce(
        || "slack",
        |_| gate.lc(CS::one(), BnScalar::ONE),
        |_| expr,
        |_| rhs,
    );
    Ok(())
}

impl StepCircuit<BnScalar> for Mnr05UnifiedBatchStep {
    fn arity(&self) -> usize {
        UNIFIED_ARITY
    }

    fn synthesize<CS: ConstraintSystem<BnScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<BnScalar>],
    ) -> Result<Vec<AllocatedNum<BnScalar>>, SynthesisError> {
        assert_eq!(z.len(), UNIFIED_ARITY);

        // --- 1. Fold Partition (`k in {0, 1, 2}`) ---
        let is_k0 = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_k0"),
            Some(self.fold_idx == 0),
        )?);
        let is_k1 = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_k1"),
            Some(self.fold_idx == 1),
        )?);
        let is_k2 = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_k2"),
            Some(self.fold_idx == 2),
        )?);
        cs.enforce(
            || "fold partition sum == 1",
            |_| {
                is_k0.lc(CS::one(), BnScalar::ONE)
                    + &is_k1.lc(CS::one(), BnScalar::ONE)
                    + &is_k2.lc(CS::one(), BnScalar::ONE)
            },
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
        cs.enforce(
            || "fold_idx == z[0]",
            |_| is_k1.lc(CS::one(), BnScalar::ONE) + &is_k2.lc(CS::one(), BnScalar::from(2u64)),
            |lc| lc + CS::one(),
            |lc| lc + z[0].get_variable(),
        );

        // --- 2. Exact `348`-Byte Stripped Bitcoin Clearing Transaction + `SHA256d` + Conservation ---
        let tx_bits = alloc_bytes_bits(cs.namespace(|| "stripped_tx_348b"), &self.stripped_tx_348b)?;

        // Structural header checks: version == 2, n_vin == 3, empty scriptSigs, n_vout == 5
        cs.enforce(
            || "tx_version == 2",
            |_| le_lc::<CS>(&tx_bits[0..32]),
            |lc| lc + CS::one(),
            |lc| lc + (BnScalar::from(2u64), CS::one()),
        );
        cs.enforce(
            || "n_vin == 3",
            |_| le_lc::<CS>(&tx_bits[32..40]),
            |lc| lc + CS::one(),
            |lc| lc + (BnScalar::from(3u64), CS::one()),
        );
        for (i, byte_off) in [41usize, 82, 123].into_iter().enumerate() {
            cs.enforce(
                || format!("empty_scriptsig_{i}"),
                |_| le_lc::<CS>(&tx_bits[byte_off * 8..(byte_off + 1) * 8]),
                |lc| lc + CS::one(),
                |lc| lc,
            );
        }
        cs.enforce(
            || "n_vout == 5",
            |_| le_lc::<CS>(&tx_bits[128 * 8..129 * 8]),
            |lc| lc + CS::one(),
            |lc| lc + (BnScalar::from(5u64), CS::one()),
        );

        // Extract 5 output values directly from `tx_bits` at byte offsets `[129, 172, 215, 258, 301]`!
        let vout_offsets = [129usize, 172, 215, 258, 301];
        let mut out_sum_lc = LinearCombination::zero();
        for &off in &vout_offsets {
            out_sum_lc = out_sum_lc + &le_lc::<CS>(&tx_bits[off * 8..(off + 8) * 8]);
        }
        // Dust-safe CPFP anchor check (`vout[4] >= 330`)
        let vout4_val = u64::from_le_bytes(self.stripped_tx_348b[301..309].try_into().unwrap());
        slack_nonneg(
            cs.namespace(|| "anchor_ge_330"),
            &Boolean::constant(true),
            le_lc::<CS>(&tx_bits[301 * 8..309 * 8])
                - &(LinearCombination::zero() + (BnScalar::from(330u64), CS::one())),
            i128::from(vout4_val) - 330,
            64,
        )?;

        let in0_bits = alloc_bytes_bits(
            cs.namespace(|| "in0_sats"),
            &self.input_amounts_sats[0].to_le_bytes(),
        )?;
        let in1_bits = alloc_bytes_bits(
            cs.namespace(|| "in1_sats"),
            &self.input_amounts_sats[1].to_le_bytes(),
        )?;
        let in2_bits = alloc_bytes_bits(
            cs.namespace(|| "in2_sats"),
            &self.input_amounts_sats[2].to_le_bytes(),
        )?;
        let fee_bits =
            alloc_bytes_bits(cs.namespace(|| "miner_fee"), &self.miner_fee_sats.to_le_bytes())?;
        slack_nonneg(
            cs.namespace(|| "fee_ge_300"),
            &Boolean::constant(true),
            le_lc::<CS>(&fee_bits)
                - &(LinearCombination::zero() + (BnScalar::from(300u64), CS::one())),
            i128::from(self.miner_fee_sats) - 300,
            64,
        )?;
        cs.enforce(
            || "exact funding conservation",
            |_| le_lc::<CS>(&in0_bits) + &le_lc::<CS>(&in1_bits) + &le_lc::<CS>(&in2_bits),
            |lc| lc + CS::one(),
            |_| out_sum_lc + &le_lc::<CS>(&fee_bits),
        );

        // Double SHA-256 of the 348-byte stripped transaction -> `settlement_txid_be`!
        let tx_sha1 = sha256(cs.namespace(|| "tx_sha256_1"), &tx_bits)?;
        let tx_sha2 = sha256(cs.namespace(|| "tx_sha256_2"), &tx_sha1)?;
        let txid_be_bits = reverse_digest_bits(&tx_sha2);
        cs.enforce(
            || "bind settlement_txid_lo == z[5]",
            |_| le_lc::<CS>(&txid_be_bits[0..128]),
            |lc| lc + CS::one(),
            |lc| lc + z[5].get_variable(),
        );
        cs.enforce(
            || "bind settlement_txid_hi == z[6]",
            |_| le_lc::<CS>(&txid_be_bits[128..256]),
            |lc| lc + CS::one(),
            |lc| lc + z[6].get_variable(),
        );

        // --- 3. Select `vin[k]` 36-Byte Outpoint & Enforce Nullifier Non-Membership -> Consumption ---
        let outp0 = &tx_bits[5 * 8..41 * 8];
        let outp1 = &tx_bits[46 * 8..82 * 8];
        let outp2 = &tx_bits[87 * 8..123 * 8];
        let sel_01 = pick_bits(cs.namespace(|| "mux_outp_01"), &is_k1, outp0, outp1)?;
        let selected_outp = pick_bits(cs.namespace(|| "mux_outp_2"), &is_k2, &sel_01, outp2)?;

        let mut null_pre = constant_bits(NULL_LEAF_DOMAIN);
        null_pre.extend(selected_outp);
        let nullifier_bits = sha256(cs.namespace(|| "vault_nullifier_sha256"), &null_pre)?;

        let slot_bits = alloc_bytes_bits(cs.namespace(|| "vault_slot"), &[self.vault_slot])?;
        // `vault_slot` must fit in 3 bits (`0..8`)
        let mut high_slot_sum = LinearCombination::zero();
        for b in &slot_bits[0..5] {
            high_slot_sum = high_slot_sum + &b.lc(CS::one(), BnScalar::ONE);
        }
        cs.enforce(|| "slot < 8", |_| high_slot_sum, |lc| lc + CS::one(), |lc| lc);

        let mut old_cur = constant_bits(&[0u8; 32]); // EMPTY leaf == [0u8; 32]
        let mut new_cur = nullifier_bits;
        for lvl in 0..NULL_TREE_DEPTH {
            let sib = alloc_bytes_bits(
                cs.namespace(|| format!("null_sib_{lvl}")),
                &self.nullifier_siblings[lvl],
            )?;
            let dir = &slot_bits[7 - lvl];

            let old_l = pick_bits(cs.namespace(|| format!("old_l_{lvl}")), dir, &old_cur, &sib)?;
            let old_r = pick_bits(cs.namespace(|| format!("old_r_{lvl}")), dir, &sib, &old_cur)?;
            let mut old_node = constant_bits(NULL_NODE_DOMAIN);
            old_node.extend(old_l);
            old_node.extend(old_r);
            old_cur = sha256(cs.namespace(|| format!("old_null_sha_{lvl}")), &old_node)?;

            let new_l = pick_bits(cs.namespace(|| format!("new_l_{lvl}")), dir, &new_cur, &sib)?;
            let new_r = pick_bits(cs.namespace(|| format!("new_r_{lvl}")), dir, &sib, &new_cur)?;
            let mut new_node = constant_bits(NULL_NODE_DOMAIN);
            new_node.extend(new_l);
            new_node.extend(new_r);
            new_cur = sha256(cs.namespace(|| format!("new_null_sha_{lvl}")), &new_node)?;
        }

        // Bind `old_cur` to `z[1..3]` (`cur_nullifier_root`)!
        cs.enforce(
            || "old_nullifier_lo == z[1]",
            |_| le_lc::<CS>(&old_cur[0..128]),
            |lc| lc + CS::one(),
            |lc| lc + z[1].get_variable(),
        );
        cs.enforce(
            || "old_nullifier_hi == z[2]",
            |_| le_lc::<CS>(&old_cur[128..256]),
            |lc| lc + CS::one(),
            |lc| lc + z[2].get_variable(),
        );

        let (next_null_lo_u, next_null_hi_u) = le_u128_halves(&self.next_nullifier_root);
        let next_null_lo = AllocatedNum::alloc_infallible(cs.namespace(|| "next_null_lo"), || {
            bn_from_u128(next_null_lo_u)
        });
        let next_null_hi = AllocatedNum::alloc_infallible(cs.namespace(|| "next_null_hi"), || {
            bn_from_u128(next_null_hi_u)
        });
        cs.enforce(
            || "bind next_null_lo",
            |_| le_lc::<CS>(&new_cur[0..128]),
            |lc| lc + CS::one(),
            |lc| lc + next_null_lo.get_variable(),
        );
        cs.enforce(
            || "bind next_null_hi",
            |_| le_lc::<CS>(&new_cur[128..256]),
            |lc| lc + CS::one(),
            |lc| lc + next_null_hi.get_variable(),
        );

        // --- 4. Authenticated `INDEX-03` Hourly Oracle Opening -> `oracle_checkpoint_root32` ---
        let o = &self.oracle;
        let o_pos = alloc_bytes_bits(cs.namespace(|| "o_pos"), &[o.position])?;
        let o_gen = alloc_bytes_bits(cs.namespace(|| "o_gen"), &o.genesis)?;
        let o_pol = alloc_bytes_bits(cs.namespace(|| "o_pol"), &o.policy_hash)?;
        let o_start = alloc_bytes_bits(cs.namespace(|| "o_start"), &o.start_hour.to_le_bytes())?;
        let o_hour = alloc_bytes_bits(cs.namespace(|| "o_hour"), &o.hour_id.to_le_bytes())?;
        let o_p = alloc_bytes_bits(cs.namespace(|| "o_p"), &o.pyth_price_e8.to_le_bytes())?;
        let o_c = alloc_bytes_bits(cs.namespace(|| "o_c"), &o.chainlink_price_e8.to_le_bytes())?;
        let o_idx = alloc_bytes_bits(cs.namespace(|| "o_idx"), &o.index_price_e8.to_le_bytes())?;
        let o_pt = alloc_bytes_bits(cs.namespace(|| "o_pt"), &o.pyth_publish_us.to_le_bytes())?;
        let o_ct = alloc_bytes_bits(cs.namespace(|| "o_ct"), &o.chainlink_publish_us.to_le_bytes())?;
        let o_ph = alloc_bytes_bits(cs.namespace(|| "o_ph"), &o.pyth_report_hash)?;
        let o_ch = alloc_bytes_bits(cs.namespace(|| "o_ch"), &o.chainlink_report_hash)?;

        // Midpoint floor `(p + c - 2*idx) in {0, 1}` & `<= 50 bps` relative spread!
        let pv = i128::from(o.pyth_price_e8);
        let cv = i128::from(o.chainlink_price_e8);
        let iv = i128::from(o.index_price_e8);
        slack_nonneg(
            cs.namespace(|| "oracle_midpoint_floor"),
            &Boolean::constant(true),
            le_lc::<CS>(&o_p) + &le_lc::<CS>(&o_c) - &le_lc::<CS>(&o_idx) - &le_lc::<CS>(&o_idx),
            pv + cv - 2 * iv,
            1,
        )?;
        let scaled = |bits: &[Boolean], coeff: u64| -> LinearCombination<BnScalar> {
            let mut lc = LinearCombination::zero();
            let mut w = BnScalar::from(coeff);
            for byte in bits.as_chunks::<8>().0 {
                for b in byte.iter().rev() {
                    lc = lc + &b.lc(CS::one(), w);
                    w = w.double();
                }
            }
            lc
        };
        slack_nonneg(
            cs.namespace(|| "oracle_spread_p_c"),
            &Boolean::constant(true),
            scaled(&o_c, 20_050) - &scaled(&o_p, 19_950),
            20_050 * cv - 19_950 * pv,
            80,
        )?;
        slack_nonneg(
            cs.namespace(|| "oracle_spread_c_p"),
            &Boolean::constant(true),
            scaled(&o_p, 20_050) - &scaled(&o_c, 19_950),
            20_050 * pv - 19_950 * cv,
            80,
        )?;

        let mut idx_leaf = constant_bits(IDX_LEAF_DOMAIN);
        for b in [
            &o_gen,
            &o_pol,
            &o_hour,
            &constant_bits(&[1u8, 0u8]), // VALID = 1, reason = 0 (HOLD strictly forbidden for clearing!)
            &o_p,
            &o_c,
            &o_idx,
            &o_pt,
            &o_ct,
            &o_ph,
            &o_ch,
        ] {
            idx_leaf.extend(b.iter().cloned());
        }
        let mut idx_d = sha256(cs.namespace(|| "idx_leaf_sha"), &idx_leaf)?;
        for lvl in 0..3 {
            let sib = alloc_bytes_bits(
                cs.namespace(|| format!("idx_sib_{lvl}")),
                &o.merkle_siblings[lvl],
            )?;
            let dir = &o_pos[7 - lvl];
            let l = pick_bits(cs.namespace(|| format!("idx_l_{lvl}")), dir, &idx_d, &sib)?;
            let r = pick_bits(cs.namespace(|| format!("idx_r_{lvl}")), dir, &sib, &idx_d)?;
            let mut n = constant_bits(IDX_NODE_DOMAIN);
            n.extend(l);
            n.extend(r);
            idx_d = sha256(cs.namespace(|| format!("idx_node_sha_{lvl}")), &n)?;
        }
        let mut idx_root_pre = constant_bits(IDX_ROOT_DOMAIN);
        idx_root_pre.extend(o_gen);
        idx_root_pre.extend(o_pol);
        idx_root_pre.extend(o_start);
        idx_root_pre.extend(idx_d);
        let idx_root_bits = sha256(cs.namespace(|| "idx_ckpt_root_sha"), &idx_root_pre)?;
        cs.enforce(
            || "bind ckpt_lo == z[3]",
            |_| le_lc::<CS>(&idx_root_bits[0..128]),
            |lc| lc + CS::one(),
            |lc| lc + z[3].get_variable(),
        );
        cs.enforce(
            || "bind ckpt_hi == z[4]",
            |_| le_lc::<CS>(&idx_root_bits[128..256]),
            |lc| lc + CS::one(),
            |lc| lc + z[4].get_variable(),
        );

        // --- 5. Canonical `304`-Byte `UtxoRefL2SettlementStatementV0` Binding ---
        // Allocate dynamic suffix `[35..304]` (`269` bytes) and prepend constant `magic (33B) || reserved (2B) == 0`!
        let mut stmt_bits = constant_bits(BITVM3_STATEMENT_MAGIC);
        stmt_bits.extend(constant_bits(&[0u8, 0u8]));
        let stmt_body_bits =
            alloc_bytes_bits(cs.namespace(|| "stmt_body_269b"), &self.statement_304b[35..304])?;
        stmt_bits.extend(stmt_body_bits);
        assert_eq!(stmt_bits.len(), BITVM3_STATEMENT_LEN * 8);

        // Bind `statement.settlement_txid` (`bytes[164..196]`) == `z[5..7]`!
        cs.enforce(
            || "stmt.settlement_txid_lo == z[5]",
            |_| le_lc::<CS>(&stmt_bits[164 * 8..180 * 8]),
            |lc| lc + CS::one(),
            |lc| lc + z[5].get_variable(),
        );
        cs.enforce(
            || "stmt.settlement_txid_hi == z[6]",
            |_| le_lc::<CS>(&stmt_bits[180 * 8..196 * 8]),
            |lc| lc + CS::one(),
            |lc| lc + z[6].get_variable(),
        );

        // Bind `statement.verifying_key_hash` (`bytes[228..260]`) == `auth_accumulator_root` (`z[7..9]`)!
        cs.enforce(
            || "stmt.auth_acc_lo == z[7]",
            |_| le_lc::<CS>(&stmt_bits[228 * 8..244 * 8]),
            |lc| lc + CS::one(),
            |lc| lc + z[7].get_variable(),
        );
        cs.enforce(
            || "stmt.auth_acc_hi == z[8]",
            |_| le_lc::<CS>(&stmt_bits[244 * 8..260 * 8]),
            |lc| lc + CS::one(),
            |lc| lc + z[8].get_variable(),
        );

        // Bind `statement.policy_hash` (`bytes[260..292]`) == `oracle_checkpoint_root` (`z[3..5]`)!
        cs.enforce(
            || "stmt.ckpt_lo == z[3]",
            |_| le_lc::<CS>(&stmt_bits[260 * 8..276 * 8]),
            |lc| lc + CS::one(),
            |lc| lc + z[3].get_variable(),
        );
        cs.enforce(
            || "stmt.ckpt_hi == z[4]",
            |_| le_lc::<CS>(&stmt_bits[276 * 8..292 * 8]),
            |lc| lc + CS::one(),
            |lc| lc + z[4].get_variable(),
        );

        // On terminal fold `k == 2`, force `statement.commitment_hash` (`bytes[100..132]`) == `next_nullifier_root`!
        cs.enforce(
            || "terminal fold binds stmt.commitment_hash_lo == final_nullifier_lo",
            |_| is_k2.lc(CS::one(), BnScalar::ONE),
            |_| le_lc::<CS>(&stmt_bits[100 * 8..116 * 8]) - next_null_lo.get_variable(),
            |lc| lc,
        );
        cs.enforce(
            || "terminal fold binds stmt.commitment_hash_hi == final_nullifier_hi",
            |_| is_k2.lc(CS::one(), BnScalar::ONE),
            |_| le_lc::<CS>(&stmt_bits[116 * 8..132 * 8]) - next_null_hi.get_variable(),
            |lc| lc,
        );

        // Compute `SHA256(statement_304b)` and bind big-endian 128-bit halves directly to `z[9..11]`!
        let stmt_digest_bits = sha256(cs.namespace(|| "stmt_304b_sha256"), &stmt_bits)?;
        cs.enforce(
            || "stmt_hi128_be == z[9]",
            |_| be_lc::<CS>(&stmt_digest_bits[0..128]),
            |lc| lc + CS::one(),
            |lc| lc + z[9].get_variable(),
        );
        cs.enforce(
            || "stmt_lo128_be == z[10]",
            |_| be_lc::<CS>(&stmt_digest_bits[128..256]),
            |lc| lc + CS::one(),
            |lc| lc + z[10].get_variable(),
        );

        let next_count = AllocatedNum::alloc_infallible(cs.namespace(|| "next_count"), || {
            BnScalar::from(u64::from(self.fold_idx) + 1)
        });
        cs.enforce(
            || "next_count == z[0] + 1",
            |lc| lc + z[0].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + next_count.get_variable(),
        );

        Ok(vec![
            next_count,
            next_null_lo,
            next_null_hi,
            z[3].clone(),
            z[4].clone(),
            z[5].clone(),
            z[6].clone(),
            z[7].clone(),
            z[8].clone(),
            z[9].clone(),
            z[10].clone(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedBatchProofReceipt {
    pub relation: String,
    pub curve_cycle: String,
    pub trusted_setup_ceremony: bool,
    pub folds: usize,
    pub primary_constraints: usize,
    pub secondary_constraints: usize,
    pub initial_nullifier_root_hex: String,
    pub final_nullifier_root_hex: String,
    pub oracle_checkpoint_root_hex: String,
    pub settlement_txid_hex: String,
    pub auth_accumulator_root_hex: String,
    pub bitvm3_statement_304b_sha256_hex: String,
    pub bitvm3_public_limbs_be_dec: [String; 2],
    pub vk_sha256_hex: String,
    pub proof_bytes: usize,
    pub proof_sha256_hex: String,
    pub setup_seconds: f64,
    pub fold_seconds: f64,
    pub compress_seconds: f64,
    pub verify_seconds: f64,
    pub wrong_txid_rejected: bool,
    pub wrong_nullifier_root_rejected: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn build_unified_batch_steps_and_claim(
    network_code: BitcoinNetworkCode,
    chain_genesis_hash: [u8; 32],
    contract_id: [u8; 32],
    assertion_txid: [u8; 32],
    assertion_vout: u32,
    program_hash: [u8; 32],
    auth_accumulator_root: [u8; 32],
    epoch_id: u64,
    stripped_tx_348b: [u8; 348],
    input_amounts_sats: [u64; 3],
    miner_fee_sats: u64,
    vault_slots: [u8; 3],
    oracle: OracleOpeningWitness,
) -> Result<
    (
        Vec<Mnr05UnifiedBatchStep>,
        UnifiedBatchPublicClaim,
        UtxoRefL2SettlementStatementV0,
    ),
    String,
> {
    let mut tree = BatchVaultNullifierTree::new();
    let initial_nullifier_root = tree.root();

    let outpoints: [[u8; 36]; 3] = [
        stripped_tx_348b[5..41].try_into().unwrap(),
        stripped_tx_348b[46..82].try_into().unwrap(),
        stripped_tx_348b[87..123].try_into().unwrap(),
    ];
    let mut transitions = Vec::with_capacity(3);
    for k in 0..3 {
        transitions.push(tree.consume_vault_slot(vault_slots[k], &outpoints[k])?);
    }
    let final_nullifier_root = tree.root();
    let oracle_checkpoint_root = oracle.checkpoint_root();
    let settlement_txid_be = reverse32(double_sha256_bytes(&stripped_tx_348b));

    let stmt = UtxoRefL2SettlementStatementV0 {
        network_code,
        chain_genesis_hash,
        contract_id,
        commitment_hash: final_nullifier_root,
        assertion_txid,
        settlement_txid: settlement_txid_be,
        program_hash,
        verifying_key_hash: auth_accumulator_root,
        policy_hash: oracle_checkpoint_root,
        epoch_id,
        assertion_vout,
    };
    let stmt_bytes = stmt.encode();
    let stmt_sha = sha256_bytes(&stmt_bytes);
    let limbs_be = split_statement_digest_be_u128(&stmt_sha);

    let steps = (0..3)
        .map(|k| {
            let (cur_r, sibs, next_r) = transitions[k];
            Mnr05UnifiedBatchStep {
                fold_idx: k as u8,
                vault_slot: vault_slots[k],
                cur_nullifier_root: cur_r,
                next_nullifier_root: next_r,
                nullifier_siblings: sibs,
                stripped_tx_348b,
                input_amounts_sats,
                miner_fee_sats,
                oracle: oracle.clone(),
                statement_304b: stmt_bytes,
            }
        })
        .collect();

    let claim = UnifiedBatchPublicClaim {
        initial_nullifier_root,
        final_nullifier_root,
        oracle_checkpoint_root,
        settlement_txid_be,
        auth_accumulator_root,
        bitvm3_statement_304b_sha256: stmt_sha,
        bitvm3_public_limbs_be: limbs_be,
    };
    Ok((steps, claim, stmt))
}

pub fn prove_and_verify_unified_batch(
    steps: &[Mnr05UnifiedBatchStep],
    claim: &UnifiedBatchPublicClaim,
) -> Result<(Vec<u8>, [u8; 32], UnifiedBatchProofReceipt), String> {
    prove_and_verify_unified_batch_with_progress(steps, claim, &mut |_, _, _, _| {})
}

pub fn prove_and_verify_unified_batch_with_progress<F>(
    steps: &[Mnr05UnifiedBatchStep],
    claim: &UnifiedBatchPublicClaim,
    on_progress: &mut F,
) -> Result<(Vec<u8>, [u8; 32], UnifiedBatchProofReceipt), String>
where
    F: FnMut(&str, String, Option<u32>, Option<u32>),
{
    if steps.len() != UNIFIED_FOLDS {
        return Err("expected exactly 3 vault folds".into());
    }
    on_progress(
        "unified_setup",
        "Deriving Bn256EngineIPA/Grumpkin public params & Spartan keys".into(),
        None,
        None,
    );
    let t_setup = std::time::Instant::now();
    let blank = Mnr05UnifiedBatchStep::blank();
    let pp = PublicParams::<B1, B2, Mnr05UnifiedBatchStep>::setup(&blank, &*BS1::ck_floor(), &*BS2::ck_floor())
        .map_err(|e| format!("Unified PublicParams::setup: {e:?}"))?;
    let (pk, vk) = CompressedSNARK::<B1, B2, Mnr05UnifiedBatchStep, BS1, BS2>::setup(&pp)
        .map_err(|e| format!("Unified CompressedSNARK::setup: {e:?}"))?;
    let setup_seconds = t_setup.elapsed().as_secs_f64();

    let z0 = claim.state(0);
    let expected_z3 = claim.state(UNIFIED_FOLDS as u64);

    let vault_names = ["U_AB (99M)", "U_BC (90M)", "U_CA (55M)"];
    let t_fold = std::time::Instant::now();
    let mut rec = RecursiveSNARK::new(&pp, &steps[0], &z0)
        .map_err(|e| format!("Unified RecursiveSNARK::new: {e:?}"))?;
    for (idx, s) in steps.iter().enumerate() {
        on_progress(
            "unified_fold",
            format!(
                "BN254 Unified Batch + Nullifier fold {} / {} ({})",
                idx + 1,
                UNIFIED_FOLDS,
                vault_names[idx]
            ),
            Some((idx + 1) as u32),
            Some(UNIFIED_FOLDS as u32),
        );
        rec.prove_step(&pp, s)
            .map_err(|e| format!("Unified prove_step: {e:?}"))?;
    }
    let z3 = rec
        .verify(&pp, UNIFIED_FOLDS, &z0)
        .map_err(|e| format!("Unified RecursiveSNARK::verify: {e:?}"))?;
    if z3 != expected_z3 {
        return Err("Unified recursive final state mismatch".into());
    }
    let fold_seconds = t_fold.elapsed().as_secs_f64();

    on_progress(
        "unified_compress",
        "Compressing 3-fold BN254 Unified Batch SNARK via Spartan/IPA".into(),
        Some(UNIFIED_FOLDS as u32),
        Some(UNIFIED_FOLDS as u32),
    );
    let t_comp = std::time::Instant::now();
    let compressed = CompressedSNARK::<B1, B2, Mnr05UnifiedBatchStep, BS1, BS2>::prove(&pp, &pk, &rec)
        .map_err(|e| format!("Unified CompressedSNARK::prove: {e:?}"))?;
    let compress_seconds = t_comp.elapsed().as_secs_f64();

    let proof_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&compressed)
        .map_err(|e| format!("serialize Unified proof: {e}"))?;
    let vk_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&vk)
        .map_err(|e| format!("serialize Unified VK: {e}"))?;
    let vk_sha = sha256_bytes(&vk_bytes);
    let proof_sha = sha256_bytes(&proof_bytes);

    let t_ver = std::time::Instant::now();
    let decoded: CompressedSNARK<B1, B2, Mnr05UnifiedBatchStep, BS1, BS2> =
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(&proof_bytes)
            .map_err(|e| format!("deserialize Unified proof: {e}"))?;
    let verified_z3 = decoded
        .verify(&vk, UNIFIED_FOLDS, &z0)
        .map_err(|e| format!("independent Unified verify: {e:?}"))?;
    if verified_z3 != expected_z3 {
        return Err("independent Unified terminal state mismatch".into());
    }

    let mut bad_txid_z0 = z0.clone();
    bad_txid_z0[5] += BnScalar::ONE;
    let wrong_txid_rejected = decoded.verify(&vk, UNIFIED_FOLDS, &bad_txid_z0).is_err();

    let mut bad_null_z3 = expected_z3.clone();
    bad_null_z3[1] += BnScalar::ONE;
    let wrong_null_rejected = verified_z3 != bad_null_z3
        && decoded
            .verify(&vk, UNIFIED_FOLDS, &{
                let mut z = z0.clone();
                z[1] += BnScalar::ONE;
                z
            })
            .is_err();

    if !wrong_txid_rejected || !wrong_null_rejected {
        return Err("Unified negative control failed".into());
    }
    let verify_seconds = t_ver.elapsed().as_secs_f64();
    let (c1, c2) = pp.num_constraints();

    let receipt = UnifiedBatchProofReceipt {
        relation: RELATION_UNIFIED_BATCH_V1.into(),
        curve_cycle: "Bn256EngineIPA / GrumpkinEngine (Spartan + IPA, zero trusted setup)".into(),
        trusted_setup_ceremony: false,
        folds: UNIFIED_FOLDS,
        primary_constraints: c1,
        secondary_constraints: c2,
        initial_nullifier_root_hex: hex::encode(claim.initial_nullifier_root),
        final_nullifier_root_hex: hex::encode(claim.final_nullifier_root),
        oracle_checkpoint_root_hex: hex::encode(claim.oracle_checkpoint_root),
        settlement_txid_hex: hex::encode(claim.settlement_txid_be),
        auth_accumulator_root_hex: hex::encode(claim.auth_accumulator_root),
        bitvm3_statement_304b_sha256_hex: hex::encode(claim.bitvm3_statement_304b_sha256),
        bitvm3_public_limbs_be_dec: [
            claim.bitvm3_public_limbs_be[0].to_string(),
            claim.bitvm3_public_limbs_be[1].to_string(),
        ],
        vk_sha256_hex: hex::encode(vk_sha),
        proof_bytes: proof_bytes.len(),
        proof_sha256_hex: hex::encode(proof_sha),
        setup_seconds,
        fold_seconds,
        compress_seconds,
        verify_seconds,
        wrong_txid_rejected,
        wrong_nullifier_root_rejected: wrong_null_rejected,
    };
    Ok((proof_bytes, vk_sha, receipt))
}
