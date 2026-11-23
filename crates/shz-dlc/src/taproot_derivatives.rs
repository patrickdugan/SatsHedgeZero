//! 4-Leaf `UTXORef` NUMS `P2TR` Taproot Tree for Bilateral Option & Swap Contracts
//! (`taproot_derivatives.rs`).
//!
//! Unifies **Inverse Swaps** (`Perpetual` / `Dated`) and **European Vanilla Options** (`Call` / `Put`)
//! under a balanced 2-level, 4-leaf BIP-341 Tapscript (`0xc0`) Merkle tree anchored to the
//! unspendable `UTXORef` NUMS internal key (`c99e9965166e7ff80516494709db8fdfdc31b0626500bb70dc3652fc2ff584ab`):
//!
//! - **Leaf 0 (`coop_novation_leaf`):** `<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
//!   Enables instant 0-fee off-chain cooperative close OR **atomic L1 Taproot position transfer
//!   (novation)** from `Holder` (`Alice`) to `Transferee` (`Dave`) into a successor `P2TR`!
//! - **Leaf 1 (`routed_clearing_leaf`, `nLockTime = maturity_height`):**
//!   `<P_Holder> OP_CHECKSIGVERIFY <P_ClearingGuard> OP_CHECKSIGVERIFY <P_Counterparty> OP_CHECKSIG`
//!   Enables `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) origination pre-signatures so
//!   multilateral portfolio clearing & offline-counterparty claim assignment execute even when
//!   `Counterparty` is **100% offline**!
//! - **Leaf 2 (`unilateral_cet_leaf`, `nLockTime = maturity_height + grace_blocks`):**
//!   `<maturity + grace> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
//!   Pre-signed BIP-340 adaptor signatures over dyadic-compressed Option/Swap CET ranges,
//!   preserving trustless unilateral exercise/settlement if `ClearingGuard` disappears!
//! - **Leaf 3 (`refund_leaf`, `nLockTime = maturity_height + refund_delay_blocks`):**
//!   `<maturity + refund_delay> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
//!   Pre-signed 2-of-2 timeout recovery returning initial margins/premiums if the oracle fails.

use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    AffinePoint, ProjectivePoint, Scalar, U256,
    elliptic_curve::{Group, ops::Reduce, sec1::ToEncodedPoint},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_margin::DerivativeContractSpec;

use crate::{
    AdaptorSignature, Bip340Signature, DlcError, adaptor_sign, adaptor_verify, bip340_sign,
    bip340_verify, lift_x_even, pubkey_x_from_secret, tagged_hash,
};

pub const UTXOREF_NUMS_DOMAIN: &str = "UTXORef DLC funding NUMS internal key v1";
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;
pub const MIN_P2TR_DUST_SATS: u64 = 330;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn compact_size(value: usize) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(value as u32).to_le_bytes());
            out
        }
    }
}

fn push_script_num(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    if value <= 16 {
        return vec![0x50 + value as u8];
    }
    let mut bytes = Vec::new();
    let mut rem = value;
    while rem > 0 {
        bytes.push((rem & 0xff) as u8);
        rem >>= 8;
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(0);
    }
    let mut script = vec![bytes.len() as u8];
    script.extend(bytes);
    script
}

fn point_xy(point: ProjectivePoint) -> Result<([u8; 32], [u8; 32]), DlcError> {
    if bool::from(point.is_identity()) {
        return Err(DlcError::InvalidAdaptorPoint);
    }
    let enc = AffinePoint::from(point).to_encoded_point(false);
    let x: [u8; 32] = enc.x().ok_or(DlcError::InvalidPublicKey)?[..]
        .try_into()
        .map_err(|_| DlcError::InvalidPublicKey)?;
    let y: [u8; 32] = enc.y().ok_or(DlcError::InvalidPublicKey)?[..]
        .try_into()
        .map_err(|_| DlcError::InvalidPublicKey)?;
    Ok((x, y))
}

pub fn tap_leaf_hash(script: &[u8]) -> [u8; 32] {
    let mut payload = vec![TAPSCRIPT_LEAF_VERSION];
    payload.extend(compact_size(script.len()));
    payload.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &payload)
}

pub fn tap_branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    if left <= right {
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
    } else {
        buf[..32].copy_from_slice(right);
        buf[32..].copy_from_slice(left);
    }
    tagged_hash(b"TapBranch", &buf)
}

pub fn derive_utxoref_nums_internal_key() -> Result<[u8; 32], DlcError> {
    for counter in 0..1024u32 {
        let candidate = sha256(format!("{UTXOREF_NUMS_DOMAIN}:{counter}").as_bytes());
        if lift_x_even(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(DlcError::InvalidPublicKey)
}

/// Balanced 4-leaf `UTXORef` NUMS `P2TR` Taproot descriptor for Option and Swap contracts.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TaprootDerivativeTree {
    pub internal_xonly: [u8; 32],
    pub holder_pubkey_x: [u8; 32],
    pub counterparty_pubkey_x: [u8; 32],
    pub clearing_guard_pubkey_x: [u8; 32],
    pub sorted_pair: [[u8; 32]; 2],
    pub maturity_height: u32,
    pub unilateral_cltv_height: u32,
    pub refund_cltv_height: u32,
    pub coop_novation_script: Vec<u8>,
    pub routed_clearing_script: Vec<u8>,
    pub unilateral_cet_script: Vec<u8>,
    pub refund_script: Vec<u8>,
    pub coop_novation_leaf_hash: [u8; 32],
    pub routed_clearing_leaf_hash: [u8; 32],
    pub unilateral_cet_leaf_hash: [u8; 32],
    pub refund_leaf_hash: [u8; 32],
    pub coop_novation_control_block: Vec<u8>,
    pub routed_clearing_control_block: Vec<u8>,
    pub unilateral_cet_control_block: Vec<u8>,
    pub refund_control_block: Vec<u8>,
    pub tap_merkle_root: [u8; 32],
    pub script_pubkey: Vec<u8>,
}

impl TaprootDerivativeTree {
    pub fn build(
        holder_pubkey_x: [u8; 32],
        counterparty_pubkey_x: [u8; 32],
        clearing_guard_pubkey_x: [u8; 32],
        maturity_height: u32,
        grace_blocks: u32,
        refund_delay_blocks: u32,
    ) -> Result<Self, DlcError> {
        if holder_pubkey_x == counterparty_pubkey_x
            || holder_pubkey_x == clearing_guard_pubkey_x
            || counterparty_pubkey_x == clearing_guard_pubkey_x
        {
            return Err(DlcError::InvalidPublicKey);
        }
        if grace_blocks == 0 || refund_delay_blocks <= grace_blocks {
            return Err(DlcError::InvalidState(
                "require 0 < grace_blocks < refund_delay_blocks",
            ));
        }
        lift_x_even(&holder_pubkey_x)?;
        lift_x_even(&counterparty_pubkey_x)?;
        lift_x_even(&clearing_guard_pubkey_x)?;

        let internal_xonly = derive_utxoref_nums_internal_key()?;
        let sorted_pair = if holder_pubkey_x < counterparty_pubkey_x {
            [holder_pubkey_x, counterparty_pubkey_x]
        } else {
            [counterparty_pubkey_x, holder_pubkey_x]
        };

        // Leaf 0: `<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
        let mut coop_novation_script = Vec::with_capacity(68);
        coop_novation_script.push(0x20);
        coop_novation_script.extend_from_slice(&sorted_pair[0]);
        coop_novation_script.extend_from_slice(&[0xad, 0x20]);
        coop_novation_script.extend_from_slice(&sorted_pair[1]);
        coop_novation_script.push(0xac);

        // Leaf 1: `<P_Holder> OP_CHECKSIGVERIFY <P_Guard> OP_CHECKSIGVERIFY <P_Counterparty> OP_CHECKSIG`
        let mut routed_clearing_script = Vec::with_capacity(101);
        routed_clearing_script.push(0x20);
        routed_clearing_script.extend_from_slice(&holder_pubkey_x);
        routed_clearing_script.extend_from_slice(&[0xad, 0x20]);
        routed_clearing_script.extend_from_slice(&clearing_guard_pubkey_x);
        routed_clearing_script.extend_from_slice(&[0xad, 0x20]);
        routed_clearing_script.extend_from_slice(&counterparty_pubkey_x);
        routed_clearing_script.push(0xac);

        let unilateral_cltv_height = maturity_height + grace_blocks;
        let refund_cltv_height = maturity_height + refund_delay_blocks;

        // Leaf 2: `<unilateral_cltv> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
        let mut unilateral_cet_script = push_script_num(unilateral_cltv_height as u64);
        unilateral_cet_script.extend_from_slice(&[0xb1, 0x75, 0x20]);
        unilateral_cet_script.extend_from_slice(&sorted_pair[0]);
        unilateral_cet_script.extend_from_slice(&[0xad, 0x20]);
        unilateral_cet_script.extend_from_slice(&sorted_pair[1]);
        unilateral_cet_script.push(0xac);

        // Leaf 3: `<refund_cltv> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
        let mut refund_script = push_script_num(refund_cltv_height as u64);
        refund_script.extend_from_slice(&[0xb1, 0x75, 0x20]);
        refund_script.extend_from_slice(&sorted_pair[0]);
        refund_script.extend_from_slice(&[0xad, 0x20]);
        refund_script.extend_from_slice(&sorted_pair[1]);
        refund_script.push(0xac);

        let l0 = tap_leaf_hash(&coop_novation_script);
        let l1 = tap_leaf_hash(&routed_clearing_script);
        let l2 = tap_leaf_hash(&unilateral_cet_script);
        let l3 = tap_leaf_hash(&refund_script);

        // Balanced 2-level Merkle tree: `branch_01 = (l0, l1)`, `branch_23 = (l2, l3)` -> `97`-byte control blocks!
        let branch_01 = tap_branch_hash(&l0, &l1);
        let branch_23 = tap_branch_hash(&l2, &l3);
        let tap_merkle_root = tap_branch_hash(&branch_01, &branch_23);

        let mut tweak_in = [0u8; 64];
        tweak_in[..32].copy_from_slice(&internal_xonly);
        tweak_in[32..].copy_from_slice(&tap_merkle_root);
        let tweak = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tagged_hash(
            b"TapTweak",
            &tweak_in,
        )));

        let internal_pt = lift_x_even(&internal_xonly)?;
        let (out_x, out_y) = point_xy(internal_pt + ProjectivePoint::GENERATOR * tweak)?;
        let parity_bit = out_y[31] & 1;
        let ctrl_hdr = TAPSCRIPT_LEAF_VERSION | parity_bit;

        let make_cb = |sibling_leaf: &[u8; 32], sibling_branch: &[u8; 32]| -> Vec<u8> {
            let mut cb = Vec::with_capacity(97);
            cb.push(ctrl_hdr);
            cb.extend_from_slice(&internal_xonly);
            cb.extend_from_slice(sibling_leaf);
            cb.extend_from_slice(sibling_branch);
            cb
        };

        let mut script_pubkey = Vec::with_capacity(34);
        script_pubkey.extend_from_slice(&[0x51, 0x20]);
        script_pubkey.extend_from_slice(&out_x);

        Ok(Self {
            internal_xonly,
            holder_pubkey_x,
            counterparty_pubkey_x,
            clearing_guard_pubkey_x,
            sorted_pair,
            maturity_height,
            unilateral_cltv_height,
            refund_cltv_height,
            coop_novation_script,
            routed_clearing_script,
            unilateral_cet_script,
            refund_script,
            coop_novation_leaf_hash: l0,
            routed_clearing_leaf_hash: l1,
            unilateral_cet_leaf_hash: l2,
            refund_leaf_hash: l3,
            coop_novation_control_block: make_cb(&l1, &branch_23),
            routed_clearing_control_block: make_cb(&l0, &branch_23),
            unilateral_cet_control_block: make_cb(&l3, &branch_01),
            refund_control_block: make_cb(&l2, &branch_01),
            tap_merkle_root,
            script_pubkey,
        })
    }

    /// Independently verifies that `(script, control_block)` cryptographically reconstructs `self.script_pubkey`.
    pub fn verify_control_block(&self, script: &[u8], control_block: &[u8]) -> Result<[u8; 32], DlcError> {
        if control_block.len() != 97 || (control_block[0] & 0xfe) != TAPSCRIPT_LEAF_VERSION {
            return Err(DlcError::InvalidState("expected 97-byte 4-leaf Tapscript control block"));
        }
        let expected_parity = control_block[0] & 1;
        let internal: [u8; 32] = control_block[1..33].try_into().unwrap();
        if internal != self.internal_xonly {
            return Err(DlcError::InvalidPublicKey);
        }
        let sib1: [u8; 32] = control_block[33..65].try_into().unwrap();
        let sib2: [u8; 32] = control_block[65..97].try_into().unwrap();

        let leaf_hash = tap_leaf_hash(script);
        let b1 = tap_branch_hash(&leaf_hash, &sib1);
        let root = tap_branch_hash(&b1, &sib2);

        let mut tweak_in = [0u8; 64];
        tweak_in[..32].copy_from_slice(&internal);
        tweak_in[32..].copy_from_slice(&root);
        let tweak = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tagged_hash(
            b"TapTweak",
            &tweak_in,
        )));
        let (out_x, out_y) = point_xy(lift_x_even(&internal)? + ProjectivePoint::GENERATOR * tweak)?;
        if (out_y[31] & 1) != expected_parity || self.script_pubkey[2..] != out_x {
            return Err(DlcError::InvalidState(
                "Taproot control block failed P2TR output reconstruction",
            ));
        }
        Ok(leaf_hash)
    }
}

/// Pre-signed outcome commitment for a Taproot Option or Swap contract at `price_usd`.
#[derive(Debug, Clone)]
pub struct PreSignedDerivativeOutcome {
    pub price_usd: u64,
    pub holder_payout_sats: u64,
    pub counterparty_payout_sats: u64,
    pub counterparty_0x83_sighash: [u8; 32],
    pub counterparty_0x83_adaptor_sig: AdaptorSignature,
    pub unilateral_sighash: [u8; 32],
    pub holder_unilateral_adaptor_sig: AdaptorSignature,
    pub counterparty_unilateral_adaptor_sig: AdaptorSignature,
}

/// Verified origination bundle for a Taproot Option or Swap contract (`zero secret keys` retained).
#[derive(Debug, Clone)]
pub struct TaprootDerivativeOrigination {
    pub contract_id: [u8; 32],
    pub contract: DerivativeContractSpec,
    pub tree: TaprootDerivativeTree,
    pub funding_sats: u64,
    pub miner_fee_sats: u64,
    pub refund_sighash: [u8; 32],
    pub holder_refund_sig: Bip340Signature,
    pub counterparty_refund_sig: Bip340Signature,
    pub outcomes: Vec<PreSignedDerivativeOutcome>,
}

/// Constructs and verifies a complete `TaprootDerivativeOrigination` package for either an
/// **Inverse Swap** or a **European Call/Put Option** in Taproot!
#[allow(clippy::too_many_arguments)]
pub fn build_taproot_derivative_origination(
    contract_id: [u8; 32],
    contract: DerivativeContractSpec,
    holder_sk: &[u8; 32],
    counterparty_sk: &[u8; 32],
    clearing_guard_pk: [u8; 32],
    maturity_height: u32,
    grace_blocks: u32,
    refund_delay_blocks: u32,
    miner_fee_sats: u64,
    refund_sighash_fn: impl Fn(&TaprootDerivativeTree, u64, u64) -> [u8; 32],
    outcome_sighash_fn: impl Fn(&TaprootDerivativeTree, u64, u64, u64) -> ([u8; 32], [u8; 32]),
    outcome_prices_and_points: &[(u64, ProjectivePoint)],
) -> Result<TaprootDerivativeOrigination, DlcError> {
    contract.validate_v0()?;
    let holder_pk = pubkey_x_from_secret(holder_sk)?;
    let counterparty_pk = pubkey_x_from_secret(counterparty_sk)?;

    let tree = TaprootDerivativeTree::build(
        holder_pk,
        counterparty_pk,
        clearing_guard_pk,
        maturity_height,
        grace_blocks,
        refund_delay_blocks,
    )?;

    // Verify all 4 control blocks reconstruct `tree.script_pubkey`!
    tree.verify_control_block(&tree.coop_novation_script, &tree.coop_novation_control_block)?;
    tree.verify_control_block(&tree.routed_clearing_script, &tree.routed_clearing_control_block)?;
    tree.verify_control_block(&tree.unilateral_cet_script, &tree.unilateral_cet_control_block)?;
    tree.verify_control_block(&tree.refund_script, &tree.refund_control_block)?;

    let funding_sats = contract.total_collateral_sats();
    let distributable = funding_sats
        .checked_sub(miner_fee_sats + MIN_P2TR_DUST_SATS)
        .ok_or(DlcError::InvalidState("derivative collateral < fee + 330 anchor"))?;
    if distributable < 2 * MIN_P2TR_DUST_SATS {
        return Err(DlcError::InvalidState("distributable collateral < 2 * 330 dust"));
    }

    let refund_holder = contract
        .holder_contribution_sats()
        .saturating_sub(miner_fee_sats / 2 + MIN_P2TR_DUST_SATS / 2)
        .clamp(MIN_P2TR_DUST_SATS, distributable - MIN_P2TR_DUST_SATS);
    let refund_cp = distributable - refund_holder;

    let refund_sighash = refund_sighash_fn(&tree, refund_holder, refund_cp);
    let holder_refund_sig = bip340_sign(holder_sk, &refund_sighash)?;
    let counterparty_refund_sig = bip340_sign(counterparty_sk, &refund_sighash)?;
    bip340_verify(&holder_pk, &refund_sighash, &holder_refund_sig)?;
    bip340_verify(&counterparty_pk, &refund_sighash, &counterparty_refund_sig)?;

    let mut outcomes = Vec::with_capacity(outcome_prices_and_points.len());
    for &(price_usd, ref adaptor_pt) in outcome_prices_and_points {
        let raw_split = contract.payout_at_price(price_usd);
        // Scale/clamp exact economic split onto L1 `distributable` keeping both >= 330-sat P2TR dust!
        let raw_cp = raw_split
            .short_sats
            .clamp(MIN_P2TR_DUST_SATS, distributable - MIN_P2TR_DUST_SATS);
        let raw_holder = distributable - raw_cp;

        let (sighash_0x83, sighash_uni) =
            outcome_sighash_fn(&tree, price_usd, raw_holder, raw_cp);

        let cp_0x83_asig = adaptor_sign(counterparty_sk, &sighash_0x83, adaptor_pt)?;
        adaptor_verify(&counterparty_pk, &sighash_0x83, adaptor_pt, &cp_0x83_asig)?;

        let holder_uni_asig = adaptor_sign(holder_sk, &sighash_uni, adaptor_pt)?;
        let cp_uni_asig = adaptor_sign(counterparty_sk, &sighash_uni, adaptor_pt)?;
        adaptor_verify(&holder_pk, &sighash_uni, adaptor_pt, &holder_uni_asig)?;
        adaptor_verify(&counterparty_pk, &sighash_uni, adaptor_pt, &cp_uni_asig)?;

        outcomes.push(PreSignedDerivativeOutcome {
            price_usd,
            holder_payout_sats: raw_holder,
            counterparty_payout_sats: raw_cp,
            counterparty_0x83_sighash: sighash_0x83,
            counterparty_0x83_adaptor_sig: cp_0x83_asig,
            unilateral_sighash: sighash_uni,
            holder_unilateral_adaptor_sig: holder_uni_asig,
            counterparty_unilateral_adaptor_sig: cp_uni_asig,
        });
    }

    Ok(TaprootDerivativeOrigination {
        contract_id,
        contract,
        tree,
        funding_sats,
        miner_fee_sats,
        refund_sighash,
        holder_refund_sig,
        counterparty_refund_sig,
        outcomes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shz_margin::{InverseContractSpec, InverseOptionSpec, OptionKind, SwapTenor};

    #[test]
    fn test_four_leaf_taproot_tree_verifies_both_option_and_swap_originations() {
        let alice_sk = [0x11u8; 32];
        let bob_sk = [0x22u8; 32];
        let guard_pk = pubkey_x_from_secret(&[0x24u8; 32]).unwrap();

        let t_90k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(90_000));
        let t_125k = <Scalar as Reduce<U256>>::reduce(U256::from_u64(125_000));
        let grid = vec![
            (90_000, ProjectivePoint::GENERATOR * t_90k),
            (125_000, ProjectivePoint::GENERATOR * t_125k),
        ];

        // 1. European Call Option in Taproot ($100k strike, 1.0 BTC covered)
        let call = DerivativeContractSpec::EuropeanOption(
            InverseOptionSpec::new_v0(
                OptionKind::Call,
                100_000,
                1_800_000_000,
                100_000_000,
                5_000_000,
                100_000_000,
            )
            .unwrap(),
        );
        let call_orig = build_taproot_derivative_origination(
            [0xAA; 32],
            call,
            &alice_sk,
            &bob_sk,
            guard_pk,
            200,
            20,
            60,
            1_000,
            |tree, h, c| tagged_hash(b"test-refund", &[&tree.refund_leaf_hash[..], &h.to_le_bytes(), &c.to_le_bytes()].concat()),
            |tree, p, h, c| {
                let s83 = tagged_hash(b"test-0x83", &[&tree.routed_clearing_leaf_hash[..], &p.to_le_bytes(), &c.to_le_bytes()].concat());
                let suni = tagged_hash(b"test-uni", &[&tree.unilateral_cet_leaf_hash[..], &p.to_le_bytes(), &h.to_le_bytes(), &c.to_le_bytes()].concat());
                (s83, suni)
            },
            &grid,
        )
        .unwrap();
        assert_eq!(call_orig.tree.script_pubkey.len(), 34);
        assert_eq!(call_orig.outcomes[1].holder_payout_sats, 20_000_000 - 1_330);

        // 2. Dated Inverse Swap in Taproot ($10,000 @ $100,000, 5x Long vs 1x Short)
        let swap = DerivativeContractSpec::InverseSwap {
            tenor: SwapTenor::Dated {
                expiry_timestamp: 1_800_000_000,
            },
            spec: InverseContractSpec::from_leverages_v0(10_000, 100_000, 50_000, 10_000).unwrap(),
        };
        let swap_orig = build_taproot_derivative_origination(
            [0xBB; 32],
            swap,
            &alice_sk,
            &bob_sk,
            guard_pk,
            200,
            20,
            60,
            1_000,
            |tree, h, c| tagged_hash(b"test-refund", &[&tree.refund_leaf_hash[..], &h.to_le_bytes(), &c.to_le_bytes()].concat()),
            |tree, p, h, c| {
                let s83 = tagged_hash(b"test-0x83", &[&tree.routed_clearing_leaf_hash[..], &p.to_le_bytes(), &c.to_le_bytes()].concat());
                let suni = tagged_hash(b"test-uni", &[&tree.unilateral_cet_leaf_hash[..], &p.to_le_bytes(), &h.to_le_bytes(), &c.to_le_bytes()].concat());
                (s83, suni)
            },
            &grid,
        )
        .unwrap();
        assert_eq!(swap_orig.funding_sats, 12_000_000);
        assert_eq!(swap_orig.outcomes.len(), 2);
    }
}
