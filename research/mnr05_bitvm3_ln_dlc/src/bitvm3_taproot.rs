//! `Gate 1b`: Live BitVM3 On-Chain Taproot Assertion & Disprove Tree (`BitVm3AssertionTree`).
//!
//! Implements a 4-leaf BIP-341 NUMS `P2TR` assertion bond contract (`U_Assert`) executable on
//! unmodified `Bitcoin Core v31.1.0` (`BIP-340/341/342`, zero covenant soft-forks):
//! - **Leaf 0 (`optimistic_payout_leaf`)**:
//!   `<challenge_csv> OP_CSV OP_DROP <operator_pk_x> OP_CHECKSIG`
//!   Allows the Operator to reclaim their posted assertion bond (`1,000,000` sats) ONLY after
//!   `challenge_csv_blocks` confirmations elapse unchallenged (`non-BIP68-final` beforehand).
//! - **Leaf 1 (`disprove_boundary_leaf`)**:
//!   `OP_SHA256 OP_DUP <operator_boundary_commit32> OP_EQUALVERIFY <canonical_boundary_hash32> OP_EQUAL OP_NOT OP_VERIFY <challenger_pk_x> OP_CHECKSIG`
//!   Enforces both anti-griefing (`SHA256(preimage) == operator_boundary_commit32`) and objective
//!   fraud detection (`SHA256(preimage) != canonical_boundary_hash32`), allowing any Challenger to
//!   slash a faulty Operator who commits a mismatched `SHZIDX01` oracle checkpoint root or stale
//!   `BatchVaultNullifierTree` root, while making an honest Operator consensus-unslashable.
//! - **Leaf 2 (`disprove_equivocation_leaf`)**:
//!   `OP_SHA256 <h_wire_1> OP_EQUALVERIFY OP_SHA256 <h_wire_0> OP_EQUALVERIFY <challenger_pk_x> OP_CHECKSIG`
//!   Dual-hash BitVM3 state-connector slash: if a dishonest Operator reveals both `0` and `1`
//!   preimages `(pre_0, pre_1)` for an intermediate transcript/circuit bit slot, Challenger
//!   immediately slashes the bond on L1.
//! - **Leaf 3 (`cooperative_close_leaf`)**:
//!   `<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
//!   Sorted 2-of-2 early bond release once watchtowers independently verify the transparent Nova proofs.
#![forbid(unsafe_code)]

use k256::{
    elliptic_curve::{bigint::U256, ops::Reduce},
    ProjectivePoint, Scalar,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shz_dlc::{bip340_sign, bip340_verify, lift_x_even, pubkey_x_from_secret, tagged_hash};
use shz_utxoref::{
    mnr02::{encode_taproot_witness_sig, SegwitTx, SegwitTxIn, SIGHASH_DEFAULT},
    signing_target::{
        point_coordinates, tap_branch_hash, tap_leaf_hash, utxoref_nums_internal_key,
        LEAF_VERSION_TAPSCRIPT,
    },
    UtxoRefError,
};

/// 8-byte domain tag so the complete boundary witness item (`8 + 32 + 32 = 72` bytes) stays
/// strictly within Bitcoin Core's `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80` bytes relay policy!
pub const BITVM3_BOUNDARY_DOMAIN: &[u8; 8] = b"SHZBND01";
pub const BITVM3_WIRE0_DOMAIN: &[u8; 16] = b"SHZ/MNR05/WIRE0:";
pub const BITVM3_WIRE1_DOMAIN: &[u8; 16] = b"SHZ/MNR05/WIRE1:";

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
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

/// Encodes the canonical 72-byte (`<= 80B` Tapscript standardness limit) BitVM3 boundary preimage:
/// `BITVM3_BOUNDARY_DOMAIN (8B) || oracle_checkpoint_root32 (32B) || initial_nullifier_root32 (32B)`.
pub fn encode_boundary_preimage(
    oracle_checkpoint_root: &[u8; 32],
    initial_nullifier_root: &[u8; 32],
) -> [u8; 72] {
    let mut out = [0u8; 72];
    out[0..8].copy_from_slice(BITVM3_BOUNDARY_DOMAIN);
    out[8..40].copy_from_slice(oracle_checkpoint_root);
    out[40..72].copy_from_slice(initial_nullifier_root);
    out
}

pub fn hash_boundary_preimage(
    oracle_checkpoint_root: &[u8; 32],
    initial_nullifier_root: &[u8; 32],
) -> [u8; 32] {
    sha256_bytes(&encode_boundary_preimage(
        oracle_checkpoint_root,
        initial_nullifier_root,
    ))
}

/// Derives a deterministic BitVM3 dual-hash wire state-connector pair `(pre_0, pre_1, h_0, h_1)`.
pub fn derive_wire_connector_pair(
    operator_connector_seed: &[u8; 32],
    wire_index: u32,
) -> ([u8; 52], [u8; 52], [u8; 32], [u8; 32]) {
    let mut sec0_in = b"SHZ/MNR05/CONNECTOR_SEC0:".to_vec();
    sec0_in.extend_from_slice(operator_connector_seed);
    sec0_in.extend_from_slice(&wire_index.to_le_bytes());
    let sec0 = sha256_bytes(&sec0_in);

    let mut sec1_in = b"SHZ/MNR05/CONNECTOR_SEC1:".to_vec();
    sec1_in.extend_from_slice(operator_connector_seed);
    sec1_in.extend_from_slice(&wire_index.to_le_bytes());
    let sec1 = sha256_bytes(&sec1_in);

    let mut pre0 = [0u8; 52];
    pre0[0..16].copy_from_slice(BITVM3_WIRE0_DOMAIN);
    pre0[16..20].copy_from_slice(&wire_index.to_le_bytes());
    pre0[20..52].copy_from_slice(&sec0);

    let mut pre1 = [0u8; 52];
    pre1[0..16].copy_from_slice(BITVM3_WIRE1_DOMAIN);
    pre1[16..20].copy_from_slice(&wire_index.to_le_bytes());
    pre1[20..52].copy_from_slice(&sec1);

    let h0 = sha256_bytes(&pre0);
    let h1 = sha256_bytes(&pre1);
    assert_ne!(h0, h1);
    (pre0, pre1, h0, h1)
}

/// Balanced 4-leaf BIP-341 NUMS `P2TR` BitVM3 assertion bond descriptor (`U_Assert`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitVm3AssertionTree {
    pub internal_xonly: [u8; 32],
    pub operator_pubkey_x: [u8; 32],
    pub challenger_pubkey_x: [u8; 32],
    pub sorted_op_chal: [[u8; 32]; 2],
    pub challenge_csv_blocks: u16,
    pub canonical_boundary_hash: [u8; 32],
    pub operator_boundary_commit: [u8; 32],
    pub wire_hash_0: [u8; 32],
    pub wire_hash_1: [u8; 32],
    pub optimistic_payout_script: Vec<u8>,
    pub disprove_boundary_script: Vec<u8>,
    pub disprove_equivocation_script: Vec<u8>,
    pub cooperative_close_script: Vec<u8>,
    pub optimistic_leaf_hash: [u8; 32],
    pub disprove_boundary_leaf_hash: [u8; 32],
    pub disprove_equivocation_leaf_hash: [u8; 32],
    pub cooperative_leaf_hash: [u8; 32],
    pub optimistic_control_block: Vec<u8>,
    pub disprove_boundary_control_block: Vec<u8>,
    pub disprove_equivocation_control_block: Vec<u8>,
    pub cooperative_control_block: Vec<u8>,
    pub tap_merkle_root: [u8; 32],
    pub script_pubkey: Vec<u8>,
}

impl BitVm3AssertionTree {
    pub fn build(
        operator_pubkey_x: [u8; 32],
        challenger_pubkey_x: [u8; 32],
        challenge_csv_blocks: u16,
        canonical_boundary_hash: [u8; 32],
        operator_boundary_commit: [u8; 32],
        wire_hash_0: [u8; 32],
        wire_hash_1: [u8; 32],
    ) -> Result<Self, UtxoRefError> {
        if operator_pubkey_x == challenger_pubkey_x {
            return Err(UtxoRefError::InvalidFunding(
                "operator and challenger pubkeys must be distinct",
            ));
        }
        if challenge_csv_blocks == 0 {
            return Err(UtxoRefError::InvalidFunding(
                "challenge_csv_blocks must be >= 1",
            ));
        }
        if wire_hash_0 == wire_hash_1 {
            return Err(UtxoRefError::InvalidFunding(
                "dual wire connector hashes must be distinct",
            ));
        }

        let internal_xonly = utxoref_nums_internal_key()?;

        // Leaf 0 (`optimistic_payout_leaf`): `<csv> OP_CSV OP_DROP <operator_pk> OP_CHECKSIG`
        let mut optimistic_payout_script = push_script_num(u64::from(challenge_csv_blocks));
        optimistic_payout_script.extend_from_slice(&[0xb2, 0x75, 0x20]); // OP_CSV OP_DROP <32B>
        optimistic_payout_script.extend_from_slice(&operator_pubkey_x);
        optimistic_payout_script.push(0xac); // OP_CHECKSIG

        // Leaf 1 (`disprove_boundary_leaf`):
        // `OP_SHA256 OP_DUP <operator_commit> OP_EQUALVERIFY <canonical_hash> OP_EQUAL OP_NOT OP_VERIFY <challenger_pk> OP_CHECKSIG`
        let mut disprove_boundary_script = Vec::with_capacity(108);
        disprove_boundary_script.extend_from_slice(&[0xa8, 0x76, 0x20]); // OP_SHA256 OP_DUP <32B>
        disprove_boundary_script.extend_from_slice(&operator_boundary_commit);
        disprove_boundary_script.extend_from_slice(&[0x88, 0x20]); // OP_EQUALVERIFY <32B>
        disprove_boundary_script.extend_from_slice(&canonical_boundary_hash);
        disprove_boundary_script.extend_from_slice(&[0x87, 0x91, 0x69, 0x20]); // OP_EQUAL OP_NOT OP_VERIFY <32B>
        disprove_boundary_script.extend_from_slice(&challenger_pubkey_x);
        disprove_boundary_script.push(0xac); // OP_CHECKSIG

        // Leaf 2 (`disprove_equivocation_leaf`):
        // `OP_SHA256 <h_wire_1> OP_EQUALVERIFY OP_SHA256 <h_wire_0> OP_EQUALVERIFY <challenger_pk> OP_CHECKSIG`
        let mut disprove_equivocation_script = Vec::with_capacity(103);
        disprove_equivocation_script.extend_from_slice(&[0xa8, 0x20]); // OP_SHA256 <32B>
        disprove_equivocation_script.extend_from_slice(&wire_hash_1);
        disprove_equivocation_script.extend_from_slice(&[0x88, 0xa8, 0x20]); // OP_EQUALVERIFY OP_SHA256 <32B>
        disprove_equivocation_script.extend_from_slice(&wire_hash_0);
        disprove_equivocation_script.extend_from_slice(&[0x88, 0x20]); // OP_EQUALVERIFY <32B>
        disprove_equivocation_script.extend_from_slice(&challenger_pubkey_x);
        disprove_equivocation_script.push(0xac); // OP_CHECKSIG

        // Leaf 3 (`cooperative_close_leaf`): `<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`
        let sorted_op_chal = if operator_pubkey_x < challenger_pubkey_x {
            [operator_pubkey_x, challenger_pubkey_x]
        } else {
            [challenger_pubkey_x, operator_pubkey_x]
        };
        let mut cooperative_close_script = Vec::with_capacity(68);
        cooperative_close_script.push(0x20);
        cooperative_close_script.extend_from_slice(&sorted_op_chal[0]);
        cooperative_close_script.extend_from_slice(&[0xad, 0x20]);
        cooperative_close_script.extend_from_slice(&sorted_op_chal[1]);
        cooperative_close_script.push(0xac);

        let optimistic_leaf_hash = tap_leaf_hash(&optimistic_payout_script);
        let disprove_boundary_leaf_hash = tap_leaf_hash(&disprove_boundary_script);
        let disprove_equivocation_leaf_hash = tap_leaf_hash(&disprove_equivocation_script);
        let cooperative_leaf_hash = tap_leaf_hash(&cooperative_close_script);

        let branch_01 = tap_branch_hash(&optimistic_leaf_hash, &disprove_boundary_leaf_hash);
        let branch_23 = tap_branch_hash(&disprove_equivocation_leaf_hash, &cooperative_leaf_hash);
        let tap_merkle_root = tap_branch_hash(&branch_01, &branch_23);

        let mut tweak_in = [0u8; 64];
        tweak_in[..32].copy_from_slice(&internal_xonly);
        tweak_in[32..].copy_from_slice(&tap_merkle_root);
        let tweak = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tagged_hash(
            b"TapTweak",
            &tweak_in,
        )));
        let internal_pt = lift_x_even(&internal_xonly)
            .map_err(|_| UtxoRefError::InvalidCrypto("NUMS lift_x"))?;
        let (out_x, out_y) = point_coordinates(internal_pt + ProjectivePoint::GENERATOR * tweak)?;
        let ctrl_header = LEAF_VERSION_TAPSCRIPT | (out_y[31] & 1);

        let make_ctrl = |sib_leaf: &[u8; 32], sib_branch: &[u8; 32]| -> Vec<u8> {
            let mut cb = Vec::with_capacity(97);
            cb.push(ctrl_header);
            cb.extend_from_slice(&internal_xonly);
            cb.extend_from_slice(sib_leaf);
            cb.extend_from_slice(sib_branch);
            cb
        };

        let mut script_pubkey = Vec::with_capacity(34);
        script_pubkey.extend_from_slice(&[0x51, 0x20]);
        script_pubkey.extend_from_slice(&out_x);

        Ok(Self {
            internal_xonly,
            operator_pubkey_x,
            challenger_pubkey_x,
            sorted_op_chal,
            challenge_csv_blocks,
            canonical_boundary_hash,
            operator_boundary_commit,
            wire_hash_0,
            wire_hash_1,
            optimistic_payout_script,
            disprove_boundary_script,
            disprove_equivocation_script,
            cooperative_close_script,
            optimistic_leaf_hash,
            disprove_boundary_leaf_hash,
            disprove_equivocation_leaf_hash,
            cooperative_leaf_hash,
            optimistic_control_block: make_ctrl(&disprove_boundary_leaf_hash, &branch_23),
            disprove_boundary_control_block: make_ctrl(&optimistic_leaf_hash, &branch_23),
            disprove_equivocation_control_block: make_ctrl(&cooperative_leaf_hash, &branch_01),
            cooperative_control_block: make_ctrl(&disprove_equivocation_leaf_hash, &branch_01),
            tap_merkle_root,
            script_pubkey,
        })
    }

    /// Builds and signs the Operator's CSV-timelocked optimistic bond reclaim transaction (`Leaf 0`).
    pub fn sign_optimistic_payout_tx(
        &self,
        assert_txid_display: &str,
        assert_vout: u32,
        bond_sats: u64,
        fee_sats: u64,
        operator_sk: &[u8; 32],
        operator_payout_spk: Vec<u8>,
    ) -> Result<SegwitTx, UtxoRefError> {
        if pubkey_x_from_secret(operator_sk).map_err(|_| UtxoRefError::InvalidCrypto("op_sk"))?
            != self.operator_pubkey_x
        {
            return Err(UtxoRefError::InvalidCrypto("operator_sk mismatch"));
        }
        let inp = SegwitTxIn::from_display_txid(
            assert_txid_display,
            assert_vout,
            u32::from(self.challenge_csv_blocks),
            bond_sats,
            self.script_pubkey.clone(),
        )?;
        let mut tx = SegwitTx {
            version: 2,
            inputs: vec![inp],
            outputs: vec![(
                bond_sats
                    .checked_sub(fee_sats)
                    .ok_or(UtxoRefError::AccountingViolation("bond < fee"))?,
                operator_payout_spk,
            )],
            locktime: 0,
        };
        let sh = tx.bip341_sighash(0, SIGHASH_DEFAULT, Some(&self.optimistic_leaf_hash))?;
        let sig =
            bip340_sign(operator_sk, &sh).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
        bip340_verify(&self.operator_pubkey_x, &sh, &sig)
            .map_err(|_| UtxoRefError::InvalidCrypto("verify"))?;
        tx.inputs[0].witness = vec![
            encode_taproot_witness_sig(&sig, SIGHASH_DEFAULT),
            self.optimistic_payout_script.clone(),
            self.optimistic_control_block.clone(),
        ];
        Ok(tx)
    }

    /// Builds and signs Challenger's immediate boundary-fraud slash transaction (`Leaf 1`).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_disprove_boundary_tx(
        &self,
        assert_txid_display: &str,
        assert_vout: u32,
        bond_sats: u64,
        fee_sats: u64,
        challenger_sk: &[u8; 32],
        challenger_payout_spk: Vec<u8>,
        revealed_operator_boundary_preimage: &[u8],
    ) -> Result<SegwitTx, UtxoRefError> {
        if pubkey_x_from_secret(challenger_sk)
            .map_err(|_| UtxoRefError::InvalidCrypto("chal_sk"))?
            != self.challenger_pubkey_x
        {
            return Err(UtxoRefError::InvalidCrypto("challenger_sk mismatch"));
        }
        let inp = SegwitTxIn::from_display_txid(
            assert_txid_display,
            assert_vout,
            0xffff_fffe,
            bond_sats,
            self.script_pubkey.clone(),
        )?;
        let mut tx = SegwitTx {
            version: 2,
            inputs: vec![inp],
            outputs: vec![(
                bond_sats
                    .checked_sub(fee_sats)
                    .ok_or(UtxoRefError::AccountingViolation("bond < fee"))?,
                challenger_payout_spk,
            )],
            locktime: 0,
        };
        let sh =
            tx.bip341_sighash(0, SIGHASH_DEFAULT, Some(&self.disprove_boundary_leaf_hash))?;
        let sig =
            bip340_sign(challenger_sk, &sh).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
        bip340_verify(&self.challenger_pubkey_x, &sh, &sig)
            .map_err(|_| UtxoRefError::InvalidCrypto("verify"))?;
        tx.inputs[0].witness = vec![
            encode_taproot_witness_sig(&sig, SIGHASH_DEFAULT),
            revealed_operator_boundary_preimage.to_vec(),
            self.disprove_boundary_script.clone(),
            self.disprove_boundary_control_block.clone(),
        ];
        Ok(tx)
    }

    /// Builds and signs Challenger's immediate dual-hash equivocation slash transaction (`Leaf 2`).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_disprove_equivocation_tx(
        &self,
        assert_txid_display: &str,
        assert_vout: u32,
        bond_sats: u64,
        fee_sats: u64,
        challenger_sk: &[u8; 32],
        challenger_payout_spk: Vec<u8>,
        revealed_preimage_0: &[u8],
        revealed_preimage_1: &[u8],
    ) -> Result<SegwitTx, UtxoRefError> {
        if pubkey_x_from_secret(challenger_sk)
            .map_err(|_| UtxoRefError::InvalidCrypto("chal_sk"))?
            != self.challenger_pubkey_x
        {
            return Err(UtxoRefError::InvalidCrypto("challenger_sk mismatch"));
        }
        let inp = SegwitTxIn::from_display_txid(
            assert_txid_display,
            assert_vout,
            0xffff_fffe,
            bond_sats,
            self.script_pubkey.clone(),
        )?;
        let mut tx = SegwitTx {
            version: 2,
            inputs: vec![inp],
            outputs: vec![(
                bond_sats
                    .checked_sub(fee_sats)
                    .ok_or(UtxoRefError::AccountingViolation("bond < fee"))?,
                challenger_payout_spk,
            )],
            locktime: 0,
        };
        let sh = tx.bip341_sighash(
            0,
            SIGHASH_DEFAULT,
            Some(&self.disprove_equivocation_leaf_hash),
        )?;
        let sig =
            bip340_sign(challenger_sk, &sh).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
        bip340_verify(&self.challenger_pubkey_x, &sh, &sig)
            .map_err(|_| UtxoRefError::InvalidCrypto("verify"))?;
        tx.inputs[0].witness = vec![
            encode_taproot_witness_sig(&sig, SIGHASH_DEFAULT),
            revealed_preimage_0.to_vec(),
            revealed_preimage_1.to_vec(),
            self.disprove_equivocation_script.clone(),
            self.disprove_equivocation_control_block.clone(),
        ];
        Ok(tx)
    }
}
