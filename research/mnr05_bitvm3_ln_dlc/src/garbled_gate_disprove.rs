//! `Track 4 / Milestone M5`: BitVM3 Garbled `NAND` Gate Commitment & Live `Bitcoin Core v31.1.0`
//! Tapscript Gate-Evaluation Disprover (`disprove_garbled_gate_leaf`).
//!
//! Combines:
//! 1. **Off-Chain Yao / SHA-256 Garbled Gate Table (`GarbledNandGate`):**
//!    Encrypts each truth-table row `(u, v) in {0,1}^2` as
//!    `C_{u,v} = L_{c, NAND(u,v)} XOR SHA256("SHZ/MNR05/GARBLE_ROW/V1" || gate_id || L_{a,u} || L_{b,v})`
//!    so an evaluator holding only `(L_{a,u}, L_{b,v})` recovers `L_{c, NAND(u,v)}` without learning
//!    any complementary wire labels.
//! 2. **On-Chain BIP-342 Tapscript Gate Disprover (`GarbledGateTaprootTree`):**
//!    Commits `(H_{a,0}, H_{a,1}), (H_{b,0}, H_{b,1}), (H_{c,0}, H_{c,1})` (`H_{w,b} = SHA256(L_{w,b})`)
//!    with 32-byte labels (`<= 80 B` `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`).
//!    In pure unmodified Bitcoin Script (`OP_SHA256`, `OP_EQUAL`, `OP_BOOLOR`, `OP_BOOLAND`,
//!    `OP_NOT`, `OP_NUMNOTEQUAL`, `OP_VERIFY`, `OP_CHECKSIG`), verifies that `(L_a, L_b, L_c)` are
//!    authentic Operator-revealed wire labels AND proves `bit_c != NAND(bit_a, bit_b)`, slashing
//!    the Operator's bond on `Bitcoin Core v31.1.0` whenever ANY gate in the circuit is falsified!
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

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GarbledWireCommitments {
    pub hash_a: [[u8; 32]; 2],
    pub hash_b: [[u8; 32]; 2],
    pub hash_c: [[u8; 32]; 2],
}

#[derive(Clone, Debug)]
pub struct GarbledNandGate {
    pub gate_id: u32,
    pub labels_a: [[u8; 32]; 2],
    pub labels_b: [[u8; 32]; 2],
    pub labels_c: [[u8; 32]; 2],
    pub commitments: GarbledWireCommitments,
    /// Permuted/indexed ciphertexts `ciphertexts[u][v]` (`u, v in {0, 1}`).
    pub ciphertexts: [[[u8; 32]; 2]; 2],
}

impl GarbledNandGate {
    pub fn garble_deterministic(master_seed: &[u8; 32], gate_id: u32) -> Self {
        let derive_label = |wire: u8, bit: u8| -> [u8; 32] {
            let mut pre = b"SHZ/MNR05/WIRE_LABEL/V1:".to_vec();
            pre.extend_from_slice(master_seed);
            pre.extend_from_slice(&gate_id.to_le_bytes());
            pre.push(wire);
            pre.push(bit);
            sha256_bytes(&pre)
        };

        let labels_a = [derive_label(0, 0), derive_label(0, 1)];
        let labels_b = [derive_label(1, 0), derive_label(1, 1)];
        let labels_c = [derive_label(2, 0), derive_label(2, 1)];

        let commitments = GarbledWireCommitments {
            hash_a: [sha256_bytes(&labels_a[0]), sha256_bytes(&labels_a[1])],
            hash_b: [sha256_bytes(&labels_b[0]), sha256_bytes(&labels_b[1])],
            hash_c: [sha256_bytes(&labels_c[0]), sha256_bytes(&labels_c[1])],
        };

        let mut ciphertexts = [[[0u8; 32]; 2]; 2];
        for u in 0..2usize {
            for v in 0..2usize {
                let nand_bit = usize::from(!(u == 1 && v == 1));
                let pad = Self::row_pad(gate_id, &labels_a[u], &labels_b[v]);
                ciphertexts[u][v] = xor32(&labels_c[nand_bit], &pad);
            }
        }

        Self {
            gate_id,
            labels_a,
            labels_b,
            labels_c,
            commitments,
            ciphertexts,
        }
    }

    fn row_pad(gate_id: u32, la: &[u8; 32], lb: &[u8; 32]) -> [u8; 32] {
        let mut pre = b"SHZ/MNR05/GARBLE_ROW/V1:".to_vec();
        pre.extend_from_slice(&gate_id.to_le_bytes());
        pre.extend_from_slice(la);
        pre.extend_from_slice(lb);
        sha256_bytes(&pre)
    }

    /// Evaluates the garbled gate given active input wire labels `(la, lb)` and their committed bits `(u, v)`.
    pub fn evaluate(&self, u: usize, v: usize, la: &[u8; 32], lb: &[u8; 32]) -> Result<(usize, [u8; 32]), String> {
        if u > 1 || v > 1 {
            return Err("bit index out of bounds".into());
        }
        if sha256_bytes(la) != self.commitments.hash_a[u]
            || sha256_bytes(lb) != self.commitments.hash_b[v]
        {
            return Err("input label does not match wire commitment".into());
        }
        let pad = Self::row_pad(self.gate_id, la, lb);
        let lc = xor32(&self.ciphertexts[u][v], &pad);
        let h_lc = sha256_bytes(&lc);
        if h_lc == self.commitments.hash_c[0] {
            Ok((0, lc))
        } else if h_lc == self.commitments.hash_c[1] {
            Ok((1, lc))
        } else {
            Err("decrypted output label failed wire commitment".into())
        }
    }
}

/// Appends the 74-byte Tapscript gadget that authenticates a 32-byte wire label on top of stack
/// against `(H_{w,0}, H_{w,1})` and replaces it with its exact boolean value `bit_w in {0, 1}`!
///
/// Stack trace:
/// - `[..., L_w]`
/// - `OP_SHA256 (0xa8) OP_DUP (0x76)` -> `[..., h, h]`
/// - `<0x20 || H_{w,0}> OP_EQUAL (0x87)` -> `[..., h, is_0]`
/// - `OP_SWAP (0x7c)` -> `[..., is_0, h]`
/// - `<0x20 || H_{w,1}> OP_EQUAL (0x87)` -> `[..., is_0, is_1]`
/// - `OP_2DUP (0x6e) OP_BOOLOR (0x9b) OP_VERIFY (0x69)` -> enforces `is_0 || is_1 == 1`!
/// - `OP_NIP (0x77)` -> drops `is_0`, leaving `[..., is_1]` (`== bit_w`)!
fn append_decode_committed_wire_bit(script: &mut Vec<u8>, h0: &[u8; 32], h1: &[u8; 32]) {
    script.extend_from_slice(&[0xa8, 0x76, 0x20]); // OP_SHA256 OP_DUP <32B>
    script.extend_from_slice(h0);
    script.extend_from_slice(&[0x87, 0x7c, 0x20]); // OP_EQUAL OP_SWAP <32B>
    script.extend_from_slice(h1);
    script.extend_from_slice(&[0x87, 0x6e, 0x9b, 0x69, 0x77]); // OP_EQUAL OP_2DUP OP_BOOLOR OP_VERIFY OP_NIP
}

/// 2-leaf NUMS `P2TR` BitVM3 Garbled-Gate Assertion & Disprove contract (`optimistic_csv_leaf` + `disprove_garbled_nand_leaf`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarbledGateTaprootTree {
    pub internal_xonly: [u8; 32],
    pub operator_pubkey_x: [u8; 32],
    pub challenger_pubkey_x: [u8; 32],
    pub challenge_csv_blocks: u16,
    pub commitments: GarbledWireCommitments,
    pub optimistic_script: Vec<u8>,
    pub disprove_gate_script: Vec<u8>,
    pub optimistic_leaf_hash: [u8; 32],
    pub disprove_gate_leaf_hash: [u8; 32],
    pub optimistic_control_block: Vec<u8>,
    pub disprove_gate_control_block: Vec<u8>,
    pub script_pubkey: Vec<u8>,
}

impl GarbledGateTaprootTree {
    pub fn build(
        operator_pubkey_x: [u8; 32],
        challenger_pubkey_x: [u8; 32],
        challenge_csv_blocks: u16,
        commitments: GarbledWireCommitments,
    ) -> Result<Self, UtxoRefError> {
        let internal_xonly = utxoref_nums_internal_key()?;

        let csv_op = if challenge_csv_blocks <= 16 {
            vec![0x50 + challenge_csv_blocks as u8]
        } else {
            let b = challenge_csv_blocks.to_le_bytes();
            vec![0x02, b[0], b[1]]
        };
        let mut optimistic_script = csv_op;
        optimistic_script.extend_from_slice(&[0xb2, 0x75, 0x20]); // OP_CSV OP_DROP <32B>
        optimistic_script.extend_from_slice(&operator_pubkey_x);
        optimistic_script.push(0xac);

        // Disprove Garbled NAND Gate Script:
        // Witness stack (bottom to top): `[challenger_sig, L_c, L_b, L_a]`
        let mut disprove_gate_script = Vec::with_capacity(260);
        // 1. Decode `L_a -> bit_a`: stack `[sig, L_c, L_b, bit_a]`
        append_decode_committed_wire_bit(
            &mut disprove_gate_script,
            &commitments.hash_a[0],
            &commitments.hash_a[1],
        );
        // 2. `OP_SWAP (0x7c)` -> `[sig, L_c, bit_a, L_b]`, decode `L_b -> bit_b`
        disprove_gate_script.push(0x7c);
        append_decode_committed_wire_bit(
            &mut disprove_gate_script,
            &commitments.hash_b[0],
            &commitments.hash_b[1],
        );
        // 3. `expected_c = NAND(bit_a, bit_b)`: `OP_BOOLAND (0x9a) OP_NOT (0x91)` -> `[sig, L_c, expected_c]`
        disprove_gate_script.extend_from_slice(&[0x9a, 0x91]);
        // 4. `OP_SWAP (0x7c)` -> `[sig, expected_c, L_c]`, decode `L_c -> claimed_c`
        disprove_gate_script.push(0x7c);
        append_decode_committed_wire_bit(
            &mut disprove_gate_script,
            &commitments.hash_c[0],
            &commitments.hash_c[1],
        );
        // 5. Require `expected_c != claimed_c`: `OP_NUMNOTEQUAL (0x9e) OP_VERIFY (0x69)` -> `[sig]`
        disprove_gate_script.extend_from_slice(&[0x9e, 0x69, 0x20]);
        disprove_gate_script.extend_from_slice(&challenger_pubkey_x);
        disprove_gate_script.push(0xac); // OP_CHECKSIG

        let optimistic_leaf_hash = tap_leaf_hash(&optimistic_script);
        let disprove_gate_leaf_hash = tap_leaf_hash(&disprove_gate_script);
        let merkle_root = tap_branch_hash(&optimistic_leaf_hash, &disprove_gate_leaf_hash);

        let mut tweak_in = [0u8; 64];
        tweak_in[..32].copy_from_slice(&internal_xonly);
        tweak_in[32..].copy_from_slice(&merkle_root);
        let tweak = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&tagged_hash(
            b"TapTweak",
            &tweak_in,
        )));
        let internal_pt = lift_x_even(&internal_xonly)
            .map_err(|_| UtxoRefError::InvalidCrypto("NUMS lift_x"))?;
        let (out_x, out_y) = point_coordinates(internal_pt + ProjectivePoint::GENERATOR * tweak)?;
        let ctrl_header = LEAF_VERSION_TAPSCRIPT | (out_y[31] & 1);

        let mut optimistic_control_block = Vec::with_capacity(65);
        optimistic_control_block.push(ctrl_header);
        optimistic_control_block.extend_from_slice(&internal_xonly);
        optimistic_control_block.extend_from_slice(&disprove_gate_leaf_hash);

        let mut disprove_gate_control_block = Vec::with_capacity(65);
        disprove_gate_control_block.push(ctrl_header);
        disprove_gate_control_block.extend_from_slice(&internal_xonly);
        disprove_gate_control_block.extend_from_slice(&optimistic_leaf_hash);

        let mut script_pubkey = vec![0x51, 0x20];
        script_pubkey.extend_from_slice(&out_x);

        Ok(Self {
            internal_xonly,
            operator_pubkey_x,
            challenger_pubkey_x,
            challenge_csv_blocks,
            commitments,
            optimistic_script,
            disprove_gate_script,
            optimistic_leaf_hash,
            disprove_gate_leaf_hash,
            optimistic_control_block,
            disprove_gate_control_block,
            script_pubkey,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_disprove_garbled_gate_tx(
        &self,
        assert_txid_display: &str,
        assert_vout: u32,
        bond_sats: u64,
        fee_sats: u64,
        challenger_sk: &[u8; 32],
        challenger_payout_spk: Vec<u8>,
        label_a: &[u8; 32],
        label_b: &[u8; 32],
        claimed_label_c: &[u8; 32],
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
            tx.bip341_sighash(0, SIGHASH_DEFAULT, Some(&self.disprove_gate_leaf_hash))?;
        let sig =
            bip340_sign(challenger_sk, &sh).map_err(|_| UtxoRefError::InvalidCrypto("sign"))?;
        bip340_verify(&self.challenger_pubkey_x, &sh, &sig)
            .map_err(|_| UtxoRefError::InvalidCrypto("verify"))?;

        tx.inputs[0].witness = vec![
            encode_taproot_witness_sig(&sig, SIGHASH_DEFAULT),
            claimed_label_c.to_vec(),
            label_b.to_vec(),
            label_a.to_vec(),
            self.disprove_gate_script.clone(),
            self.disprove_gate_control_block.clone(),
        ];
        Ok(tx)
    }
}
