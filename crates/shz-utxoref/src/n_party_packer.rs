//! Dynamic $N$-Party ($N \ge 2$) Multilateral Atomic Clearing Transaction Packer (`Track 3`).
//!
//! Generalizes `SHZ-MNR-03` beyond fixed 3-party `(AB, BC, CA)` clearing to arbitrary $N$ vaults:
//! - Places all $K$ offline `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) vaults at `vin[0..K]`
//!   paired 1-for-1 with their exact pinned `vout[0..K]` outputs (`SigMsg(0x83)` omits `input_index`,
//!   so any origination-time 1-in/1-out `0x83` adaptor pre-signature is valid at any matched `(k, k)` slot!).
//! - Appends $M$ online or PTLC-adaptor-unlocked (`0x01` / `0x00`) vaults at `vin[K..K+M]`.
//! - Appends net winner / residual `P2TR` outputs + the mandatory `330`-sat `UTXORef` CPFP anchor.
#![forbid(unsafe_code)]

use k256::Scalar;
use serde::{Deserialize, Serialize};
use shz_dlc::{
    adaptor_complete, bip340_sign, bip340_verify, lift_x_even, pubkey_x_from_secret, tagged_hash,
    AdaptorSignature,
};

use crate::{
    mnr02::{
        encode_taproot_witness_sig, Mnr02TaprootTree, SegwitTx, SegwitTxIn, SIGHASH_ALL,
        SIGHASH_DEFAULT, SIGHASH_SINGLE_ANYONECANPAY,
    },
    signing_target::{
        point_coordinates, UtxoRefFundingOutput, DEFAULT_CPFP_ANCHOR_SATS, LEAF_VERSION_TAPSCRIPT,
    },
    UtxoRefError,
};

/// Input vault leg for dynamic $N$-party clearing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum DynamicVaultInputSpec {
    /// Vault where one counterparty (`offline_bob`) pre-signed `0x83` at origination and is now offline,
    /// while the other counterparty (`online_or_ptlc`) signs `0x01` (directly or via extracted PTLC scalar `y`)
    /// alongside `router_guard_sk`.
    Offline0x83RouteLeg {
        label: String,
        tree: Mnr02TaprootTree,
        funding_txid_display: String,
        funding_vout: u32,
        funding_sats: u64,
        offline_pinned_sats: u64,
        offline_pinned_spk: Vec<u8>,
        offline_0x83_adaptor_sig: AdaptorSignature,
        counterparty_auth: CounterpartyAuthMode,
    },
    /// Interactive or PTLC-unlocked 2-of-2 `UTXORef` bilateral vault (`SIGHASH_DEFAULT = 0x00`).
    Bilateral0x00Leg {
        label: String,
        tree: UtxoRefFundingOutput,
        funding_txid_display: String,
        funding_vout: u32,
        funding_sats: u64,
        party_a_sk: [u8; 32],
        party_b_sk: [u8; 32],
    },
}

#[derive(Debug, Clone)]
pub enum CounterpartyAuthMode {
    OnlineSecretKey([u8; 32]),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicNPartyPackingReceipt {
    pub total_vault_inputs: usize,
    pub offline_0x83_vaults: usize,
    pub bilateral_0x00_vaults: usize,
    pub total_outputs: usize,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub miner_fee_sats: u64,
    pub txid_hex: String,
    pub wtxid_hex: String,
    pub vsize: usize,
}

/// Packs and cryptographically signs an $N$-input, $(K + P + 1)$-output atomic Taproot clearing
/// transaction across arbitrary $N \ge 2$ vaults!
pub fn pack_dynamic_n_party_clearing_tx(
    vault_legs: &[DynamicVaultInputSpec],
    extra_net_payouts: &[(u64, Vec<u8>)],
    anchor_spk: Vec<u8>,
    miner_fee_sats: u64,
    maturity_height: u32,
    oracle_scalar_t: &Scalar,
    router_guard_sk: &[u8; 32],
) -> Result<(SegwitTx, DynamicNPartyPackingReceipt), UtxoRefError> {
    if vault_legs.len() < 2 {
        return Err(UtxoRefError::InvalidTransaction(
            "dynamic N-party packer requires >= 2 vault legs",
        ));
    }
    let guard_pk =
        pubkey_x_from_secret(router_guard_sk).map_err(|_| UtxoRefError::InvalidCrypto("guard_sk"))?;

    // Partition so all `Offline0x83RouteLeg`s come FIRST (`0..K`) matching `outputs[0..K]`!
    let mut offline_legs = Vec::new();
    let mut bilateral_legs = Vec::new();
    for leg in vault_legs {
        match leg {
            DynamicVaultInputSpec::Offline0x83RouteLeg { .. } => offline_legs.push(leg),
            DynamicVaultInputSpec::Bilateral0x00Leg { .. } => bilateral_legs.push(leg),
        }
    }

    let mut inputs = Vec::with_capacity(vault_legs.len());
    let mut outputs = Vec::with_capacity(offline_legs.len() + extra_net_payouts.len() + 1);
    let mut total_in_sats = 0u64;

    for leg in &offline_legs {
        if let DynamicVaultInputSpec::Offline0x83RouteLeg {
            tree,
            funding_txid_display,
            funding_vout,
            funding_sats,
            offline_pinned_sats,
            offline_pinned_spk,
            ..
        } = leg
        {
            if tree.router_guard_pubkey_x != guard_pk {
                return Err(UtxoRefError::InvalidCrypto("guard pubkey mismatch on 0x83 leg"));
            }
            if *offline_pinned_sats < DEFAULT_CPFP_ANCHOR_SATS {
                return Err(UtxoRefError::AccountingViolation("0x83 pinned output < 330 dust"));
            }
            inputs.push(SegwitTxIn::from_display_txid(
                funding_txid_display,
                *funding_vout,
                0xffff_fffe,
                *funding_sats,
                tree.script_pubkey.clone(),
            )?);
            outputs.push((*offline_pinned_sats, offline_pinned_spk.clone()));
            total_in_sats = total_in_sats.saturating_add(*funding_sats);
        }
    }

    for leg in &bilateral_legs {
        if let DynamicVaultInputSpec::Bilateral0x00Leg {
            tree,
            funding_txid_display,
            funding_vout,
            funding_sats,
            ..
        } = leg
        {
            inputs.push(SegwitTxIn::from_display_txid(
                funding_txid_display,
                *funding_vout,
                0xffff_fffe,
                *funding_sats,
                tree.script_pubkey.clone(),
            )?);
            total_in_sats = total_in_sats.saturating_add(*funding_sats);
        }
    }

    for (amt, spk) in extra_net_payouts {
        if *amt < DEFAULT_CPFP_ANCHOR_SATS {
            return Err(UtxoRefError::AccountingViolation("extra net payout < 330 dust"));
        }
        outputs.push((*amt, spk.clone()));
    }
    outputs.push((DEFAULT_CPFP_ANCHOR_SATS, anchor_spk));

    let total_out_sats: u64 = outputs.iter().map(|(v, _)| *v).sum();
    if total_in_sats != total_out_sats.saturating_add(miner_fee_sats) {
        return Err(UtxoRefError::AccountingViolation(
            "dynamic N-party clearing failed exact satoshi conservation",
        ));
    }

    let mut tx = SegwitTx {
        version: 2,
        inputs,
        outputs,
        locktime: maturity_height,
    };

    // Sign `0..K` offline `0x83` inputs
    for (idx, leg) in offline_legs.iter().enumerate() {
        if let DynamicVaultInputSpec::Offline0x83RouteLeg {
            tree,
            offline_0x83_adaptor_sig,
            counterparty_auth: CounterpartyAuthMode::OnlineSecretKey(cp_sk),
            ..
        } = leg
        {
            let bob_completed = adaptor_complete(offline_0x83_adaptor_sig, oracle_scalar_t)
                .map_err(|_| UtxoRefError::InvalidCrypto("complete 0x83 adaptor"))?;
            let sh_0x83 =
                tx.bip341_sighash(idx, SIGHASH_SINGLE_ANYONECANPAY, Some(&tree.route_leaf_hash))?;
            bip340_verify(&tree.bob_pubkey_x, &sh_0x83, &bob_completed)
                .map_err(|_| UtxoRefError::InvalidCrypto("verify 0x83 sig on N-party tx"))?;

            let sh_0x01 = tx.bip341_sighash(idx, SIGHASH_ALL, Some(&tree.route_leaf_hash))?;
            let cp_sig =
                bip340_sign(cp_sk, &sh_0x01).map_err(|_| UtxoRefError::InvalidCrypto("cp 0x01"))?;
            let guard_sig = bip340_sign(router_guard_sk, &sh_0x01)
                .map_err(|_| UtxoRefError::InvalidCrypto("guard 0x01"))?;
            bip340_verify(&tree.alice_pubkey_x, &sh_0x01, &cp_sig)
                .map_err(|_| UtxoRefError::InvalidCrypto("cp 0x01 verify"))?;

            tx.inputs[idx].witness = vec![
                encode_taproot_witness_sig(&bob_completed, SIGHASH_SINGLE_ANYONECANPAY),
                encode_taproot_witness_sig(&guard_sig, SIGHASH_ALL),
                encode_taproot_witness_sig(&cp_sig, SIGHASH_ALL),
                tree.route_cet_script.clone(),
                tree.route_control_block.clone(),
            ];
        }
    }

    // Sign `K..K+M` bilateral `0x00` inputs
    let k_off = offline_legs.len();
    for (j, leg) in bilateral_legs.iter().enumerate() {
        let idx = k_off + j;
        if let DynamicVaultInputSpec::Bilateral0x00Leg {
            tree,
            party_a_sk,
            party_b_sk,
            ..
        } = leg
        {
            let pk_a =
                pubkey_x_from_secret(party_a_sk).map_err(|_| UtxoRefError::InvalidCrypto("pk_a"))?;
            let sh = tx.bip341_sighash(idx, SIGHASH_DEFAULT, Some(&tree.cet_leaf_hash))?;
            let sig_a =
                bip340_sign(party_a_sk, &sh).map_err(|_| UtxoRefError::InvalidCrypto("sig_a"))?;
            let sig_b =
                bip340_sign(party_b_sk, &sh).map_err(|_| UtxoRefError::InvalidCrypto("sig_b"))?;
            let (sig0, sig1) = if tree.party_pubkeys_sorted[0] == pk_a {
                (sig_a, sig_b)
            } else {
                (sig_b, sig_a)
            };

            let mut cet_script = Vec::with_capacity(68);
            cet_script.push(0x20);
            cet_script.extend_from_slice(&tree.party_pubkeys_sorted[0]);
            cet_script.extend_from_slice(&[0xad, 0x20]);
            cet_script.extend_from_slice(&tree.party_pubkeys_sorted[1]);
            cet_script.push(0xac);

            let mut tweak_in = [0u8; 64];
            tweak_in[..32].copy_from_slice(&tree.internal_xonly);
            tweak_in[32..].copy_from_slice(&tree.tap_merkle_root);
            let tweak = <Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce(
                k256::U256::from_be_slice(&tagged_hash(b"TapTweak", &tweak_in)),
            );
            let internal_pt = lift_x_even(&tree.internal_xonly)
                .map_err(|_| UtxoRefError::InvalidCrypto("lift_x"))?;
            let (_, out_y) =
                point_coordinates(internal_pt + k256::ProjectivePoint::GENERATOR * tweak)?;
            let mut ctrl = Vec::with_capacity(65);
            ctrl.push(LEAF_VERSION_TAPSCRIPT | (out_y[31] & 1));
            ctrl.extend_from_slice(&tree.internal_xonly);
            ctrl.extend_from_slice(&tree.refund_leaf_hash);

            tx.inputs[idx].witness = vec![
                encode_taproot_witness_sig(&sig1, SIGHASH_DEFAULT),
                encode_taproot_witness_sig(&sig0, SIGHASH_DEFAULT),
                cet_script,
                ctrl,
            ];
        }
    }

    let receipt = DynamicNPartyPackingReceipt {
        total_vault_inputs: tx.inputs.len(),
        offline_0x83_vaults: offline_legs.len(),
        bilateral_0x00_vaults: bilateral_legs.len(),
        total_outputs: tx.outputs.len(),
        total_input_sats: total_in_sats,
        total_output_sats: total_out_sats,
        miner_fee_sats,
        txid_hex: tx.txid_hex(),
        wtxid_hex: tx.wtxid_hex(),
        vsize: tx.vsize(),
    };
    Ok((tx, receipt))
}
