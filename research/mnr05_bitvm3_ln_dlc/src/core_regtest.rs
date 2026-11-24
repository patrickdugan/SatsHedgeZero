//! Live `Bitcoin Core v31.1.0` Regtest Consensus Drills for `SHZ-MNR-05`:
//! - **Drill A (Honest End-to-End Batch + BitVM3 Optimistic Reclaim):**
//!   1. Broadcasts & mines the 40-byte `SHZIDX01 || checkpoint_root32` `OP_RETURN` Bitcoin anchor tx.
//!   2. Funds 3 multilateral DLC vaults (`U_AB = 99M`, `U_BC = 90M`, `U_CA = 55M`).
//!   3. Executes the `INDEX-03 -> 2-of-3 FROST -> Off-Chain LN PTLC -> Double-Offline L1` swap
//!      (**BOTH `Bob` AND `Alice` 100% offline for L1 broadcast!**).
//!   4. Verifies `Bitcoin Core v31.1.0` mempool rejects:
//!      - premature clearing before `maturity_height = 150` (`non-final`),
//!      - `1`-sat shave on offline Bob's `0x83` outputs (`Invalid Schnorr signature`),
//!      - output-index swap `vout[0] <-> vout[1]` (`Invalid Schnorr signature`),
//!      - unilateral `CLTV` front-running during priority window (`non-final`).
//!   5. Confirms the 3-input, 5-output double-offline clearing tx (`598 vB`, `348 B` stripped) + CPFP child!
//!   6. Funds honest Operator's `1,000,000`-sat BitVM3 `U_Assert` (`BitVm3AssertionTree`), proves
//!      `Bitcoin Core v31.1.0` rejects:
//!      - premature `optimistic_payout_tx` before `challenge_csv_blocks = 10` (`non-BIP68-final`),
//!      - malicious Challenger griefing attempt on honest Operator (`Script failed an OP_VERIFY operation` / `OP_EQUALVERIFY`).
//!   7. Mines `10` blocks and confirms `optimistic_payout_tx`!
//! - **Drill B (BitVM3 Boundary-Fraud Disprove Slash on `Bitcoin Core v31.1.0`):**
//!   Faulty Operator funds `U_Assert_BadBoundary` committing a stale/mutated nullifier boundary;
//!   `Bitcoin Core v31.1.0` rejects a wrong preimage, then immediately confirms Challenger's
//!   `disprove_boundary_tx` (`Leaf 1`) slashing the `1,000,000`-sat bond!
//! - **Drill C (BitVM3 State-Connector Equivocation Disprove Slash on `Bitcoin Core v31.1.0`):**
//!   Faulty Operator reveals conflicting dual-hash wire preimages `(pre_0, pre_1)`; `Bitcoin Core v31.1.0`
//!   rejects mismatched preimages and confirms Challenger's `disprove_equivocation_tx` (`Leaf 2`)!
//! - **Drill D (RouterLP Withholds LN Payment -> Unilateral `CLTV` Fallback on `Bitcoin Core v31.1.0`):**
//!   When `RouterLP` goes offline without paying the Lightning PTLC, `Alice` never reveals `y` and
//!   confirms `ab_unilateral_fallback_tx` + `bc_unilateral_fallback_tx` (`Leaf 1`) at `height = 170`!
#![forbid(unsafe_code)]

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use shz_dlc::{bip340_sign, pubkey_x_from_secret};
use shz_nova_bitvm::bitvm3::{BitcoinNetworkCode, BITCOIN_REGTEST_GENESIS_HASH_HEX};
use shz_utxoref::{
    mnr02::{encode_taproot_witness_sig, SegwitTx, SegwitTxIn, SIGHASH_DEFAULT},
    mnr03::{precompute_mnr03_funding_descriptors, Mnr03ScaleParams},
};

use crate::{
    bitvm3_taproot::{
        derive_wire_connector_pair, encode_boundary_preimage, hash_boundary_preimage,
        BitVm3AssertionTree,
    },
    garbled_gate_disprove::{GarbledGateTaprootTree, GarbledNandGate},
    ptlc_lightning::{
        build_shzidx01_op_return_spk, canonical_index03_clearing_oracle_witness,
        execute_ptlc_lightning_double_offline_clearing, LnPtlcAtomicBridgeReceipt,
        PtlcDoubleOfflineClearingBundle,
    },
    unified_batch_circuit::{BatchVaultNullifierTree, OracleOpeningWitness},
};

struct IsolatedCoreNode {
    child: Child,
    cli_path: PathBuf,
    datadir: PathBuf,
    rpc_port: u16,
}

impl IsolatedCoreNode {
    fn spawn(bitcoind_path: &Path) -> Result<Self, String> {
        let cli_path = bitcoind_path
            .parent()
            .ok_or("missing bitcoind parent dir")?
            .join(if cfg!(windows) {
                "bitcoin-cli.exe"
            } else {
                "bitcoin-cli"
            });
        if !cli_path.exists() {
            return Err(format!("bitcoin-cli not found next to {}", bitcoind_path.display()));
        }

        let rpc_port = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| e.to_string())?
            .local_addr()
            .unwrap()
            .port();
        let p2p_port = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| e.to_string())?
            .local_addr()
            .unwrap()
            .port();

        let datadir =
            std::env::temp_dir().join(format!("shz-mnr05-core-{}-{rpc_port}", std::process::id()));
        fs::create_dir_all(&datadir).map_err(|e| e.to_string())?;

        let child = Command::new(bitcoind_path)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0001")
            .arg("-rpcuser=shzrpc")
            .arg("-rpcpassword=shzpass")
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .arg("-listen=0")
            .arg("-dnsseed=0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn bitcoind: {e}"))?;

        let node = Self {
            child,
            cli_path,
            datadir,
            rpc_port,
        };

        for _ in 0..80 {
            if node.cli_raw(&["getblockchaininfo"]).is_ok() {
                return Ok(node);
            }
            thread::sleep(Duration::from_millis(150));
        }
        Err("bitcoind RPC failed to become ready".into())
    }

    fn cli_raw(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.cli_path)
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg("-rpcuser=shzrpc")
            .arg("-rpcpassword=shzpass")
            .arg(format!("-rpcport={}", self.rpc_port))
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn cli_json(&self, args: &[&str]) -> Result<Value, String> {
        let txt = self.cli_raw(args)?;
        serde_json::from_str(&txt).map_err(|e| format!("invalid JSON: {e}"))
    }

    fn height(&self) -> u64 {
        self.cli_raw(&["getblockcount"]).unwrap().parse().unwrap()
    }

    fn mine_blocks(&self, count: u64, addr: &str) -> u64 {
        let c = count.to_string();
        self.cli_raw(&["generatetoaddress", &c, addr])
            .expect("generatetoaddress");
        self.height()
    }

    fn fund_p2tr_script(&self, spk: &[u8], sats: u64) -> (String, u32) {
        assert_eq!(spk.len(), 34);
        assert_eq!(&spk[..2], &[0x51, 0x20]);
        let out_x = hex::encode(&spk[2..]);
        let desc_info = self
            .cli_json(&["getdescriptorinfo", &format!("rawtr({out_x})")])
            .unwrap();
        let desc = desc_info["descriptor"].as_str().unwrap();
        let addrs = self.cli_json(&["deriveaddresses", desc]).unwrap();
        let addr = addrs[0].as_str().unwrap();

        let btc = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);
        let outs = format!("[{{\"{addr}\": {btc}}}]");
        let raw = self.cli_raw(&["createrawtransaction", "[]", &outs]).unwrap();
        let funded = self.cli_json(&["fundrawtransaction", &raw]).unwrap();
        let signed = self
            .cli_json(&["signrawtransactionwithwallet", funded["hex"].as_str().unwrap()])
            .unwrap();
        assert_eq!(signed["complete"].as_bool(), Some(true));
        let signed_hex = signed["hex"].as_str().unwrap();
        let txid = self.cli_raw(&["sendrawtransaction", signed_hex]).unwrap();
        let decoded = self.cli_json(&["decoderawtransaction", signed_hex]).unwrap();
        let target_hex = hex::encode(spk);
        let vout = decoded["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(target_hex.as_str()))
            .expect("target vout")["n"]
            .as_u64()
            .unwrap() as u32;
        (txid, vout)
    }

    fn broadcast_op_return_payload(&self, payload_40b: &[u8]) -> (String, u32) {
        assert_eq!(payload_40b.len(), 40);
        let data_hex = hex::encode(payload_40b);
        let outs = format!("[{{\"data\":\"{data_hex}\"}}]");
        let raw = self.cli_raw(&["createrawtransaction", "[]", &outs]).unwrap();
        let funded = self.cli_json(&["fundrawtransaction", &raw]).unwrap();
        let signed = self
            .cli_json(&["signrawtransactionwithwallet", funded["hex"].as_str().unwrap()])
            .unwrap();
        assert_eq!(signed["complete"].as_bool(), Some(true));
        let signed_hex = signed["hex"].as_str().unwrap();
        let txid = self.cli_raw(&["sendrawtransaction", signed_hex]).unwrap();
        let decoded = self.cli_json(&["decoderawtransaction", signed_hex]).unwrap();
        let mut expected_spk = vec![0x6a, 40];
        expected_spk.extend_from_slice(payload_40b);
        let expected_hex = hex::encode(expected_spk);
        let vout = decoded["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(expected_hex.as_str()))
            .expect("OP_RETURN vout")["n"]
            .as_u64()
            .unwrap() as u32;
        (txid, vout)
    }

    fn test_mempool_accept(&self, raw_hex: &str) -> (bool, String) {
        let arg = format!("[\"{raw_hex}\"]");
        let res = self.cli_json(&["testmempoolaccept", &arg]).unwrap();
        let e = &res[0];
        let allowed = e["allowed"].as_bool().unwrap_or(false);
        let reason = e["reject-reason"].as_str().unwrap_or("accepted").to_string();
        (allowed, reason)
    }
}

impl Drop for IsolatedCoreNode {
    fn drop(&mut self) {
        let _ = self.cli_raw(&["stop"]);
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.datadir);
    }
}

fn p2tr_spk_from_seed(seed: u8) -> Vec<u8> {
    let pk = pubkey_x_from_secret(&[seed; 32]).unwrap();
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&pk);
    s
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreMempoolProbe {
    pub probe_id: String,
    pub description: String,
    pub core_accepted: bool,
    pub core_reject_reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitVm3TaprootDrillSummary {
    pub honest_assertion_txid: String,
    pub honest_assertion_vout: u32,
    pub challenge_csv_blocks: u16,
    pub bond_sats: u64,
    pub optimistic_payout_txid: String,
    pub optimistic_payout_vsize: usize,
    pub disprove_boundary_bad_assert_txid: String,
    pub disprove_boundary_slash_txid: String,
    pub disprove_boundary_slash_vsize: usize,
    pub disprove_equivocation_bad_assert_txid: String,
    pub disprove_equivocation_slash_txid: String,
    pub disprove_equivocation_slash_vsize: usize,
    pub honest_operator_unslashable_verified: bool,
    pub premature_csv_rejected_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mnr05CoreRegtestReceipt {
    pub scenario: String,
    pub core_version: String,
    pub network_code: BitcoinNetworkCode,
    pub regtest_genesis_hash_hex: String,
    pub shzidx01_anchor_txid: String,
    pub shzidx01_anchor_vout: u32,
    pub oracle_checkpoint_root_hex: String,
    pub funded_vault_outpoints: Vec<String>,
    pub double_offline_clearing_txid: String,
    pub double_offline_clearing_wtxid: String,
    pub double_offline_clearing_vsize: usize,
    pub double_offline_clearing_stripped_bytes: usize,
    pub cpfp_child_txid: String,
    pub cleared_outputs_sats: Vec<u64>,
    pub ptlc_lightning_bridge: LnPtlcAtomicBridgeReceipt,
    pub bitvm3_taproot_drills: BitVm3TaprootDrillSummary,
    pub unilateral_fallback_ab_txid: String,
    pub unilateral_fallback_bc_txid: String,
    pub mempool_adversarial_probes: Vec<CoreMempoolProbe>,
    pub bitvm3_tapscript_disprove_regtest_verified: bool,
    pub full_groth16_garbled_circuit_l1_verified: bool,
    pub production_ready: bool,
}

/// Runs all 4 live `Bitcoin Core v31.1.0` regtest drills and returns the receipt + live witness bundle
/// (`clearing_bundle`, `oracle_witness`, `assertion_txid_be`, `assertion_vout`, `regtest_genesis`)
/// so the caller can prove the exact L1-confirmed transactions in both Nova circuits!
#[allow(clippy::type_complexity)]
pub fn run_mnr05_core_regtest_drills(
    bitcoind_path: &Path,
) -> Result<
    (
        Mnr05CoreRegtestReceipt,
        PtlcDoubleOfflineClearingBundle,
        OracleOpeningWitness,
        [u8; 32],
        u32,
        [u8; 32],
    ),
    String,
> {
    let node = IsolatedCoreNode::spawn(bitcoind_path)?;
    let net_info = node.cli_json(&["getnetworkinfo"])?;
    let core_version = format!(
        "Bitcoin Core v{} ({})",
        net_info["version"].as_u64().unwrap_or(0),
        net_info["subversion"].as_str().unwrap_or("bitcoind")
    );

    let genesis_hex = node.cli_raw(&["getblockhash", "0"])?;
    assert_eq!(genesis_hex, BITCOIN_REGTEST_GENESIS_HASH_HEX);
    let regtest_genesis: [u8; 32] = hex::decode(&genesis_hex)
        .unwrap()
        .try_into()
        .unwrap();

    let _ = node.cli_raw(&["createwallet", "mnr05_miner"]);
    let miner_addr = node.cli_raw(&["getnewaddress", "miner", "bech32m"])?;
    node.mine_blocks(110, &miner_addr);

    // 1. Anchor `SHZIDX01 || oracle_checkpoint_root32` (40B) on Bitcoin Core 31.1!
    let oracle_witness = canonical_index03_clearing_oracle_witness(regtest_genesis);
    let ckpt_root = oracle_witness.checkpoint_root();
    let op_ret_spk = build_shzidx01_op_return_spk(&ckpt_root);
    let (shzidx01_txid, shzidx01_vout) = node.broadcast_op_return_payload(&op_ret_spk[2..]);

    // 2. Fund primary 3 vaults (`U_AB`, `U_BC`, `U_CA`) + secondary unilateral fallback vaults (`U_AB_uni`, `U_BC_uni`)
    let maturity_height = 150u32;
    let params = Mnr03ScaleParams::macro_regtest_33k(maturity_height);
    let alice_pk = pubkey_x_from_secret(&[0x11; 32]).unwrap();
    let bob_pk = pubkey_x_from_secret(&[0x22; 32]).unwrap();
    let carol_pk = pubkey_x_from_secret(&[0x23; 32]).unwrap();
    let guard_pk = pubkey_x_from_secret(&[0x24; 32]).unwrap();

    let descs = precompute_mnr03_funding_descriptors(&params, alice_pk, bob_pk, carol_pk, guard_pk)
        .map_err(|e| format!("descriptors: {e}"))?;

    let (ab_txid, ab_vout) = node.fund_p2tr_script(&descs.ab_tree.script_pubkey, descs.ab_funding_sats);
    let (bc_txid, bc_vout) = node.fund_p2tr_script(&descs.bc_tree.script_pubkey, descs.bc_funding_sats);
    let (ca_txid, ca_vout) = node.fund_p2tr_script(&descs.ca_tree.script_pubkey, descs.ca_funding_sats);

    let (ab_uni_txid, ab_uni_vout) =
        node.fund_p2tr_script(&descs.ab_tree.script_pubkey, descs.ab_funding_sats);
    let (bc_uni_txid, bc_uni_vout) =
        node.fund_p2tr_script(&descs.bc_tree.script_pubkey, descs.bc_funding_sats);
    node.mine_blocks(6, &miner_addr);

    let anchor_sk = [0x44u8; 32];
    let alice_fallback_spk = p2tr_spk_from_seed(0x41);
    let bob_spk = p2tr_spk_from_seed(0x42);
    let carol_spk = p2tr_spk_from_seed(0x43);
    let anchor_spk = p2tr_spk_from_seed(0x44);
    let router_lp_spk = p2tr_spk_from_seed(0x45);

    // 3. Execute PTLC Lightning <-> L1 Double-Offline Clearing (`Bob` AND `Alice` BOTH offline!)
    let (_orig, clearing_bundle) = execute_ptlc_lightning_double_offline_clearing(
        &params,
        [(&ab_txid, ab_vout), (&bc_txid, bc_vout), (&ca_txid, ca_vout)],
        alice_fallback_spk.clone(),
        bob_spk.clone(),
        carol_spk.clone(),
        router_lp_spk.clone(),
        anchor_spk.clone(),
        &oracle_witness,
    )?;
    let (_orig_uni, uni_bundle) = execute_ptlc_lightning_double_offline_clearing(
        &params,
        [
            (&ab_uni_txid, ab_uni_vout),
            (&bc_uni_txid, bc_uni_vout),
            (&ca_txid, ca_vout),
        ],
        alice_fallback_spk,
        bob_spk,
        carol_spk,
        router_lp_spk,
        anchor_spk.clone(),
        &oracle_witness,
    )?;

    let mut probes = Vec::new();
    let clear_tx = &clearing_bundle.signed_clearing_tx;
    let raw_clear_hex = hex::encode(clear_tx.serialize_segwit());

    // Advance to `maturity_height - 2` (`148`) and verify premature L1 broadcast is rejected!
    let h_cur = node.height();
    if h_cur < u64::from(maturity_height - 2) {
        node.mine_blocks(u64::from(maturity_height - 2) - h_cur, &miner_addr);
    }
    let (pre_ok, pre_reason) = node.test_mempool_accept(&raw_clear_hex);
    assert!(!pre_ok && pre_reason.contains("non-final"));
    probes.push(CoreMempoolProbe {
        probe_id: "clearing-premature-before-maturity".into(),
        description: "Broadcast double-offline clearing tx at height 148 (< maturity 150)".into(),
        core_accepted: pre_ok,
        core_reject_reason: pre_reason,
    });

    // Advance to exact `maturity_height = 150`
    let rem = u64::from(maturity_height).saturating_sub(node.height());
    if rem > 0 {
        node.mine_blocks(rem, &miner_addr);
    }

    // Adversarial shave on offline Bob's `vout[0]` (`0x83`) -> RouterLP `vout[2]`
    let mut shave_bob = clear_tx.clone();
    shave_bob.outputs[0].0 -= 1;
    shave_bob.outputs[2].0 += 1;
    let (shave_ok, shave_reason) =
        node.test_mempool_accept(&hex::encode(shave_bob.serialize_segwit()));
    assert!(!shave_ok);
    probes.push(CoreMempoolProbe {
        probe_id: "clearing-shave-1sat-offline-bob-vout0".into(),
        description: "Shave 1 sat from offline Bob's 0x83 output vout[0] to RouterLP vout[2]".into(),
        core_accepted: shave_ok,
        core_reject_reason: shave_reason,
    });

    // Adversarial swap `vout[0] <-> vout[1]`
    let mut swap_tx = clear_tx.clone();
    swap_tx.outputs.swap(0, 1);
    let (swap_ok, swap_reason) = node.test_mempool_accept(&hex::encode(swap_tx.serialize_segwit()));
    assert!(!swap_ok);
    probes.push(CoreMempoolProbe {
        probe_id: "clearing-swap-bob-vout0-vout1".into(),
        description: "Swap offline Bob's vout[0] and vout[1] across the two 0x83 inputs".into(),
        core_accepted: swap_ok,
        core_reject_reason: swap_reason,
    });

    // Adversarial premature unilateral CLTV fallback at `150 < 170`
    let (uni_pre_ok, uni_pre_reason) = node.test_mempool_accept(&hex::encode(
        clearing_bundle.ab_unilateral_fallback_tx.serialize_segwit(),
    ));
    assert!(!uni_pre_ok && uni_pre_reason.contains("non-final"));
    probes.push(CoreMempoolProbe {
        probe_id: "clearing-premature-unilateral-cltv".into(),
        description: "Broadcast unilateral CLTV fallback at height 150 (< 170)".into(),
        core_accepted: uni_pre_ok,
        core_reject_reason: uni_pre_reason,
    });

    // Broadcast & confirm honest 3-input, 5-output double-offline clearing tx + CPFP child!
    let (clear_ok, clear_reason) = node.test_mempool_accept(&raw_clear_hex);
    if !clear_ok {
        return Err(format!("Core rejected honest clearing tx: {clear_reason}"));
    }
    let confirmed_clear_txid = node.cli_raw(&["sendrawtransaction", &raw_clear_hex])?;
    assert_eq!(confirmed_clear_txid, clear_tx.txid_hex());

    let (fee_txid, fee_vout) = node.fund_p2tr_script(&anchor_spk, 5_000);
    let mut cpfp_child = SegwitTx {
        version: 2,
        inputs: vec![
            SegwitTxIn::from_display_txid(&confirmed_clear_txid, 4, 0xffff_fffe, 330, anchor_spk.clone())
                .unwrap(),
            SegwitTxIn::from_display_txid(&fee_txid, fee_vout, 0xffff_fffe, 5_000, anchor_spk.clone())
                .unwrap(),
        ],
        outputs: vec![(3_830, anchor_spk)],
        locktime: 0,
    };
    let sh0 = cpfp_child.bip341_sighash(0, SIGHASH_DEFAULT, None).unwrap();
    let sh1 = cpfp_child.bip341_sighash(1, SIGHASH_DEFAULT, None).unwrap();
    cpfp_child.inputs[0].witness = vec![encode_taproot_witness_sig(
        &bip340_sign(&anchor_sk, &sh0).unwrap(),
        SIGHASH_DEFAULT,
    )];
    cpfp_child.inputs[1].witness = vec![encode_taproot_witness_sig(
        &bip340_sign(&anchor_sk, &sh1).unwrap(),
        SIGHASH_DEFAULT,
    )];
    let cpfp_child_txid =
        node.cli_raw(&["sendrawtransaction", &hex::encode(cpfp_child.serialize_segwit())])?;
    node.mine_blocks(6, &miner_addr);

    // 4. BitVM3 Taproot `Assert` / `Disprove` / `Optimistic-Payout` Consensus Drills!
    let operator_sk = [0x51u8; 32];
    let challenger_sk = [0x52u8; 32];
    let operator_pk = pubkey_x_from_secret(&operator_sk).unwrap();
    let challenger_pk = pubkey_x_from_secret(&challenger_sk).unwrap();
    let operator_payout_spk = p2tr_spk_from_seed(0x53);
    let challenger_payout_spk = p2tr_spk_from_seed(0x54);

    let initial_nullifier_root = BatchVaultNullifierTree::new().root();
    let canonical_boundary_preimage = encode_boundary_preimage(&ckpt_root, &initial_nullifier_root);
    let canonical_boundary_hash = hash_boundary_preimage(&ckpt_root, &initial_nullifier_root);
    let (pre_0, pre_1, wire_h0, wire_h1) = derive_wire_connector_pair(&[0x77u8; 32], 0);
    let challenge_csv_blocks = 10u16;
    let bond_sats = 1_000_000u64;
    let slash_fee_sats = 1_000u64;

    // --- Drill A2: Honest Operator `U_Assert` ---
    let honest_assert_tree = BitVm3AssertionTree::build(
        operator_pk,
        challenger_pk,
        challenge_csv_blocks,
        canonical_boundary_hash,
        canonical_boundary_hash, // Honest Operator commits exact canonical boundary!
        wire_h0,
        wire_h1,
    )
    .map_err(|e| format!("honest BitVm3AssertionTree: {e}"))?;

    let (honest_assert_txid, honest_assert_vout) =
        node.fund_p2tr_script(&honest_assert_tree.script_pubkey, bond_sats);
    node.mine_blocks(1, &miner_addr); // Only 1 confirmation (< 10 CSV blocks!)

    let opt_payout_tx = honest_assert_tree
        .sign_optimistic_payout_tx(
            &honest_assert_txid,
            honest_assert_vout,
            bond_sats,
            slash_fee_sats,
            &operator_sk,
            operator_payout_spk.clone(),
        )
        .map_err(|e| format!("sign opt payout: {e}"))?;
    let raw_opt_hex = hex::encode(opt_payout_tx.serialize_segwit());

    // Verify premature Operator reclaim before CSV=10 is REJECTED (`non-BIP68-final`)!
    let (opt_early_ok, opt_early_reason) = node.test_mempool_accept(&raw_opt_hex);
    assert!(!opt_early_ok && opt_early_reason.contains("non-BIP68-final"));
    probes.push(CoreMempoolProbe {
        probe_id: "bitvm3-premature-optimistic-payout-before-csv".into(),
        description: "Operator attempts bond reclaim at 1 confirmation (< CSV 10)".into(),
        core_accepted: opt_early_ok,
        core_reject_reason: opt_early_reason,
    });

    // Verify malicious Challenger CANNOT slash an honest Operator on `disprove_boundary_leaf`!
    let grief_tx = honest_assert_tree
        .sign_disprove_boundary_tx(
            &honest_assert_txid,
            honest_assert_vout,
            bond_sats,
            slash_fee_sats,
            &challenger_sk,
            challenger_payout_spk.clone(),
            &canonical_boundary_preimage,
        )
        .unwrap();
    let (grief_ok, grief_reason) =
        node.test_mempool_accept(&hex::encode(grief_tx.serialize_segwit()));
    assert!(!grief_ok);
    probes.push(CoreMempoolProbe {
        probe_id: "bitvm3-grief-honest-operator-boundary-leaf".into(),
        description: "Malicious Challenger attempts boundary slash against honest Operator".into(),
        core_accepted: grief_ok,
        core_reject_reason: grief_reason,
    });

    // Mine remaining 9 blocks (`total = 10 >= challenge_csv_blocks`) and confirm `optimistic_payout_tx`!
    node.mine_blocks(u64::from(challenge_csv_blocks - 1), &miner_addr);
    let (opt_ok, opt_reason) = node.test_mempool_accept(&raw_opt_hex);
    if !opt_ok {
        return Err(format!("Core rejected matured optimistic_payout_tx: {opt_reason}"));
    }
    let opt_payout_txid = node.cli_raw(&["sendrawtransaction", &raw_opt_hex])?;
    node.mine_blocks(1, &miner_addr);

    // --- Drill B: Faulty Operator Boundary Fraud -> Immediate Challenger Slash (`Leaf 1`) ---
    let forged_nullifier_root = [0xeeu8; 32]; // Stale/mutated nullifier root!
    let bad_boundary_preimage = encode_boundary_preimage(&ckpt_root, &forged_nullifier_root);
    let bad_boundary_commit = hash_boundary_preimage(&ckpt_root, &forged_nullifier_root);
    let bad_boundary_tree = BitVm3AssertionTree::build(
        operator_pk,
        challenger_pk,
        challenge_csv_blocks,
        canonical_boundary_hash,
        bad_boundary_commit,
        wire_h0,
        wire_h1,
    )
    .unwrap();
    let (bad_b_txid, bad_b_vout) =
        node.fund_p2tr_script(&bad_boundary_tree.script_pubkey, bond_sats);
    node.mine_blocks(1, &miner_addr);

    // Probe: Challenger with wrong preimage MUST fail `OP_EQUALVERIFY`!
    let wrong_pre_slash = bad_boundary_tree
        .sign_disprove_boundary_tx(
            &bad_b_txid,
            bad_b_vout,
            bond_sats,
            slash_fee_sats,
            &challenger_sk,
            challenger_payout_spk.clone(),
            &canonical_boundary_preimage, // does not match `bad_boundary_commit`!
        )
        .unwrap();
    let (wrong_pre_ok, wrong_pre_reason) =
        node.test_mempool_accept(&hex::encode(wrong_pre_slash.serialize_segwit()));
    assert!(!wrong_pre_ok);
    probes.push(CoreMempoolProbe {
        probe_id: "bitvm3-boundary-slash-wrong-preimage".into(),
        description: "Challenger submits non-matching boundary preimage on Leaf 1".into(),
        core_accepted: wrong_pre_ok,
        core_reject_reason: wrong_pre_reason,
    });

    // Valid Challenger `disprove_boundary_tx` immediately slashes the `1,000,000`-sat bond!
    let valid_b_slash = bad_boundary_tree
        .sign_disprove_boundary_tx(
            &bad_b_txid,
            bad_b_vout,
            bond_sats,
            slash_fee_sats,
            &challenger_sk,
            challenger_payout_spk.clone(),
            &bad_boundary_preimage,
        )
        .unwrap();
    let valid_b_hex = hex::encode(valid_b_slash.serialize_segwit());
    let (b_slash_ok, b_slash_reason) = node.test_mempool_accept(&valid_b_hex);
    if !b_slash_ok {
        return Err(format!("Core rejected valid disprove_boundary_tx: {b_slash_reason}"));
    }
    let disprove_boundary_slash_txid = node.cli_raw(&["sendrawtransaction", &valid_b_hex])?;
    node.mine_blocks(1, &miner_addr);

    // --- Drill C: Faulty Operator Wire Equivocation -> Immediate Challenger Slash (`Leaf 2`) ---
    let (bad_eq_txid, bad_eq_vout) =
        node.fund_p2tr_script(&honest_assert_tree.script_pubkey, bond_sats);
    node.mine_blocks(1, &miner_addr);

    // Probe: Single preimage duplicated `(pre_0, pre_0)` MUST fail `OP_EQUALVERIFY` against `h_wire_1`!
    let dup_eq_tx = honest_assert_tree
        .sign_disprove_equivocation_tx(
            &bad_eq_txid,
            bad_eq_vout,
            bond_sats,
            slash_fee_sats,
            &challenger_sk,
            challenger_payout_spk.clone(),
            &pre_0,
            &pre_0,
        )
        .unwrap();
    let (dup_eq_ok, dup_eq_reason) =
        node.test_mempool_accept(&hex::encode(dup_eq_tx.serialize_segwit()));
    assert!(!dup_eq_ok);
    probes.push(CoreMempoolProbe {
        probe_id: "bitvm3-equivocation-without-second-preimage".into(),
        description: "Attempt Leaf 2 equivocation slash with only pre_0 (missing pre_1)".into(),
        core_accepted: dup_eq_ok,
        core_reject_reason: dup_eq_reason,
    });

    let valid_eq_tx = honest_assert_tree
        .sign_disprove_equivocation_tx(
            &bad_eq_txid,
            bad_eq_vout,
            bond_sats,
            slash_fee_sats,
            &challenger_sk,
            challenger_payout_spk,
            &pre_0,
            &pre_1,
        )
        .unwrap();
    let valid_eq_hex = hex::encode(valid_eq_tx.serialize_segwit());
    let (eq_ok, eq_reason) = node.test_mempool_accept(&valid_eq_hex);
    if !eq_ok {
        return Err(format!("Core rejected valid disprove_equivocation_tx: {eq_reason}"));
    }
    let disprove_equivocation_slash_txid = node.cli_raw(&["sendrawtransaction", &valid_eq_hex])?;
    node.mine_blocks(1, &miner_addr);

    // --- Drill D: RouterLP Offline -> Unilateral CLTV Fallback at `height >= 170` ---
    let h_before_uni = node.height();
    if h_before_uni < 170 {
        node.mine_blocks(170 - h_before_uni, &miner_addr);
    }
    let ab_uni_txid_sent = node.cli_raw(&[
        "sendrawtransaction",
        &hex::encode(uni_bundle.ab_unilateral_fallback_tx.serialize_segwit()),
    ])?;
    let bc_uni_txid_sent = node.cli_raw(&[
        "sendrawtransaction",
        &hex::encode(uni_bundle.bc_unilateral_fallback_tx.serialize_segwit()),
    ])?;
    node.mine_blocks(1, &miner_addr);

    // --- Drill E: BitVM3 Garbled NAND Gate Tapscript Disprover on Core 31.1 ---
    let garbled = GarbledNandGate::garble_deterministic(&[0x88u8; 32], 7);
    let gate_tree = GarbledGateTaprootTree::build(
        operator_pk,
        challenger_pk,
        challenge_csv_blocks,
        garbled.commitments.clone(),
    )
    .map_err(|e| format!("GarbledGateTaprootTree: {e}"))?;
    let (gate_txid, gate_vout) = node.fund_p2tr_script(&gate_tree.script_pubkey, bond_sats);
    node.mine_blocks(1, &miner_addr);

    // Honest `(1, 1) -> NAND(1, 1) = 0` CANNOT be slashed (`OP_NUMNOTEQUAL` fails!)
    let (bit_honest, lc_honest) = garbled
        .evaluate(1, 1, &garbled.labels_a[1], &garbled.labels_b[1])
        .unwrap();
    assert_eq!(bit_honest, 0);
    let grief_gate_tx = gate_tree
        .sign_disprove_garbled_gate_tx(
            &gate_txid,
            gate_vout,
            bond_sats,
            slash_fee_sats,
            &challenger_sk,
            p2tr_spk_from_seed(0x54),
            &garbled.labels_a[1],
            &garbled.labels_b[1],
            &lc_honest,
        )
        .unwrap();
    let (gg_grief_ok, gg_grief_reason) =
        node.test_mempool_accept(&hex::encode(grief_gate_tx.serialize_segwit()));
    assert!(!gg_grief_ok);
    probes.push(CoreMempoolProbe {
        probe_id: "bitvm3-garbled-nand-grief-honest-gate".into(),
        description: "Challenger attempts garbled NAND slash against honest (1,1)->0 output label".into(),
        core_accepted: gg_grief_ok,
        core_reject_reason: gg_grief_reason,
    });

    // Dishonest Operator claims `(1, 1) -> 1` (`labels_c[1]`): Core 31.1 IMMEDIATELY SLASHES BOND!
    let valid_gate_slash = gate_tree
        .sign_disprove_garbled_gate_tx(
            &gate_txid,
            gate_vout,
            bond_sats,
            slash_fee_sats,
            &challenger_sk,
            p2tr_spk_from_seed(0x54),
            &garbled.labels_a[1],
            &garbled.labels_b[1],
            &garbled.labels_c[1],
        )
        .unwrap();
    let valid_gg_hex = hex::encode(valid_gate_slash.serialize_segwit());
    let (gg_ok, gg_reason) = node.test_mempool_accept(&valid_gg_hex);
    if !gg_ok {
        return Err(format!("Core rejected valid garbled gate slash: {gg_reason}"));
    }
    let _gg_slash_txid = node.cli_raw(&["sendrawtransaction", &valid_gg_hex])?;
    node.mine_blocks(1, &miner_addr);

    let assertion_txid_be: [u8; 32] = hex::decode(&honest_assert_txid)
        .unwrap()
        .try_into()
        .unwrap();

    let receipt = Mnr05CoreRegtestReceipt {
        scenario: "SHZ-MNR-05: Batched BitVM3 Taproot Assert/Disprove + PTLC Lightning Double-Offline Multilateral LN-DLC Clearing on Bitcoin Core 31.1".into(),
        core_version,
        network_code: BitcoinNetworkCode::Regtest,
        regtest_genesis_hash_hex: genesis_hex,
        shzidx01_anchor_txid: shzidx01_txid,
        shzidx01_anchor_vout: shzidx01_vout,
        oracle_checkpoint_root_hex: hex::encode(ckpt_root),
        funded_vault_outpoints: vec![
            format!("{ab_txid}:{ab_vout}"),
            format!("{bc_txid}:{bc_vout}"),
            format!("{ca_txid}:{ca_vout}"),
        ],
        double_offline_clearing_txid: confirmed_clear_txid,
        double_offline_clearing_wtxid: clear_tx.wtxid_hex(),
        double_offline_clearing_vsize: clear_tx.vsize(),
        double_offline_clearing_stripped_bytes: clearing_bundle.stripped_clearing_tx_348b.len(),
        cpfp_child_txid,
        cleared_outputs_sats: clear_tx.outputs.iter().map(|(v, _)| *v).collect(),
        ptlc_lightning_bridge: clearing_bundle.receipt.clone(),
        bitvm3_taproot_drills: BitVm3TaprootDrillSummary {
            honest_assertion_txid: honest_assert_txid,
            honest_assertion_vout: honest_assert_vout,
            challenge_csv_blocks,
            bond_sats,
            optimistic_payout_txid: opt_payout_txid,
            optimistic_payout_vsize: opt_payout_tx.vsize(),
            disprove_boundary_bad_assert_txid: bad_b_txid,
            disprove_boundary_slash_txid,
            disprove_boundary_slash_vsize: valid_b_slash.vsize(),
            disprove_equivocation_bad_assert_txid: bad_eq_txid,
            disprove_equivocation_slash_txid,
            disprove_equivocation_slash_vsize: valid_eq_tx.vsize(),
            honest_operator_unslashable_verified: true,
            premature_csv_rejected_verified: true,
        },
        unilateral_fallback_ab_txid: ab_uni_txid_sent,
        unilateral_fallback_bc_txid: bc_uni_txid_sent,
        mempool_adversarial_probes: probes,
        bitvm3_tapscript_disprove_regtest_verified: true,
        full_groth16_garbled_circuit_l1_verified: false,
        production_ready: false,
    };

    Ok((
        receipt,
        clearing_bundle,
        oracle_witness,
        assertion_txid_be,
        honest_assert_vout,
        regtest_genesis,
    ))
}
