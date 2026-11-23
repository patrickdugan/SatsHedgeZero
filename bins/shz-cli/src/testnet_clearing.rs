//! Live 3-Party, 3-Trade Multilateral DLC Collation + `lnm-nova` (`nova-snark 0.76.0`) Prover
//! + Bitcoin Core v31.1 Clearing Execution Harness (`shz testnet-clearing`).

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use serde::Serialize;
use serde_json::Value;
use shz_nova_bitvm::{
    DEFAULT_TESTNET4_ANCHOR_HASH_HEX, DEFAULT_TESTNET4_ANCHOR_HEIGHT, ExternalNovaSnarkReceipt,
    Hash, Script, ThreePartyClearingConfig, ThreePartyClearingReport, VerificationHonestyFlags,
    build_live_testnet4_micro_clearing_ceremony, build_three_party_clearing_ceremony,
    precompute_live_testnet4_micro_dlc_templates, precompute_three_party_dlc_funding_templates,
};

use crate::mnr02_regtest::{AdversarialProbeReceipt, CoreConfirmedTxReceipt};

#[derive(Serialize)]
pub struct FundedDlcUtxoReceipt {
    pub trade_no: u8,
    pub label: String,
    pub txid: String,
    pub vout: u32,
    pub sats: u64,
    pub script_pubkey_hex: String,
}

#[derive(Serialize)]
pub struct UnspentClearedOutputCheck {
    pub owner: &'static str,
    pub vout: u32,
    pub sats: u64,
    pub utxo_present_in_core: bool,
}

#[derive(Serialize)]
pub struct TestnetThreePartyClearingReceipt {
    pub scenario: &'static str,
    pub core_version: String,
    pub bitcoin_spend_enforced: bool,
    pub nova_compressed_snark_verified: bool,
    pub production_ready: bool,
    pub funded_dlc_utxos: Vec<FundedDlcUtxoReceipt>,
    pub core_confirmed_atomic_clearing_tx: CoreConfirmedTxReceipt,
    pub post_clearing_utxo_checks: Vec<UnspentClearedOutputCheck>,
    pub adversarial_probes: Vec<AdversarialProbeReceipt>,
    pub clearing_report: ThreePartyClearingReport,
}

pub(crate) struct IsolatedCoreNode {
    child: Child,
    cli_path: PathBuf,
    datadir: PathBuf,
    rpc_port: u16,
}

impl IsolatedCoreNode {
    pub(crate) fn spawn(bitcoind_path: &Path) -> Self {
        let cli_path = bitcoind_path
            .parent()
            .expect("bin dir")
            .join(if cfg!(windows) {
                "bitcoin-cli.exe"
            } else {
                "bitcoin-cli"
            });
        assert!(
            cli_path.exists(),
            "bitcoin-cli not found next to {}",
            bitcoind_path.display()
        );

        let port = {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral rpc port");
            l.local_addr().unwrap().port()
        };
        let p2p_port = {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral p2p port");
            l.local_addr().unwrap().port()
        };

        let unique = format!(
            "shz-testnet-clearing-{}-{}",
            std::process::id(),
            port
        );
        let datadir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&datadir).expect("create temp core datadir");

        let child = Command::new(bitcoind_path)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0001")
            .arg("-rpcuser=shzrpc")
            .arg("-rpcpassword=shzpass")
            .arg(format!("-rpcport={port}"))
            .arg(format!("-port={p2p_port}"))
            .arg("-listen=0")
            .arg("-dnsseed=0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind");

        let node = Self {
            child,
            cli_path,
            datadir,
            rpc_port: port,
        };

        for _ in 0..80 {
            if node.cli_raw(&["getblockchaininfo"]).is_ok() {
                return node;
            }
            thread::sleep(Duration::from_millis(150));
        }
        panic!("bitcoind RPC failed to become ready");
    }

    pub(crate) fn cli_raw(&self, args: &[&str]) -> Result<String, String> {
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

    pub(crate) fn cli_json(&self, args: &[&str]) -> Value {
        let txt = self.cli_raw(args).expect("bitcoin-cli JSON call succeeded");
        serde_json::from_str(&txt).expect("valid JSON from bitcoin-cli")
    }

    pub(crate) fn height(&self) -> u64 {
        self.cli_raw(&["getblockcount"]).unwrap().parse().unwrap()
    }

    pub(crate) fn mine_blocks(&self, count: u64, miner_addr: &str) -> u64 {
        let c = count.to_string();
        self.cli_raw(&["generatetoaddress", &c, miner_addr])
            .expect("generatetoaddress");
        self.height()
    }

    pub(crate) fn fund_raw_script(&self, script_pubkey: &[u8], sats: u64) -> (String, u32) {
        assert_eq!(script_pubkey.len(), 34);
        assert_eq!(&script_pubkey[..2], &[0x51, 0x20]);
        let out_x_hex = hex::encode(&script_pubkey[2..]);
        let desc_info = self.cli_json(&["getdescriptorinfo", &format!("rawtr({out_x_hex})")]);
        let desc = desc_info["descriptor"].as_str().unwrap();
        let addrs = self.cli_json(&["deriveaddresses", desc]);
        let addr = addrs[0].as_str().unwrap();

        let btc_str = format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000);
        let outputs_arg = format!("[{{\"{addr}\": {btc_str}}}]");
        let raw_hex = self
            .cli_raw(&["createrawtransaction", "[]", &outputs_arg])
            .unwrap();

        let funded = self.cli_json(&["fundrawtransaction", &raw_hex]);
        let funded_hex = funded["hex"].as_str().unwrap();
        let signed = self.cli_json(&["signrawtransactionwithwallet", funded_hex]);
        assert!(signed["complete"].as_bool().unwrap());
        let signed_hex = signed["hex"].as_str().unwrap();
        let txid = self.cli_raw(&["sendrawtransaction", signed_hex]).unwrap();

        let decoded = self.cli_json(&["decoderawtransaction", signed_hex]);
        let target_spk_hex = hex::encode(script_pubkey);
        let vout = decoded["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(target_spk_hex.as_str()))
            .expect("funded target vout")["n"]
            .as_u64()
            .unwrap() as u32;
        (txid, vout)
    }

    pub(crate) fn test_mempool_accept(&self, raw_tx_hex: &str) -> (bool, String) {
        let arg = format!("[\"{raw_tx_hex}\"]");
        let res = self.cli_json(&["testmempoolaccept", &arg]);
        let entry = &res[0];
        let allowed = entry["allowed"].as_bool().unwrap_or(false);
        let reason = entry["reject-reason"]
            .as_str()
            .unwrap_or("accepted")
            .to_string();
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

pub(crate) fn run_external_lnm_nova_prover(
    lnm_nova_bin: &Path,
    witness_bytes: &[u8],
    persist_dir: Option<&Path>,
) -> ExternalNovaSnarkReceipt {
    let work_dir = std::env::temp_dir().join(format!(
        "shz-lnm-nova-work-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&work_dir).expect("create temp nova work dir");

    let witness_path = work_dir.join("3party_clearing_witness.lnmbat01");
    let expect_path = work_dir.join("expected_pins.json");
    let bundle_dir = work_dir.join("nova_bundle");
    fs::write(&witness_path, witness_bytes).expect("write witness.lnmbat01");

    // 1. Independently derive receiver-owned VerifierPins (`lnmarkets-nova-expect/v2`)
    let prep_out = Command::new(lnm_nova_bin)
        .arg("prepare")
        .arg("--witness")
        .arg(&witness_path)
        .arg("--out")
        .arg(&expect_path)
        .output()
        .expect("invoke lnm-nova prepare");
    assert!(
        prep_out.status.success(),
        "lnm-nova prepare failed: {}",
        String::from_utf8_lossy(&prep_out.stderr)
    );

    // 2. Prove 3-step RecursiveSNARK + CompressedSNARK (`nova-snark 0.76.0` Spartan + IPA)
    let prove_out = Command::new(lnm_nova_bin)
        .arg("prove")
        .arg("--witness")
        .arg(&witness_path)
        .arg("--compressed")
        .arg("--out")
        .arg(&bundle_dir)
        .output()
        .expect("invoke lnm-nova prove --compressed");
    assert!(
        prove_out.status.success(),
        "lnm-nova prove failed: {}",
        String::from_utf8_lossy(&prove_out.stderr)
    );
    let prove_json: Value =
        serde_json::from_slice(&prove_out.stdout).expect("parse lnm-nova prove JSON");

    // 3. Verify persisted CompressedSNARK bundle against independently supplied expectations
    let verify_out = Command::new(lnm_nova_bin)
        .arg("verify")
        .arg("--bundle")
        .arg(&bundle_dir)
        .arg("--expect")
        .arg(&expect_path)
        .output()
        .expect("invoke lnm-nova verify");
    assert!(
        verify_out.status.success(),
        "lnm-nova verify failed: {}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let verify_json: Value =
        serde_json::from_slice(&verify_out.stdout).expect("parse lnm-nova verify JSON");

    assert_eq!(verify_json["nova_compressed_verified"].as_bool(), Some(true));
    assert_eq!(
        verify_json["independently_supplied_expectations_matched"].as_bool(),
        Some(true)
    );

    // Optionally copy public, path-free proof artifacts (`expected_pins.json`, `manifest.json`, `proof.bin`)
    if let Some(dest) = persist_dir {
        fs::create_dir_all(dest).expect("create persist_dir");
        fs::copy(&expect_path, dest.join("expected_pins.json")).expect("copy expected_pins.json");
        fs::copy(bundle_dir.join("manifest.json"), dest.join("manifest.json"))
            .expect("copy manifest.json");
        fs::copy(bundle_dir.join("proof.bin"), dest.join("proof.bin")).expect("copy proof.bin");
    }

    let _ = fs::remove_dir_all(&work_dir);

    let prove_secs = prove_json["nova_prove_seconds"].as_f64().unwrap_or(0.0)
        + prove_json["compressed_prove_seconds"]
            .as_f64()
            .unwrap_or(0.0);
    let verify_secs = verify_json["compressed_verify_seconds"]
        .as_f64()
        .unwrap_or(0.0);

    ExternalNovaSnarkReceipt {
        schema: verify_json["schema"].as_str().unwrap_or("").to_owned(),
        relation: verify_json["relation"].as_str().unwrap_or("").to_owned(),
        nova_version: verify_json["nova_version"].as_str().unwrap_or("").to_owned(),
        steps: verify_json["rows"].as_u64().unwrap_or(0) as u32,
        compressed_proof_bytes: verify_json["compressed_bytes"].as_u64().unwrap_or(0) as usize,
        proof_sha256_hex: verify_json["proof_sha256"].as_str().unwrap_or("").to_owned(),
        verifier_key_sha256_hex: verify_json["verifier_key_sha256"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        verifier_key_serialized_bytes: verify_json["verifier_key_serialized_bytes"]
            .as_u64()
            .unwrap_or(0),
        public_params_digest_hex: verify_json["nova_public_params_digest"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        primary_constraints: verify_json["nova_augmented_constraints_primary"]
            .as_u64()
            .unwrap_or(0),
        secondary_constraints: verify_json["nova_augmented_constraints_secondary"]
            .as_u64()
            .unwrap_or(0),
        prove_wall_seconds: format!("{prove_secs:.4}"),
        verify_wall_seconds: format!("{verify_secs:.4}"),
        independently_supplied_expectations_matched: true,
        nova_compressed_verified: true,
    }
}

pub fn run_testnet_three_party_clearing(
    bitcoind_path: &Path,
    lnm_nova_bin: Option<&Path>,
    persist_bundle_dir: Option<&Path>,
) -> TestnetThreePartyClearingReceipt {
    let node = IsolatedCoreNode::spawn(bitcoind_path);
    let net_info = node.cli_json(&["getnetworkinfo"]);
    let core_version = format!(
        "Bitcoin Core v{} ({})",
        net_info["version"].as_u64().unwrap_or(0),
        net_info["subversion"].as_str().unwrap_or("bitcoind")
    );

    node.cli_raw(&["createwallet", "shz-clearing-miner"])
        .expect("createwallet");
    let miner_addr = node.cli_raw(&["getnewaddress"]).expect("getnewaddress");
    node.mine_blocks(105, &miner_addr);

    let refund_csv = 144u16;
    let templates =
        precompute_three_party_dlc_funding_templates(refund_csv).expect("precompute 3 DLC scripts");

    let mut funded_outpoints: [(Hash, u32); 3] = [([0u8; 32], 0); 3];
    let mut funded_receipts = Vec::with_capacity(3);

    for (idx, tpl) in templates.iter().enumerate() {
        let spk_bytes = hex::decode(&tpl.funding_script_pubkey_hex).expect("spk hex");
        let (txid_hex, vout) = node.fund_raw_script(&spk_bytes, tpl.total_funding_sats);
        let txid_bytes: Hash = hex::decode(&txid_hex)
            .expect("txid hex")
            .try_into()
            .expect("32B");
        funded_outpoints[idx] = (txid_bytes, vout);
        funded_receipts.push(FundedDlcUtxoReceipt {
            trade_no: (idx + 1) as u8,
            label: tpl.label.clone(),
            txid: txid_hex,
            vout,
            sats: tpl.total_funding_sats,
            script_pubkey_hex: tpl.funding_script_pubkey_hex.clone(),
        });
    }
    node.mine_blocks(1, &miner_addr); // height = 106

    let anchor_height = std::env::var("SHZ_TESTNET4_TIP_HEIGHT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TESTNET4_ANCHOR_HEIGHT);
    let anchor_hash = std::env::var("SHZ_TESTNET4_TIP_HASH")
        .ok()
        .filter(|s| s.len() == 64)
        .unwrap_or_else(|| DEFAULT_TESTNET4_ANCHOR_HASH_HEX.to_owned());

    let cfg = ThreePartyClearingConfig {
        funding_outpoints: Some(funded_outpoints),
        maturity_height: 120,
        evaluation_height: 120,
        valid_until_height: 200,
        refund_height: 240,
        refund_csv,
        testnet4_anchor_height: anchor_height,
        testnet4_anchor_block_hash_hex: anchor_hash,
    };

    let mut artifacts =
        build_three_party_clearing_ceremony(&cfg).expect("build 3-party clearing ceremony");
    let raw_honest_hex = hex::encode(artifacts.signed_clearing_tx.serialize_segwit());

    let mut probes = Vec::new();

    // Probe 1: Premature broadcast before maturity_height = 120 (at height 106)
    let (ok_premature, reason_premature) = node.test_mempool_accept(&raw_honest_hex);
    assert!(!ok_premature, "premature clearing tx must be rejected before height 120");
    probes.push(AdversarialProbeReceipt {
        probe_id: "premature-clearing-before-maturity-120",
        description: "Broadcast 3-input LNMBAT01 clearing tx at height 106 (< nLockTime 120)",
        core_accepted: ok_premature,
        core_reject_reason: reason_premature,
    });

    // Advance chain to exact evaluation/maturity height = 120
    let current_h = node.height();
    node.mine_blocks(120 - current_h, &miner_addr);
    assert_eq!(node.height(), 120);

    // Probe 2: Shave 1 sat from Bob's 90,000,000 freed collateral and divert to Alice
    let mut shave_bob_tx = artifacts.signed_clearing_tx.clone();
    let bob_out_idx = shave_bob_tx
        .outputs
        .iter()
        .position(|(v, _)| *v == 90_000_000)
        .expect("Bob 90M output");
    let alice_out_idx = shave_bob_tx
        .outputs
        .iter()
        .position(|(v, _)| *v == 71_500_000)
        .expect("Alice 71.5M output");
    shave_bob_tx.outputs[bob_out_idx].0 -= 1;
    shave_bob_tx.outputs[alice_out_idx].0 += 1;
    let (ok_shave_bob, reason_shave_bob) =
        node.test_mempool_accept(&hex::encode(shave_bob_tx.serialize_segwit()));
    assert!(!ok_shave_bob, "shaving Bob's freed collateral by 1 sat must fail BIP-341 sighash");
    probes.push(AdversarialProbeReceipt {
        probe_id: "shave-loser-bob-freed-collateral-by-1-sat",
        description: "Divert 1 sat from Bob's 90,000,000 freed collateral to Alice",
        core_accepted: ok_shave_bob,
        core_reject_reason: reason_shave_bob,
    });

    // Probe 3: Shave 1 sat from Winner Alice's 71,500,000 cleared PnL payout
    let mut shave_alice_tx = artifacts.signed_clearing_tx.clone();
    shave_alice_tx.outputs[alice_out_idx].0 -= 1;
    shave_alice_tx.outputs[bob_out_idx].0 += 1;
    let (ok_shave_alice, reason_shave_alice) =
        node.test_mempool_accept(&hex::encode(shave_alice_tx.serialize_segwit()));
    assert!(!ok_shave_alice, "shaving Alice's routed PnL by 1 sat must fail BIP-341 sighash");
    probes.push(AdversarialProbeReceipt {
        probe_id: "shave-winner-alice-routed-pnl-by-1-sat",
        description: "Divert 1 sat from Winner Alice's 71,500,000 cleared payout to Bob",
        core_accepted: ok_shave_alice,
        core_reject_reason: reason_shave_alice,
    });

    // Broadcast and confirm the exact 3-input, 4-output LNMBAT01 Taproot clearing transaction!
    let sent_txid = node
        .cli_raw(&["sendrawtransaction", &raw_honest_hex])
        .expect("sendrawtransaction honest 3-party clearing tx");
    assert_eq!(sent_txid, artifacts.report.atomic_clearing_txid_hex);
    assert_eq!(sent_txid, artifacts.report.journal.batch_txid_hex);
    assert_eq!(
        sent_txid,
        artifacts.report.bitvm3_testnet4_statement.settlement_txid_hex
    );

    let confirmed_h = node.mine_blocks(1, &miner_addr);
    let block_hash = node
        .cli_raw(&["getblockhash", &confirmed_h.to_string()])
        .expect("getblockhash");
    let tx_info = node.cli_json(&["getrawtransaction", &sent_txid, "true"]);
    let confirmations = tx_info["confirmations"].as_u64().unwrap_or(0);
    assert!(confirmations >= 1);

    // Verify all 3 input DLC UTXOs are spent and all 4 cleared outputs exist in Core's UTXO set!
    for f in &funded_receipts {
        let spent_check = node
            .cli_raw(&["gettxout", &f.txid, &f.vout.to_string()])
            .expect("gettxout spent");
        assert!(spent_check.is_empty(), "funded DLC UTXO must be spent");
    }

    let mut utxo_checks = Vec::with_capacity(4);
    for (vout_idx, &(sats, _)) in artifacts.signed_clearing_tx.outputs.iter().enumerate() {
        let out_txt = node
            .cli_raw(&["gettxout", &sent_txid, &vout_idx.to_string()])
            .expect("gettxout cleared output");
        assert!(!out_txt.is_empty(), "cleared output vout {vout_idx} must exist");
        let owner = match sats {
            71_500_000 => "Alice (Winner: 60.5M margin + 11M routed PnL)",
            90_000_000 => "Bob (Loser: 90M freed collateral returned)",
            82_500_000 => "Carol (Market-Maker: 82.5M freed collateral returned)",
            990 => "Aggregated CPFP Anchor (3 x 330 sats)",
            _ => "Unknown",
        };
        utxo_checks.push(UnspentClearedOutputCheck {
            owner,
            vout: vout_idx as u32,
            sats,
            utxo_present_in_core: true,
        });
    }

    let witness_lens: Vec<usize> = artifacts.signed_clearing_tx.inputs[0]
        .witness
        .iter()
        .map(Vec::len)
        .collect();
    let core_confirmed_tx = CoreConfirmedTxReceipt {
        label: "3-party-3-trade-collated-lnmbat01-clearing-tx",
        txid: sent_txid,
        wtxid: artifacts.signed_clearing_tx.wtxid_hex(),
        vsize: artifacts.signed_clearing_tx.vsize(),
        locktime: artifacts.signed_clearing_tx.locktime,
        script_path_used: "UTXORef NUMS P2TR Leaf 0 (<pk0> CHECKSIGVERIFY <pk1> CHECKSIG) x 3 inputs",
        sighash_flags_hex: vec![
            "0x00 (SIGHASH_DEFAULT)".to_owned(),
            "0x00 (SIGHASH_DEFAULT)".to_owned(),
        ],
        outputs_sats: artifacts.report.atomic_clearing_outputs_sats.clone(),
        witness_item_lengths: witness_lens,
        raw_tx_hex: raw_honest_hex,
        confirmed_block_height: confirmed_h,
        confirmed_block_hash: block_hash,
        core_confirmations: confirmations,
    };

    let mut nova_verified = false;
    if let Some(nova_bin) = lnm_nova_bin.filter(|p| p.exists()) {
        let snark_receipt = run_external_lnm_nova_prover(
            nova_bin,
            &artifacts.batch_witness_bytes,
            persist_bundle_dir,
        );
        nova_verified = snark_receipt.nova_compressed_verified;
        artifacts.report.external_nova_snark_receipt = Some(snark_receipt);
        if nova_verified {
            let flags = VerificationHonestyFlags::with_external_nova_snark_verified();
            artifacts.report.honesty = flags;
            artifacts.report.nova_expected_statement.honesty = flags;
            artifacts.report.bitvm3_testnet4_statement.honesty = flags;
        }
    }

    TestnetThreePartyClearingReceipt {
        scenario: "3-Party, 3-Trade ($50k -> $55k -> $60k) Collated DLC Margin Clearing via BitVM3 Nova & Bitcoin Core",
        core_version,
        bitcoin_spend_enforced: true,
        nova_compressed_snark_verified: nova_verified,
        production_ready: false,
        funded_dlc_utxos: funded_receipts,
        core_confirmed_atomic_clearing_tx: core_confirmed_tx,
        post_clearing_utxo_checks: utxo_checks,
        adversarial_probes: probes,
        clearing_report: artifacts.report,
    }
}

#[derive(Serialize)]
pub struct LiveTestnet4BroadcastReceipt {
    pub scenario: &'static str,
    pub network: &'static str,
    pub core_version: String,
    pub testnet4_tip_height: u32,
    pub testnet4_tip_block_hash: String,
    pub funding_txid: String,
    pub funding_tx_explorer_uri: String,
    pub atomic_clearing_txid: String,
    pub atomic_clearing_tx_explorer_uri: String,
    pub atomic_clearing_wtxid: String,
    pub atomic_clearing_vsize: usize,
    pub mempool_accepted_live_testnet4: bool,
    pub wallet_balance_before_sats: u64,
    pub wallet_balance_after_sats: u64,
    pub net_network_miner_fee_cost_sats: u64,
    pub funded_dlc_utxos: Vec<FundedDlcUtxoReceipt>,
    pub adversarial_probes_live_testnet4: Vec<AdversarialProbeReceipt>,
    pub nova_compressed_snark_verified: bool,
    pub production_ready: bool,
    pub clearing_report: ThreePartyClearingReport,
}

pub(crate) fn wsl_testnet4_cli(wallet: Option<&str>, args: &[&str]) -> Result<String, String> {
    let cli_bin =
        std::env::var("SHZ_WSL_BITCOIN_CLI").unwrap_or_else(|_| "bitcoin-cli".to_owned());
    let mut cmd = Command::new("wsl");
    cmd.arg("-e").arg(&cli_bin);
    if let Ok(datadir) = std::env::var("SHZ_WSL_BITCOIN_DATADIR") {
        cmd.arg(format!("-datadir={datadir}"));
    }
    cmd.arg("-testnet4");
    if let Some(w) = wallet {
        cmd.arg(format!("-rpcwallet={w}"));
    }
    cmd.args(args);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub(crate) fn wsl_testnet4_json(wallet: Option<&str>, args: &[&str]) -> Value {
    let txt = wsl_testnet4_cli(wallet, args).expect("WSL testnet4 bitcoin-cli JSON call succeeded");
    serde_json::from_str(&txt).expect("valid JSON from WSL bitcoin-cli")
}

pub(crate) fn btc_float_to_sats(val: f64) -> u64 {
    (val * 100_000_000.0).round() as u64
}

pub fn run_wsl_testnet4_live_broadcast(
    wallet_name: &str,
    lnm_nova_bin: Option<&Path>,
    persist_bundle_dir: Option<&Path>,
) -> LiveTestnet4BroadcastReceipt {
    let chain_info = wsl_testnet4_json(None, &["getblockchaininfo"]);
    assert_eq!(chain_info["chain"].as_str(), Some("testnet4"));
    assert_eq!(chain_info["initialblockdownload"].as_bool(), Some(false));
    let tip_height = chain_info["blocks"].as_u64().expect("tip height") as u32;
    let tip_hash = chain_info["bestblockhash"]
        .as_str()
        .expect("bestblockhash")
        .to_owned();

    let net_info = wsl_testnet4_json(None, &["getnetworkinfo"]);
    let core_version = format!(
        "Bitcoin Core v{} ({})",
        net_info["version"].as_u64().unwrap_or(0),
        net_info["subversion"].as_str().unwrap_or("bitcoind")
    );

    let bal_before = wsl_testnet4_json(Some(wallet_name), &["getbalances"]);
    let sats_before = btc_float_to_sats(
        bal_before["mine"]["trusted"].as_f64().unwrap_or(0.0)
            + bal_before["mine"]["untrusted_pending"].as_f64().unwrap_or(0.0),
    );
    assert!(
        sats_before >= 5_400,
        "wallet {wallet_name} needs >= 5,400 sats on Testnet4 (got {sats_before})"
    );

    // 1. Derive 4 fresh bech32m P2TR payout addresses inside the live Testnet4 wallet
    //    so all cleared margin + routed PnL returns directly to the wallet!
    let labels = [
        "shz:alice-winner-closeout",
        "shz:bob-loser-freed-collateral",
        "shz:carol-mm-freed-collateral",
        "shz:cpfp-anchor",
    ];
    let mut payout_scripts: [Script; 4] = [[0u8; 34]; 4];
    for (i, label) in labels.iter().enumerate() {
        let addr = wsl_testnet4_cli(Some(wallet_name), &["getnewaddress", label, "bech32m"])
            .expect("getnewaddress bech32m");
        let info = wsl_testnet4_json(Some(wallet_name), &["getaddressinfo", &addr]);
        let spk_hex = info["scriptPubKey"].as_str().expect("scriptPubKey hex");
        let spk_bytes: Script = hex::decode(spk_hex)
            .expect("decode spk")
            .try_into()
            .expect("34-byte P2TR script");
        payout_scripts[i] = spk_bytes;
    }

    // 2. Precompute the 3 UTXORef NUMS P2TR DLC funding scripts ($80k / $100k / $125k)
    let refund_csv = 144u16;
    let templates =
        precompute_live_testnet4_micro_dlc_templates(refund_csv).expect("micro DLC templates");
    let mut dlc_addrs = Vec::with_capacity(3);
    for tpl in &templates {
        let out_x = &tpl.funding_script_pubkey_hex[4..];
        let desc_info = wsl_testnet4_json(None, &["getdescriptorinfo", &format!("rawtr({out_x})")]);
        let desc = desc_info["descriptor"].as_str().unwrap();
        let addrs = wsl_testnet4_json(None, &["deriveaddresses", desc]);
        dlc_addrs.push(addrs[0].as_str().unwrap().to_owned());
    }

    // 3. Construct & sign a single multi-output Testnet4 funding tx creating all 3 DLC vaults
    let outputs_json = format!(
        "[{{\"{}\":0.00002095}},{{\"{}\":0.00001595}},{{\"{}\":0.00001270}}]",
        dlc_addrs[0], dlc_addrs[1], dlc_addrs[2]
    );
    let raw_fund = wsl_testnet4_cli(
        Some(wallet_name),
        &["createrawtransaction", "[]", &outputs_json],
    )
    .expect("createrawtransaction funding");
    let funded = wsl_testnet4_json(
        Some(wallet_name),
        &["fundrawtransaction", &raw_fund, "{\"fee_rate\":1}"],
    );
    let funded_hex = funded["hex"].as_str().expect("funded hex");
    let signed_fund = wsl_testnet4_json(
        Some(wallet_name),
        &["signrawtransactionwithwallet", funded_hex],
    );
    assert_eq!(signed_fund["complete"].as_bool(), Some(true));
    let signed_fund_hex = signed_fund["hex"].as_str().expect("signed fund hex").to_owned();

    let decoded_fund = wsl_testnet4_json(None, &["decoderawtransaction", &signed_fund_hex]);
    let fund_txid_hex = decoded_fund["txid"].as_str().expect("fund txid").to_owned();
    let fund_txid_bytes: Hash = hex::decode(&fund_txid_hex)
        .unwrap()
        .try_into()
        .unwrap();

    let mut outpoints: [(Hash, u32); 3] = [([0u8; 32], 0); 3];
    let mut funded_receipts = Vec::with_capacity(3);
    for (idx, tpl) in templates.iter().enumerate() {
        let vout = decoded_fund["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| {
                o["scriptPubKey"]["hex"].as_str() == Some(tpl.funding_script_pubkey_hex.as_str())
            })
            .expect("locate DLC funding vout")["n"]
            .as_u64()
            .unwrap() as u32;
        outpoints[idx] = (fund_txid_bytes, vout);
        funded_receipts.push(FundedDlcUtxoReceipt {
            trade_no: (idx + 1) as u8,
            label: tpl.label.clone(),
            txid: fund_txid_hex.clone(),
            vout,
            sats: tpl.total_funding_sats,
            script_pubkey_hex: tpl.funding_script_pubkey_hex.clone(),
        });
    }

    // 4. Collate & sign the 3-input, 4-output LNMBAT01 clearing tx BEFORE broadcasting tx_fund!
    let mut artifacts = build_live_testnet4_micro_clearing_ceremony(
        outpoints,
        payout_scripts,
        tip_height,
        &tip_hash,
        refund_csv,
    )
    .expect("build live Testnet4 3-party clearing ceremony");
    let raw_clear_hex = hex::encode(artifacts.signed_clearing_tx.serialize_segwit());

    // Pre-flight check: verify the [tx_fund, tx_clear] package passes Testnet4 mempool + BIP-341
    // consensus BEFORE broadcasting a single satoshi to Testnet4!
    let pkg_accept = wsl_testnet4_json(
        None,
        &[
            "testmempoolaccept",
            &format!("[\"{signed_fund_hex}\",\"{raw_clear_hex}\"]"),
        ],
    );
    assert_eq!(
        pkg_accept[0]["allowed"].as_bool(),
        Some(true),
        "Testnet4 funding tx preflight failed: {pkg_accept}"
    );
    assert_eq!(
        pkg_accept[1]["allowed"].as_bool(),
        Some(true),
        "Testnet4 clearing tx package preflight failed: {pkg_accept}"
    );

    // 5. Broadcast tx_fund to LIVE PUBLIC BITCOIN TESTNET4!
    let broadcast_fund_txid =
        wsl_testnet4_cli(None, &["sendrawtransaction", &signed_fund_hex]).expect("broadcast tx_fund");
    assert_eq!(broadcast_fund_txid, fund_txid_hex);

    // 6. Adversarial probes against live Testnet4 mempool (1-sat shave on Bob's freed margin & Alice's PnL)
    let mut probes = Vec::new();
    let bob_idx = artifacts
        .signed_clearing_tx
        .outputs
        .iter()
        .position(|(v, _)| *v == 1_250)
        .expect("Bob 1250 output");
    let alice_idx = artifacts
        .signed_clearing_tx
        .outputs
        .iter()
        .position(|(v, _)| *v == 1_475)
        .expect("Alice 1475 output");

    let mut shave_bob = artifacts.signed_clearing_tx.clone();
    shave_bob.outputs[bob_idx].0 -= 1;
    shave_bob.outputs[alice_idx].0 += 1;
    let shave_bob_res = wsl_testnet4_json(
        None,
        &[
            "testmempoolaccept",
            &format!("[\"{}\"]", hex::encode(shave_bob.serialize_segwit())),
        ],
    );
    assert_eq!(shave_bob_res[0]["allowed"].as_bool(), Some(false));
    probes.push(AdversarialProbeReceipt {
        probe_id: "testnet4-shave-bob-freed-collateral-by-1-sat",
        description: "Live Testnet4 mempool probe: shave 1 sat from Bob's 1,250 freed sats",
        core_accepted: false,
        core_reject_reason: shave_bob_res[0]["reject-reason"]
            .as_str()
            .unwrap_or("rejected")
            .to_owned(),
    });

    let mut shave_alice = artifacts.signed_clearing_tx.clone();
    shave_alice.outputs[alice_idx].0 -= 1;
    shave_alice.outputs[bob_idx].0 += 1;
    let shave_alice_res = wsl_testnet4_json(
        None,
        &[
            "testmempoolaccept",
            &format!("[\"{}\"]", hex::encode(shave_alice.serialize_segwit())),
        ],
    );
    assert_eq!(shave_alice_res[0]["allowed"].as_bool(), Some(false));
    probes.push(AdversarialProbeReceipt {
        probe_id: "testnet4-shave-alice-routed-pnl-by-1-sat",
        description: "Live Testnet4 mempool probe: shave 1 sat from Winner Alice's 1,475 cleared sats",
        core_accepted: false,
        core_reject_reason: shave_alice_res[0]["reject-reason"]
            .as_str()
            .unwrap_or("rejected")
            .to_owned(),
    });

    // Verify honest clearing tx passes Testnet4 mempool policy & broadcast to LIVE BITCOIN TESTNET4!
    let clear_accept = wsl_testnet4_json(
        None,
        &["testmempoolaccept", &format!("[\"{raw_clear_hex}\"]")],
    );
    assert_eq!(
        clear_accept[0]["allowed"].as_bool(),
        Some(true),
        "Live Testnet4 clearing tx rejected: {clear_accept}"
    );
    let broadcast_clear_txid = wsl_testnet4_cli(None, &["sendrawtransaction", &raw_clear_hex])
        .expect("broadcast tx_clear on Testnet4");
    assert_eq!(broadcast_clear_txid, artifacts.report.atomic_clearing_txid_hex);
    assert_eq!(broadcast_clear_txid, artifacts.report.journal.batch_txid_hex);
    assert_eq!(
        broadcast_clear_txid,
        artifacts.report.bitvm3_testnet4_statement.settlement_txid_hex
    );

    // Confirm presence in live Testnet4 mempool (or already mined block!)
    let in_mempool_or_chain = wsl_testnet4_cli(None, &["getmempoolentry", &broadcast_clear_txid])
        .is_ok()
        || wsl_testnet4_cli(None, &["getrawtransaction", &broadcast_clear_txid, "true"]).is_ok();
    assert!(in_mempool_or_chain);

    let bal_after = wsl_testnet4_json(Some(wallet_name), &["getbalances"]);
    let sats_after = btc_float_to_sats(
        bal_after["mine"]["trusted"].as_f64().unwrap_or(0.0)
            + bal_after["mine"]["untrusted_pending"].as_f64().unwrap_or(0.0),
    );

    // 7. Prove & verify the exact live Testnet4 3-row LNMBAT01 witness with external `lnm-nova`!
    let mut nova_verified = false;
    if let Some(nova_bin) = lnm_nova_bin.filter(|p| p.exists()) {
        let snark_receipt = run_external_lnm_nova_prover(
            nova_bin,
            &artifacts.batch_witness_bytes,
            persist_bundle_dir,
        );
        nova_verified = snark_receipt.nova_compressed_verified;
        artifacts.report.external_nova_snark_receipt = Some(snark_receipt);
        if nova_verified {
            let flags = VerificationHonestyFlags::with_external_nova_snark_verified();
            artifacts.report.honesty = flags;
            artifacts.report.nova_expected_statement.honesty = flags;
            artifacts.report.bitvm3_testnet4_statement.honesty = flags;
        }
    }

    LiveTestnet4BroadcastReceipt {
        scenario: "Live Public Bitcoin Testnet4 3-Party, 3-Trade ($80k -> $100k -> $125k) Collated DLC Margin Clearing + BitVM3 Nova CompressedSNARK",
        network: "bitcoin-testnet4",
        core_version,
        testnet4_tip_height: tip_height,
        testnet4_tip_block_hash: tip_hash,
        funding_tx_explorer_uri: format!("https://mempool.space/testnet4/tx/{broadcast_fund_txid}"),
        funding_txid: broadcast_fund_txid,
        atomic_clearing_tx_explorer_uri: format!(
            "https://mempool.space/testnet4/tx/{broadcast_clear_txid}"
        ),
        atomic_clearing_txid: broadcast_clear_txid,
        atomic_clearing_wtxid: artifacts.signed_clearing_tx.wtxid_hex(),
        atomic_clearing_vsize: artifacts.signed_clearing_tx.vsize(),
        mempool_accepted_live_testnet4: true,
        wallet_balance_before_sats: sats_before,
        wallet_balance_after_sats: sats_after,
        net_network_miner_fee_cost_sats: sats_before.saturating_sub(sats_after),
        funded_dlc_utxos: funded_receipts,
        adversarial_probes_live_testnet4: probes,
        nova_compressed_snark_verified: nova_verified,
        production_ready: false,
        clearing_report: artifacts.report,
    }
}
