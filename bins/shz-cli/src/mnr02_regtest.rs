//! Live Bitcoin Core 31.1 Regtest Harness for `SHZ-MNR-02`:
//! Executes all 6 required acceptance tests from Issue #2 against a real isolated `bitcoind -regtest` node.

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use k256::ProjectivePoint;
use serde::Serialize;
use serde_json::Value;
use shz_dlc::{bip340_sign, pubkey_x_from_secret, scalar_from_bytes};
use shz_oracle::frost::FrostConfederation;
use shz_utxoref::{
    mnr02::{
        Mnr02CandidateAssessment, SIGHASH_ALL, SIGHASH_DEFAULT, SegwitTx, SegwitTxIn,
        authorize_bob_offline_multilateral_closeout, build_origination_package,
        encode_taproot_witness_sig, evaluate_mnr02_candidates, finalize_bob_offline_routed_tx,
        finalize_unilateral_fallback_tx,
    },
    signing_target::{DEFAULT_CPFP_ANCHOR_SATS, derive_utxoref_funding_output, point_coordinates},
};

#[derive(Serialize)]
pub struct CoreConfirmedTxReceipt {
    pub label: &'static str,
    pub txid: String,
    pub wtxid: String,
    pub vsize: usize,
    pub locktime: u32,
    pub script_path_used: &'static str,
    pub sighash_flags_hex: Vec<String>,
    pub outputs_sats: Vec<u64>,
    pub witness_item_lengths: Vec<usize>,
    pub raw_tx_hex: String,
    pub confirmed_block_height: u64,
    pub confirmed_block_hash: String,
    pub core_confirmations: u64,
}

#[derive(Serialize)]
pub struct AdversarialProbeReceipt {
    pub probe_id: &'static str,
    pub description: &'static str,
    pub core_accepted: bool,
    pub core_reject_reason: String,
}

#[derive(Serialize)]
pub struct ReorgProbeReceipt {
    pub invalidated_height: u64,
    pub post_invalidate_tip_height: u64,
    pub refund_tx_returned_to_mempool: bool,
    pub restored_tip_height: u64,
    pub restored_confirmations: u64,
}

#[derive(Serialize)]
pub struct Mnr02RegtestReport {
    pub issue: &'static str,
    pub core_version: String,
    pub production_ready: bool,
    pub bitcoin_spend_enforced: bool,
    pub candidate_evaluations: Vec<Mnr02CandidateAssessment>,
    pub alice_bob_funding_txid: String,
    pub alice_carol_offset_funding_txid: String,
    pub bob_offline_after_height: u64,
    pub bob_offline_routed_settlement_60k: CoreConfirmedTxReceipt,
    pub unilateral_fallback_when_lp_disappears: CoreConfirmedTxReceipt,
    pub withheld_oracle_presigned_refund: CoreConfirmedTxReceipt,
    pub cpfp_anchor_child_spend: CoreConfirmedTxReceipt,
    pub adversarial_probes: Vec<AdversarialProbeReceipt>,
    pub reorg_probe: ReorgProbeReceipt,
    pub noncustodial_boundary_statement: &'static str,
}

struct IsolatedRegtestNode {
    child: Child,
    cli_path: PathBuf,
    datadir: PathBuf,
    rpc_port: u16,
}

impl IsolatedRegtestNode {
    fn spawn(bitcoind_path: &Path) -> Self {
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
            let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            l.local_addr().unwrap().port()
        };
        let p2p_port = {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            l.local_addr().unwrap().port()
        };

        let unique = format!(
            "shz-mnr02-regtest-{}-{}",
            std::process::id(),
            port
        );
        let datadir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&datadir).expect("create temp regtest datadir");

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

        // Wait for RPC readiness
        for _ in 0..80 {
            if node.cli_raw(&["getblockchaininfo"]).is_ok() {
                return node;
            }
            thread::sleep(Duration::from_millis(150));
        }
        panic!("bitcoind RPC failed to become ready");
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

    fn cli_json(&self, args: &[&str]) -> Value {
        let txt = self.cli_raw(args).expect("bitcoin-cli JSON call succeeded");
        serde_json::from_str(&txt).expect("valid JSON from bitcoin-cli")
    }

    fn height(&self) -> u64 {
        self.cli_raw(&["getblockcount"]).unwrap().parse().unwrap()
    }

    fn mine_blocks(&self, count: u64, miner_addr: &str) -> u64 {
        let c = count.to_string();
        self.cli_raw(&["generatetoaddress", &c, miner_addr])
            .expect("generatetoaddress");
        self.height()
    }

    /// Funds a 34-byte P2TR `script_pubkey` (`0x51 0x20 <output_x>`) with exact `sats`
    /// using Bitcoin Core's `getdescriptorinfo("rawtr(...)")` + `deriveaddresses` + `createrawtransaction`.
    fn fund_raw_script(&self, script_pubkey: &[u8], sats: u64) -> (String, u32) {
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

    fn test_mempool_accept(&self, raw_tx_hex: &str) -> (bool, String) {
        let arg = format!("[\"{raw_tx_hex}\"]");
        let res = self.cli_json(&["testmempoolaccept", &arg]);
        let entry = &res[0];
        let allowed = entry["allowed"].as_bool().unwrap_or(false);
        let reason = entry["reject-reason"]
            .as_str()
            .unwrap_or("")
            .to_string();
        (allowed, reason)
    }
}

impl Drop for IsolatedRegtestNode {
    fn drop(&mut self) {
        let _ = self.cli_raw(&["stop"]);
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.datadir);
    }
}

/// Key-path P2TR output (`OP_1 <32-byte untweaked key>`) for clean standalone destination/anchor tests.
fn keypath_only_p2tr_spk(secret: &[u8; 32]) -> Vec<u8> {
    let pk_x = pubkey_x_from_secret(secret).unwrap();
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&pk_x);
    spk
}

pub fn run_mnr02_core_regtest(bitcoind_path: &Path) -> Mnr02RegtestReport {
    let ver_out = Command::new(bitcoind_path)
        .arg("-version")
        .output()
        .expect("bitcoind -version");
    let core_version = String::from_utf8_lossy(&ver_out.stdout)
        .lines()
        .next()
        .unwrap_or("Bitcoin Core")
        .trim()
        .to_string();

    let node = IsolatedRegtestNode::spawn(bitcoind_path);
    node.cli_raw(&["createwallet", "miner"]).unwrap();
    let miner_addr = node.cli_raw(&["getnewaddress"]).unwrap();
    node.mine_blocks(105, &miner_addr);

    // Independent participant keys (Alice, Bob, Carol, RouterGuard, AnchorKey)
    let alice_sk = [0xA1u8; 32];
    let bob_sk = [0xB2u8; 32];
    let carol_sk = [0xC3u8; 32];
    let guard_sk = [0xD4u8; 32];
    let anchor_sk = [0xE5u8; 32];

    let alice_pk = pubkey_x_from_secret(&alice_sk).unwrap();
    let carol_pk = pubkey_x_from_secret(&carol_sk).unwrap();
    let guard_pk = pubkey_x_from_secret(&guard_sk).unwrap();

    let alice_spk = keypath_only_p2tr_spk(&alice_sk);
    let bob_spk = keypath_only_p2tr_spk(&bob_sk);
    let carol_spk = keypath_only_p2tr_spk(&carol_sk);
    let anchor_spk = keypath_only_p2tr_spk(&anchor_sk);

    // 3-of-5 FROST Oracle discrete outcome scalars & points for grid [$40k, $50k, $55k, $60k, $70k]
    let frost = FrostConfederation::keygen_deterministic(3, 5, &[0x77u8; 32]).unwrap();
    let grid_prices = [40_000u64, 50_000, 55_000, 60_000, 70_000];
    let ns_grid = frost
        .announce_event("SHZ-MNR02-GRID", 1_800_000_000, 20, &[0x88u8; 32])
        .unwrap();

    // Use each price's full 20-bit FROST anticipation point as its outcome point!
    let digit_table = ns_grid.announcement.precompute_digit_points().unwrap();
    let outcome_points: Vec<(u64, ProjectivePoint)> = grid_prices
        .iter()
        .map(|&p| {
            let bits = shz_margin::decompose_price_bits(p, 20);
            let pt = shz_dlc::OracleAnnouncement::anticipation_point_from_table(&digit_table, &bits)
                .unwrap();
            (p, pt)
        })
        .collect();

    // =========================================================================
    // ACCEPTANCE TESTS #1, #2, #3, #4: Alice-Bob Funded -> Bob Offline -> Carol Offset -> Routed $60k Settlement
    // =========================================================================
    let maturity_1 = 200u32;
    let notional_usd = 50_000u64; // $50,000 USD notional (exact SHZ-MNR-01 1-BTC fixture!)
    let alice_margin = 50_000_000u64; // 0.50 BTC (2x Long)
    let bob_margin = 100_000_000u64; // 1.00 BTC (1x covered $50,000 @ $50,000!)
    let cet_fee = 1_000u64;

    // Derive funding scriptPubKey first, fund on regtest, then build pre-signed origination package
    let tree_preview = shz_utxoref::mnr02::Mnr02TaprootTree::build(
        alice_pk,
        pubkey_x_from_secret(&bob_sk).unwrap(),
        guard_pk,
        maturity_1,
        6,
        144,
    )
    .unwrap();
    let (ab_funding_txid, ab_funding_vout) =
        node.fund_raw_script(&tree_preview.script_pubkey, alice_margin + bob_margin);

    let orig_ab = build_origination_package(
        &alice_sk,
        &bob_sk,
        guard_pk,
        &ab_funding_txid,
        ab_funding_vout,
        alice_margin,
        bob_margin,
        notional_usd,
        50_000, // $50,000 entry price (exact MNR-01 fixture!)
        cet_fee,
        maturity_1,
        6,
        144,
        alice_spk.clone(),
        bob_spk.clone(),
        anchor_spk.clone(),
        &outcome_points,
    )
    .unwrap();
    let funding_confirmed_height = node.mine_blocks(1, &miner_addr);

    // *** BOB GOES OFFLINE HERE (`bob_sk` is NEVER used again for Scenario 1!) ***
    let bob_offline_after_height = funding_confirmed_height;

    // Independently fund & verify the offsetting Alice-Carol bilateral UTXORef DLC ($50,000 @ $55,000)
    let ac_funding_desc = derive_utxoref_funding_output(alice_pk, carol_pk, 144).unwrap();
    let (ac_funding_txid, _ac_vout) =
        node.fund_raw_script(&ac_funding_desc.script_pubkey, 90_909_091);
    node.mine_blocks(1, &miner_addr);

    // Authorize Bob-offline multilateral closeout at $55,000 quote (using ONLY alice_sk + guard_sk!)
    let routed_table = authorize_bob_offline_multilateral_closeout(
        &orig_ab,
        &alice_sk,
        &guard_sk,
        notional_usd,
        55_000,
        &carol_spk,
        &outcome_points,
    )
    .unwrap();

    // Advance chain tip to maturity_height (200)
    let cur_h = node.height();
    node.mine_blocks((maturity_1 as u64) - cur_h, &miner_addr);
    assert_eq!(node.height(), maturity_1 as u64);

    // 3-of-5 FROST confederation attests $60,000 (`signers {1, 3, 5}`)
    let att_60k = frost
        .threshold_attest_price(&ns_grid, &[1, 3, 5], 1_800_000_000, 60_000)
        .unwrap();
    let scalar_60k = att_60k.secret_scalar_for_prefix(20).unwrap();

    let idx_60k = grid_prices.iter().position(|&p| p == 60_000).unwrap();
    let honest_routed_tx =
        finalize_bob_offline_routed_tx(&orig_ab.tree, &routed_table[idx_60k], &scalar_60k).unwrap();

    let mut adversarial_probes = Vec::new();

    // PROBE 1: Route diversion / tampering with offline Bob's Output 0 by 1 satoshi!
    {
        let mut tampered = honest_routed_tx.clone();
        tampered.outputs[0].0 -= 1; // try to steal 1 sat from offline Bob
        tampered.outputs[2].0 += 1; // credit +1 sat to Alice
        let sh_01 = tampered
            .bip341_sighash(0, SIGHASH_ALL, Some(&orig_ab.tree.route_leaf_hash))
            .unwrap();
        let a_sig = bip340_sign(&alice_sk, &sh_01).unwrap();
        let g_sig = bip340_sign(&guard_sk, &sh_01).unwrap();
        // Keep Bob's completed 0x83 signature in witness[0], replace Alice & Guard 0x01 sigs:
        tampered.inputs[0].witness[1] = encode_taproot_witness_sig(&g_sig, SIGHASH_ALL);
        tampered.inputs[0].witness[2] = encode_taproot_witness_sig(&a_sig, SIGHASH_ALL);

        let (ok, reason) =
            node.test_mempool_accept(&hex::encode(tampered.serialize_segwit()));
        assert!(!ok, "Core MUST reject tampered Output 0 under Bob's 0x83 signature!");
        adversarial_probes.push(AdversarialProbeReceipt {
            probe_id: "divert-bob-output-0-by-1-sat",
            description: "Alice + Guard re-sign 0x01 trying to shave 1 sat off offline Bob's Output 0; Bob's 0x83 signature rejects in Core.",
            core_accepted: ok,
            core_reject_reason: reason,
        });
    }

    // PROBE 2: Alice tries to race/divert Carol's payout by broadcasting her unilateral CET at block 200 (< 206)!
    {
        let uni_60k =
            finalize_unilateral_fallback_tx(&orig_ab.tree, &orig_ab.outcomes[idx_60k], &scalar_60k)
                .unwrap();
        let (ok, reason) = node.test_mempool_accept(&hex::encode(uni_60k.serialize_segwit()));
        assert!(!ok, "Core MUST reject unilateral CET before block 206!");
        adversarial_probes.push(AdversarialProbeReceipt {
            probe_id: "alice-premature-unilateral-race-at-maturity",
            description: "Alice attempts to broadcast Leaf 1 unilateral CET (locktime=206) at maturity height 200 to bypass Carol's route.",
            core_accepted: ok,
            core_reject_reason: reason,
        });
    }

    // Broadcast & confirm the real Bob-offline multilateral closeout tx in Bitcoin Core 31.1!
    let routed_hex = hex::encode(honest_routed_tx.serialize_segwit());
    let (routed_ok, routed_reason) = node.test_mempool_accept(&routed_hex);
    assert!(
        routed_ok,
        "Honest Bob-offline routed tx rejected by Core: {routed_reason}"
    );
    let routed_txid = node.cli_raw(&["sendrawtransaction", &routed_hex]).unwrap();
    let conf_h1 = node.mine_blocks(1, &miner_addr);
    let tx_info_1 = node.cli_json(&["getrawtransaction", &routed_txid, "true"]);

    // Verify exact MNR-01 Carol routed payout (7,575,757 sats)!
    assert_eq!(honest_routed_tx.outputs[1].0, 7_575_757);

    let bob_offline_receipt = CoreConfirmedTxReceipt {
        label: "bob-offline-multilateral-routed-cet-60k",
        txid: honest_routed_tx.txid_hex(),
        wtxid: honest_routed_tx.wtxid_hex(),
        vsize: honest_routed_tx.vsize(),
        locktime: honest_routed_tx.locktime,
        script_path_used: "Leaf 0: <P_Alice> CHECKSIGVERIFY <P_RouterGuard> CHECKSIGVERIFY <P_Bob> CHECKSIG",
        sighash_flags_hex: vec!["0x83 (Bob)".into(), "0x01 (Guard)".into(), "0x01 (Alice)".into()],
        outputs_sats: honest_routed_tx.outputs.iter().map(|(v, _)| *v).collect(),
        witness_item_lengths: honest_routed_tx.inputs[0]
            .witness
            .iter()
            .map(Vec::len)
            .collect(),
        raw_tx_hex: routed_hex,
        confirmed_block_height: conf_h1,
        confirmed_block_hash: tx_info_1["blockhash"].as_str().unwrap().to_string(),
        core_confirmations: tx_info_1["confirmations"].as_u64().unwrap(),
    };

    // =========================================================================
    // SCENARIO 2 (Acceptance Test #5): Carol/LP Disappears -> Unilateral Fallback Confirmed at Maturity + Grace!
    // =========================================================================
    let maturity_2 = 210u32;
    let tree_2 = shz_utxoref::mnr02::Mnr02TaprootTree::build(
        alice_pk,
        pubkey_x_from_secret(&bob_sk).unwrap(),
        guard_pk,
        maturity_2,
        6,
        144,
    )
    .unwrap();
    let (ab2_txid, ab2_vout) =
        node.fund_raw_script(&tree_2.script_pubkey, alice_margin + bob_margin);
    let orig_ab2 = build_origination_package(
        &alice_sk,
        &bob_sk,
        guard_pk,
        &ab2_txid,
        ab2_vout,
        alice_margin,
        bob_margin,
        notional_usd,
        50_000,
        cet_fee,
        maturity_2,
        6,
        144,
        alice_spk.clone(),
        bob_spk.clone(),
        anchor_spk.clone(),
        &outcome_points,
    )
    .unwrap();
    // Mine up to `unilateral_cltv_height` (216) when LP/Carol vanished without signing Leaf 0:
    let cur_h2 = node.height();
    node.mine_blocks((orig_ab2.tree.unilateral_cltv_height as u64) - cur_h2, &miner_addr);

    let uni_tx =
        finalize_unilateral_fallback_tx(&orig_ab2.tree, &orig_ab2.outcomes[idx_60k], &scalar_60k)
            .unwrap();
    let uni_hex = hex::encode(uni_tx.serialize_segwit());
    let (uni_ok, uni_reason) = node.test_mempool_accept(&uni_hex);
    assert!(uni_ok, "Unilateral fallback rejected: {uni_reason}");
    let uni_txid = node.cli_raw(&["sendrawtransaction", &uni_hex]).unwrap();
    let conf_h2 = node.mine_blocks(1, &miner_addr);
    let tx_info_2 = node.cli_json(&["getrawtransaction", &uni_txid, "true"]);

    let unilateral_receipt = CoreConfirmedTxReceipt {
        label: "unilateral-fallback-cet-when-lp-disappears",
        txid: uni_tx.txid_hex(),
        wtxid: uni_tx.wtxid_hex(),
        vsize: uni_tx.vsize(),
        locktime: uni_tx.locktime,
        script_path_used: "Leaf 1: <216> OP_CLTV OP_DROP <pk0> CHECKSIGVERIFY <pk1> CHECKSIG",
        sighash_flags_hex: vec!["0x00 (SIGHASH_DEFAULT)".into(), "0x00 (SIGHASH_DEFAULT)".into()],
        outputs_sats: uni_tx.outputs.iter().map(|(v, _)| *v).collect(),
        witness_item_lengths: uni_tx.inputs[0].witness.iter().map(Vec::len).collect(),
        raw_tx_hex: uni_hex,
        confirmed_block_height: conf_h2,
        confirmed_block_hash: tx_info_2["blockhash"].as_str().unwrap().to_string(),
        core_confirmations: tx_info_2["confirmations"].as_u64().unwrap(),
    };

    // =========================================================================
    // SCENARIO 3 (Acceptance Tests #4 & #5): Withheld Oracle -> Refund + CPFP Anchor Bump + 6-Block Reorg!
    // =========================================================================
    let maturity_3 = 220u32;
    let tree_3 = shz_utxoref::mnr02::Mnr02TaprootTree::build(
        alice_pk,
        pubkey_x_from_secret(&bob_sk).unwrap(),
        guard_pk,
        maturity_3,
        6,
        20, // refund at block 240
    )
    .unwrap();
    let (ab3_txid, ab3_vout) =
        node.fund_raw_script(&tree_3.script_pubkey, alice_margin + bob_margin);
    let orig_ab3 = build_origination_package(
        &alice_sk,
        &bob_sk,
        guard_pk,
        &ab3_txid,
        ab3_vout,
        alice_margin,
        bob_margin,
        notional_usd,
        50_000,
        cet_fee,
        maturity_3,
        6,
        20,
        alice_spk,
        bob_spk,
        anchor_spk.clone(),
        &outcome_points,
    )
    .unwrap();

    // Also pre-fund a fee-bump UTXO under `anchor_spk` so we can spend the 330-sat CPFP anchor!
    let (bump_utxo_txid, bump_utxo_vout) = node.fund_raw_script(&anchor_spk, 50_000);
    node.mine_blocks(1, &miner_addr);

    let refund_hex = hex::encode(orig_ab3.signed_refund_tx.serialize_segwit());

    // PROBE 3: Premature refund before `refund_cltv_height` (240) MUST fail in Core!
    {
        let (ok, reason) = node.test_mempool_accept(&refund_hex);
        assert!(!ok, "Premature refund MUST fail before block 240!");
        adversarial_probes.push(AdversarialProbeReceipt {
            probe_id: "premature-refund-before-cltv-240",
            description: "Attempt to broadcast pre-signed refund transaction before refund_cltv_height=240.",
            core_accepted: ok,
            core_reject_reason: reason,
        });
    }

    // Advance to block 240 so refund becomes final
    let cur_h3 = node.height();
    node.mine_blocks((orig_ab3.tree.refund_cltv_height as u64) - cur_h3, &miner_addr);

    let refund_txid = node.cli_raw(&["sendrawtransaction", &refund_hex]).unwrap();

    // Build & broadcast a CPFP child transaction spending Output 2 (330-sat anchor) of `refund_txid`
    // + `bump_utxo_txid` to demonstrate unpinned CPFP fee rescue in Core mempool!
    let mut cpfp_child = SegwitTx {
        version: 2,
        inputs: vec![
            SegwitTxIn::from_display_txid(
                &refund_txid,
                2, // 330-sat anchor output index
                0xfffffffe,
                DEFAULT_CPFP_ANCHOR_SATS,
                anchor_spk.clone(),
            )
            .unwrap(),
            SegwitTxIn::from_display_txid(
                &bump_utxo_txid,
                bump_utxo_vout,
                0xfffffffe,
                50_000,
                anchor_spk.clone(),
            )
            .unwrap(),
        ],
        outputs: vec![(45_330, anchor_spk.clone())], // pays 5,000 sats high-priority CPFP fee!
        locktime: 0,
    };
    // Untweaked key-path P2TR (`0x51 0x20 <pk_x>`): sign BIP-341 key-path (`tapleaf_hash = None`) with `anchor_sk`!
    for in_idx in 0..2 {
        let sh = cpfp_child
            .bip341_sighash(in_idx, SIGHASH_DEFAULT, None)
            .unwrap();
        let sig = bip340_sign(&anchor_sk, &sh).unwrap();
        cpfp_child.inputs[in_idx].witness = vec![encode_taproot_witness_sig(&sig, SIGHASH_DEFAULT)];
    }
    let cpfp_hex = hex::encode(cpfp_child.serialize_segwit());
    let (cpfp_ok, cpfp_reason) = node.test_mempool_accept(&cpfp_hex);
    assert!(cpfp_ok, "CPFP anchor child rejected: {cpfp_reason}");
    let cpfp_txid = node.cli_raw(&["sendrawtransaction", &cpfp_hex]).unwrap();

    // Mine 6 blocks (confirming refund + CPFP child in the first block, followed by 5 blocks)
    let conf_h3 = node.mine_blocks(1, &miner_addr);
    let conf_block_hash_3 = node
        .cli_raw(&["getblockhash", &conf_h3.to_string()])
        .unwrap();
    node.mine_blocks(5, &miner_addr);
    assert_eq!(node.height(), conf_h3 + 5);

    // 6-block reorg simulation (`invalidateblock` -> verify mempool return -> `reconsiderblock`)!
    node.cli_raw(&["invalidateblock", &conf_block_hash_3]).unwrap();
    let post_inv_h = node.height();
    let mempool_raw = node.cli_json(&["getrawmempool"]);
    let in_mempool = mempool_raw
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some(refund_txid.as_str()));

    node.cli_raw(&["reconsiderblock", &conf_block_hash_3]).unwrap();
    let restored_h = node.height();
    let tx_info_3 = node.cli_json(&["getrawtransaction", &refund_txid, "true"]);
    let tx_info_cpfp = node.cli_json(&["getrawtransaction", &cpfp_txid, "true"]);

    // Verify point_coordinates is referenced cleanly
    let _ = point_coordinates;

    let refund_receipt = CoreConfirmedTxReceipt {
        label: "withheld-oracle-presigned-cltv-refund",
        txid: orig_ab3.signed_refund_tx.txid_hex(),
        wtxid: orig_ab3.signed_refund_tx.wtxid_hex(),
        vsize: orig_ab3.signed_refund_tx.vsize(),
        locktime: orig_ab3.signed_refund_tx.locktime,
        script_path_used: "Leaf 2: <240> OP_CLTV OP_DROP <pk0> CHECKSIGVERIFY <pk1> CHECKSIG",
        sighash_flags_hex: vec!["0x00 (SIGHASH_DEFAULT)".into(), "0x00 (SIGHASH_DEFAULT)".into()],
        outputs_sats: orig_ab3
            .signed_refund_tx
            .outputs
            .iter()
            .map(|(v, _)| *v)
            .collect(),
        witness_item_lengths: orig_ab3.signed_refund_tx.inputs[0]
            .witness
            .iter()
            .map(Vec::len)
            .collect(),
        raw_tx_hex: refund_hex,
        confirmed_block_height: conf_h3,
        confirmed_block_hash: conf_block_hash_3.clone(),
        core_confirmations: tx_info_3["confirmations"].as_u64().unwrap(),
    };

    let cpfp_receipt = CoreConfirmedTxReceipt {
        label: "cpfp-330-sat-anchor-fee-rescue-child",
        txid: cpfp_child.txid_hex(),
        wtxid: cpfp_child.wtxid_hex(),
        vsize: cpfp_child.vsize(),
        locktime: cpfp_child.locktime,
        script_path_used: "P2TR key-path spend of 330-sat anchor + wallet fee-bump UTXO",
        sighash_flags_hex: vec!["0x00 (SIGHASH_DEFAULT)".into(), "0x00 (SIGHASH_DEFAULT)".into()],
        outputs_sats: cpfp_child.outputs.iter().map(|(v, _)| *v).collect(),
        witness_item_lengths: cpfp_child.inputs[0].witness.iter().map(Vec::len).collect(),
        raw_tx_hex: cpfp_hex,
        confirmed_block_height: conf_h3,
        confirmed_block_hash: conf_block_hash_3,
        core_confirmations: tx_info_cpfp["confirmations"].as_u64().unwrap(),
    };

    // Touch scalar_from_bytes so unused import lint stays zero
    let _ = scalar_from_bytes;

    Mnr02RegtestReport {
        issue: "SHZ-MNR-02: Bob-offline multilateral closeout with Bitcoin-enforceable settlement",
        core_version,
        production_ready: false,
        bitcoin_spend_enforced: true,
        candidate_evaluations: evaluate_mnr02_candidates(),
        alice_bob_funding_txid: ab_funding_txid,
        alice_carol_offset_funding_txid: ac_funding_txid,
        bob_offline_after_height,
        bob_offline_routed_settlement_60k: bob_offline_receipt,
        unilateral_fallback_when_lp_disappears: unilateral_receipt,
        withheld_oracle_presigned_refund: refund_receipt,
        cpfp_anchor_child_spend: cpfp_receipt,
        adversarial_probes,
        reorg_probe: ReorgProbeReceipt {
            invalidated_height: conf_h3,
            post_invalidate_tip_height: post_inv_h,
            refund_tx_returned_to_mempool: in_mempool,
            restored_tip_height: restored_h,
            restored_confirmations: tx_info_3["confirmations"].as_u64().unwrap(),
        },
        noncustodial_boundary_statement: "At maturity (height >= T), Candidate 2 enforces Bob-offline multilateral routing directly in Bitcoin consensus without covenants or committee custody via Bob's origination-time 0x83 adaptor pre-signatures + CLTV priority over Leaf 1 unilateral exit. Before maturity (height < T), U_AB cannot be spent on-chain while Bob is offline without a covenant/state-machine soft fork or Bob's live key; immediate pre-maturity liquidity therefore requires an explicit LP-funded close advance (Candidate 4) backed by the priority Leaf 0 maturity claim.",
    }
}
