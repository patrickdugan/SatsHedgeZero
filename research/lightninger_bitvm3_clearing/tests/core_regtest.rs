//! Ground truth from Bitcoin Core 31.1 on an isolated regtest node.
//!
//! 1. Three transactions spending the Core wallet's own P2TR (bech32m) coinbase outputs,
//!    each input signed by `signrawtransactionwithwallet` with a different hash type
//!    (all seven across the three), accepted by `testmempoolaccept` and mined.
//! 2. A transaction spending `rawtr` outputs whose keys this test holds, signed here
//!    with an annex on two inputs (one 5 bytes, one 33 bytes), mined with `generateblock`
//!    (consensus validation without the mempool's no-annex policy). The same transaction
//!    signed without committing to the annex is rejected by `generateblock`.
//!
//! For every input the native BIP-341 sighash verifies Core's (or the consensus-accepted)
//! signature, and the TapSighash step is satisfied with the expected outputs. The signed
//! transactions are written to `artifacts/core_sighash_txs.json` for the Nova runs.
//!
//! Run: `LIGHTNINGER_BITCOIND=<path to bitcoind.exe> cargo test --test core_regtest -- --ignored`.
use lightninger_bitvm3_clearing::{
    clearing_step::check_step,
    tapsighash_step::{sighash_steps, spent_commitment, tap_sighash, tap_z, SigSlot, Tx, TxShape},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shz_dlc::{bip340_sign, bip340_verify, pubkey_x_from_secret, Bip340Signature};
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

struct Node {
    child: Child,
    cli: PathBuf,
    datadir: PathBuf,
    port: u16,
}

impl Node {
    fn spawn(bitcoind: &Path) -> Node {
        let cli = bitcoind.with_file_name(if cfg!(windows) { "bitcoin-cli.exe" } else { "bitcoin-cli" });
        let free = || TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (port, p2p) = (free(), free());
        let base = std::env::var_os("LIGHTNINGER_TRACE_TMP").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let datadir = base.join(format!("lightninger-core-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&datadir).unwrap();
        let child = Command::new(bitcoind)
            .args(["-regtest", "-server=1", "-txindex=1", "-fallbackfee=0.0001", "-rpcuser=lbc", "-rpcpassword=lbc", "-listen=0", "-dnsseed=0"])
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={port}"))
            .arg(format!("-port={p2p}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind");
        let n = Node { child, cli, datadir, port };
        for _ in 0..200 {
            if n.try_cli(&["getblockchaininfo"]).is_ok() {
                return n;
            }
            thread::sleep(Duration::from_millis(150));
        }
        panic!("bitcoind RPC not ready");
    }
    fn try_cli(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.cli)
            .args(["-regtest", "-rpcuser=lbc", "-rpcpassword=lbc"])
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg(format!("-rpcport={}", self.port))
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
    fn cli(&self, args: &[&str]) -> String {
        self.try_cli(args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }
    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.cli(args)).unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.try_cli(&["stop"]);
        for _ in 0..50 {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

fn serialize_signed(tx: &Tx) -> Vec<u8> {
    let s = tx.stripped();
    let mut v = s[..4].to_vec();
    v.extend([0, 1]);
    v.extend(&s[4..s.len() - 4]);
    for w in &tx.witness {
        v.push(w.len() as u8);
        for item in w {
            assert!(item.len() < 0xfd);
            v.push(item.len() as u8);
            v.extend(item);
        }
    }
    v.extend(&s[s.len() - 4..]);
    v
}

const NAMES: [(u8, &str); 7] = [(0x00, "DEFAULT"), (0x01, "ALL"), (0x02, "NONE"), (0x03, "SINGLE"), (0x81, "ALL|ANYONECANPAY"), (0x82, "NONE|ANYONECANPAY"), (0x83, "SINGLE|ANYONECANPAY")];

#[derive(Serialize, Deserialize)]
pub struct CoreTx {
    pub label: String,
    pub signed_hex: String,
    pub amounts: Vec<u64>,
    pub spks: Vec<String>,
    pub slots: Vec<SigSlot>,
    pub how_validated: String,
}

fn btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

fn slots_of(tx: &Tx, types: &[u8]) -> Vec<SigSlot> {
    tx.witness
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let sig = &w[0];
            assert_eq!(sig.len(), if types[i] == 0 { 64 } else { 65 });
            let annex = (w.len() == 2 && w[1][0] == 0x50).then(|| w[1].clone());
            SigSlot { input: i, hash_type: types[i], annex, sig_rx: sig[..32].try_into().unwrap(), sig_s: sig[32..64].try_into().unwrap() }
        })
        .collect()
}

fn check_all(tx: &Tx, amounts: &[u64], spks: &[Vec<u8>], slots: &[SigSlot], shape: &TxShape) {
    for s in slots {
        let h = tap_sighash(tx, amounts, spks, s.input, s.hash_type, s.annex.as_deref()).unwrap();
        let px: [u8; 32] = spks[s.input][2..34].try_into().unwrap();
        assert!(bip340_verify(&px, &h, &Bip340Signature { r_x: s.sig_rx, s: s.sig_s }).is_ok(), "native sighash does not verify input {} {:#04x}", s.input, s.hash_type);
    }
    let (steps, b, _, _) = sighash_steps(shape, tx, amounts, spks, slots);
    for (i, st) in steps.iter().enumerate() {
        let (ok, which, out, n) = check_step(st, &st.z_in());
        assert!(ok, "input {} {:#04x}: unsatisfied at {which:?}", st.slot.input, st.slot.hash_type);
        assert_eq!(out, tap_z(i as u64 + 1, &b[i].next_accumulator(&st.prev_acc), &tx.txid(), &spent_commitment(amounts, spks), st.mask | 1 << st.slot.input));
        eprintln!("  input {} {:#04x} annex {:?}: circuit ok ({n} constraints)", st.slot.input, st.slot.hash_type, st.slot.annex.as_ref().map(|a| a.len()));
    }
}

#[test]
#[ignore = "needs LIGHTNINGER_BITCOIND (Bitcoin Core 31.1 bitcoind)"]
fn core_signed_and_consensus_accepted_transactions() {
    let bitcoind = PathBuf::from(std::env::var("LIGHTNINGER_BITCOIND").expect("LIGHTNINGER_BITCOIND"));
    let node = Node::spawn(&bitcoind);
    let version = node.json(&["getnetworkinfo"])["subversion"].as_str().unwrap().to_string();
    eprintln!("node {version}");
    node.cli(&["createwallet", "w"]);
    let mine_to = node.cli(&["getnewaddress", "", "bech32m"]);
    node.cli(&["generatetoaddress", "12", &mine_to]);
    let sink = node.cli(&["getnewaddress", "", "bech32m"]);
    node.cli(&["generatetoaddress", "101", &sink]);
    let mut utxos: Vec<Value> = node.json(&["listunspent"]).as_array().unwrap().iter().filter(|u| u["address"] == mine_to.as_str()).cloned().collect();
    utxos.sort_by_key(|u| u["txid"].as_str().unwrap().to_string());
    assert!(utxos.len() >= 9);
    let shape_of = |tx: &Tx, spks: &[Vec<u8>]| TxShape::of(tx, spks, 40);
    let mut out: Vec<CoreTx> = Vec::new();
    let mut shape: Option<TxShape> = None;

    // ---- 1. wallet-signed, one hash type per input
    let plans: [[u8; 3]; 3] = [[0x83, 0x01, 0x00], [0x03, 0x02, 0x82], [0x81, 0x00, 0x01]];
    for (t, types) in plans.iter().enumerate() {
        let ins: Vec<&Value> = utxos[3 * t..3 * t + 3].iter().collect();
        let inputs = json!(ins.iter().map(|u| json!({"txid": u["txid"], "vout": u["vout"]})).collect::<Vec<_>>()).to_string();
        let total: u64 = ins.iter().map(|u| (u["amount"].as_f64().unwrap() * 1e8).round() as u64).sum();
        let each = (total - 30_000) / 3;
        let outs = json!((0..3).map(|_| json!({node.cli(&["getnewaddress", "", "bech32m"]): btc(each)})).collect::<Vec<_>>()).to_string();
        let raw = node.cli(&["createrawtransaction", &inputs, &outs]);
        let mut tx = Tx::parse(&hex::decode(&raw).unwrap());
        let amounts: Vec<u64> = ins.iter().map(|u| (u["amount"].as_f64().unwrap() * 1e8).round() as u64).collect();
        let spks: Vec<Vec<u8>> = ins.iter().map(|u| hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap()).collect();
        let mut witness = vec![Vec::new(); 3];
        for (i, &ty) in types.iter().enumerate() {
            let name = NAMES.iter().find(|n| n.0 == ty).unwrap().1;
            let signed = node.json(&["signrawtransactionwithwallet", &raw, "[]", name]);
            assert_eq!(signed["complete"], true, "{name}: {signed}");
            witness[i] = Tx::parse(&hex::decode(signed["hex"].as_str().unwrap()).unwrap()).witness[i].clone();
        }
        tx.witness = witness;
        let hexs = hex::encode(serialize_signed(&tx));
        let accept = node.json(&["testmempoolaccept", &json!([hexs]).to_string()]);
        assert_eq!(accept[0]["allowed"], true, "{accept}");
        let txid = node.cli(&["sendrawtransaction", &hexs]);
        assert_eq!(txid, hex::encode(tx.txid()));
        node.cli(&["generatetoaddress", "1", &sink]);
        let slots = slots_of(&tx, types);
        let sh = shape_of(&tx, &spks);
        if let Some(s) = &shape {
            assert_eq!(*s, sh);
        }
        shape = Some(sh.clone());
        eprintln!("wallet tx {t} {txid} types {types:02x?}: testmempoolaccept allowed, mined");
        check_all(&tx, &amounts, &spks, &slots, &sh);
        out.push(CoreTx {
            label: format!("wallet_{t}"),
            signed_hex: hexs,
            amounts,
            spks: spks.iter().map(hex::encode).collect(),
            slots,
            how_validated: format!("{version}: signrawtransactionwithwallet per input, testmempoolaccept allowed, sendrawtransaction, mined"),
        });
    }

    // ---- 2. annex spends signed here, consensus-checked by generateblock
    let sks = [[0x31u8; 32], [0x32; 32], [0x33; 32]];
    let mut prev = Vec::new();
    for sk in &sks {
        let x = pubkey_x_from_secret(sk).unwrap();
        let desc = node.json(&["getdescriptorinfo", &format!("rawtr({})", hex::encode(x))])["descriptor"].as_str().unwrap().to_string();
        let addr = node.json(&["deriveaddresses", &desc])[0].as_str().unwrap().to_string();
        let txid = node.cli(&["sendtoaddress", &addr, "1.25"]);
        let spk = [vec![0x51, 0x20], x.to_vec()].concat();
        let d = node.json(&["getrawtransaction", &txid, "true"]);
        let vout = d["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == hex::encode(&spk).as_str()).unwrap()["n"].as_u64().unwrap();
        prev.push((txid, vout, spk));
    }
    node.cli(&["generatetoaddress", "1", &sink]);
    let inputs = json!(prev.iter().map(|(t, v, _)| json!({"txid": t, "vout": v})).collect::<Vec<_>>()).to_string();
    let outs = json!((0..3).map(|_| json!({node.cli(&["getnewaddress", "", "bech32m"]): btc(124_990_000)})).collect::<Vec<_>>()).to_string();
    let raw = node.cli(&["createrawtransaction", &inputs, &outs]);
    let unsigned = Tx::parse(&hex::decode(&raw).unwrap());
    let amounts = vec![125_000_000u64; 3];
    let spks: Vec<Vec<u8>> = prev.iter().map(|p| p.2.clone()).collect();
    let annexes: [Option<Vec<u8>>; 3] = [Some(vec![0x50, 1, 2, 3, 4]), Some([vec![0x50], vec![0xa5; 32]].concat()), None];
    let types = [0x00u8, 0x01, 0x83];
    let sign = |commit_annex: bool| -> Tx {
        let mut tx = unsigned.clone();
        tx.witness = (0..3)
            .map(|i| {
                let committed = if commit_annex { annexes[i].as_deref() } else { None };
                let h = tap_sighash(&unsigned, &amounts, &spks, i, types[i], committed).unwrap();
                let s = bip340_sign(&sks[i], &h).unwrap();
                let mut sig = [s.r_x, s.s].concat();
                if types[i] != 0 {
                    sig.push(types[i]);
                }
                let mut w = vec![sig];
                if let Some(a) = &annexes[i] {
                    w.push(a.clone());
                }
                w
            })
            .collect();
        tx
    };
    let bad = hex::encode(serialize_signed(&sign(false)));
    let bad_res = node.try_cli(&["generateblock", &sink, &json!([bad]).to_string()]);
    assert!(bad_res.is_err(), "annex not committed but block accepted");
    eprintln!("annex tx signed without the annex: generateblock rejected ({})", bad_res.unwrap_err().lines().next().unwrap_or(""));
    let tx = sign(true);
    let good = hex::encode(serialize_signed(&tx));
    let policy = node.json(&["testmempoolaccept", &json!([good]).to_string()]);
    eprintln!("annex tx testmempoolaccept: {}", policy[0]);
    node.cli(&["generateblock", &sink, &json!([good]).to_string()]);
    let conf = node.json(&["getrawtransaction", &hex::encode(tx.txid()), "true"]);
    assert!(conf["confirmations"].as_u64().unwrap() >= 1);
    eprintln!("annex tx {} mined by generateblock", hex::encode(tx.txid()));
    let slots = slots_of(&tx, &types);
    let sh = shape_of(&tx, &spks);
    assert_eq!(shape.as_ref(), Some(&sh), "one relation covers wallet and annex transactions");
    check_all(&tx, &amounts, &spks, &slots, &sh);
    out.push(CoreTx {
        label: "annex".into(),
        signed_hex: good,
        amounts,
        spks: spks.iter().map(hex::encode).collect(),
        slots,
        how_validated: format!("{version}: signed with the native BIP-341 sighash (annex on inputs 0 and 1), testmempoolaccept {}, generateblock accepted; the same tx signed without committing to the annex rejected by generateblock", policy[0]),
    });
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/core_sighash_txs.json");
    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
    eprintln!("wrote {}", path.display());
}
