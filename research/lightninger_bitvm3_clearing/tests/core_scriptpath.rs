//! Script-path (tapscript) ground truth from Bitcoin Core 31.1 for the TapSighash bind mode.
//!
//! One transaction, 3 inputs, 3 P2TR outputs:
//! - input 0 spends a leaf `<A> CHECKSIGVERIFY <B> CHECKSIG` with two signatures (A: DEFAULT,
//!   B: ALL, i.e. a 65-byte signature);
//! - input 1 spends a leaf `1 DROP CODESEPARATOR <C> CHECKSIG` (codeseparator at opcode 2) with
//!   SINGLE|ANYONECANPAY;
//! - input 2 is a key-path spend of a `rawtr` output (DEFAULT).
//!
//! Signed with the native reference (`tap_sighash_ext`), accepted by `testmempoolaccept` and
//! mined; the same transaction with input 1 signed for "no codeseparator" is refused. Every
//! slot is then synthesized in the bind-mode relation and must output the expected
//! accumulators. Written to `artifacts/core_scriptpath_txs.json`.
//!
//! Run: `LIGHTNINGER_BITCOIND=<bitcoind.exe> cargo test --test core_scriptpath -- --ignored`.
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    schnorr::VerifyingKey,
    ProjectivePoint, Scalar,
};
use lightninger_bitvm3_clearing::{
    clearing_step::check_step,
    gadgets::tagged_hash,
    tapsighash_step::{bound_steps, spent_commitment, tap_sighash_ext, tap_z, BoundSlot, ScriptPath, SigSlot, Tx, TxShape},
};
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
        let datadir = base.join(format!("lightninger-core-sp-{}-{port}", std::process::id()));
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

fn tapleaf(script: &[u8]) -> [u8; 32] {
    let mut m = vec![0xc0, script.len() as u8];
    m.extend(script);
    tagged_hash(b"TapLeaf", &m)
}

/// Output key and parity of internal key `p` committing to one leaf.
fn tweak(p: &[u8; 32], leaf: &[u8; 32]) -> ([u8; 32], u8) {
    let vk = VerifyingKey::from_bytes(p).unwrap();
    let pp: ProjectivePoint = (*vk.as_affine()).into();
    let t = tagged_hash(b"TapTweak", &[&p[..], &leaf[..]].concat());
    let ts = Option::<Scalar>::from(Scalar::from_repr(t.into())).unwrap();
    let q = (pp + ProjectivePoint::GENERATOR * ts).to_affine();
    let e = q.to_encoded_point(true);
    (e.as_bytes()[1..33].try_into().unwrap(), e.as_bytes()[0] & 1)
}

fn fund(node: &Node, x: &[u8; 32]) -> (String, u64, Vec<u8>) {
    let desc = node.json(&["getdescriptorinfo", &format!("rawtr({})", hex::encode(x))])["descriptor"].as_str().unwrap().to_string();
    let addr = node.json(&["deriveaddresses", &desc])[0].as_str().unwrap().to_string();
    let txid = node.cli(&["sendtoaddress", &addr, "1.25"]);
    let spk = [vec![0x51, 0x20], x.to_vec()].concat();
    let d = node.json(&["getrawtransaction", &txid, "true"]);
    let vout = d["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == hex::encode(&spk).as_str()).unwrap()["n"].as_u64().unwrap();
    (txid, vout, spk)
}

#[test]
#[ignore = "needs LIGHTNINGER_BITCOIND (Bitcoin Core 31.1 bitcoind)"]
fn core_accepts_script_path_spends_and_the_bind_relation_folds_them() {
    let node = Node::spawn(&PathBuf::from(std::env::var("LIGHTNINGER_BITCOIND").expect("LIGHTNINGER_BITCOIND")));
    let version = node.json(&["getnetworkinfo"])["subversion"].as_str().unwrap().to_string();
    node.cli(&["createwallet", "w"]);
    let sink = node.cli(&["getnewaddress", "", "bech32m"]);
    node.cli(&["generatetoaddress", "110", &sink]);
    let sk = |n: u8| [n; 32];
    let x = |n: u8| pubkey_x_from_secret(&sk(n)).unwrap();
    let (a, b, c, internal, kp) = (0x61, 0x62, 0x63, 0x64, 0x65);
    let leaf1 = [vec![0x20], x(a).to_vec(), vec![0xad, 0x20], x(b).to_vec(), vec![0xac]].concat();
    let leaf2 = [vec![0x51, 0x75, 0xab, 0x20], x(c).to_vec(), vec![0xac]].concat();
    let (l1, l2) = (tapleaf(&leaf1), tapleaf(&leaf2));
    let (q1, par1) = tweak(&x(internal), &l1);
    let (q2, par2) = tweak(&x(internal), &l2);
    let prev = [fund(&node, &q1), fund(&node, &q2), fund(&node, &x(kp))];
    node.cli(&["generatetoaddress", "1", &sink]);
    let inputs = json!(prev.iter().map(|(t, v, _)| json!({"txid": t, "vout": v})).collect::<Vec<_>>()).to_string();
    let outs = json!((0..3).map(|_| json!({node.cli(&["getnewaddress", "", "bech32m"]): "1.24990000"})).collect::<Vec<_>>()).to_string();
    let unsigned = Tx::parse(&hex::decode(node.cli(&["createrawtransaction", &inputs, &outs])).unwrap());
    let amounts = vec![125_000_000u64; 3];
    let spks: Vec<Vec<u8>> = prev.iter().map(|p| p.2.clone()).collect();
    let control = |parity: u8| [vec![0xc0 | parity], x(internal).to_vec()].concat();
    let sp = |key: u8, leaf: [u8; 32], codesep: u32| ScriptPath { key: x(key), tapleaf: leaf, codesep };
    // (input, signer, hash type, script path)
    let plan: Vec<(usize, u8, u8, Option<ScriptPath>)> = vec![
        (0, a, 0x00, Some(sp(a, l1, u32::MAX))),
        (0, b, 0x01, Some(sp(b, l1, u32::MAX))),
        (1, c, 0x83, Some(sp(c, l2, 2))),
        (2, kp, 0x00, None),
    ];
    let sign = |wrong_codesep: bool| -> (Tx, Vec<BoundSlot>) {
        let mut slots = Vec::new();
        let mut sigs: Vec<Vec<u8>> = Vec::new();
        for (input, signer, ht, e) in &plan {
            let mut e2 = e.clone();
            if wrong_codesep && *input == 1 {
                e2.as_mut().unwrap().codesep = u32::MAX;
            }
            let h = tap_sighash_ext(&unsigned, &amounts, &spks, *input, *ht, None, e2.as_ref()).unwrap();
            let s = bip340_sign(&sk(*signer), &h).unwrap();
            let mut sig = [s.r_x, s.s].concat();
            if *ht != 0 {
                sig.push(*ht);
            }
            sigs.push(sig);
            slots.push(BoundSlot { slot: SigSlot { input: *input, hash_type: *ht, annex: None, sig_rx: s.r_x, sig_s: s.s }, script_path: e.clone() });
        }
        let mut tx = unsigned.clone();
        tx.witness = vec![
            vec![sigs[1].clone(), sigs[0].clone(), leaf1.clone(), control(par1)],
            vec![sigs[2].clone(), leaf2.clone(), control(par2)],
            vec![sigs[3].clone()],
        ];
        (tx, slots)
    };
    let (bad, _) = sign(true);
    let r = node.json(&["testmempoolaccept", &json!([hex::encode(serialize_signed(&bad))]).to_string()]);
    assert_eq!(r[0]["allowed"], false, "{r}");
    eprintln!("signed for no codeseparator: refused ({})", r[0]["reject-reason"]);
    let (tx, slots) = sign(false);
    let hexs = hex::encode(serialize_signed(&tx));
    let r = node.json(&["testmempoolaccept", &json!([hexs]).to_string()]);
    assert_eq!(r[0]["allowed"], true, "{r}");
    assert_eq!(node.cli(&["sendrawtransaction", &hexs]), hex::encode(tx.txid()));
    node.cli(&["generatetoaddress", "1", &sink]);
    eprintln!("script-path tx {} accepted by testmempoolaccept and mined ({version})", hex::encode(tx.txid()));

    let mut shape = TxShape::of(&tx, &spks, 0);
    shape.bind = true;
    let pairs: Vec<(SigSlot, Option<ScriptPath>)> = slots.iter().map(|s| (s.slot.clone(), s.script_path.clone())).collect();
    let (steps, b, _, _, _) = bound_steps(&shape, &tx, &amounts, &spks, &pairs);
    for (i, st) in steps.iter().enumerate() {
        assert!(bip340_verify(&b[i].pubkey_x, &b[i].sighash32, &Bip340Signature { r_x: st.slot.sig_rx, s: st.slot.sig_s }).is_ok());
        let (ok, which, out, n) = check_step(st, &st.z_in());
        assert!(ok, "slot {i}: unsatisfied at {which:?}");
        let next = if i + 1 < steps.len() { steps[i + 1].z_in() } else {
            let (_, _, acc, mask, par) = bound_steps(&shape, &tx, &amounts, &spks, &pairs);
            let mut z = tap_z(steps.len() as u64, &acc, &tx.txid(), &spent_commitment(&amounts, &spks), mask);
            let (p0, p1) = lightninger_bitvm3_clearing::gadgets::le_halves(&par);
            z.extend([lightninger_bitvm3_clearing::gadgets::fu(p0), lightninger_bitvm3_clearing::gadgets::fu(p1)]);
            z
        };
        assert_eq!(out, next, "slot {i}: output");
        eprintln!("  slot {i} input {} {:#04x} {}: bind relation ok ({n} constraints)", st.slot.input, st.slot.hash_type, if st.ext.is_some() { "script path" } else { "key path" });
    }
    // a key-path slot claiming a tapleaf, and a script-path slot with another codeseparator
    let mut s = steps[3].clone();
    s.ext = Some(ScriptPath { key: s.pubkey_x(), tapleaf: [1; 32], codesep: 0 });
    let fake = s.clone();
    s.ext = None;
    let (ok, _, out_kp, _) = check_step(&s, &s.z_in());
    assert!(ok);
    let (ok2, _, out_fake, _) = check_step(&fake, &fake.z_in());
    assert!(!ok2 || out_fake != out_kp, "a tapleaf on a key-path signature left the outputs unchanged");
    let mut s = steps[2].clone();
    s.ext.as_mut().unwrap().codesep = u32::MAX;
    let (ok, _, out, _) = check_step(&s, &s.z_in());
    assert!(!ok || out[1..3] != steps[3].z_in()[1..3], "another codeseparator reached the real accumulator");
    #[derive(serde::Serialize)]
    struct CoreTx<'a> {
        label: &'a str,
        signed_hex: String,
        amounts: Vec<u64>,
        spks: Vec<String>,
        slots: Vec<BoundSlot>,
        how_validated: String,
    }
    let out = vec![CoreTx {
        label: "scriptpath",
        signed_hex: hexs,
        amounts,
        spks: spks.iter().map(hex::encode).collect(),
        slots,
        how_validated: format!("{version}: signed with the native BIP-341/342 reference, testmempoolaccept allowed, sendrawtransaction, mined; input 1 signed for no codeseparator refused"),
    }];
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/core_scriptpath_txs.json");
    std::fs::write(&p, serde_json::to_string_pretty(&out).unwrap()).unwrap();
}
