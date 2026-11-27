//! DLC-style CET and refund spends on Bitcoin Core 31.1 regtest, checked end to end through
//! M17 (script execution) and the bind-mode TapSighash relation, with the binding check.
//!
//! The funding output is P2TR with internal key I and two leaves:
//! - CET: `<A> CHECKSIGVERIFY <B> CHECKSIG` (the co-signed CET; an oracle adaptor signature
//!   completes to an ordinary BIP-340 signature on chain);
//! - refund: `<h> CHECKLOCKTIMEVERIFY DROP <A> CHECKSIGVERIFY <B> CHECKSIG`.
//! Two funding outputs are created; one is spent by a CET through the CET leaf, the other by a
//! refund transaction (nLockTime = h) through the refund leaf. Both are signed with the native
//! BIP-341/342 reference, accepted by `testmempoolaccept` and mined. Each input then runs
//! through M17 natively (valid, its deferred Taproot signatures must be exactly the slots that
//! were signed, codeseparator and leaf included), every slot satisfies the bind relation, and
//! the binding check passes on the natively computed accumulators. A CET signed for the refund
//! leaf's tapleaf is refused by Core. Written to `artifacts/core_cet_txs.json`.
//!
//! Run: `LIGHTNINGER_BITCOIND=<bitcoind.exe> cargo test --test core_cet -- --ignored`.
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    schnorr::VerifyingKey,
    ProjectivePoint, Scalar,
};
use lightninger_bitvm3_clearing::{
    cet::{expected_slots, params_of},
    clearing_step::check_step,
    gadgets::tagged_hash,
    tapsighash_step::{bound_steps, tap_sighash_ext, BoundSlot, ScriptPath, SigSlot, Tx, TxShape},
};
use m17_nova_script::{circuit, sigcheck::flags as mf, Case};
use serde_json::{json, Value};
use shz_dlc::{bip340_sign, pubkey_x_from_secret};
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
        let datadir = base.join(format!("lightninger-core-cet-{}-{port}", std::process::id()));
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

fn branch(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (x, y) = if a < b { (a, b) } else { (b, a) };
    tagged_hash(b"TapBranch", &[&x[..], &y[..]].concat())
}

fn tweak(p: &[u8; 32], root: &[u8; 32]) -> ([u8; 32], u8) {
    let vk = VerifyingKey::from_bytes(p).unwrap();
    let pp: ProjectivePoint = (*vk.as_affine()).into();
    let t = tagged_hash(b"TapTweak", &[&p[..], &root[..]].concat());
    let ts = Option::<Scalar>::from(Scalar::from_repr(t.into())).unwrap();
    let q = (pp + ProjectivePoint::GENERATOR * ts).to_affine();
    let e = q.to_encoded_point(true);
    (e.as_bytes()[1..33].try_into().unwrap(), e.as_bytes()[0] & 1)
}

/// Core's standard script flags for a Taproot spend, as the script_assets vectors set them.
pub const FLAGS: u32 = mf::P2SH | mf::DERSIG | mf::CHECKLOCKTIMEVERIFY | mf::CHECKSEQUENCEVERIFY | mf::WITNESS | mf::NULLDUMMY | mf::TAPROOT;

#[derive(serde::Serialize)]
struct CoreTx {
    label: String,
    signed_hex: String,
    amounts: Vec<u64>,
    spks: Vec<String>,
    slots: Vec<BoundSlot>,
    m17_flags: u32,
    how_validated: String,
}

#[test]
#[ignore = "needs LIGHTNINGER_BITCOIND (Bitcoin Core 31.1 bitcoind)"]
fn cet_and_refund_spends_pass_core_m17_and_the_binding() {
    let node = Node::spawn(&PathBuf::from(std::env::var("LIGHTNINGER_BITCOIND").expect("LIGHTNINGER_BITCOIND")));
    let version = node.json(&["getnetworkinfo"])["subversion"].as_str().unwrap().to_string();
    node.cli(&["createwallet", "w"]);
    let sink = node.cli(&["getnewaddress", "", "bech32m"]);
    node.cli(&["generatetoaddress", "110", &sink]);
    let sk = |n: u8| [n; 32];
    let x = |n: u8| pubkey_x_from_secret(&sk(n)).unwrap();
    let (a, b, internal) = (0x71, 0x72, 0x73);
    let h: u32 = node.cli(&["getblockcount"]).parse::<u32>().unwrap() + 3;
    let cet_leaf = [vec![0x20], x(a).to_vec(), vec![0xad, 0x20], x(b).to_vec(), vec![0xac]].concat();
    // minimal CScriptNum push of h (a block height above 16 and below 2^23)
    let mut hb = h.to_le_bytes().to_vec();
    while hb.len() > 1 && hb[hb.len() - 1] == 0 && hb[hb.len() - 2] & 0x80 == 0 {
        hb.pop();
    }
    assert!(h > 16 && hb[hb.len() - 1] & 0x80 == 0);
    let refund_leaf = [vec![hb.len() as u8], hb, vec![0xb1, 0x75, 0x20], x(a).to_vec(), vec![0xad, 0x20], x(b).to_vec(), vec![0xac]].concat();
    let (lc, lr) = (tapleaf(&cet_leaf), tapleaf(&refund_leaf));
    let (q, parity) = tweak(&x(internal), &branch(&lc, &lr));
    let control = |sibling: &[u8; 32]| [vec![0xc0 | parity], x(internal).to_vec(), sibling.to_vec()].concat();
    let desc = node.json(&["getdescriptorinfo", &format!("rawtr({})", hex::encode(q))])["descriptor"].as_str().unwrap().to_string();
    let addr = node.json(&["deriveaddresses", &desc])[0].as_str().unwrap().to_string();
    let spk = [vec![0x51, 0x20], q.to_vec()].concat();
    let mut funding = Vec::new();
    for _ in 0..2 {
        let txid = node.cli(&["sendtoaddress", &addr, "0.50"]);
        let d = node.json(&["getrawtransaction", &txid, "true"]);
        let vout = d["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == hex::encode(&spk).as_str()).unwrap()["n"].as_u64().unwrap();
        funding.push((txid, vout));
    }
    node.cli(&["generatetoaddress", "1", &sink]);
    let amount = 50_000_000u64;
    let mut out = Vec::new();
    let pp = circuit::setup();
    for (label, (txid, vout), leaf, lh, sib, locktime) in [("cet", &funding[0], &cet_leaf, lc, lr, 0u32), ("refund", &funding[1], &refund_leaf, lr, lc, h)] {
        let inputs = json!([{"txid": txid, "vout": vout, "sequence": 0xffff_fffeu32}]).to_string();
        let outs = json!([{node.cli(&["getnewaddress", "", "bech32m"]): "0.30000000"}, {node.cli(&["getnewaddress", "", "bech32m"]): "0.19990000"}]).to_string();
        let unsigned = Tx::parse(&hex::decode(node.cli(&["createrawtransaction", &inputs, &outs, &locktime.to_string()])).unwrap());
        let (amounts, spks) = (vec![amount], vec![spk.clone()]);
        let sign = |leaf_hash: [u8; 32]| -> (Tx, Vec<BoundSlot>) {
            let mut slots = Vec::new();
            let mut sigs = Vec::new();
            for signer in [a, b] {
                let e = ScriptPath { key: x(signer), tapleaf: leaf_hash, codesep: u32::MAX };
                let m = tap_sighash_ext(&unsigned, &amounts, &spks, 0, 0x00, None, Some(&e)).unwrap();
                let s = bip340_sign(&sk(signer), &m).unwrap();
                sigs.push([s.r_x, s.s].concat());
                slots.push(BoundSlot { slot: SigSlot { input: 0, hash_type: 0, annex: None, sig_rx: s.r_x, sig_s: s.s }, script_path: Some(ScriptPath { tapleaf: lh, ..e }) });
            }
            let mut tx = unsigned.clone();
            tx.witness = vec![vec![sigs[1].clone(), sigs[0].clone(), leaf.clone(), control(&sib)]];
            (tx, slots)
        };
        if label == "cet" {
            let (bad, _) = sign(lr);
            let r = node.json(&["testmempoolaccept", &json!([hex::encode(serialize_signed(&bad))]).to_string()]);
            assert_eq!(r[0]["allowed"], false, "{r}");
            eprintln!("CET signed for the refund leaf's tapleaf: refused ({})", r[0]["reject-reason"]);
        } else {
            node.cli(&["generatetoaddress", "3", &sink]);
        }
        let (tx, slots) = sign(lh);
        let hexs = hex::encode(serialize_signed(&tx));
        let r = node.json(&["testmempoolaccept", &json!([hexs]).to_string()]);
        assert_eq!(r[0]["allowed"], true, "{label}: {r}");
        node.cli(&["sendrawtransaction", &hexs]);
        node.cli(&["generatetoaddress", "1", &sink]);
        eprintln!("{label} {} (nLockTime {locktime}) accepted and mined ({version})", hex::encode(tx.txid()));
        // M17: the script execution, with Taproot signatures deferred
        let case = Case {
            id: format!("core_cet/{label}"),
            category: "cet".into(),
            flags: "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT".into(),
            flag_bits: FLAGS,
            expect_valid: true,
            description: format!("DLC {label} leaf"),
            tx: hexs.clone(),
            prevouts: vec![(amount as i64, hex::encode(&spk))],
            index: 0,
        };
        let f = circuit::fold_case(&pp, &case).unwrap_or_else(|e| panic!("{label}: M17 {e}"));
        let want: Vec<(SigSlot, Option<ScriptPath>)> = slots.iter().map(|s| (s.slot.clone(), s.script_path.clone())).collect();
        assert_eq!(expected_slots(0, &f).unwrap(), want, "{label}: M17's deferred signatures are not the signed slots");
        eprintln!("  M17: {} steps folded and verified ({:.1} s), {} claims, {} Taproot signatures deferred", f.steps, f.prove_seconds, f.claims.len(), f.deferred.len());
        let mut shape = TxShape::of(&tx, &spks, 0);
        shape.bind = true;
        let (steps, _, _, _, par) = bound_steps(&shape, &tx, &amounts, &spks, &want);
        assert_eq!(par, params_of(&want, |_| spk[2..34].try_into().unwrap()));
        for (i, st) in steps.iter().enumerate() {
            let (ok, which, _, n) = check_step(st, &st.z_in());
            assert!(ok, "{label} slot {i}: {which:?}");
            eprintln!("  slot {i}: bind relation satisfied ({n} constraints)");
        }
        out.push(CoreTx {
            label: label.into(),
            signed_hex: hexs,
            amounts,
            spks: vec![hex::encode(&spk)],
            slots,
            m17_flags: FLAGS,
            how_validated: format!("{version}: signed with the native BIP-341/342 reference, testmempoolaccept allowed, sendrawtransaction, mined; M17 native run valid with deferred signatures equal to the signed slots"),
        });
    }
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/core_cet_txs.json");
    std::fs::write(&p, serde_json::to_string_pretty(&out).unwrap()).unwrap();
}
