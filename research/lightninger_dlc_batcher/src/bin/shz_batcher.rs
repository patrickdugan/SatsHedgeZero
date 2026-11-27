//! `shz-batcher`: the Lightninger settlement daemon.
//!
//! On every oracle maturity it reads the venue's committed batches since the last settled one,
//! splits them into seq-contiguous segments (a venue abort leaves a gap), and settles each segment
//! in one transaction: every collateral account that moved spends through its settle leaf and is
//! paid `collateral + carry_in + net` (to a fresh account with a new refund height, or to the
//! address the trader asked to withdraw to), the operator's liquidity input covers the pool's net
//! and the fee, output `N` is `OP_RETURN SHZB || manifest_hash`. Traders sign their own input with
//! SIGHASH_SINGLE|ANYONECANPAY through the venue's co-sign endpoints; the batcher waits until a
//! deadline, drops accounts that did not sign (their coins and refund leaf stay untouched, their
//! segment net is carried in the manifest and paid at their next settlement), co-signs, adds the
//! operator input and then broadcasts (regtest, or testnet4 with `--broadcast`) or writes the staged
//! package after `testmempoolaccept` (testnet4 without `--broadcast`).
//!
//! State lives in `--state DIR/state.json` (written atomically after every step); receipts per
//! segment in `--receipts DIR/<event>/seg<k>/`. With `--prove`, each settled segment is proved by
//! `dlc-batcher prove` (clearing fold of the segment's batches, M17/TapSighash/Secq over the
//! settlement, the 304-byte joint statement) in a background queue.
//!
//! Subcommands: `run`, `init`, `bump`, `status`, `traders` (regtest trader bots that check and sign
//! packages), `drill-setup` (regtest: fund accounts and liquidity, write a venue registry),
//! `vector` (co-sign test vector). See `ops/shz-batcher/README.md`.
#![forbid(unsafe_code)]

use lightninger_bitvm3_clearing::tapsighash_step::{tap_sighash_ext, BoundSlot, ScriptPath, SigSlot, Tx};
use lightninger_dlc_batch_relation as rel;
use lightninger_dlc_batcher::{account_output, input, key_output, out, serialize_signed, sign_leaf, venue_batches, xonly, Node, TapOutput, SIGHASH_SINGLE_ACP};
use m17_nova_script::sigcheck::flags as mf;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shz_dlc::{bip340_sign, bip340_verify, Bip340Signature};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type H32 = [u8; 32];
const SEQUENCE: u32 = 0xffff_fffd;
const DUST: u64 = 330;
const M17_FLAGS: u32 = mf::P2SH | mf::DERSIG | mf::CHECKLOCKTIMEVERIFY | mf::CHECKSEQUENCEVERIFY | mf::WITNESS | mf::NULLDUMMY | mf::TAPROOT;
const POST_TAG: &[u8] = b"SHZ/BATCHER/POST/V1";
const WITHDRAW_TAG: &[u8] = b"SHZ/WITHDRAW/V1";

fn log(s: &str) {
    let t = now_us();
    eprintln!("[{}.{:03}] {s}", t / 1_000_000, (t / 1000) % 1000);
}

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
}

fn h32(s: &str) -> Result<H32, String> {
    hex::decode(s).map_err(|e| e.to_string())?.try_into().map_err(|_| format!("{s}: not 32 bytes"))
}

/// Oracle event id of the maturity at Unix second `s`: `SHZ-BTCUSD-YYYYMMDDTHHMMZ` on the
/// 15-minute grid (the FROST oracle's), with seconds appended for sub-minute drill epochs.
fn event_id(s: u64, epoch_secs: u64) -> String {
    let (days, rem) = (s / 86_400, s % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    let hm = format!("{:02}{:02}", rem / 3600, rem % 3600 / 60);
    if epoch_secs % 60 == 0 {
        format!("SHZ-BTCUSD-{y:04}{m:02}{d:02}T{hm}Z")
    } else {
        format!("SHZ-BTCUSD-{y:04}{m:02}{d:02}T{hm}{:02}Z", rem % 60)
    }
}

// ------------------------------------------------------------------ config ----

#[derive(Clone)]
struct Cfg {
    network: String,
    venue: String,
    cli: PathBuf,
    cli_args: Vec<String>,
    state: PathBuf,
    receipts: PathBuf,
    keys: PathBuf,
    epoch_secs: u64,
    settle_delay_secs: u64,
    sign_secs: u64,
    attest_wait_secs: u64,
    oracle: bool,
    refund_delta: u32,
    fee_rate: f64,
    bump_rate: f64,
    bump_after_blocks: u32,
    bump_after_secs: u64,
    broadcast: bool,
    prove: bool,
    prover: PathBuf,
    table: usize,
    rows: usize,
    max_epochs: Option<u32>,
    flags: BTreeMap<String, String>,
}

fn parse_args(a: &[String]) -> Cfg {
    let mut f = BTreeMap::new();
    let mut i = 0;
    let bools = ["--broadcast", "--prove", "--oracle", "--stage"];
    while i < a.len() {
        let k = a[i].as_str();
        if bools.contains(&k) {
            f.insert(k.trim_start_matches("--").to_string(), "1".to_string());
            i += 1;
        } else if let Some(k) = k.strip_prefix("--") {
            let v = a.get(i + 1).cloned().unwrap_or_else(|| panic!("--{k} needs a value"));
            f.insert(k.to_string(), v);
            i += 2;
        } else {
            panic!("unexpected argument {k}");
        }
    }
    let g = |k: &str, d: &str| f.get(k).cloned().unwrap_or_else(|| d.to_string());
    let network = g("network", "regtest");
    assert!(network == "regtest" || network == "testnet4", "--network regtest|testnet4");
    let regtest = network == "regtest";
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    Cfg {
        venue: g("venue", "http://127.0.0.1:8098").trim_end_matches('/').to_string(),
        cli: PathBuf::from(g("cli", "C:/Users/patri/bitcoin-core-31.1/bin/bitcoin-cli.exe")),
        // bitcoin-cli arguments: --cli-args, else $SHZ_BATCHER_CLI_ARGS (systemd splits unquoted args)
        cli_args: f.get("cli-args").cloned().or_else(|| std::env::var("SHZ_BATCHER_CLI_ARGS").ok()).unwrap_or_default().split_whitespace().map(String::from).collect(),
        state: PathBuf::from(g("state", "D:/shz/tmp/shz-batcher/state")),
        receipts: PathBuf::from(g("receipts", &here.join("artifacts/epochs").display().to_string())),
        keys: PathBuf::from(g("keys", "D:/shz/tmp/shz-batcher/batcher-keys.json")),
        epoch_secs: g("epoch-secs", "900").parse().unwrap(),
        settle_delay_secs: g("settle-delay-secs", "5").parse().unwrap(),
        sign_secs: g("sign-secs", "120").parse().unwrap(),
        attest_wait_secs: g("attest-wait-secs", "120").parse().unwrap(),
        oracle: f.contains_key("oracle"),
        refund_delta: g("refund-delta", if regtest { "30" } else { "432" }).parse().unwrap(),
        fee_rate: g("fee-rate", if regtest { "2" } else { "1" }).parse().unwrap(),
        bump_rate: g("bump-rate", "5").parse().unwrap(),
        bump_after_blocks: g("bump-after-blocks", "3").parse().unwrap(),
        bump_after_secs: g("bump-after-secs", "0").parse().unwrap(),
        // regtest broadcasts unless --stage; testnet4 only with --broadcast
        broadcast: (regtest || f.contains_key("broadcast")) && !f.contains_key("stage"),
        prove: f.contains_key("prove"),
        prover: PathBuf::from(g("prover", &here.join(if cfg!(windows) { "target/release/dlc-batcher.exe" } else { "target/release/dlc-batcher" }).display().to_string())),
        table: g("table", "4").parse().unwrap(),
        rows: g("rows", "2").parse().unwrap(),
        max_epochs: f.get("max-epochs").map(|x| x.parse().unwrap()),
        network,
        flags: f,
    }
}

#[derive(Deserialize)]
struct KeysFile {
    batcher_sk: String,
    operator_sk: String,
}

struct Keys {
    batcher_sk: H32,
    operator_sk: H32,
    b: H32,
    o: H32,
}

fn load_keys(p: &Path) -> Keys {
    let k: KeysFile = serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).expect("keys file");
    let (batcher_sk, operator_sk) = (h32(&k.batcher_sk).unwrap(), h32(&k.operator_sk).unwrap());
    Keys { batcher_sk, operator_sk, b: xonly(&batcher_sk), o: xonly(&operator_sk) }
}

// ------------------------------------------------------------------- state ----

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AcctState {
    owner: String,
    channel_txid: String,
    channel_vout: u32,
    txid: String,
    vout: u32,
    collateral: u64,
    refund_height: u32,
    carry_in: i64,
    status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pending {
    event: String,
    segment: usize,
    txid: String,
    fee: u64,
    vsize: u64,
    broadcast_height: u32,
    broadcast_us: u64,
    confirmed_height: Option<u32>,
    bumped_by: Option<String>,
    receipts: String,
}

/// A package posted to the venue and not yet settled: reused on restart so trader signatures
/// already given stay valid.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Collecting {
    event: String,
    segment: usize,
    first_seq: u64,
    last_seq: u64,
    deadline_us: u64,
    package: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct State {
    network: String,
    batcher: String,
    operator: Option<Utxo>,
    last_settled_seq: u64,
    last_maturity_s: u64,
    /// Pool fund and carry after `last_settled_seq` (the pre-state of the next segment's fold).
    fund_after: Option<u64>,
    carry_after: Option<u64>,
    accounts: BTreeMap<String, AcctState>,
    pending: Vec<Pending>,
    collecting: Option<Collecting>,
    withdrawals_done: BTreeSet<String>,
    epochs: Vec<Value>,
}

fn load_state(dir: &Path) -> State {
    let p = dir.join("state.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e} (run `shz-batcher init` first)", p.display()))).expect("state.json")
}

fn save_state(dir: &Path, s: &State) {
    std::fs::create_dir_all(dir).unwrap();
    let tmp = dir.join("state.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(s).unwrap()).unwrap();
    std::fs::rename(&tmp, dir.join("state.json")).unwrap();
}

fn write_json(p: &Path, v: &impl Serialize) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

// -------------------------------------------------------------------- http ----

fn curl(url: &str, headers: &[String], body: Option<&[u8]>) -> Result<(u16, Value), String> {
    let mut c = Command::new("curl");
    c.args(["-s", "-m", "20", "-A", "shz-batcher/1", "-w", "\n%{http_code}"]);
    for h in headers {
        c.args(["-H", h]);
    }
    if body.is_some() {
        c.args(["-X", "POST", "-H", "Content-Type: application/json", "--data-binary", "@-"]);
        c.stdin(Stdio::piped());
    }
    c.arg(url).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().map_err(|e| format!("curl: {e}"))?;
    if let Some(b) = body {
        ch.stdin.take().unwrap().write_all(b).map_err(|e| e.to_string())?;
    }
    let o = ch.wait_with_output().map_err(|e| e.to_string())?;
    let s = String::from_utf8_lossy(&o.stdout).to_string();
    let (b, code) = s.rsplit_once('\n').ok_or_else(|| format!("{url}: no response"))?;
    let code: u16 = code.trim().parse().map_err(|_| format!("{url}: no status"))?;
    if code == 0 {
        return Err(format!("{url}: connection failed"));
    }
    Ok((code, serde_json::from_str(b).unwrap_or(Value::String(b.chars().take(300).collect()))))
}

struct Venue {
    url: String,
    batcher_sk: H32,
}

impl Venue {
    fn get(&self, path: &str) -> Result<Value, String> {
        match curl(&format!("{}{path}", self.url), &[], None)? {
            (200, v) => Ok(v),
            (c, v) => Err(format!("GET {path}: {c} {v}")),
        }
    }
    fn get_opt(&self, path: &str) -> Result<Option<Value>, String> {
        match curl(&format!("{}{path}", self.url), &[], None)? {
            (200, v) => Ok(Some(v)),
            (404, _) => Ok(None),
            (c, v) => Err(format!("GET {path}: {c} {v}")),
        }
    }
    /// POST signed by the batcher key: `X-SHZ-Batcher` = BIP340 over tagged_hash(POST_TAG, body).
    fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let b = serde_json::to_vec(body).unwrap();
        let s = bip340_sign(&self.batcher_sk, &rel::tagged_hash(POST_TAG, &b)).unwrap();
        match curl(&format!("{}{path}", self.url), &[format!("X-SHZ-Batcher: {}", hex::encode(s.to_bytes()))], Some(&b))? {
            (200, v) => Ok(v),
            (c, v) => Err(format!("POST {path}: {c} {v}")),
        }
    }
    fn post_plain(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        curl(&format!("{}{path}", self.url), &[], Some(&serde_json::to_vec(body).unwrap()))
    }
    fn batches(&self) -> Result<Vec<Value>, String> {
        let v = self.get("/api/explorer/batches?limit=500")?;
        let mut a: Vec<Value> = v.as_array().ok_or("batches: not an array")?.clone();
        a.sort_by_key(|b| b["seq"].as_u64().unwrap_or(0));
        Ok(a)
    }
}

fn sats(btc: &Value) -> u64 {
    (btc.as_f64().unwrap_or(0.0) * 1e8).round() as u64
}

/// `gettxout` (mempool included): (value, scriptPubKey hex) of an unspent output.
fn txout(node: &Node, txid: &str, vout: u32) -> Option<(u64, String)> {
    let v = node.try_cli(&["gettxout", txid, &vout.to_string(), "true"]).ok()?;
    let v: Value = serde_json::from_str(&v).ok()?;
    Some((sats(&v["value"]), v["scriptPubKey"]["hex"].as_str()?.to_string()))
}

// ---------------------------------------------------------------- sighash ----

/// What trader `owner` signs for its account input: BIP341 tapscript sighash, hash type 0x83.
/// SINGLE|ANYONECANPAY commits to the input's own outpoint, amount, script and sequence and to the
/// output at the same index only, so a one-input one-output transaction gives the same sighash as
/// the full settlement at any index.
#[allow(clippy::too_many_arguments)]
fn trader_sighash(prev_txid: &str, vout: u32, amount: u64, spk: &[u8], sequence: u32, out_value: u64, out_spk: &[u8], version: u32, locktime: u32, leaf_hash: &H32, owner: &H32) -> H32 {
    let tx = Tx { version, inputs: vec![input(prev_txid, vout, sequence)], outputs: vec![out(out_value, out_spk.to_vec())], locktime, witness: vec![] };
    tap_sighash_ext(&tx, &[amount], &[spk.to_vec()], 0, SIGHASH_SINGLE_ACP, None, Some(&ScriptPath { key: *owner, tapleaf: *leaf_hash, codesep: u32::MAX })).unwrap()
}

fn sighash_of_entry(e: &Value, tx: &Value) -> Result<H32, String> {
    let i = &e["input"];
    let o = &e["output"];
    let hx = |v: &Value| hex::decode(v.as_str().unwrap_or("")).map_err(|x| x.to_string());
    Ok(trader_sighash(
        i["txid"].as_str().ok_or("input.txid")?,
        i["vout"].as_u64().ok_or("input.vout")? as u32,
        i["amount"].as_u64().ok_or("input.amount")?,
        &hx(&i["spk"])?,
        i["sequence"].as_u64().ok_or("input.sequence")? as u32,
        o["value"].as_u64().ok_or("output.value")?,
        &hx(&o["spk"])?,
        tx["version"].as_u64().unwrap_or(2) as u32,
        tx["locktime"].as_u64().unwrap_or(0) as u32,
        &h32(i["leaf_hash"].as_str().ok_or("leaf_hash")?)?,
        &h32(e["owner"].as_str().ok_or("owner")?)?,
    ))
}

fn verify_sig(owner: &H32, msg: &H32, sig: &[u8]) -> bool {
    if sig.len() != 65 || sig[64] != SIGHASH_SINGLE_ACP {
        return false;
    }
    let s = Bip340Signature { r_x: sig[..32].try_into().unwrap(), s: sig[32..64].try_into().unwrap() };
    bip340_verify(owner, msg, &s).is_ok()
}

/// A txid as hex: explorer outpoints carry hex strings, clearing rows serialize `[u8; 32]` arrays.
fn txid_hex(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => hex::encode(a.iter().map(|x| x.as_u64().unwrap_or(0) as u8).collect::<Vec<u8>>()),
        _ => String::new(),
    }
}

fn withdraw_msg(owner: &H32, spk: &[u8], time_us: u64) -> H32 {
    let mut m = owner.to_vec();
    m.extend((spk.len() as u32).to_le_bytes());
    m.extend(spk);
    m.extend(time_us.to_le_bytes());
    rel::tagged_hash(WITHDRAW_TAG, &m)
}

// ----------------------------------------------------------------- daemon ----

enum Gate {
    Go,
    Wait,
    Skip(String),
}

enum Outcome {
    /// Settled on chain (broadcast) — the next segment may follow.
    Settled,
    /// Built and checked, not broadcast (testnet4 without --broadcast): the batches stay unsettled.
    Staged,
    /// Nothing on chain to do (no account moved); the segment counts as settled.
    Nothing,
    /// Not settled (no signer, liquidity, a check failed): the batches roll into the next epoch.
    Rolled(String),
}

struct ProveJob {
    dir: PathBuf,
    result: Value,
}

struct Daemon {
    cfg: Cfg,
    keys: Keys,
    node: Node,
    venue: Venue,
    st: State,
    prove_tx: Option<mpsc::Sender<ProveJob>>,
}

impl Daemon {
    fn new(cfg: Cfg) -> Daemon {
        let keys = load_keys(&cfg.keys);
        let node = Node::existing(cfg.cli.clone(), cfg.cli_args.clone());
        let venue = Venue { url: cfg.venue.clone(), batcher_sk: keys.batcher_sk };
        Daemon { cfg, keys, node, venue, st: State::default(), prove_tx: None }
    }

    fn save(&self) {
        save_state(&self.cfg.state, &self.st);
    }

    fn check_chain(&self) {
        let chain = self.node.json(&["getblockchaininfo"])["chain"].as_str().unwrap_or("").to_string();
        assert_eq!(chain, self.cfg.network, "node chain {chain} differs from --network {}", self.cfg.network);
    }

    fn acct_output(&self, owner: &H32, h: u32) -> TapOutput {
        account_output(owner, &self.keys.b, h)
    }

    /// Register venue accounts of kind utxo whose deposit pays account(owner, B, h).
    fn sync_accounts(&mut self) -> Result<(), String> {
        let list = self.venue.get("/api/explorer/accounts")?;
        for a in list.as_array().ok_or("accounts: not an array")? {
            // any kind (utxo, collateral) whose explorer entry carries the on-chain account
            if !a["account"].is_object() || a["closed"] == true {
                continue;
            }
            let owner_hex = a["owner"].as_str().unwrap_or("").to_string();
            if self.st.accounts.contains_key(&owner_hex) {
                continue;
            }
            let Ok(owner) = h32(&owner_hex) else { continue };
            let acc = &a["account"];
            let h = acc["refund_height"].as_u64().unwrap_or(0) as u32;
            let fund = if acc["funding"].is_object() { &acc["funding"] } else { &a["outpoint"] };
            let (ftxid, fvout) = (fund["txid"].as_str().unwrap_or("").to_string(), fund["vout"].as_u64().unwrap_or(0) as u32);
            let spk = hex::encode(self.acct_output(&owner, h).spk());
            match txout(&self.node, &ftxid, fvout) {
                Some((value, s)) if s == spk => {
                    log(&format!("account {}: {ftxid}:{fvout} {value} sats, refund at {h}", &owner_hex[..8]));
                    self.st.accounts.insert(
                        owner_hex.clone(),
                        AcctState {
                            owner: owner_hex,
                            channel_txid: a["outpoint"]["txid"].as_str().unwrap_or("").to_string(),
                            channel_vout: a["outpoint"]["vout"].as_u64().unwrap_or(0) as u32,
                            txid: ftxid,
                            vout: fvout,
                            collateral: value,
                            refund_height: h,
                            carry_in: 0,
                            status: "active".into(),
                        },
                    );
                }
                Some((_, s)) => log(&format!("account {}: {ftxid}:{fvout} pays {s}, not account(owner, B, {h}) = {spk}; skipped", &owner_hex[..8])),
                None => log(&format!("account {}: {ftxid}:{fvout} is not an unspent output on this node; skipped", &owner_hex[..8])),
            }
        }
        Ok(())
    }

    /// The oracle's status for the maturity, through the venue's DLC explorer proxy.
    fn oracle_gate(&self, m: u64) -> Gate {
        if !self.cfg.oracle {
            return Gate::Go;
        }
        let late = now_us() / 1_000_000 >= m + self.cfg.attest_wait_secs;
        let v = match self.venue.get("/api/explorer/dlc") {
            Ok(v) => v,
            Err(e) if late => return Gate::Skip(format!("oracle unreachable: {e}")),
            Err(_) => return Gate::Wait,
        };
        let evs = v.get("events").cloned().unwrap_or(v);
        let ev = evs.as_array().and_then(|a| a.iter().find(|e| e["maturity_unix"].as_u64() == Some(m)).cloned());
        match ev.as_ref().and_then(|e| e["status"].as_str()) {
            Some("attested") => Gate::Go,
            Some(s) if s.starts_with("unattestable") => Gate::Skip(format!("oracle declared the event {s}")),
            _ if late => Gate::Skip(format!("no attestation {}s after maturity", self.cfg.attest_wait_secs)),
            _ => Gate::Wait,
        }
    }

    fn verified_withdrawals(&self) -> BTreeMap<String, (Vec<u8>, u64)> {
        let mut w = BTreeMap::new();
        let Ok(v) = self.venue.get("/api/settlement/withdrawals") else { return w };
        for x in v.as_array().cloned().unwrap_or_default() {
            let (Some(o), Some(spk), Some(t), Some(sig)) = (x["owner"].as_str(), x["spk"].as_str(), x["time_us"].as_u64(), x["sig"].as_str()) else { continue };
            let key = format!("{o}:{t}");
            if self.st.withdrawals_done.contains(&key) {
                continue;
            }
            let (Ok(owner), Ok(spk), Ok(sig)) = (h32(o), hex::decode(spk), hex::decode(sig)) else { continue };
            if sig.len() != 64 || spk.is_empty() {
                continue;
            }
            let s = Bip340Signature { r_x: sig[..32].try_into().unwrap(), s: sig[32..].try_into().unwrap() };
            if bip340_verify(&owner, &withdraw_msg(&owner, &spk, t), &s).is_ok() {
                w.insert(o.to_string(), (spk, t));
            } else {
                log(&format!("withdrawal of {}: signature does not verify; ignored", &o[..8]));
            }
        }
        w
    }

    /// One maturity: gate on the oracle, then settle each contiguous segment of committed batches.
    fn epoch(&mut self, m: u64) -> Gate {
        let event = event_id(m, self.cfg.epoch_secs);
        match self.oracle_gate(m) {
            Gate::Go => {}
            Gate::Wait => return Gate::Wait,
            Gate::Skip(why) => {
                log(&format!("{event}: not settled, {why}; its batches roll into the next epoch"));
                self.st.epochs.push(json!({"event": event, "maturity_unix": m, "status": "unattestable", "why": why}));
                return Gate::Skip(why);
            }
        }
        if let Err(e) = self.sync_accounts() {
            log(&format!("{event}: venue accounts: {e}"));
        }
        let batches = match self.venue.batches() {
            Ok(b) => b,
            Err(e) => {
                log(&format!("{event}: venue batches: {e}; epoch rolls"));
                self.st.epochs.push(json!({"event": event, "maturity_unix": m, "status": "venue-unreachable", "why": e}));
                return Gate::Skip(e);
            }
        };
        let mu = m * 1_000_000;
        let mut taken: Vec<Value> = Vec::new();
        let mut aborted = Vec::new();
        for b in batches.into_iter().filter(|b| b["seq"].as_u64().unwrap_or(0) > self.st.last_settled_seq) {
            match b["phase"].as_str().unwrap_or("") {
                "committed" if b["committed_us"].as_u64().unwrap_or(u64::MAX) <= mu => taken.push(b),
                "committed" => break,
                "aborted" => aborted.push(b["seq"].as_u64().unwrap_or(0)),
                _ => break,
            }
        }
        let mut segments: Vec<Vec<Value>> = Vec::new();
        for b in taken {
            let s = b["seq"].as_u64().unwrap();
            match segments.last_mut() {
                Some(seg) if seg.last().unwrap()["seq"].as_u64().unwrap() + 1 == s => seg.push(b),
                _ => segments.push(vec![b]),
            }
        }
        log(&format!(
            "{event}: {} segment(s) {:?}, aborted seqs {aborted:?}",
            segments.len(),
            segments.iter().map(|s| format!("{}..{}", s[0]["seq"], s.last().unwrap()["seq"])).collect::<Vec<_>>()
        ));
        let mut summary = Vec::new();
        // no new batches: one batch-less settlement still pays carried nets, withdrawals and refreshes
        if segments.is_empty() {
            segments.push(vec![]);
        }
        for (k, seg) in segments.into_iter().enumerate() {
            let (first, last) = match (seg.first(), seg.last()) {
                (Some(a), Some(b)) => (a["seq"].as_u64().unwrap(), b["seq"].as_u64().unwrap()),
                _ => (self.st.last_settled_seq, self.st.last_settled_seq),
            };
            let r = self.settle_segment(&event, k, seg).unwrap_or_else(|e| Outcome::Rolled(e));
            let (status, stop) = match &r {
                Outcome::Settled => ("settled".to_string(), false),
                Outcome::Nothing => ("nothing-on-chain".to_string(), false),
                Outcome::Staged => ("staged".to_string(), true),
                Outcome::Rolled(why) => (format!("rolled: {why}"), true),
            };
            log(&format!("{event} segment {k} ({first}..{last}): {status}"));
            summary.push(json!({"segment": k, "first_seq": first, "last_seq": last, "status": status}));
            self.save();
            if stop {
                break;
            }
        }
        self.st.epochs.push(json!({"event": event, "maturity_unix": m, "status": "processed", "aborted_seqs": aborted, "segments": summary}));
        Gate::Go
    }

    #[allow(clippy::too_many_lines)]
    fn settle_segment(&mut self, event: &str, k: usize, seg: Vec<Value>) -> Result<Outcome, String> {
        let rb = venue_batches(&json!({ "batches": seg }))?;
        let (first, last) = match (rb.first(), rb.last()) {
            (Some(a), Some(b)) => (a.seq, b.seq),
            _ => (self.st.last_settled_seq, self.st.last_settled_seq),
        };
        let dir = self.cfg.receipts.join(event).join(format!("seg{k}"));
        let tip = self.node.height();
        // per-channel nets and rows, owners from the batches' account lists
        let mut net: BTreeMap<(H32, u32), i64> = BTreeMap::new();
        let mut rows: BTreeMap<(H32, u32), Vec<Value>> = BTreeMap::new();
        for b in &rb {
            for r in &b.rows {
                *net.entry((r.channel_txid, r.channel_vout)).or_default() += r.net;
                rows.entry((r.channel_txid, r.channel_vout)).or_default().push(json!({"seq": b.seq, "net": r.net}));
            }
        }
        let mut owner_of: BTreeMap<(H32, u32), H32> = BTreeMap::new();
        for b in &seg {
            for a in b["accounts"].as_array().cloned().unwrap_or_default() {
                if let (Some(t), Some(v), Some(o)) = (a["channel"]["txid"].as_str(), a["channel"]["vout"].as_u64(), a["owner"].as_str()) {
                    if let (Ok(t), Ok(o)) = (h32(t), h32(o)) {
                        owner_of.insert((t, v as u32), o);
                    }
                }
            }
        }
        let withdrawals = self.verified_withdrawals();
        let chan_of = |a: &AcctState| (h32(&a.channel_txid).unwrap_or([0; 32]), a.channel_vout);

        // candidates: accounts that moved, carry a net, asked to withdraw, or near their refund height
        let mut cands: Vec<AcctState> = Vec::new();
        let mut carried: Vec<rel::Carry> = Vec::new();
        let mut excluded: Vec<(String, String)> = Vec::new();
        let mut known = BTreeSet::new();
        for a in self.st.accounts.values().filter(|a| a.status == "active") {
            let ch = chan_of(a);
            known.insert(ch);
            let moved = net.contains_key(&ch);
            let n = net.get(&ch).copied().unwrap_or(0);
            if !(moved || a.carry_in != 0 || withdrawals.contains_key(&a.owner) || a.refund_height <= tip + self.cfg.refund_delta / 2) {
                continue;
            }
            let why = match txout(&self.node, &a.txid, a.vout) {
                Some((v, s)) if v == a.collateral && s == hex::encode(self.acct_output(&h32(&a.owner)?, a.refund_height).spk()) => None,
                Some(_) => Some("account output differs from the state".to_string()),
                None => Some("account output is spent or unknown".to_string()),
            };
            let payout = a.collateral as i64 + a.carry_in + n;
            let why = why.or_else(|| (payout < DUST as i64).then(|| format!("payout {payout} below dust")));
            match why {
                None => cands.push(a.clone()),
                Some(w) => {
                    excluded.push((a.owner.clone(), w));
                    if moved {
                        carried.push(rel::Carry { channel_txid: ch.0, channel_vout: ch.1, owner: h32(&a.owner)?, net: n });
                    }
                }
            }
        }
        // channels with no on-chain account (venue demo allocations): their nets stay on the venue
        for (ch, n) in &net {
            if !known.contains(ch) {
                carried.push(rel::Carry { channel_txid: ch.0, channel_vout: ch.1, owner: owner_of.get(ch).copied().unwrap_or([0; 32]), net: *n });
            }
        }
        if cands.is_empty() {
            if net.keys().all(|c| !known.contains(c)) {
                self.advance(&rb);
                return Ok(Outcome::Nothing);
            }
            return Ok(Outcome::Rolled(format!("no account can settle ({excluded:?})")));
        }

        // the package: reuse a posted one for this (event, segment) after a restart
        let reuse = self.st.collecting.as_ref().filter(|c| c.event == event && c.segment == k && c.first_seq == first && c.last_seq == last).cloned();
        let col = match reuse {
            Some(c) => {
                log(&format!("{event} segment {k}: resuming the posted package (deadline {})", c.deadline_us));
                c
            }
            None => {
                let deadline_us = now_us() + self.cfg.sign_secs * 1_000_000;
                let mut entries = Vec::new();
                for a in &cands {
                    let owner = h32(&a.owner)?;
                    let ch = chan_of(a);
                    let n = net.get(&ch).copied().unwrap_or(0);
                    let ao = self.acct_output(&owner, a.refund_height);
                    let payout = (a.collateral as i64 + a.carry_in + n) as u64;
                    let (out_spk, kind, rh) = match withdrawals.get(&a.owner) {
                        Some((spk, _)) => (spk.clone(), "withdraw", None),
                        None => {
                            let h = tip + self.cfg.refund_delta;
                            (self.acct_output(&owner, h).spk(), "roll", Some(h))
                        }
                    };
                    let leaf_hash = ao.leaf_hash(0);
                    let sh = trader_sighash(&a.txid, a.vout, a.collateral, &ao.spk(), SEQUENCE, payout, &out_spk, 2, 0, &leaf_hash, &owner);
                    entries.push(json!({
                        "owner": a.owner, "channel": {"txid": a.channel_txid, "vout": a.channel_vout},
                        "input": {"txid": a.txid, "vout": a.vout, "amount": a.collateral, "spk": hex::encode(ao.spk()), "sequence": SEQUENCE,
                                  "leaf": hex::encode(&ao.leaves[0]), "leaf_hash": hex::encode(leaf_hash), "refund_height": a.refund_height},
                        "output": {"value": payout, "spk": hex::encode(&out_spk), "kind": kind, "refund_height": rh,
                                   "withdraw_time_us": withdrawals.get(&a.owner).map(|w| w.1)},
                        "collateral": a.collateral, "carry_in": a.carry_in, "net": n, "rows": rows.get(&ch).cloned().unwrap_or_default(),
                        "sighash_type": SIGHASH_SINGLE_ACP, "sighash": hex::encode(sh),
                    }));
                }
                let package = json!({
                    "version": 1, "network": self.cfg.network, "epoch": event, "segment": k, "first_seq": first, "last_seq": last,
                    "deadline_us": deadline_us, "batcher": hex::encode(self.keys.b), "tx": {"version": 2, "locktime": 0}, "accounts": entries,
                });
                let c = Collecting { event: event.to_string(), segment: k, first_seq: first, last_seq: last, deadline_us, package };
                self.st.collecting = Some(c.clone());
                self.save();
                c
            }
        };
        write_json(&dir.join("package.json"), &col.package);
        if let Err(e) = self.venue.post("/api/settlement/package", &col.package) {
            log(&format!("{event} segment {k}: posting the package: {e}"));
        }

        // collect signatures until every account signed or the deadline passed
        let entries: Vec<Value> = col.package["accounts"].as_array().cloned().unwrap();
        let mut sighash: BTreeMap<String, H32> = BTreeMap::new();
        for e in &entries {
            sighash.insert(e["owner"].as_str().unwrap().to_string(), h32(e["sighash"].as_str().unwrap())?);
            // the posted sighash must be what the entry's fields give
            if sighash_of_entry(e, &col.package["tx"])? != sighash[e["owner"].as_str().unwrap()] {
                return Err("package sighash differs from its fields".into());
            }
        }
        let mut sigs: BTreeMap<String, (Vec<u8>, u64)> = BTreeMap::new();
        loop {
            match self.venue.get(&format!("/api/settlement/signatures?epoch={event}&segment={k}")) {
                Ok(v) => {
                    for s in v["signatures"].as_array().cloned().unwrap_or_default() {
                        let (Some(o), Some(sig)) = (s["owner"].as_str(), s["sig"].as_str()) else { continue };
                        let Some(msg) = sighash.get(o) else { continue };
                        let Ok(sig) = hex::decode(sig) else { continue };
                        if sigs.contains_key(o) {
                            continue;
                        }
                        if verify_sig(&h32(o)?, msg, &sig) {
                            log(&format!("{event} segment {k}: signature of {}", &o[..8]));
                            sigs.insert(o.to_string(), (sig, s["received_us"].as_u64().unwrap_or(0)));
                        } else {
                            log(&format!("{event} segment {k}: signature of {} does not verify; ignored", &o[..8]));
                        }
                    }
                }
                Err(e) => log(&format!("{event} segment {k}: signatures: {e}")),
            }
            if sigs.len() == entries.len() || now_us() >= col.deadline_us {
                break;
            }
            thread::sleep(Duration::from_secs(2));
        }
        write_json(&dir.join("signatures.json"), &sigs.iter().map(|(o, (s, t))| json!({"owner": o, "sig": hex::encode(s), "received_us": t})).collect::<Vec<_>>());

        // signers settle; the rest roll with their segment net carried
        let mut signers: Vec<&Value> = Vec::new();
        let mut rolled: Vec<String> = Vec::new();
        for e in &entries {
            let o = e["owner"].as_str().unwrap();
            if sigs.contains_key(o) {
                signers.push(e);
            } else {
                rolled.push(o.to_string());
                if e["rows"].as_array().is_some_and(|r| !r.is_empty()) {
                    let ch = (h32(e["channel"]["txid"].as_str().unwrap())?, e["channel"]["vout"].as_u64().unwrap() as u32);
                    carried.push(rel::Carry { channel_txid: ch.0, channel_vout: ch.1, owner: h32(o)?, net: e["net"].as_i64().unwrap() });
                }
            }
        }
        if signers.is_empty() {
            self.st.collecting = None;
            let res = json!({"epoch": event, "segment": k, "status": "rolled", "rolled": rolled, "error": "no account signed by the deadline"});
            let _ = self.venue.post("/api/settlement/result", &res);
            write_json(&dir.join("settlement.json"), &res);
            return Ok(Outcome::Rolled("no account signed by the deadline".into()));
        }
        carried.sort_by(|a, b| (a.channel_txid, a.channel_vout).cmp(&(b.channel_txid, b.channel_vout)));

        let op = self.st.operator.clone().ok_or("no operator liquidity (run init)")?;
        if txout(&self.node, &op.txid, op.vout).map(|x| x.0) != Some(op.amount) {
            return Ok(Outcome::Rolled(format!("operator liquidity {}:{} is not unspent", op.txid, op.vout)));
        }
        let op_out = key_output(&self.keys.o);
        let manifest = rel::Manifest {
            network_code: if self.cfg.network == "testnet4" { 1 } else { 0 },
            event_id: event.to_string(),
            epoch_id: last,
            batcher: self.keys.b,
            accounts: signers
                .iter()
                .map(|e| {
                    let i = &e["input"];
                    Ok(rel::Account {
                        channel_txid: h32(e["channel"]["txid"].as_str().unwrap())?,
                        channel_vout: e["channel"]["vout"].as_u64().unwrap() as u32,
                        owner: h32(e["owner"].as_str().unwrap())?,
                        outpoint_txid: h32(i["txid"].as_str().unwrap())?,
                        outpoint_vout: i["vout"].as_u64().unwrap() as u32,
                        collateral: i["amount"].as_u64().unwrap(),
                        account_spk: hex::decode(i["spk"].as_str().unwrap()).unwrap(),
                        payout_spk: hex::decode(e["output"]["spk"].as_str().unwrap()).unwrap(),
                        carry_in: e["carry_in"].as_i64().unwrap(),
                    })
                })
                .collect::<Result<_, String>>()?,
            operator_txid: h32(&op.txid)?,
            operator_vout: op.vout,
            operator_amount: op.amount,
            operator_spk: op_out.spk(),
            carried: carried.clone(),
        };
        let n = signers.len();
        let payouts: Vec<u64> = signers.iter().map(|e| e["output"]["value"].as_u64().unwrap()).collect();
        let collat: u64 = signers.iter().map(|e| e["input"]["amount"].as_u64().unwrap()).sum();
        let base = (op.amount + collat) as i64 - payouts.iter().sum::<u64>() as i64;
        let build = |change: u64| -> (Tx, Vec<BoundSlot>) {
            let mut outs: Vec<_> = signers.iter().map(|e| out(e["output"]["value"].as_u64().unwrap(), hex::decode(e["output"]["spk"].as_str().unwrap()).unwrap())).collect();
            outs.push(out(0, rel::marker_script(&manifest.hash())));
            outs.push(out(change, op_out.spk()));
            let mut ins: Vec<_> = signers.iter().map(|e| input(e["input"]["txid"].as_str().unwrap(), e["input"]["vout"].as_u64().unwrap() as u32, SEQUENCE)).collect();
            ins.push(input(&op.txid, op.vout, SEQUENCE));
            let mut tx = Tx { version: 2, inputs: ins, outputs: outs, locktime: 0, witness: vec![] };
            let (amounts, spks) = manifest.spent();
            let mut wit = Vec::new();
            let mut slots = Vec::new();
            for (i, e) in signers.iter().enumerate() {
                let owner = h32(e["owner"].as_str().unwrap()).unwrap();
                let ao = account_output(&owner, &self.keys.b, e["input"]["refund_height"].as_u64().unwrap() as u32);
                let (sb, bs) = sign_leaf(&tx, &amounts, &spks, i, &ao, 0, &self.keys.batcher_sk, 0);
                let st = sigs[e["owner"].as_str().unwrap()].0.clone();
                slots.push(BoundSlot {
                    slot: SigSlot { input: i, hash_type: SIGHASH_SINGLE_ACP, annex: None, sig_rx: st[..32].try_into().unwrap(), sig_s: st[32..64].try_into().unwrap() },
                    script_path: Some(ScriptPath { key: owner, tapleaf: ao.leaf_hash(0), codesep: u32::MAX }),
                });
                slots.push(bs);
                wit.push(vec![sb, st, ao.leaves[0].clone(), ao.control(0)]);
            }
            let (so, bo) = sign_leaf(&tx, &amounts, &spks, n, &op_out, 0, &self.keys.operator_sk, 0);
            wit.push(vec![so, op_out.leaves[0].clone(), op_out.control(0)]);
            slots.push(bo);
            tx.witness = wit;
            (tx, slots)
        };
        let vsize = |tx: &Tx| (tx.stripped().len() as u64 * 3 + serialize_signed(tx).len() as u64).div_ceil(4);
        let draft = build(DUST);
        let vs = vsize(&draft.0);
        let fee = (self.cfg.fee_rate * vs as f64).ceil() as u64;
        let change = base - fee as i64;
        if change < DUST as i64 {
            return Ok(Outcome::Rolled(format!("operator liquidity {} short: change would be {change}", op.amount)));
        }
        let (tx, slots) = build(change as u64);
        let raw = serialize_signed(&tx);
        let txid = hex::encode(tx.txid());
        let settled = rel::check_settlement(&raw, &manifest, &rb).map_err(|e| format!("settlement relation: {e}"))?;
        let accept = self.node.accept(&[&raw]);
        let allowed = accept[0]["allowed"] == true;
        log(&format!("{event} segment {k}: settlement {txid}, {} signers, {} rolled, {vs} vB, fee {fee}, change {change}, fronted {}, testmempoolaccept {}", n, rolled.len(), settled.fronted, accept[0]));

        let (amounts, spks) = manifest.spent();
        write_json(&dir.join("manifest.json"), &manifest);
        write_json(&dir.join("batches.json"), &rb);
        write_json(
            &dir.join("txs.json"),
            &json!([{"label": "settlement", "signed_hex": hex::encode(&raw), "amounts": amounts, "spks": spks.iter().map(hex::encode).collect::<Vec<_>>(),
                     "slots": slots, "m17_flags": M17_FLAGS, "how_validated": format!("testmempoolaccept {}", accept[0])}]),
        );
        let (fund0, carry0) = self.pre_fund_carry();
        let cash0 = seg.first().map_or(0, |b| b["clearing"]["cash_before"].as_i64().unwrap_or(0));
        if !seg.is_empty() {
            write_json(
            &dir.join("venue_batches.json"),
            &json!({"name": format!("{event}-seg{k}"), "venue": self.cfg.venue,
                    "status_before": {"clearing": {"cash": cash0, "fund": fund0, "carry": carry0, "claims": 0, "book": cash0 - fund0 as i64 + carry0 as i64}},
                    "batches": seg.iter().map(|b| json!({"batch": b})).collect::<Vec<_>>()}),
            );
        }
        if !allowed {
            self.st.collecting = None;
            let res = json!({"epoch": event, "segment": k, "status": "failed", "txid": txid, "error": format!("testmempoolaccept {}", accept[0]), "rolled": rolled});
            write_json(&dir.join("settlement.json"), &res);
            let _ = self.venue.post("/api/settlement/result", &res);
            return Ok(Outcome::Rolled(format!("testmempoolaccept refused: {}", accept[0])));
        }
        let mut res = json!({
            "epoch": event, "segment": k, "first_seq": first, "last_seq": last, "batch_count": rb.len(), "txid": txid, "hex": hex::encode(&raw),
            "manifest_hash": hex::encode(manifest.hash()), "statement_sha256": null, "fee": fee, "fee_rate": self.cfg.fee_rate, "vsize": vs,
            "operator_change": change, "fronted": settled.fronted, "height": null,
            "payouts": signers.iter().enumerate().map(|(i, e)| json!({"owner": e["owner"], "vout": i, "value": e["output"]["value"], "kind": e["output"]["kind"], "net": e["net"], "carry_in": e["carry_in"]})).collect::<Vec<_>>(),
            "rolled": rolled, "excluded": excluded.iter().map(|(o, w)| json!({"owner": o, "why": w})).collect::<Vec<_>>(),
            "carried": carried.iter().map(|c| json!({"channel": format!("{}:{}", hex::encode(c.channel_txid), c.channel_vout), "owner": hex::encode(c.owner), "net": c.net})).collect::<Vec<_>>(),
            "testmempoolaccept": accept[0], "tip": tip, "network": self.cfg.network,
            "receipts": dir.display().to_string().replace('\\', "/"),
        });
        if !self.cfg.broadcast {
            res["status"] = json!("staged");
            // no node arguments here: they carry the RPC credentials and the venue journals results
            res["broadcast_command"] = json!(format!("bitcoin-cli <node args> sendrawtransaction {}", hex::encode(&raw)));
            write_json(&dir.join("settlement.json"), &res);
            write_readme(&dir, &self.cfg, &res);
            let _ = self.venue.post("/api/settlement/result", &res);
            // the package stays posted; the batches stay unsettled until broadcast
            return Ok(Outcome::Staged);
        }
        let sent = self.node.try_cli(&["sendrawtransaction", &hex::encode(&raw)]).map_err(|e| format!("sendrawtransaction: {e}"))?;
        assert_eq!(sent, txid);
        res["status"] = json!("broadcast");
        // apply: signers move to their payout, rolled accounts carry their net, operator change chains
        for (i, e) in signers.iter().enumerate() {
            let o = e["owner"].as_str().unwrap();
            let a = self.st.accounts.get_mut(o).unwrap();
            a.txid = txid.clone();
            a.vout = i as u32;
            a.collateral = payouts[i];
            a.carry_in = 0;
            if e["output"]["kind"] == "withdraw" {
                a.status = "withdrawn".into();
                self.st.withdrawals_done.insert(format!("{o}:{}", e["output"]["withdraw_time_us"].as_u64().unwrap_or(0)));
            } else {
                a.refund_height = e["output"]["refund_height"].as_u64().unwrap() as u32;
            }
        }
        for e in &entries {
            let o = e["owner"].as_str().unwrap();
            if rolled.iter().any(|r| r == o) {
                self.st.accounts.get_mut(o).unwrap().carry_in += e["net"].as_i64().unwrap();
            }
        }
        self.st.operator = Some(Utxo { txid: txid.clone(), vout: n as u32 + 1, amount: change as u64 });
        self.st.pending.push(Pending {
            event: event.to_string(),
            segment: k,
            txid: txid.clone(),
            fee,
            vsize: vs,
            broadcast_height: tip,
            broadcast_us: now_us(),
            confirmed_height: None,
            bumped_by: None,
            receipts: dir.display().to_string(),
        });
        self.st.collecting = None;
        self.advance(&rb);
        write_json(&dir.join("settlement.json"), &res);
        write_readme(&dir, &self.cfg, &res);
        if let Err(e) = self.venue.post("/api/settlement/result", &res) {
            log(&format!("{event} segment {k}: posting the result: {e}"));
        }
        // a batch-less settlement has no clearing fold to prove
        if let (Some(tx), false) = (&self.prove_tx, rb.is_empty()) {
            let _ = tx.send(ProveJob { dir: dir.clone(), result: res.clone() });
        }
        Ok(Outcome::Settled)
    }

    fn pre_fund_carry(&self) -> (u64, u64) {
        match (self.st.fund_after, self.st.carry_after) {
            (Some(f), Some(c)) => (f, c),
            _ => {
                let s = self.venue.get("/api/status").unwrap_or(Value::Null);
                (s["clearing"]["fund"].as_u64().unwrap_or(0), s["clearing"]["carry"].as_u64().unwrap_or(0))
            }
        }
    }

    fn advance(&mut self, rb: &[rel::Batch]) {
        let Some(l) = rb.last() else { return };
        self.st.last_settled_seq = l.seq;
        self.st.fund_after = Some(l.fund_after);
        self.st.carry_after = Some(l.carry_after);
    }

    /// Confirmations of broadcast settlements; CPFP when one waits too long.
    fn reconcile(&mut self) {
        let tip = self.node.height();
        let mut need_bump = false;
        for p in self.st.pending.iter_mut().filter(|p| p.confirmed_height.is_none()) {
            if let Ok(v) = self.node.try_cli(&["getrawtransaction", &p.txid, "true"]) {
                let v: Value = serde_json::from_str(&v).unwrap_or(Value::Null);
                if let Some(c) = v["confirmations"].as_u64().filter(|c| *c > 0) {
                    p.confirmed_height = Some(tip + 1 - c as u32);
                    log(&format!("{} segment {}: {} confirmed at {}", p.event, p.segment, p.txid, tip + 1 - c as u32));
                    continue;
                }
            }
            if p.bumped_by.is_none()
                && ((self.cfg.bump_after_blocks > 0 && tip >= p.broadcast_height + self.cfg.bump_after_blocks) || (self.cfg.bump_after_secs > 0 && now_us() >= p.broadcast_us + self.cfg.bump_after_secs * 1_000_000))
                && self.node.try_cli(&["getmempoolentry", &p.txid]).is_ok()
            {
                need_bump = true;
            }
        }
        if need_bump {
            match self.bump(self.cfg.bump_rate) {
                Ok(c) => log(&format!("CPFP child {c} at {} sat/vB", self.cfg.bump_rate)),
                Err(e) => log(&format!("CPFP: {e}")),
            }
        }
    }

    /// CPFP: spend the operator's latest (unconfirmed) change so the package of every unconfirmed
    /// settlement before it reaches `rate` sat/vB.
    fn bump(&mut self, rate: f64) -> Result<String, String> {
        let op = self.st.operator.clone().ok_or("no operator output")?;
        let entry = self.node.try_cli(&["getmempoolentry", &op.txid]).map_err(|e| format!("{} is not in the mempool: {e}", op.txid))?;
        let entry: Value = serde_json::from_str(&entry).unwrap();
        let anc_vsize = entry["ancestorsize"].as_u64().unwrap_or(0);
        let anc_fee = sats(&entry["fees"]["ancestor"]);
        let op_out = key_output(&self.keys.o);
        let child = |value: u64| {
            let mut tx = Tx { version: 2, inputs: vec![input(&op.txid, op.vout, SEQUENCE)], outputs: vec![out(value, op_out.spk())], locktime: 0, witness: vec![] };
            let (s, _) = sign_leaf(&tx, &[op.amount], &[op_out.spk()], 0, &op_out, 0, &self.keys.operator_sk, 0);
            tx.witness = vec![vec![s, op_out.leaves[0].clone(), op_out.control(0)]];
            tx
        };
        let cv = {
            let t = child(op.amount - 1000);
            (t.stripped().len() as u64 * 3 + serialize_signed(&t).len() as u64).div_ceil(4)
        };
        let fee = ((rate * (anc_vsize + cv) as f64).ceil() as i64 - anc_fee as i64).max(cv as i64) as u64;
        if op.amount < fee + DUST {
            return Err(format!("operator change {} cannot pay a {fee}-sat child", op.amount));
        }
        let tx = child(op.amount - fee);
        let raw = serialize_signed(&tx);
        let before = entry.clone();
        let txid = self.node.try_cli(&["sendrawtransaction", &hex::encode(&raw)]).map_err(|e| format!("sendrawtransaction child: {e}"))?;
        let after: Value = serde_json::from_str(&self.node.try_cli(&["getmempoolentry", &op.txid]).unwrap_or_default()).unwrap_or(Value::Null);
        let rec = json!({"child_txid": txid, "child_hex": hex::encode(&raw), "child_vsize": cv, "child_fee": fee, "target_rate": rate,
                         "parent": op.txid, "parent_entry_before": before, "parent_entry_after": after});
        if let Some(p) = self.st.pending.iter().rev().find(|p| p.confirmed_height.is_none()) {
            write_json(&Path::new(&p.receipts).join("cpfp.json"), &rec);
        }
        for p in self.st.pending.iter_mut().filter(|p| p.confirmed_height.is_none()) {
            p.bumped_by = Some(txid.clone());
        }
        self.st.operator = Some(Utxo { txid: txid.clone(), vout: 0, amount: op.amount - fee });
        self.save();
        Ok(txid)
    }

    fn run(&mut self) {
        self.check_chain();
        self.st = load_state(&self.cfg.state);
        assert_eq!(self.st.network, self.cfg.network, "state is for {}", self.st.network);
        assert_eq!(self.st.batcher, hex::encode(self.keys.b), "state is for another batcher key");
        let worker = self.cfg.prove.then(|| {
            let (tx, rx) = mpsc::channel::<ProveJob>();
            self.prove_tx = Some(tx);
            let (cfg, sk) = (self.cfg.clone(), self.keys.batcher_sk);
            thread::spawn(move || prove_worker(cfg, sk, rx))
        });
        let mut done = 0u32;
        log(&format!("shz-batcher {} venue {} last settled seq {} last maturity {}", self.cfg.network, self.cfg.venue, self.st.last_settled_seq, self.st.last_maturity_s));
        loop {
            self.reconcile();
            self.save();
            let m = self.st.last_maturity_s + self.cfg.epoch_secs;
            let now = now_us() / 1_000_000;
            if now < m + self.cfg.settle_delay_secs {
                thread::sleep(Duration::from_secs((m + self.cfg.settle_delay_secs - now).min(5)));
                continue;
            }
            match self.epoch(m) {
                Gate::Wait => {
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
                Gate::Go | Gate::Skip(_) => {
                    self.st.last_maturity_s = m;
                    self.save();
                    done += 1;
                }
            }
            if self.cfg.max_epochs.is_some_and(|x| done >= x) {
                break;
            }
        }
        log("epochs done; waiting for the prover queue");
        self.prove_tx = None;
        if let Some(w) = worker {
            let _ = w.join();
        }
        self.reconcile();
        self.save();
    }
}

fn write_readme(dir: &Path, cfg: &Cfg, res: &Value) {
    // the receipt directory as the re-prove commands name it: relative to the crate when inside it
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let norm = |p: &Path| p.display().to_string().replace('\\', "/");
    let full = norm(dir);
    let base = norm(crate_dir);
    let rd = full.strip_prefix(&format!("{base}/")).map(String::from).unwrap_or(full.clone());
    if res["batch_count"] == 0 {
        let s = format!(
            "# {} segment {}

Settlement `{}` ({}, {}) with no new venue batches: it pays carried nets, withdrawals and              refund-height refreshes only (`settlement.json`). There is no clearing fold to prove; the carried nets were              stated in the manifests of the segments that left them unpaid.
",
            res["epoch"].as_str().unwrap_or(""), res["segment"], res["txid"].as_str().unwrap_or(""), res["status"].as_str().unwrap_or(""), cfg.network
        );
        std::fs::write(dir.join("README.md"), s).unwrap();
        return;
    }
    let s = format!(
        "# {epoch} segment {seg}\n\n\
Settlement `{txid}` ({status}, {network}): batches {first}..{last}, fee {fee} sats at {rate} sat/vB, {vs} vB.\n\n\
| File | Content |\n| --- | --- |\n\
| `package.json` | what the venue showed each trader (input, output, net per batch row, 0x83 sighash) |\n\
| `signatures.json` | trader signatures collected before the deadline |\n\
| `manifest.json`, `batches.json`, `txs.json` | `dlc-batcher prove` inputs (manifest, V3 batch vectors, signed settlement with its signature slots) |\n\
| `venue_batches.json` | the segment's explorer batches with the pool pre-state, for `trace::from_venue` |\n\
| `settlement.json` | the result posted to the venue |\n\
| `joint_statement.json`, `guest_input.json`, `prove.log` | written by the prover |\n\n\
Re-prove from a clean checkout (table {a}, {r} rows per batch):\n\n\
```\ncd research/lightninger_dlc_batcher\n\
CARGO_INCREMENTAL=0 cargo build --release --bin dlc-batcher\n\
LIGHTNINGER_DLC_BATCH_VENUE={rd}/venue_batches.json \\\n\
LIGHTNINGER_DLC_BATCH_GUEST_DIR=/tmp/guest-{epoch}-{seg} \\\n\
  target/release/dlc-batcher prove {rd} {a} {r}\n```\n\n\
The clearing fold alone, through the clearing crate:\n\n\
```\ncd research/lightninger_bitvm3_clearing\n\
cargo run --release -- prove-clearing journal:../lightninger_dlc_batcher/{rd}/venue_batches.json {k} {a} {r} {txid}\n```\n",
        epoch = res["epoch"].as_str().unwrap_or(""),
        seg = res["segment"],
        txid = res["txid"].as_str().unwrap_or(""),
        status = res["status"].as_str().unwrap_or(""),
        network = cfg.network,
        first = res["first_seq"],
        last = res["last_seq"],
        fee = res["fee"],
        rate = cfg.fee_rate,
        vs = res["vsize"],
        a = cfg.table,
        r = cfg.rows,
        k = res["last_seq"].as_u64().unwrap_or(0) + 1 - res["first_seq"].as_u64().unwrap_or(0),
        rd = rd,
    );
    std::fs::write(dir.join("README.md"), s).unwrap();
}

/// Proves settled segments one at a time with `dlc-batcher prove`; posts the statement hash.
fn prove_worker(cfg: Cfg, batcher_sk: H32, rx: mpsc::Receiver<ProveJob>) {
    let venue = Venue { url: cfg.venue.clone(), batcher_sk };
    for job in rx {
        let t = std::time::Instant::now();
        let logf = std::fs::File::create(job.dir.join("prove.log")).unwrap();
        log(&format!("proving {}", job.dir.display()));
        let st = Command::new(&cfg.prover)
            .arg("prove")
            .arg(&job.dir)
            .arg(cfg.table.to_string())
            .arg(cfg.rows.to_string())
            .env("LIGHTNINGER_DLC_BATCH_VENUE", job.dir.join("venue_batches.json"))
            .env("LIGHTNINGER_DLC_BATCH_GUEST_DIR", cfg.state.join("guest"))
            .stdout(logf.try_clone().unwrap())
            .stderr(logf)
            .status();
        let js = std::fs::read_to_string(job.dir.join("joint_statement.json")).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok());
        let mut res = job.result.clone();
        match (st, js) {
            (Ok(s), Some(j)) if s.success() => {
                res["statement_sha256"] = j["bitvm3_statement_sha256"].clone();
                res["prove_seconds"] = json!(t.elapsed().as_secs());
                log(&format!("{}: statement {} ({}s)", job.dir.display(), res["statement_sha256"], t.elapsed().as_secs()));
            }
            (s, _) => {
                res["prove_error"] = json!(format!("prover exit {:?}; see prove.log", s.map(|x| x.code())));
                log(&format!("{}: prover failed ({:?})", job.dir.display(), res["prove_error"]));
            }
        }
        write_json(&job.dir.join("settlement.json"), &res);
        if let Err(e) = venue.post("/api/settlement/result", &res) {
            log(&format!("posting the statement: {e}"));
        }
    }
}

// --------------------------------------------------------------- commands ----

fn cmd_init(cfg: Cfg) {
    let d = Daemon::new(cfg.clone());
    d.check_chain();
    let p = cfg.state.join("state.json");
    assert!(!p.exists(), "{} exists; remove it to start over", p.display());
    let op = cfg.flags.get("operator").expect("--operator TXID:VOUT");
    let (t, v) = op.split_once(':').expect("--operator TXID:VOUT");
    let v: u32 = v.parse().unwrap();
    let (amount, spk) = txout(&d.node, t, v).expect("operator outpoint is not unspent");
    assert_eq!(spk, hex::encode(key_output(&d.keys.o).spk()), "operator outpoint does not pay <O> CHECKSIG");
    let start = match cfg.flags.get("start-seq") {
        Some(s) => s.parse().unwrap(),
        None => d.venue.batches().expect("venue").iter().filter_map(|b| b["seq"].as_u64()).max().unwrap_or(0),
    };
    let t0 = cfg.flags.get("t0").map(|x| x.parse().unwrap()).unwrap_or(now_us() / 1_000_000 / cfg.epoch_secs * cfg.epoch_secs);
    let status = d.venue.get("/api/status").unwrap_or(Value::Null);
    let st = State {
        network: cfg.network.clone(),
        batcher: hex::encode(d.keys.b),
        operator: Some(Utxo { txid: t.to_string(), vout: v, amount }),
        last_settled_seq: start,
        last_maturity_s: t0,
        fund_after: status["clearing"]["fund"].as_u64(),
        carry_after: status["clearing"]["carry"].as_u64(),
        ..Default::default()
    };
    save_state(&cfg.state, &st);
    println!("{}", json!({"state": p.display().to_string(), "batcher": hex::encode(d.keys.b), "operator": format!("{t}:{v}"), "amount": amount, "start_seq": start, "t0": t0}));
}

/// Regtest trader bots: for each key, fetch its package, check it against the venue's batches
/// and its own keys, sign (or refuse the configured nth package), optionally ask to withdraw.
fn cmd_traders(cfg: Cfg) {
    let keys: Value = serde_json::from_str(&std::fs::read_to_string(cfg.flags.get("trader-keys").expect("--trader-keys")).unwrap()).unwrap();
    let sks: Vec<H32> = keys["accounts"].as_array().unwrap().iter().map(|k| h32(k.as_str().unwrap()).unwrap()).collect();
    let pairs = |k: &str| -> BTreeMap<usize, usize> {
        cfg.flags.get(k).map(|s| s.split(',').filter(|x| !x.is_empty()).map(|x| {
            let (a, b) = x.split_once(':').unwrap();
            (a.parse().unwrap(), b.parse().unwrap())
        }).collect()).unwrap_or_default()
    };
    let refuse = pairs("refuse"); // index:nth package to leave unsigned
    let withdraw = pairs("withdraw"); // index:after nth signed package, ask to withdraw
    let only: Option<BTreeSet<usize>> = cfg.flags.get("only").map(|s| s.split(',').map(|x| x.parse().unwrap()).collect());
    let until = now_us() + cfg.flags.get("for-secs").map_or(3600, |x| x.parse().unwrap()) * 1_000_000;
    let venue = Venue { url: cfg.venue.clone(), batcher_sk: [1; 32] };
    let mut seen: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    let mut count: BTreeMap<usize, usize> = BTreeMap::new();
    let mut signed: BTreeMap<usize, usize> = BTreeMap::new();
    let mut asked: BTreeSet<usize> = BTreeSet::new();
    while now_us() < until {
        let batches = venue.batches().unwrap_or_default();
        for (i, sk) in sks.iter().enumerate() {
            if only.as_ref().is_some_and(|o| !o.contains(&i)) {
                continue;
            }
            let t = xonly(sk);
            let th = hex::encode(t);
            let Ok(Some(p)) = venue.get_opt(&format!("/api/settlement/package?owner={th}")) else { continue };
            let id = format!("{}#{}", p["epoch"].as_str().unwrap_or(""), p["segment"]);
            if !seen.entry(i).or_default().insert(id.clone()) {
                continue;
            }
            let nth = { let c = count.entry(i).or_default(); *c += 1; *c };
            let e = &p["account"];
            let check = || -> Result<H32, String> {
                let leaf = hex::decode(e["input"]["leaf"].as_str().ok_or("leaf")?).map_err(|x| x.to_string())?;
                if leaf.len() != 68 || leaf[1..33] != t[..] {
                    return Err("settle leaf is not mine".into());
                }
                let b: H32 = leaf[35..67].try_into().unwrap();
                let my_rows: i64 = e["rows"].as_array().ok_or("rows")?.iter().map(|r| {
                    let seq = r["seq"].as_u64().unwrap_or(0);
                    batches.iter().find(|x| x["seq"].as_u64() == Some(seq)).and_then(|x| x["clearing"]["rows"].as_array().cloned()).unwrap_or_default()
                        .iter().filter(|row| txid_hex(&row["channel"]["txid"]) == txid_hex(&e["channel"]["txid"]) && row["channel"]["vout"] == e["channel"]["vout"]).map(|row| row["net"].as_i64().unwrap_or(0)).sum::<i64>()
                }).sum();
                if my_rows != e["net"].as_i64().unwrap_or(i64::MIN) {
                    return Err(format!("net {} differs from my batch rows {my_rows}", e["net"]));
                }
                let payout = e["collateral"].as_i64().unwrap_or(0) + e["carry_in"].as_i64().unwrap_or(0) + my_rows;
                if e["output"]["value"].as_i64() != Some(payout) {
                    return Err(format!("output {} differs from collateral + carry + net {payout}", e["output"]["value"]));
                }
                if e["output"]["kind"] == "roll" {
                    let h = e["output"]["refund_height"].as_u64().ok_or("refund_height")? as u32;
                    if e["output"]["spk"].as_str() != Some(&hex::encode(account_output(&t, &b, h).spk())) {
                        return Err("roll output is not my account".into());
                    }
                }
                let sh = sighash_of_entry(e, &p["tx"])?;
                if e["sighash"].as_str() != Some(&hex::encode(sh)) {
                    return Err("posted sighash differs from the one I compute".into());
                }
                Ok(sh)
            };
            match check() {
                Err(why) => log(&format!("trader {i}: refusing {id}: {why}")),
                Ok(_) if refuse.get(&i) == Some(&nth) => log(&format!("trader {i}: leaving {id} unsigned (drill non-signer)")),
                Ok(sh) => {
                    let s = bip340_sign(sk, &sh).unwrap();
                    let mut sig = s.to_bytes().to_vec();
                    sig.push(SIGHASH_SINGLE_ACP);
                    let r = venue.post_plain("/api/settlement/signature", &json!({"epoch": p["epoch"], "segment": p["segment"], "owner": th, "sig": hex::encode(&sig)}));
                    match r {
                        Ok((200, _)) => log(&format!("trader {i}: signed {id} (payout {} {}, net {})", e["output"]["value"], e["output"]["kind"], e["net"])),
                        other => {
                            log(&format!("trader {i}: signature for {id} refused by the venue: {other:?}"));
                            continue;
                        }
                    }
                    let c = { let c = signed.entry(i).or_default(); *c += 1; *c };
                    if withdraw.get(&i) == Some(&c) && asked.insert(i) {
                        let spk = key_output(&t).spk();
                        let tu = now_us();
                        let ws = bip340_sign(sk, &withdraw_msg(&t, &spk, tu)).unwrap();
                        let r = venue.post_plain("/api/settlement/withdraw", &json!({"owner": th, "spk": hex::encode(&spk), "time_us": tu, "sig": hex::encode(ws.to_bytes())}));
                        log(&format!("trader {i}: asked to withdraw to <T> CHECKSIG: {:?}", r.map(|x| x.0)));
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Regtest: fund one account per trader key (collateral each, refund at tip + refund_delta) and the
/// operator's liquidity in one transaction, mine it, and write the venue registry entries.
fn cmd_drill_setup(cfg: Cfg) {
    let d = Daemon::new(cfg.clone());
    assert_eq!(cfg.network, "regtest");
    d.check_chain();
    let keys: Value = serde_json::from_str(&std::fs::read_to_string(cfg.flags.get("trader-keys").expect("--trader-keys")).unwrap()).unwrap();
    let chans: Value = serde_json::from_str(&std::fs::read_to_string(cfg.flags.get("channels").expect("--channels venue_batches.json")).unwrap()).unwrap();
    let collateral: u64 = cfg.flags.get("collateral").map_or(20_000, |x| x.parse().unwrap());
    let liquidity: u64 = cfg.flags.get("liquidity").map_or(200_000, |x| x.parse().unwrap());
    let sink = d.node.cli(&["getnewaddress", "", "bech32m"]);
    let h = d.node.height() + cfg.refund_delta;
    let owners: Vec<H32> = keys["accounts"].as_array().unwrap().iter().map(|k| xonly(&h32(k.as_str().unwrap()).unwrap())).collect();
    let mut outs = serde_json::Map::new();
    let aos: Vec<TapOutput> = owners.iter().map(|t| account_output(t, &d.keys.b, h)).collect();
    for o in &aos {
        outs.insert(lightninger_dlc_batcher::address(&d.node, &o.output_key), json!(format!("{:.8}", collateral as f64 / 1e8)));
    }
    let lo = key_output(&d.keys.o);
    outs.insert(lightninger_dlc_batcher::address(&d.node, &lo.output_key), json!(format!("{:.8}", liquidity as f64 / 1e8)));
    let raw = d.node.cli(&["createrawtransaction", "[]", &Value::Object(outs).to_string()]);
    let funded = d.node.json(&["fundrawtransaction", &raw, r#"{"fee_rate": 2}"#]);
    let signed = d.node.json(&["signrawtransactionwithwallet", funded["hex"].as_str().unwrap()]);
    let txid = d.node.cli(&["sendrawtransaction", signed["hex"].as_str().unwrap()]);
    d.node.cli(&["generatetoaddress", "1", &sink]);
    let tx = d.node.json(&["getrawtransaction", &txid, "true"]);
    let vout_of = |spk: &[u8]| tx["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == hex::encode(spk).as_str()).unwrap()["n"].as_u64().unwrap();
    let reg: Vec<Value> = owners
        .iter()
        .enumerate()
        .map(|(i, t)| {
            // the venue channel of this owner in the replayed batches, else the i-th account's (fresh drill keys)
            let ca = chans["accounts"].as_array().unwrap();
            let ch = ca.iter().find(|a| a["owner"] == hex::encode(t).as_str()).or_else(|| ca.get(i)).map(|a| a["outpoint"].clone()).unwrap_or(json!({"txid": txid, "vout": vout_of(&aos[i].spk())}));
            json!({"owner": hex::encode(t), "kind": "utxo", "label": format!("drill-{i}"), "outpoint": ch,
                   "account": {"refund_height": h, "spk": hex::encode(aos[i].spk()), "collateral_sats": collateral, "funding": {"txid": txid, "vout": vout_of(&aos[i].spk())}}})
        })
        .collect();
    let out_path = cfg.flags.get("out").expect("--out registry.json");
    write_json(Path::new(out_path), &reg);
    println!("{}", json!({"funding": txid, "operator": format!("{txid}:{}", vout_of(&lo.spk())), "refund_height": h, "registry": out_path}));
}

/// Co-sign test vector: a fixed account, output and sighash, for the venue/browser implementation.
fn cmd_vector() {
    let t_sk = [0x11u8; 32];
    let b_sk = [0x22u8; 32];
    let (t, b) = (xonly(&t_sk), xonly(&b_sk));
    let h = 200;
    let ao = account_output(&t, &b, h);
    let roll = account_output(&t, &b, h + 144);
    let prev = "1111111111111111111111111111111111111111111111111111111111111111";
    let sh = trader_sighash(prev, 3, 20_000, &ao.spk(), SEQUENCE, 20_036, &roll.spk(), 2, 0, &ao.leaf_hash(0), &t);
    let s = bip340_sign(&t_sk, &sh).unwrap();
    let wspk = key_output(&t).spk();
    let wsig = bip340_sign(&t_sk, &withdraw_msg(&t, &wspk, 1_764_300_000_000_000)).unwrap();
    let post_body = br#"{"epoch":"SHZ-BTCUSD-20261128T0300Z"}"#;
    let psig = bip340_sign(&b_sk, &rel::tagged_hash(POST_TAG, post_body)).unwrap();
    let v = json!({
        "trader_sk": hex::encode(t_sk), "trader_xonly": hex::encode(t), "batcher_sk": hex::encode(b_sk), "batcher_xonly": hex::encode(b),
        "account": {"refund_height": h, "leaf_settle": hex::encode(&ao.leaves[0]), "leaf_refund": hex::encode(&ao.leaves[1]), "spk": hex::encode(ao.spk()), "settle_leaf_hash": hex::encode(ao.leaf_hash(0))},
        "input": {"txid": prev, "vout": 3, "amount": 20_000, "sequence": SEQUENCE},
        "output": {"value": 20_036, "spk": hex::encode(roll.spk()), "kind": "roll", "refund_height": h + 144},
        "tx": {"version": 2, "locktime": 0}, "sighash_type": SIGHASH_SINGLE_ACP, "sighash": hex::encode(sh),
        "signature_aux_zero": format!("{}83", hex::encode(s.to_bytes())),
        "withdraw": {"spk": hex::encode(&wspk), "time_us": 1_764_300_000_000_000u64, "msg": hex::encode(withdraw_msg(&t, &wspk, 1_764_300_000_000_000)), "sig": hex::encode(wsig.to_bytes())},
        "post_auth": {"body": String::from_utf8_lossy(post_body), "msg": hex::encode(rel::tagged_hash(POST_TAG, post_body)), "x_shz_batcher": hex::encode(psig.to_bytes())},
    });
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let sub = a.get(1).map(String::as_str).unwrap_or("");
    let cfg = || parse_args(&a[2..]);
    match sub {
        "run" => Daemon::new(cfg()).run(),
        "init" => cmd_init(cfg()),
        "bump" => {
            let c = cfg();
            let rate = c.bump_rate;
            let mut d = Daemon::new(c);
            d.st = load_state(&d.cfg.state);
            match d.bump(rate) {
                Ok(t) => println!("{t}"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        "status" => println!("{}", serde_json::to_string_pretty(&load_state(&cfg().state)).unwrap()),
        "traders" => cmd_traders(cfg()),
        "drill-setup" => cmd_drill_setup(cfg()),
        "vector" => cmd_vector(),
        // manifest-hash <manifest.json>: the tagged manifest hash (marker output, policy_hash)
        "manifest-hash" => {
            let m: rel::Manifest = serde_json::from_str(&std::fs::read_to_string(&a[2]).unwrap()).unwrap();
            println!("{}", hex::encode(m.hash()));
        }
        "pubkeys" => {
            let k = load_keys(&cfg().keys);
            println!("{}", json!({"batcher": hex::encode(k.b), "operator": hex::encode(k.o), "operator_spk": hex::encode(key_output(&k.o).spk())}));
        }
        _ => eprintln!("usage: shz-batcher run|init|bump|status|traders|drill-setup|vector [--network regtest|testnet4] [--venue URL] [--cli PATH] [--cli-args \"...\"] [--state DIR] [--keys FILE] ..."),
    }
}
