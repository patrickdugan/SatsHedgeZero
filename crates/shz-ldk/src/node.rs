//! Regtest LDK node: `ChannelManager` + `ChainMonitor` with the journaling persister,
//! peers over loopback TCP (`lightning-net-tokio`), blocks fed from Bitcoin Core.
use crate::journal::{FilePersist, JournalingPersist};
use lightning::bitcoin::consensus::encode::{deserialize, serialize_hex};
use lightning::bitcoin::secp256k1::{PublicKey, Signing, Verification, Secp256k1};
use lightning::bitcoin::{Address, Block, BlockHash, Network, Transaction};
use lightning::blinded_path::payment::{BlindedPaymentPath, ReceiveTlvs};
use lightning::chain::chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator};
use lightning::chain::chainmonitor::ChainMonitor;
use lightning::chain::{BestBlock, Filter, Listen};
use lightning::events::{Event, EventsProvider, ReplayEvent};
use lightning::ln::channel_state::ChannelDetails;
use lightning::chain::channelmonitor::ChannelMonitor;
use lightning::ln::channelmanager::{
    ChainParameters, ChannelManager, ChannelManagerReadArgs, PaymentId, RecipientOnionFields, Retry,
};
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning::ln::peer_handler::{IgnoringMessageHandler, MessageHandler, PeerManager};
use lightning::onion_message::messenger::NullMessageRouter;
use lightning::routing::router::{InFlightHtlcs, Path, Payee, PaymentParameters, Route, RouteHop, RouteParameters, Router};
use lightning::sign::{InMemorySigner, KeysManager, NodeSigner};
use lightning::types::features::{ChannelFeatures, NodeFeatures};
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning::util::config::{MaxDustHTLCExposure, UserConfig};
use lightning::util::logger::{Level, Logger, Record};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path as FsPath, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Final CLTV delta of every lane payment.
const FINAL_CLTV: u32 = 40;

/// `bitcoin-cli` bound to one regtest node and wallet.
#[derive(Clone)]
pub struct Rpc {
    cli: PathBuf,
    args: Vec<String>,
}

impl Rpc {
    pub fn call(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.cli).args(&self.args).args(args).output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("bitcoin-cli {args:?}: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
    pub fn height(&self) -> u32 {
        self.call(&["getblockcount"]).expect("getblockcount").parse().expect("height")
    }
    pub fn block_hash(&self, h: u32) -> BlockHash {
        self.call(&["getblockhash", &h.to_string()]).expect("getblockhash").parse().expect("hash")
    }
    pub fn block(&self, h: u32) -> Block {
        let hash = self.call(&["getblockhash", &h.to_string()]).expect("getblockhash");
        let hex = self.call(&["getblock", &hash, "0"]).expect("getblock");
        deserialize(&hex::decode(hex).expect("block hex")).expect("block")
    }
    pub fn mine(&self, n: u32) {
        let addr = self.call(&["-rpcwallet=shz", "getnewaddress"]).expect("getnewaddress");
        self.call(&["generatetoaddress", &n.to_string(), &addr]).expect("generatetoaddress");
    }
    /// Funds, signs and returns a transaction paying `sats` to `script` from the node wallet.
    pub fn fund(&self, script: &lightning::bitcoin::Script, sats: u64) -> Result<Transaction, String> {
        let addr = Address::from_script(script, Network::Regtest).map_err(|e| e.to_string())?;
        let outs = format!("[{{\"{addr}\":{}.{:08}}}]", sats / 100_000_000, sats % 100_000_000);
        let raw = self.call(&["-rpcwallet=shz", "createrawtransaction", "[]", &outs])?;
        let funded: serde_json::Value =
            serde_json::from_str(&self.call(&["-rpcwallet=shz", "fundrawtransaction", &raw, "{\"lockUnspents\":true}"])?).map_err(|e| e.to_string())?;
        let signed: serde_json::Value = serde_json::from_str(
            &self.call(&["-rpcwallet=shz", "signrawtransactionwithwallet", funded["hex"].as_str().ok_or("no hex")?])?,
        )
        .map_err(|e| e.to_string())?;
        if signed["complete"] != true {
            return Err("wallet could not sign the funding transaction".into());
        }
        deserialize(&hex::decode(signed["hex"].as_str().ok_or("no hex")?).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}

/// Isolated `bitcoind -regtest` with a funded descriptor wallet `shz`. Stopped and its data
/// directory removed on drop.
pub struct Bitcoind {
    child: Child,
    datadir: PathBuf,
    pub rpc: Rpc,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Bitcoind {
    pub fn spawn(bitcoind: &FsPath, datadir: PathBuf) -> Self {
        let cli = bitcoind.with_file_name(if cfg!(windows) { "bitcoin-cli.exe" } else { "bitcoin-cli" });
        assert!(cli.exists(), "bitcoin-cli not found next to {}", bitcoind.display());
        std::fs::create_dir_all(&datadir).expect("datadir");
        let (rpc_port, p2p_port) = (free_port(), free_port());
        let child = Command::new(bitcoind)
            .args(["-regtest", "-server=1", "-listen=0", "-dnsseed=0", "-fallbackfee=0.0001", "-txindex=1"])
            .arg(format!("-datadir={}", datadir.display()))
            .args(["-rpcuser=shzldk", "-rpcpassword=shzldk"])
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind");
        let rpc = Rpc {
            cli,
            args: vec![
                "-regtest".into(),
                format!("-datadir={}", datadir.display()),
                "-rpcuser=shzldk".into(),
                "-rpcpassword=shzldk".into(),
                format!("-rpcport={rpc_port}"),
            ],
        };
        let node = Self { child, datadir, rpc };
        wait_until(Duration::from_secs(60), || node.rpc.call(&["getblockchaininfo"]).is_ok()).expect("bitcoind RPC up");
        node.rpc.call(&["createwallet", "shz"]).expect("createwallet");
        // 110 blocks: ten mature coinbases, so concurrent channel fundings never share an input.
        node.rpc.mine(110);
        node
    }
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        let _ = self.rpc.call(&["stop"]);
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(20) {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

/// Polls `f` every 20 ms until it holds or `timeout` passes.
pub fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> Result<(), String> {
    let t = Instant::now();
    loop {
        if f() {
            return Ok(());
        }
        if t.elapsed() > timeout {
            return Err(format!("condition not met within {timeout:?}"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub struct Broadcaster(Rpc);
impl BroadcasterInterface for Broadcaster {
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        for tx in txs {
            if let Err(e) = self.0.call(&["sendrawtransaction", &serialize_hex(*tx)]) {
                // Re-broadcasts of a known transaction are expected and harmless.
                if !e.contains("already") {
                    eprintln!("broadcast {}: {e}", tx.compute_txid());
                }
            }
        }
    }
}

/// Constant feerate (the 253 sat/kW floor): commitment fees never change, so a lane's
/// holder balance moves by exactly the payments on it.
pub struct FixedFee;
impl FeeEstimator for FixedFee {
    fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
        253
    }
}

pub struct Log(String);
impl Logger for Log {
    fn log(&self, r: Record) {
        if r.level >= Level::Warn || std::env::var_os("SHZ_LDK_LOG").is_some() {
            eprintln!("[{} {} {}] {}", self.0, r.level, r.module_path, r.args);
        }
    }
}

/// Routes every payment over the payer's direct channel to the payee: a lane is one channel
/// between the venue and one account, so the route is that channel and nothing else.
pub struct DirectRouter;
impl Router for DirectRouter {
    fn find_route(
        &self, _payer: &PublicKey, params: &RouteParameters, first_hops: Option<&[&ChannelDetails]>, _: InFlightHtlcs,
    ) -> Result<Route, &'static str> {
        let Payee::Clear { node_id, .. } = &params.payment_params.payee else { return Err("blinded payee") };
        let hop = first_hops
            .and_then(|h| h.iter().find(|c| c.counterparty.node_id == *node_id && c.is_usable))
            .ok_or("no usable direct channel to the payee")?;
        Ok(Route {
            paths: vec![Path {
                hops: vec![RouteHop {
                    pubkey: *node_id,
                    node_features: NodeFeatures::from_le_bytes(hop.counterparty.features.le_flags().to_vec()),
                    short_channel_id: hop.get_outbound_payment_scid().ok_or("no scid")?,
                    channel_features: ChannelFeatures::empty(),
                    fee_msat: params.final_value_msat,
                    cltv_expiry_delta: FINAL_CLTV,
                    maybe_announced_channel: false,
                }],
                blinded_tail: None,
            }],
            route_params: Some(params.clone()),
        })
    }
    fn create_blinded_payment_paths<T: Signing + Verification>(
        &self, _: PublicKey, _: Vec<ChannelDetails>, _: ReceiveTlvs, _: Option<u64>, _: &Secp256k1<T>,
    ) -> Result<Vec<BlindedPaymentPath>, ()> {
        Err(())
    }
}

pub type Persister = JournalingPersist<FilePersist>;
pub type ChainMon = ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<Broadcaster>,
    Arc<FixedFee>,
    Arc<Log>,
    Arc<Persister>,
    Arc<KeysManager>,
>;
pub type Cm = ChannelManager<
    Arc<ChainMon>,
    Arc<Broadcaster>,
    Arc<KeysManager>,
    Arc<KeysManager>,
    Arc<KeysManager>,
    Arc<FixedFee>,
    Arc<DirectRouter>,
    Arc<NullMessageRouter>,
    Arc<Log>,
>;
pub type Pm = PeerManager<
    lightning_net_tokio::SocketDescriptor,
    Arc<Cm>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<Log>,
    Arc<IgnoringMessageHandler>,
    Arc<KeysManager>,
    Arc<IgnoringMessageHandler>,
>;

/// Node configuration: HTLCs may use the whole channel (a lane's net can be any size the
/// balance allows), no announced channels, 3 confirmations.
pub fn config() -> UserConfig {
    let mut c = UserConfig::default();
    c.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel = 100;
    c.channel_handshake_config.minimum_depth = 3;
    c.channel_handshake_limits.force_announced_channel_preference = false;
    c.channel_config.max_dust_htlc_exposure = MaxDustHTLCExposure::FixedLimitMsat(50_000_000);
    c
}

pub struct LdkNode {
    pub name: String,
    pub cm: Arc<Cm>,
    pub chain_monitor: Arc<ChainMon>,
    pub pm: Arc<Pm>,
    pub persister: Arc<Persister>,
    pub addr: SocketAddr,
    rpc: Rpc,
    height: Mutex<u32>,
    events: Arc<Mutex<Vec<Event>>>,
    stop: Arc<AtomicBool>,
    crash: Arc<AtomicU8>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

/// Where a test node stops dead during a persistence flush (see [`LdkNode::crash_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CrashPoint {
    None = 0,
    /// The `ChannelManager` is on disk, the queued monitors are not.
    AfterManager = 1,
    /// Manager and monitors (with their journal records) are on disk; LDK was not told the
    /// updates completed, so nothing new reached the peer.
    AfterMonitors = 2,
}

fn write_atomic(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    std::io::Write::write_all(&mut f, bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// One persistence flush: manager first, then the queued monitors and their journal records,
/// then the completion calls that let LDK talk to the peer. `false` if `crash` stopped it.
fn flush(cm: &Cm, chm: &ChainMon, persister: &Persister, manager: &FsPath, crash: CrashPoint) -> bool {
    let queue = persister.take_queue();
    if queue.is_empty() && !cm.get_and_clear_needs_persistence() {
        return true;
    }
    write_atomic(manager, &cm.encode()).expect("persist ChannelManager");
    if queue.is_empty() {
        return true;
    }
    if crash == CrashPoint::AfterManager {
        return false;
    }
    let mut written = std::collections::BTreeSet::new();
    for (cid, _) in &queue {
        if written.insert(cid.0) {
            let m = chm.get_monitor(*cid).expect("queued monitor exists");
            persister.write(&m).expect("persist ChannelMonitor and journal record");
        }
    }
    if crash == CrashPoint::AfterMonitors {
        return false;
    }
    for (cid, id) in queue {
        if let Some(id) = id {
            chm.channel_monitor_updated(cid, id).expect("monitor update completion");
        }
    }
    true
}

impl LdkNode {
    /// Starts a fresh node with its own key seed and data directory, synced to the current tip.
    pub fn start(name: &str, seed: [u8; 32], dir: PathBuf, rpc: Rpc, rt: &tokio::runtime::Runtime) -> Arc<Self> {
        Self::build(name, seed, dir, rpc, rt, false)
    }

    /// Restarts a node from its data directory: the persisted `ChannelManager`, every
    /// persisted `ChannelMonitor` and the lane journal, same seed as the first start. Peers must
    /// be reconnected; channel reestablishment completes or fails whatever was in flight.
    pub fn restart(name: &str, seed: [u8; 32], dir: PathBuf, rpc: Rpc, rt: &tokio::runtime::Runtime) -> Arc<Self> {
        Self::build(name, seed, dir, rpc, rt, true)
    }

    fn build(name: &str, seed: [u8; 32], dir: PathBuf, rpc: Rpc, rt: &tokio::runtime::Runtime, restore: bool) -> Arc<Self> {
        std::fs::create_dir_all(&dir).expect("node dir");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let keys = Arc::new(KeysManager::new(&seed, now.as_secs(), now.subsec_nanos(), true));
        let log = Arc::new(Log(name.to_string()));
        let fee = Arc::new(FixedFee);
        let bcast = Arc::new(Broadcaster(rpc.clone()));
        let files = FilePersist::new(dir.join("monitors")).expect("monitor dir");
        let journal = dir.join("lane.journal");
        let persister = Arc::new(
            if restore { JournalingPersist::open(files, journal) } else { JournalingPersist::new(files, journal) }
                .expect("lane journal"),
        );
        let chain_monitor = Arc::new(ChainMonitor::new(
            None,
            bcast.clone(),
            log.clone(),
            fee.clone(),
            persister.clone(),
            keys.clone(),
            keys.get_peer_storage_key(),
        ));
        let manager_path = dir.join("manager.bin");
        let (cm, height) = if restore {
            let mut monitors = Vec::new();
            for e in std::fs::read_dir(dir.join("monitors")).expect("monitors") {
                let p = e.unwrap().path();
                if p.extension().is_some_and(|x| x == "monitor") {
                    let bytes = std::fs::read(&p).expect("read monitor");
                    let (_, m) = <(BlockHash, ChannelMonitor<InMemorySigner>)>::read(&mut &bytes[..], (&*keys, &*keys))
                        .expect("decode monitor");
                    monitors.push(m);
                }
            }
            let bytes = std::fs::read(&manager_path).expect("read ChannelManager");
            let args = ChannelManagerReadArgs::new(
                keys.clone(),
                keys.clone(),
                keys.clone(),
                fee,
                chain_monitor.clone(),
                bcast,
                Arc::new(DirectRouter),
                Arc::new(NullMessageRouter {}),
                log.clone(),
                config(),
                monitors.iter().collect(),
            );
            let (_, cm) = <(BlockHash, Arc<Cm>)>::read(&mut &bytes[..], args).expect("decode ChannelManager");
            for m in monitors {
                let status = chain_monitor.load_existing_monitor(m.channel_id(), m).expect("load monitor");
                assert_eq!(status, lightning::chain::ChannelMonitorUpdateStatus::Completed);
            }
            let h = cm.current_best_block().height;
            (cm, h)
        } else {
            let height = rpc.height();
            let cm = Arc::new(ChannelManager::new(
                fee,
                chain_monitor.clone(),
                bcast,
                Arc::new(DirectRouter),
                Arc::new(NullMessageRouter {}),
                log.clone(),
                keys.clone(),
                keys.clone(),
                keys.clone(),
                config(),
                ChainParameters { network: Network::Regtest, best_block: BestBlock::new(rpc.block_hash(height), height) },
                now.as_secs() as u32,
            ));
            write_atomic(&manager_path, &cm.encode()).expect("persist ChannelManager");
            (cm, height)
        };
        let ign = Arc::new(IgnoringMessageHandler {});
        let pm = Arc::new(PeerManager::new(
            MessageHandler {
                chan_handler: cm.clone(),
                route_handler: Arc::clone(&ign),
                onion_message_handler: Arc::clone(&ign),
                custom_message_handler: Arc::clone(&ign),
                send_only_message_handler: ign,
            },
            now.as_secs() as u32,
            &seed,
            log,
            keys,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let pm_in = pm.clone();
        rt.spawn(async move {
            let l = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            loop {
                let Ok((s, _)) = l.accept().await else { continue };
                let pm = pm_in.clone();
                tokio::spawn(async move {
                    lightning_net_tokio::setup_inbound(pm, s.into_std().unwrap()).await;
                });
            }
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let crash = Arc::new(AtomicU8::new(0));
        let worker = {
            let (cm, chm, pm, rpc, events, stop, crash, persister) = (
                cm.clone(),
                chain_monitor.clone(),
                pm.clone(),
                rpc.clone(),
                events.clone(),
                stop.clone(),
                crash.clone(),
                persister.clone(),
            );
            let name = name.to_string();
            thread::spawn(move || {
                let handler = |ev: Event| -> Result<(), ReplayEvent> {
                    handle_event(&name, &cm, &rpc, &events, ev);
                    Ok(())
                };
                let point = || match crash.load(Ordering::Relaxed) {
                    1 => CrashPoint::AfterManager,
                    2 => CrashPoint::AfterMonitors,
                    _ => CrashPoint::None,
                };
                while !stop.load(Ordering::Relaxed) {
                    // LDK 0.2 has no PendingHTLCsForwardable event: received HTLCs wait here.
                    if cm.needs_pending_htlc_processing() {
                        cm.process_pending_htlc_forwards();
                    }
                    cm.process_pending_events(&handler);
                    chm.process_pending_events(&handler);
                    if !flush(&cm, &chm, &persister, &manager_path, point()) {
                        // Simulated crash: no further processing, connections dropped.
                        stop.store(true, Ordering::Relaxed);
                        pm.disconnect_all_peers();
                        break;
                    }
                    pm.process_events();
                    thread::sleep(Duration::from_millis(5));
                }
            })
        };
        Arc::new(Self {
            name: name.to_string(),
            cm,
            chain_monitor,
            pm,
            persister,
            addr,
            rpc,
            height: Mutex::new(height),
            events,
            stop,
            crash,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Arms a crash at the next persistence flush that has queued monitors.
    pub fn crash_at(&self, point: CrashPoint) {
        self.crash.store(point as u8, Ordering::Relaxed);
    }

    /// Whether the worker has stopped (crashed or killed).
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Stops the node without a final flush: the worker exits after its current step and every
    /// connection is dropped. What is on disk is what a restart sees.
    pub fn kill(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(w) = self.worker.lock().unwrap().take() {
            let _ = w.join();
        }
        self.pm.disconnect_all_peers();
    }

    pub fn node_id(&self) -> PublicKey {
        self.cm.get_our_node_id()
    }

    /// Connects to `other` over loopback TCP and waits until both sides list the peer.
    pub fn connect(&self, other: &LdkNode, rt: &tokio::runtime::Runtime) {
        let (pm, id, addr) = (self.pm.clone(), other.node_id(), other.addr);
        rt.block_on(async move {
            let conn = lightning_net_tokio::connect_outbound(pm, id, addr).await.expect("connect");
            tokio::spawn(conn);
        });
        wait_until(Duration::from_secs(20), || {
            self.pm.peer_by_node_id(&other.node_id()).is_some() && other.pm.peer_by_node_id(&self.node_id()).is_some()
        })
        .expect("peers connected");
    }

    /// Connects every block above the node's best block to the channel manager and monitor.
    pub fn sync(&self) {
        let mut h = self.height.lock().unwrap();
        let tip = self.rpc.height();
        while *h < tip {
            let block = self.rpc.block(*h + 1);
            self.cm.block_connected(&block, *h + 1);
            self.chain_monitor.block_connected(&block, *h + 1);
            *h += 1;
        }
    }

    pub fn channel_with(&self, peer: &PublicKey) -> Option<ChannelDetails> {
        self.cm.list_channels_with_counterparty(peer).into_iter().next()
    }

    /// Keysend of `amount_msat` to `to` over the direct channel. Idempotent per `id`.
    pub fn pay(&self, to: PublicKey, amount_msat: u64, id: PaymentId, preimage: PaymentPreimage) -> Result<PaymentHash, String> {
        let params = RouteParameters::from_payment_params_and_value(
            PaymentParameters::for_keysend(to, FINAL_CLTV, false),
            amount_msat,
        );
        self.cm
            .send_spontaneous_payment(Some(preimage), RecipientOnionFields::spontaneous_empty(), id, params, Retry::Attempts(0))
            .map_err(|e| format!("{e:?}"))
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

impl Drop for LdkNode {
    fn drop(&mut self) {
        self.kill();
    }
}

fn handle_event(name: &str, cm: &Cm, rpc: &Rpc, events: &Mutex<Vec<Event>>, ev: Event) {
    match &ev {
        Event::FundingGenerationReady {
            temporary_channel_id, counterparty_node_id, channel_value_satoshis, output_script, ..
        } => match rpc.fund(output_script, *channel_value_satoshis) {
            Ok(tx) => {
                if let Err(e) = cm.funding_transaction_generated(*temporary_channel_id, *counterparty_node_id, tx) {
                    eprintln!("[{name}] funding_transaction_generated: {e:?}");
                }
            }
            Err(e) => eprintln!("[{name}] funding: {e}"),
        },
        Event::PaymentClaimable { purpose, .. } => {
            if let Some(preimage) = purpose.preimage() {
                cm.claim_funds(preimage);
            }
        }
        _ => {}
    }
    events.lock().unwrap().push(ev);
}
