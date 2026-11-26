//! Minimal deterministic CLI over `DurableTieredRouter` withdrawal state machine
//! used by the SHZ-RGB-01F adversarial process-death & reconciliation harness.

use shz_dex::routing::durable::{FeeRecipients, Head, Lane};
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dex::routing::withdrawal::*;
use shz_dex::routing::*;
use shz_dlc::{Bip340Signature, BtcOutPoint, bip340_sign};
use std::{env, path::Path};

type Key = [u8; 32];
const AUTH: Key = [77; 32];
const RELAY: u8 = 60;
const ROUTER_SIGNER: u8 = 120;
const CAP: u64 = 10_000_000;
const ZERO: Bip340Signature = Bip340Signature { r_x: [0; 32], s: [0; 32] };

fn sk(n: u8) -> Key { [n; 32] }
fn pk(n: u8) -> Key { public(&sk(n)) }
fn ch(n: u8) -> BtcOutPoint { BtcOutPoint { txid: [n; 32], vout: 0 } }
fn regtest_setup() -> (Registry, TieredConfig, Vec<Lane>, FeeRecipients) {
    let p = Policy { network: network_id("regtest"), epoch: 7, relay_keys: [pk(50), pk(51)] };
    let plans = (1..=2u8)
        .map(|n| Allocation::signed(p.scope(), &sk(n), &AUTH, ch(n), CAP, vec![Share { router: 1, sats: CAP }]).unwrap())
        .collect();
    let reg = Registry::new(p.scope(), public(&AUTH), plans).unwrap();
    let cfg = TieredConfig {
        scope: p.scope(),
        router: 1,
        entitlement_key: pk(RELAY),
        tariff: TariffSchedule::default_candidate(),
        execution: ExecutionPolicy::defaults(Arm::FeedOnly),
        revenue: RevenuePolicy::default(),
    };
    let lanes = (1..=2u8)
        .map(|n| Lane { channel: ch(n), peer: pk(70 + n), monitor: pk(90 + n), initial: Head { revision: 0, commitment: 10, state: [110 + n; 32] } })
        .collect();
    let rcpts = FeeRecipients { oracle: pk(110), router: pk(111) };
    (reg, cfg, lanes, rcpts)
}

fn parse_hex32(s: &str) -> Key {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn state_json(d: &DurableTieredRouter) -> serde_json::Value {
    let b = d.balance(&ch(1)).unwrap().unwrap();
    let tip = d.tip().unwrap();
    let ws: Vec<serde_json::Value> = d.withdrawals().unwrap().into_iter().map(|w| serde_json::json!({
        "withdrawal_id": hex::encode(w.withdrawal_id),
        "nonce": w.request.nonce.to_string(),
        "amount_sats": w.request.amount_sats.to_string(),
        "state": w.state.as_str(),
        "payment_hash": w.payment_hash.map(hex::encode),
        "btc_evidence": w.btc_evidence.map(hex::encode),
        "settlement_evidence": w.settlement_evidence.map(hex::encode),
    })).collect();
    serde_json::json!({
        "config_hash": hex::encode(d.config_hash()),
        "router_signer": hex::encode(pk(ROUTER_SIGNER)),
        "tip": { "records": tip.records.to_string(), "digest": hex::encode(tip.digest) },
        "balance": {
            "cap": b.cap.to_string(),
            "free": b.free.to_string(),
            "withdrawal_reserved": b.withdrawal_reserved.to_string(),
            "withdrawn": b.withdrawn.to_string(),
            "conserved": b.conserved(),
        },
        "invariants_ok": d.verify_withdrawal_invariants().unwrap(),
        "withdrawals": ws,
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map_or("", String::as_str);
    let wal = Path::new(args.get(2).expect("wal path"));
    let (reg, cfg, lanes, rcpts) = regtest_setup();

    match cmd {
        "create" => {
            let d = DurableTieredRouter::create(wal, &reg, cfg, lanes, rcpts).unwrap();
            println!("{}", serde_json::to_string(&state_json(&d)).unwrap());
        }
        "inspect" => {
            let d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            println!("{}", serde_json::to_string(&state_json(&d)).unwrap());
        }
        "reserve" | "reserve-crash" => {
            // args: <wal> <nonce> <amount_sats> <script_hex> <now_us> <expires_us>
            let nonce: u64 = args[3].parse().unwrap();
            let amount: u64 = args[4].parse().unwrap();
            let script = hex::decode(&args[5]).unwrap();
            let now: u64 = args[6].parse().unwrap();
            let expires: u64 = args[7].parse().unwrap();
            let mut d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            let req = WithdrawalRequest {
                network: network_id("regtest"),
                router_config: d.config_hash(),
                router: 1,
                channel: ch(1),
                owner: [0; 32],
                nonce,
                amount_sats: amount,
                destination_script: script,
                expires_us: expires,
                clearing_sequence: 0,
                batch_digest: [0; 32],
                clearing_digest: [0; 32],
                owner_sig: ZERO,
            }.signed(&sk(1)).unwrap();
            if cmd == "reserve-crash" {
                let wid = req.withdrawal_id();
                d.append_withdrawal_reserve_without_apply(req, now).unwrap();
                // Simulate hard process death right after WAL fsync without clean close/apply
                eprintln!("FSYNCED_BEFORE_CRASH:{}", hex::encode(wid));
                std::process::abort();
            }
            let wid = d.reserve_withdrawal(req, now).unwrap();
            let receipt = d.export_withdrawal_receipt(&wid, "regtest", &sk(ROUTER_SIGNER)).unwrap();
            println!("{}", serde_json::to_string(&serde_json::json!({
                "state": state_json(&d),
                "receipt": receipt,
            })).unwrap());
        }
        "export-receipt" => {
            let wid = parse_hex32(&args[3]);
            let d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            let receipt = d.export_withdrawal_receipt(&wid, "regtest", &sk(ROUTER_SIGNER)).unwrap();
            println!("{}", serde_json::to_string(&receipt).unwrap());
        }
        "submit" => {
            let wid = parse_hex32(&args[3]);
            let ph = parse_hex32(&args[4]);
            let now: u64 = args[5].parse().unwrap();
            let mut d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            d.submit_withdrawal(wid, ph, now).unwrap();
            println!("{}", serde_json::to_string(&state_json(&d)).unwrap());
        }
        "ambiguous" => {
            let wid = parse_hex32(&args[3]);
            let now: u64 = args[4].parse().unwrap();
            let mut d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            d.mark_withdrawal_ambiguous(wid, now).unwrap();
            println!("{}", serde_json::to_string(&state_json(&d)).unwrap());
        }
        "reconcile" | "reconcile-crash" => {
            let wid = parse_hex32(&args[3]);
            let btc_ev = parse_hex32(&args[4]);
            let settle_ev = parse_hex32(&args[5]);
            let now: u64 = args[6].parse().unwrap();
            let mut d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            let msg = d.withdrawal_reconcile_message(&wid, &btc_ev, &settle_ev).unwrap();
            let att = WithdrawalReconcileAttestation {
                withdrawal_id: wid,
                btc_evidence: btc_ev,
                settlement_evidence: settle_ev,
                signatures: [bip340_sign(&sk(71), &msg).unwrap(), bip340_sign(&sk(91), &msg).unwrap()],
            };
            d.reconcile_withdrawal(att, now).unwrap();
            if cmd == "reconcile-crash" {
                // Hard kill immediately after WAL fsync of final resolution (before returning reply)
                std::process::abort();
            }
            println!("{}", serde_json::to_string(&state_json(&d)).unwrap());
        }
        "freeze" => {
            let wid = parse_hex32(&args[3]);
            let conflict_ev = parse_hex32(&args[4]);
            let now: u64 = args[5].parse().unwrap();
            let mut d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            let msg = d.withdrawal_freeze_message(&wid, &conflict_ev).unwrap();
            let att = WithdrawalFreezeAttestation {
                withdrawal_id: wid,
                conflict_evidence: conflict_ev,
                monitor_sig: bip340_sign(&sk(91), &msg).unwrap(),
            };
            d.freeze_withdrawal(att, now).unwrap();
            println!("{}", serde_json::to_string(&state_json(&d)).unwrap());
        }
        "cancel" => {
            let wid = parse_hex32(&args[3]);
            let cancel_ev = parse_hex32(&args[4]);
            let now: u64 = args[5].parse().unwrap();
            let mut d = DurableTieredRouter::open(wal, &reg, cfg, lanes, rcpts, None).unwrap();
            let msg = d.withdrawal_cancel_message(&wid, &cancel_ev).unwrap();
            let att = WithdrawalCancelAttestation {
                withdrawal_id: wid,
                cancellation_evidence: cancel_ev,
                signatures: [bip340_sign(&sk(1), &msg).unwrap(), bip340_sign(&sk(71), &msg).unwrap(), bip340_sign(&sk(91), &msg).unwrap()],
            };
            d.cancel_withdrawal(att, now).unwrap();
            println!("{}", serde_json::to_string(&state_json(&d)).unwrap());
        }
        _ => panic!("unknown command: {cmd}"),
    }
}
