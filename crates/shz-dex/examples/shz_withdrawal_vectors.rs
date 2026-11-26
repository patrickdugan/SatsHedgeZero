//! Deterministic cross-language golden vector generator for `SHZ/WITHDRAWAL-RECEIPT/V1`.
//! Prints JSON to stdout so `integrations/utexo-rgb/withdrawal-vectors.json` can be
//! verified identically by both Rust (`shz-dex`) and JavaScript (`integrations/utexo-rgb`).

use shz_dex::OrderSide;
use shz_dex::routing::durable::{AckBundle, ChannelAck, Disposition, FeeRecipients, Head, Lane};
use shz_dex::routing::tiered::*;
use shz_dex::routing::tiered_durable::*;
use shz_dex::routing::withdrawal::*;
use shz_dex::routing::*;
use shz_dlc::{Bip340Signature, BtcOutPoint, bip340_sign};
use std::fs;

type Key = [u8; 32];
const T0: u64 = 1_700_000_000_000_000;
const AUTH: Key = [77; 32];
const RELAY: u8 = 60;
const ROUTER_SIGNER: u8 = 120;
const CAP: u64 = 100_000_000;
const PRICE: u64 = 10_000_000_000_000;
const ZERO: Bip340Signature = Bip340Signature {
    r_x: [0; 32],
    s: [0; 32],
};

fn sk(n: u8) -> Key {
    [n; 32]
}
fn pk(n: u8) -> Key {
    public(&sk(n))
}
fn channel(n: u8) -> BtcOutPoint {
    BtcOutPoint {
        txid: [n; 32],
        vout: 0,
    }
}

fn build_vector(
    label: &str,
    network_name: &str,
    script: Vec<u8>,
    amount_sats: u64,
    nonce: u64,
    with_clearing: bool,
) -> serde_json::Value {
    let dir = std::env::temp_dir().join(format!(
        "shz-vec-{}-{}",
        label,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let wal = dir.join("router.wal");

    let p = Policy {
        network: network_id(network_name),
        epoch: 7,
        relay_keys: [pk(50), pk(51)],
    };
    let plans: Vec<Allocation> = (1..=2)
        .map(|n| {
            Allocation::signed(
                p.scope(),
                &sk(n),
                &AUTH,
                channel(n),
                CAP,
                vec![Share { router: 1, sats: CAP }],
            )
            .unwrap()
        })
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
    let lanes: Vec<Lane> = (1..=2u8)
        .map(|n| Lane {
            channel: channel(n),
            peer: pk(70 + n),
            monitor: pk(90 + n),
            initial: Head {
                revision: 0,
                commitment: 10,
                state: [110 + n; 32],
            },
        })
        .collect();
    let rcpts = FeeRecipients {
        oracle: pk(110),
        router: pk(111),
    };
    let mut d = DurableTieredRouter::create(&wal, &reg, cfg.clone(), lanes, rcpts).unwrap();

    let (clearing_sequence, batch_digest, clearing_digest, now) = if with_clearing {
        d.enable_margin_release().unwrap();
        d.enable_clearing(1_000_000).unwrap();
        d.ingest_mark(
            MarkView {
                packet_digest: [101; 32],
                seq: 1,
                price_e8: Some(PRICE),
                boundary_us: T0,
                public_release_us: T0,
            },
            T0,
        )
        .unwrap();
        let t_trade = T0 + 200_000;
        let mk = |n: u8, action: Action, side: OrderSide| {
            IntentV6 {
                scope: cfg.scope,
                router: 1,
                channel: channel(n),
                owner: [0; 32],
                sequence: 1,
                expires_us: t_trade + 5_000_000,
                action,
                side,
                tier: FeedTier::Standard,
                tariff_version: cfg.tariff.version,
                entitlement_digest: [0; 32],
                execution_policy: cfg.execution.id(),
                quantity: 1_000,
                limit_usd: 100_000,
                leverage_bps: 10_000,
                max_fee_ppm: 0,
                max_fee_sats: 0,
                max_mark_age_us: 1_000_000,
                early_window_opt_in: false,
                cancel_target: [0; 32],
                signature: ZERO_SIG,
            }
            .signed(&sk(n))
            .unwrap()
        };
        d.submit(mk(2, Action::Post, OrderSide::Short), None, t_trade)
            .unwrap();
        d.process_one(t_trade).unwrap();
        d.submit(mk(1, Action::Take, OrderSide::Long), None, t_trade)
            .unwrap();
        d.process_one(t_trade).unwrap();
        d.process_one(T0 + 500_000).unwrap();
        let b = d.seal_batch().unwrap().unwrap();
        let apps: Vec<BatchApproval> = b
            .accounts()
            .iter()
            .map(|a| {
                let n = a.channel.txid[0];
                BatchApproval {
                    channel: a.channel.clone(),
                    signature: bip340_sign(&sk(n), &b.approval_message(&a.channel).unwrap())
                        .unwrap(),
                }
            })
            .collect();
        d.prepare(b.sequence(), apps).unwrap();
        let mut chs = Vec::new();
        for a in b.accounts() {
            let n = a.channel.txid[0];
            let prev = d.head(&a.channel).unwrap().unwrap();
            let next = Head {
                revision: prev.revision + 1,
                commitment: prev.commitment + 1,
                state: [200 + n; 32],
            };
            let mut c = ChannelAck {
                channel: a.channel.clone(),
                previous: prev,
                next,
                evidence: [210 + n; 32],
                fee_evidence: [0; 32],
                signatures: [ZERO; 3],
            };
            let m = d.ack_message(b.sequence(), Disposition::Commit, &c).unwrap();
            c.signatures = [
                bip340_sign(&sk(n), &m).unwrap(),
                bip340_sign(&sk(70 + n), &m).unwrap(),
                bip340_sign(&sk(90 + n), &m).unwrap(),
            ];
            chs.push(c);
        }
        d.resolve(AckBundle {
            sequence: b.sequence(),
            batch: b.digest(),
            disposition: Disposition::Commit,
            channels: chs,
        })
        .unwrap();
        (
            b.sequence(),
            b.digest(),
            d.clearing(b.sequence()).unwrap().unwrap().digest(),
            T0 + 600_000,
        )
    } else {
        (0, [0; 32], [0; 32], T0 + 100_000)
    };

    let req = WithdrawalRequest {
        network: network_id(network_name),
        router_config: d.config_hash(),
        router: 1,
        channel: channel(1),
        owner: [0; 32],
        nonce,
        amount_sats,
        destination_script: script,
        expires_us: now + 600_000_000,
        clearing_sequence,
        batch_digest,
        clearing_digest,
        owner_sig: ZERO,
    }
    .signed(&sk(1))
    .unwrap();
    let preimage_hex = hex::encode(req.preimage());
    let wid = d.reserve_withdrawal(req, now).unwrap();
    let receipt = d
        .export_withdrawal_receipt(&wid, network_name, &sk(ROUTER_SIGNER))
        .unwrap();
    receipt.verify(&d.config_hash(), &pk(ROUTER_SIGNER)).unwrap();
    let canonical_json = receipt.to_canonical_json().unwrap();
    let router_config_hex = hex::encode(d.config_hash());
    let router_signer_hex = hex::encode(pk(ROUTER_SIGNER));
    drop(d);
    let _ = fs::remove_dir_all(&dir);

    serde_json::json!({
        "label": label,
        "network": network_name,
        "router_config": router_config_hex,
        "router_signer": router_signer_hex,
        "preimage_hex": preimage_hex,
        "canonical_json": canonical_json,
        "receipt": receipt,
    })
}

fn main() {
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&[0x31; 32]);
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(&[0x42; 20]);
    let mut p2wsh = vec![0x00, 0x20];
    p2wsh.extend_from_slice(&[0x53; 32]);

    let doc = serde_json::json!({
        "schema": "SHZ/WITHDRAWAL-VECTORS/V1",
        "vectors": [
            build_vector("regtest_p2tr_clearing_v3", "regtest", p2tr, 250_000, 1, true),
            build_vector("regtest_p2wpkh_unbound", "regtest", p2wpkh, 100_000, 1, false),
            build_vector("testnet4_p2wsh_cross_network", "testnet4", p2wsh, 50_000, 1, false),
        ]
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
