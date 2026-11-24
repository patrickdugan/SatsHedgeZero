//! HFT-02A: event-time replay of the actual signed HFT-01 router.
use shz_dex::{routing::*, OrderSide};
use shz_dlc::{Bip340Signature, BtcOutPoint};
use std::collections::BTreeMap;
const NOW: u64 = 1_000_000;
const STEP: u64 = 50_000;
const END: u64 = 4_000_000;
const HORIZON: u64 = 500_000;
const CAP: u64 = 10_000_000_000;
const ZERO: Bip340Signature = Bip340Signature { r_x: [0; 32], s: [0; 32] };
fn sk(n: u8) -> [u8; 32] { [n; 32] }
fn channel(n: u8) -> BtcOutPoint { BtcOutPoint { txid: [n; 32], vout: 0 } }
fn hash(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}
fn ticket(seed: u64, id: u64, tag: u64) -> u64 {
    hash(seed ^ id.wrapping_mul(0x9e3779b97f4a7c15) ^ tag.wrapping_mul(0xd6e8feb86659fd93))
}
fn prices(seed: u64, regime: &str) -> Vec<u64> {
    let mut p = 100_000i64;
    let mut out = vec![p as u64];
    let amp = if regime == "quiet" { 6 } else { 55 };
    for i in 1..=(END + 2 * HORIZON) / STEP {
        p += (ticket(seed, i, 1) % (2 * amp + 1)) as i64 - amp as i64;
        if regime == "shock" && i % 20 == 10 {
            p += if ticket(seed, i, 2) % 2 == 0 { 450 } else { -450 };
        }
        p = p.clamp(98_000, 102_000);
        out.push(p as u64);
    }
    out
}
fn mark(path: &[u64], t: u64) -> u64 { path[(t / STEP) as usize] }
#[derive(Clone)]
struct Input {
    id: u64, action: Action, owner: u8, side: OrderSide, quantity: u64,
    limit: u64, route_ticket: u64, tier_ticket: u64,
}
fn kind(a: Action) -> &'static str {
    match a { Action::Post => "post", Action::Take => "take", Action::Cancel => "cancel" }
}
fn side(s: OrderSide) -> &'static str {
    match s { OrderSide::Long => "buy", OrderSide::Short => "sell" }
}
fn tier_name(t: Tier) -> &'static str { if t == Tier::Priority { "priority" } else { "free" } }
struct Pending { input: Input, arrival: u64, tier: Tier, key: [u8; 32] }

fn main() {
    let a: Vec<_> = std::env::args().collect();
    assert!((5..=6).contains(&a.len()), "usage: hft_event_replay SEED quiet|shock SHARDS ADOPTION [scan|indexed|joint|both]");
    let engine = match a.get(5).map(String::as_str).unwrap_or("scan") {
        "scan" => Engine::Scan, "indexed" => Engine::Indexed,
        "joint" => Engine::Joint, "both" => Engine::Both,
        _ => panic!("unknown engine"),
    };
    let seed: u64 = a[1].parse().unwrap();
    let regime = &a[2];
    assert!(regime == "quiet" || regime == "shock");
    let shards: u32 = a[3].parse().unwrap();
    let adoption: u64 = a[4].parse().unwrap();
    assert!(matches!(shards, 1 | 4) && matches!(adoption, 0 | 20 | 100));
    let path = prices(seed, regime);
    let policy = Policy { network: [99; 32], epoch: 2, relay_keys: [public(&sk(241)), public(&sk(242))] };
    let scope = policy.scope();
    let plans = (1..=32u8).map(|i| Allocation::signed(scope, &sk(i), &sk(240), channel(i), CAP,
        (1..=shards).map(|router| Share { router, sats: CAP / u64::from(shards) }).collect()).unwrap()).collect();
    let registry = Registry::new(scope, public(&sk(240)), plans).unwrap();
    let mut routers: Vec<_> = (1..=shards).map(|r| Router::new_with_engine(policy.clone(), &registry, r, engine).unwrap()).collect();
    let mut pending: Vec<BTreeMap<(u64, u64), Pending>> = (0..shards).map(|_| BTreeMap::new()).collect();
    let mut events: BTreeMap<u64, Vec<Input>> = BTreeMap::new();
    for i in 0..=(END + HORIZON) / STEP { events.entry(i * STEP).or_default(); }
    for n in 0..END / 40_000 {
        let t = n * 40_000;
        for j in 0..2u64 {
            let id = 2 * n + j + 1;
            let s = if j == 0 { OrderSide::Long } else { OrderSide::Short };
            let p = mark(&path, t);
            let input = Input {
                id, action: Action::Post, owner: 1 + (ticket(seed, id, 3) % 16) as u8,
                side: s, quantity: 300, limit: if j == 0 { p - 15 } else { p + 15 },
                route_ticket: ticket(seed, id, 4), tier_ticket: ticket(seed, id, 5),
            };
            let mut cancel = input.clone();
            cancel.action = Action::Cancel; cancel.quantity = 0; cancel.limit = 0;
            events.entry(t).or_default().push(input);
            events.entry(t + 300_000).or_default().push(cancel);
        }
    }
    let mut takes = 0u64;
    for t in (150_000..END).step_by(23_000) {
        takes += 1;
        let id = 1_000_000 + takes;
        let buy = ticket(seed, id, 6) % 2 == 0;
        let p = mark(&path, t);
        events.entry(t).or_default().push(Input {
            id, action: Action::Take, owner: 17 + (ticket(seed, id, 3) % 16) as u8,
            side: if buy { OrderSide::Long } else { OrderSide::Short },
            quantity: 100, limit: if buy { p + 250 } else { p - 250 },
            route_ticket: ticket(seed, id, 4), tier_ticket: ticket(seed, id, 5),
        });
    }
    let mut post_ids = BTreeMap::new();
    let mut seq = 0u64;
    let mut seen_takes = 0u64;
    let mut filled = 0usize;
    let mut fees = 0u128;
    let mut allocated = 0u128;
    println!("seed,regime,shards,adoption,kind,id,side,tier,router,arrival_us,execution_us,arrival_mark,execution_mark,future_mark,quantity,limit,fill_price,filled_qty,maker_fee_sats,taker_fee_sats,oracle_due_sats,router_due_sats,outcome,intent_id,maker_id,mark_id,long_margin_sats,short_margin_sats");
    while let Some((t, inputs)) = events.pop_first() {
        // Tie rule: mark first, then arrivals, then eligible FIFO.
        if t % STEP == 0 && t <= END + HORIZON {
            let tick_sequence = t / STEP + 1;
            let ticks = std::array::from_fn(|j| RelayTick {
                scope, source: j as u8 + 1, sequence: tick_sequence, publish_us: NOW + t,
                price_e8: mark(&path, t) * 100_000_000,
                report_hash: [j as u8 + 1; 32], signature: ZERO,
            }.signed(&sk(241 + j as u8)).unwrap());
            for r in &mut routers { r.update_mark(ticks.clone(), NOW + t).unwrap(); }
        }
        for input in inputs {
            seq += 1;
            let router = (input.route_ticket % u64::from(shards)) as u32 + 1;
            let ix = router as usize - 1;
            let tier = if input.tier_ticket % 100 < adoption { Tier::Priority } else { Tier::Free };
            let cancel_target = if input.action == Action::Cancel { post_ids[&input.id] } else { [0; 32] };
            let is_cancel = input.action == Action::Cancel;
            let intent = Intent {
                scope, router, channel: channel(input.owner), owner: [0; 32], sequence: seq,
                expires_us: NOW + t + 900_000, action: input.action, side: input.side, tier,
                quantity: input.quantity, limit_usd: input.limit, leverage_bps: if is_cancel { 0 } else { 100_000 },
                max_fee_ppm: rate_ppm(tier, input.action), max_fee_sats: if is_cancel { 0 } else { 100_000 },
                cancel_target, signature: ZERO,
            }.signed(&sk(input.owner)).unwrap();
            let key = intent.id();
            if input.action == Action::Post { assert!(post_ids.insert(input.id, key).is_none()); }
            let due = routers[ix].submit(intent, NOW + t).unwrap() - NOW;
            assert_eq!(due - t, delay_us(tier, input.action));
            assert!(pending[ix].insert((due, seq), Pending { input, arrival: t, tier, key }).is_none());
            if due > t { events.entry(due).or_default(); }
        }
        for (ix, r) in routers.iter_mut().enumerate() {
            while pending[ix].first_key_value().is_some_and(|(k, _)| k.0 <= t) {
                let ((due, _), p) = pending[ix].pop_first().unwrap();
                assert_eq!(t, due);
                let out = r.process_one(NOW + t).unwrap().expect("eligible event");
                let (mut px, mut q, mut mf, mut tf, mut oracle, mut router_fee) = (0, 0, 0, 0, 0, 0);
                let (mut maker_id, mut mark_id) = (String::new(), String::new());
                let (mut long_margin, mut short_margin) = (0, 0);
                let outcome = match out {
                    Outcome::Posted(id) => { assert_eq!(p.input.action, Action::Post); assert_eq!(id, p.key); "posted".to_string() },
                    Outcome::Cancelled(id) => { assert_eq!(p.input.action, Action::Cancel); assert_eq!(id, post_ids[&p.input.id]); "cancelled".to_string() },
                    Outcome::Filled(f) => {
                        assert_eq!(p.input.action, Action::Take); assert_eq!(f.taker_id, p.key);
                        assert_eq!(f.execution_us, NOW + t); assert_eq!(f.spec.fee_policy, shz_margin::ZeroFeePolicy::ZERO);
                        assert_eq!(f.router, (ix + 1) as u32);
                        assert_eq!(f.scope, scope);
                        let retained = r.pending_fill(&f.taker_id).expect("pending receipt");
                        assert_eq!(format!("{retained:?}"), format!("{f:?}"));
                        maker_id = hex::encode(f.maker_id); mark_id = hex::encode(f.mark_id);
                        long_margin = f.spec.long_margin_sats; short_margin = f.spec.short_margin_sats;
                        px = f.spec.entry_price_usd; q = f.spec.usd_notional;
                        mf = f.maker_fee_sats; tf = f.taker_fee_sats; oracle = f.oracle_due_sats; router_fee = f.router_due_sats;
                        assert_eq!(q, p.input.quantity); assert_eq!(mf + tf, oracle + router_fee);
                        filled += 1; fees += u128::from(mf + tf); allocated += u128::from(oracle + router_fee);
                        "filled".to_string()
                    }
                    Outcome::Rejected(e) => format!("{e:?}"),
                };
                if p.input.action == Action::Take { seen_takes += 1; }
                println!("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    seed, regime, shards, adoption, kind(p.input.action), p.input.id, side(p.input.side),
                    tier_name(p.tier), ix + 1, p.arrival, t, mark(&path, p.arrival), mark(&path, t),
                    mark(&path, t + HORIZON), p.input.quantity, p.input.limit, px, q, mf, tf, oracle, router_fee, outcome,
                    hex::encode(p.key), maker_id, mark_id, long_margin, short_margin);
            }
            assert!(r.process_one(NOW + t).unwrap().is_none());
        }
    }
    assert!(pending.iter().all(BTreeMap::is_empty));
    assert_eq!(seen_takes, takes);
    assert_eq!(fees, allocated);
    assert_eq!(routers.iter().map(Router::pending_fills).sum::<usize>(), filled);
    for (ix, r) in routers.iter().enumerate() {
        assert_eq!(r.pending_orders(), 0);
        assert_eq!(r.resting(), 0);
        eprintln!("router={},pending_fills={},resting={}", ix+1, r.pending_fills(), r.resting());
        for i in 1..=32u8 {
            let b = r.balance(&channel(i)).unwrap();
            assert!(b.conserved());
            eprintln!("router={},channel={},cap={},free={},resting={},pending={}", ix+1, i, b.cap, b.free, b.resting, b.pending);
        }
    }
}
