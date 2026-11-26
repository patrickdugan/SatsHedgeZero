//! Seeds `<state>/router.wal` + `<state>/venue.seed` the way `Venue::open` builds them
//! (crates/shz-venue/src/core.rs), but enables multilateral clearing with a fund of 0 sats.
//! `Venue::open` then finds clearing already on (`enable_clearing` is idempotent), so the venue
//! binary runs unchanged with an empty clearing fund.
//!
//!   seed-fund0 <state-dir> <seed-hex-32>

use shz_dex::routing::{
    Policy, Registry, public,
    durable::FeeRecipients,
    tiered::{Arm, ExecutionPolicy, RevenuePolicy, TariffSchedule, TieredConfig},
    tiered_durable::DurableTieredRouter,
};
use shz_dlc::{pubkey_x_from_secret, tagged_hash};

fn derive(seed: &[u8; 32], label: &str) -> [u8; 32] {
    let mut ctr = 0u32;
    loop {
        let mut b = seed.to_vec();
        b.extend(label.as_bytes());
        b.extend(ctr.to_le_bytes());
        let k = tagged_hash(b"SHZ/VENUE/KEY/V1", &b);
        if pubkey_x_from_secret(&k).is_ok() {
            return k;
        }
        ctr += 1;
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let state = std::path::PathBuf::from(&a[1]);
    let seed: [u8; 32] = hex::decode(&a[2]).expect("hex").try_into().expect("32 bytes");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("venue.seed"), hex::encode(seed)).unwrap();
    let authority_sk = derive(&seed, "authority");
    let entitlement_sk = derive(&seed, "entitlement");
    let named = |l: &str| derive(&seed, l);
    let policy = Policy {
        network: tagged_hash(b"SHZ/VENUE/NETWORK/V1", b"testnet4"),
        epoch: 1,
        relay_keys: [public(&named("relay-a")), public(&named("relay-b"))],
    };
    let scope = policy.scope();
    let cfg = TieredConfig {
        scope,
        router: 1,
        entitlement_key: public(&entitlement_sk),
        tariff: TariffSchedule::default_candidate(),
        execution: ExecutionPolicy::defaults(Arm::FeedOnly),
        revenue: RevenuePolicy::default(),
    };
    let recipients = FeeRecipients { oracle: public(&named("rcpt-oracle")), router: public(&named("rcpt-router")) };
    let registry = Registry::new(scope, public(&authority_sk), vec![]).expect("registry");
    let mut r = DurableTieredRouter::create(&state.join("router.wal"), &registry, cfg, vec![], recipients).expect("create journal");
    assert!(r.enable_margin_release().expect("margin release"));
    assert!(r.enable_clearing(0).expect("clearing"));
    println!("seeded {} with clearing fund 0", state.display());
}
