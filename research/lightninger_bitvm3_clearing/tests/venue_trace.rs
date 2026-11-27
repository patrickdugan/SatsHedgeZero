//! Live-venue traces (`trace::from_venue`): every batch satisfies the clearing step with the
//! venue's exact post-state, whatever order the accounts first appear in.
use lightninger_bitvm3_clearing::{
    clearing_step::{chain_next, check_step, steps_of},
    trace,
};

fn check(path: &str, a: usize, r: usize) -> usize {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    let Ok(txt) = std::fs::read_to_string(&p) else {
        eprintln!("{path}: not present, skipped");
        return 0;
    };
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let t = trace::from_venue(&v, a).unwrap();
    assert!(t.batches[0].pre.keys.windows(2).all(|w| w[0] < w[1]), "table not ascending");
    let (steps, _, _) = steps_of(a, r, &t.batches);
    for (s, b) in steps.iter().zip(&t.batches) {
        let (ok, which, out, _) = check_step(s, &s.pre.to_z());
        assert!(ok, "{path} seq {}: unsatisfied at {which:?}", b.seq);
        let mut post = b.post.clone();
        post.chain = chain_next(&s.pre.chain, b.seq, &b.digest);
        assert_eq!(out, post.to_z(), "{path} seq {}: output", b.seq);
    }
    eprintln!("{path}: {} batches ok", t.batches.len());
    t.batches.len()
}

#[test]
fn venue_batches_satisfy_the_step() {
    let n = check("artifacts/testnet4_demo/venue_fill.json", 4, 2) + check("../lightninger_dlc_batcher/artifacts/venue_batches.json", 8, 2);
    assert!(n > 0);
}
