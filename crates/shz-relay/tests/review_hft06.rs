//! HFT-06 security review reproductions against 20a8edc. Each test asserts the safe
//! property, so it fails until the finding is fixed.

use shz_dlc::{bip340_sign, pubkey_x_from_secret};
use shz_oracle::hft_packets::{Certificate, Mark, Packet, Policy, Signer, Source};
use shz_relay::{
    authority::DurableSignLock,
    member::{MemberCore, Outcome},
    remote::RemoteFed,
    schedule::{MonoClock, ReleasePolicy, Tier},
};

fn packet(p: &Policy, seq: u64, previous: [u8; 32]) -> Packet {
    let t = p.fast_at(seq).unwrap();
    Packet {
        policy: p.id().unwrap(),
        seq,
        previous,
        mark: Mark::Valid {
            pyth: Source { report: [1; 32], published_us: t - 20_000, price_e8: 10_000_000_000_000 },
            chainlink: Source { report: [2; 32], published_us: t - 30_000, price_e8: 10_001_000_000_000 },
        },
    }
}

fn cert(p: &Policy, packet: Packet) -> Certificate {
    let mut ss: Vec<_> = (0..5).map(|i| Signer::new(p, i, [(i + 1); 32]).unwrap()).collect();
    let votes = ss.iter_mut().take(4).map(|s| s.vote(p, &packet).unwrap()).collect();
    Certificate { packet, votes }
}

fn member(dir: &std::path::Path) -> Result<MemberCore, String> {
    MemberCore::new(&policy(), 0, [1; 32], DurableSignLock::open(&dir.join("member0.lock")).unwrap())
}

/// F-12: after a restart the member must still refuse a proposal that chains to a
/// certificate older than the newest one it verified (a fork that skips packets).
#[test]
fn restarted_member_keeps_its_certified_parent_ratchet() {
    let p = policy();
    let dir = std::env::temp_dir().join(format!("shz-review-f12-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let c1 = cert(&p, packet(&p, 1, [0; 32]));
    let c2 = cert(&p, packet(&p, 2, c1.packet.digest()));
    {
        let mut m = member(&dir).unwrap();
        m.note_certified(&c1).unwrap();
        m.note_certified(&c2).unwrap();
        assert_eq!(m.parent(), Some((2, c2.packet.digest())));
    }
    // Restart: a coordinator proposes seq 3 as a child of c1, skipping c2.
    let mut m = member(&dir).unwrap();
    assert_eq!(m.parent(), Some((2, c2.packet.digest())), "ratchet reloaded from disk");
    let fork = packet(&p, 3, c1.packet.digest());
    m.push_packet(fork.clone());
    match m.on_proposal(3, &fork, Some(&c1)) {
        Outcome::Refused(r) => assert!(r.contains("stale"), "{r}"),
        o => panic!("restarted member certified a fork off an older parent: {o:?}"),
    }
    // Genesis cannot be reopened either.
    let g = packet(&p, 1, [0; 32]);
    m.push_packet(g.clone());
    assert!(matches!(m.on_proposal(1, &g, None), Outcome::Refused(_)));
    // The honest child of c2 is still accepted, and the ratchet moves on durably.
    let next = packet(&p, 3, c2.packet.digest());
    m.push_packet(next.clone());
    assert!(matches!(m.on_proposal(3, &next, Some(&c2)), Outcome::Voted { .. }));
    let c3 = cert(&p, next);
    m.note_certified(&c3).unwrap();
    drop(m);
    assert_eq!(member(&dir).unwrap().parent(), Some((3, c3.packet.digest())));
    // An edited or emptied ratchet stops start instead of resetting to "no parent".
    let path = dir.join("member0.parent");
    let rec = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, rec.replacen("3 ", "2 ", 1)).unwrap();
    assert!(member(&dir).is_err(), "edited ratchet accepted");
    std::fs::write(&path, b"").unwrap();
    assert!(member(&dir).is_err(), "emptied ratchet accepted");
    let _ = std::fs::remove_dir_all(&dir);
}

fn policy() -> Policy {
    Policy {
        network: [9; 32],
        market: [8; 32],
        epoch: 1,
        origin_us: 10_000_000,
        members: std::array::from_fn(|i| pubkey_x_from_secret(&[(i + 1) as u8; 32]).unwrap()),
    }
}

/// F-07: a certification deadline below the Standard delay passes `validate()` and then
/// the late-certificate branch hands the packet to Standard and Intermediate early.
#[test]
fn late_certificate_never_releases_a_tier_before_its_delay() {
    let p = ReleasePolicy { certification_deadline_us: 50_000, ..ReleasePolicy::default() };
    if p.validate().is_err() {
        return; // fixed by refusing the configuration
    }
    let t = 1_000_000;
    let standard = p.release_at(Tier::Standard, t, t + 60_000).0;
    let intermediate = p.release_at(Tier::Intermediate, t, t + 60_000).0;
    assert!(
        standard >= t + p.standard_delay_us + p.max_clock_uncertainty_us,
        "Standard received the packet {} us before its release time",
        t + p.standard_delay_us + p.max_clock_uncertainty_us - standard
    );
    assert!(intermediate >= t + p.intermediate_delay_us + p.max_clock_uncertainty_us);
}

/// F-07, default policy: a certificate 1 us past the deadline reaches Standard inside
/// the clock-uncertainty margin that every on-time release keeps.
#[test]
fn default_late_certificate_keeps_the_clock_uncertainty_margin() {
    let p = ReleasePolicy::default();
    let t = 1_000_000;
    let standard = p.release_at(Tier::Standard, t, t + p.certification_deadline_us + 1).0;
    assert!(standard >= t + p.standard_delay_us + p.max_clock_uncertainty_us);
}

/// F-06: one member vote with an attacker-chosen sequence must neither panic the relay
/// (overflow at `s + SEEN_WINDOW`, poisoning the federation mutex) nor erase the
/// equivocation window.
#[test]
fn member_vote_with_huge_sequence_keeps_equivocation_evidence() {
    let fed = RemoteFed::new(policy(), [7; 32], MonoClock::new(), None);
    let secret = [1u8; 32]; // member 0
    let (a, b, x) = ([0xa1; 32], [0xb2; 32], [0xc3; 32]);
    fed.on_vote(0, 1, a, bip340_sign(&secret, &a).unwrap());
    let flush = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fed.on_vote(0, u64::MAX - 5, x, bip340_sign(&secret, &x).unwrap());
        fed.on_vote(0, u64::MAX - 4, x, bip340_sign(&secret, &x).unwrap());
    }));
    assert!(flush.is_ok(), "a member vote with seq near u64::MAX panicked while holding the federation mutex");
    fed.on_vote(0, 1, b, bip340_sign(&secret, &b).unwrap());
    assert_eq!(fed.snapshot().metrics.equivocations, 1, "the equivocation on seq 1 was forgotten");
}
