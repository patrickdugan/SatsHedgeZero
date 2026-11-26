//! HFT-06 security review reproductions against 20a8edc. Each test asserts the safe
//! property, so it fails until the finding is fixed.

use shz_dlc::{bip340_sign, pubkey_x_from_secret};
use shz_oracle::hft_packets::Policy;
use shz_relay::{
    remote::RemoteFed,
    schedule::{MonoClock, ReleasePolicy, Tier},
};

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
