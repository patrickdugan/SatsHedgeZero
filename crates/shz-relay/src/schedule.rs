//! Tiered release schedule over ONE canonical certified packet.
//!
//! For slot boundary `T`, certification completion time `C` and bounded
//! clock uncertainty `e`:
//! * Premium:      `C` (immediate certified release);
//! * Intermediate: `max(C, T + d_i + e)`, candidate `d_i = 100 ms`, configurable;
//! * Standard:     `max(C, T + 200 ms + e)`.
//!
//! Lower tiers are never released before their offset (the `+e` term makes
//! "not before" hold under the clock bound). A late certificate shrinks the
//! realized premium lead; it never pushes the public deadline past
//! `T + max(certification_deadline, 200 ms + e)`. A certificate later than
//! `T + certification_deadline` is released to every tier at the same
//! instant `C` and flagged late: no tier gains any lead from it, and it keeps
//! the hash chain continuous so receivers need no resynchronization. Each tier is
//! scheduled independently, so a failed premium transport cannot delay
//! intermediate or standard delivery.

use serde::{Deserialize, Serialize};
use std::time::Instant;

pub const STANDARD_DELAY_US: u64 = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Premium,
    Intermediate,
    Standard,
}
impl Tier {
    pub const ALL: [Tier; 3] = [Tier::Premium, Tier::Intermediate, Tier::Standard];
    pub fn idx(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            Tier::Premium => "premium",
            Tier::Intermediate => "intermediate",
            Tier::Standard => "standard",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePolicy {
    pub intermediate_delay_us: u64,
    pub standard_delay_us: u64,
    pub max_clock_uncertainty_us: u64,
    pub certification_deadline_us: u64,
}

impl Default for ReleasePolicy {
    fn default() -> Self {
        Self {
            intermediate_delay_us: 100_000,
            standard_delay_us: STANDARD_DELAY_US,
            max_clock_uncertainty_us: 2_000,
            certification_deadline_us: 200_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    Invalid(&'static str),
}

impl ReleasePolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.standard_delay_us != STANDARD_DELAY_US {
            return Err(PolicyError::Invalid("standard delay is fixed at 200 ms"));
        }
        if self.intermediate_delay_us == 0 || self.intermediate_delay_us >= self.standard_delay_us {
            return Err(PolicyError::Invalid("intermediate delay must lie strictly between premium and standard"));
        }
        if self.max_clock_uncertainty_us > shz_oracle::hft_packets::MAX_CLOCK_ERROR_US {
            return Err(PolicyError::Invalid("clock uncertainty above HFT-04 bound"));
        }
        if self.certification_deadline_us == 0 || self.certification_deadline_us > shz_oracle::hft_packets::CADENCE_US {
            return Err(PolicyError::Invalid("certification deadline must be within one cadence"));
        }
        Ok(())
    }
    pub fn offset_us(&self, t: Tier) -> u64 {
        match t {
            Tier::Premium => 0,
            Tier::Intermediate => self.intermediate_delay_us,
            Tier::Standard => self.standard_delay_us,
        }
    }
    /// Release instant for `t`; `.1 == true` marks a late certificate that
    /// is released simultaneously to all tiers (no differentiated lead).
    pub fn release_at(&self, t: Tier, boundary_us: u64, certified_us: u64) -> (u64, bool) {
        if certified_us > boundary_us.saturating_add(self.certification_deadline_us) {
            // Simultaneous for all tiers, but never ahead of the Standard release time,
            // whatever the configured deadline is.
            let public = boundary_us.saturating_add(self.standard_delay_us).saturating_add(self.max_clock_uncertainty_us);
            return (certified_us.max(public), true);
        }
        (
            match t {
                Tier::Premium => certified_us.max(boundary_us),
                _ => certified_us.max(boundary_us + self.offset_us(t) + self.max_clock_uncertainty_us),
            },
            false,
        )
    }
    /// Upper bound on the public (standard) release relative to the boundary.
    pub fn public_deadline_bound_us(&self) -> u64 {
        self.certification_deadline_us.max(self.standard_delay_us + self.max_clock_uncertainty_us)
    }
}

/// Monotonic microsecond clock anchored once to Unix time. Wall-clock jumps
/// after the anchor do not move it; it never goes backwards.
#[derive(Debug, Clone, Copy)]
pub struct MonoClock {
    anchor: Instant,
    anchor_unix_us: u64,
}

impl MonoClock {
    pub fn new() -> Self {
        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock after 1970");
        Self { anchor: Instant::now(), anchor_unix_us: unix.as_micros() as u64 }
    }
    pub fn at(anchor_unix_us: u64) -> Self {
        Self { anchor: Instant::now(), anchor_unix_us }
    }
    pub fn now_us(&self) -> u64 {
        self.anchor_unix_us + self.anchor.elapsed().as_micros() as u64
    }
    /// Current difference between wall clock and this monotonic clock (for
    /// alarms when NTP or an operator steps the system clock).
    pub fn wall_offset_us(&self) -> i64 {
        let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as i64).unwrap_or(0);
        wall - self.now_us() as i64
    }
}

impl Default for MonoClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_ordered_and_bounded() {
        let p = ReleasePolicy::default();
        p.validate().unwrap();
        let t = 1_000_000;
        let r = |tier, c| p.release_at(tier, t, t + c);
        assert_eq!(r(Tier::Premium, 3_000), (t + 3_000, false));
        assert_eq!(r(Tier::Intermediate, 3_000), (t + 102_000, false));
        assert_eq!(r(Tier::Standard, 3_000), (t + 202_000, false));
        // Late certificate shrinks lead, does not extend the public deadline.
        assert_eq!(r(Tier::Premium, 150_000), (t + 150_000, false));
        assert_eq!(r(Tier::Intermediate, 150_000), (t + 150_000, false));
        assert_eq!(r(Tier::Standard, 150_000), (t + 202_000, false));
        // Missed deadline: simultaneous release, no tier lead.
        for tier in Tier::ALL {
            assert_eq!(r(tier, 200_001), (t + 202_000, true));
            assert_eq!(r(tier, 250_000), (t + 250_000, true));
        }
        for c in (0..=200_000).step_by(1_000) {
            let s = r(Tier::Standard, c).0;
            assert!(s - t <= p.public_deadline_bound_us());
            assert!(s >= r(Tier::Intermediate, c).0);
            assert!(r(Tier::Intermediate, c).0 >= r(Tier::Premium, c).0);
        }
    }

    #[test]
    fn policy_validation() {
        let d = ReleasePolicy::default;
        assert!(ReleasePolicy { intermediate_delay_us: 200_000, ..d() }.validate().is_err());
        assert!(ReleasePolicy { max_clock_uncertainty_us: 10_000, ..d() }.validate().is_err());
        assert!(ReleasePolicy { standard_delay_us: 150_000, ..d() }.validate().is_err());
        assert!(ReleasePolicy { intermediate_delay_us: 50_000, ..d() }.validate().is_ok());
    }

    #[test]
    fn mono_clock_never_regresses() {
        let c = MonoClock::at(1_000);
        let mut last = 0;
        for _ in 0..1000 {
            let n = c.now_us();
            assert!(n >= last);
            last = n;
        }
    }
}
