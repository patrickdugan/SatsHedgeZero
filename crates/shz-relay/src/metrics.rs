//! Bounded-memory latency histograms and relay counters (Prometheus text).

use serde::Serialize;

/// Log-bucketed histogram over microseconds (8 buckets per power of two,
/// <= 9.1% relative bucket width) plus exact min/max/count/sum.
#[derive(Debug, Clone)]
pub struct LogHistogram {
    buckets: Vec<u64>,
    pub count: u64,
    pub sum: u128,
    pub min: u64,
    pub max: u64,
}

const SUB: u32 = 8;
const BUCKETS: usize = 64 * SUB as usize;

fn bucket(v: u64) -> usize {
    if v < SUB as u64 {
        return v as usize;
    }
    let e = 63 - v.leading_zeros();
    let frac = ((v >> (e - 3)) & (SUB as u64 - 1)) as u32;
    (e * SUB + frac) as usize
}
fn bucket_upper(i: usize) -> u64 {
    if i < SUB as usize {
        return i as u64;
    }
    let e = (i as u32 / SUB).max(3);
    let frac = i as u128 % SUB as u128;
    u64::try_from(((SUB as u128 + frac + 1) << (e - 3)) - 1).unwrap_or(u64::MAX)
}

impl Default for LogHistogram {
    fn default() -> Self {
        Self { buckets: vec![0; BUCKETS], count: 0, sum: 0, min: u64::MAX, max: 0 }
    }
}

impl LogHistogram {
    pub fn record(&mut self, v: u64) {
        self.buckets[bucket(v)] += 1;
        self.count += 1;
        self.sum += v as u128;
        self.min = self.min.min(v);
        self.max = self.max.max(v);
    }
    /// Upper edge of the bucket containing the q-quantile (nearest rank).
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let rank = ((q * self.count as f64).ceil() as u64).clamp(1, self.count);
        let mut seen = 0;
        for (i, c) in self.buckets.iter().enumerate() {
            seen += c;
            if seen >= rank {
                return Some(bucket_upper(i).min(self.max).max(self.min));
            }
        }
        Some(self.max)
    }
    pub fn summary(&self) -> Summary {
        Summary {
            count: self.count,
            p50_us: self.quantile(0.50),
            p95_us: self.quantile(0.95),
            p99_us: self.quantile(0.99),
            max_us: (self.count > 0).then_some(self.max),
            mean_us: (self.count > 0).then(|| (self.sum / self.count as u128) as u64),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub count: u64,
    pub p50_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub p99_us: Option<u64>,
    pub max_us: Option<u64>,
    pub mean_us: Option<u64>,
}

/// Exact quantiles over a bounded sample (benchmarks).
pub fn exact_summary(samples: &mut [u64]) -> Summary {
    samples.sort_unstable();
    let n = samples.len();
    let q = |p: f64| (n > 0).then(|| samples[((p * n as f64).ceil() as usize).clamp(1, n) - 1]);
    Summary {
        count: n as u64,
        p50_us: q(0.50),
        p95_us: q(0.95),
        p99_us: q(0.99),
        max_us: samples.last().copied(),
        mean_us: (n > 0).then(|| (samples.iter().map(|&x| x as u128).sum::<u128>() / n as u128) as u64),
    }
}

#[derive(Debug, Clone, Default)]
pub struct RelayMetrics {
    pub published: u64,
    pub duplicates: u64,
    pub equivocations: u64,
    pub gaps: u64,
    pub rejected: u64,
    pub late_certificates: u64,
    pub hold_packets: u64,
    /// Sequence numbers jumped by linked federated certificates (slots that never reached quorum).
    pub skipped_slots: u64,
    pub deliveries: [u64; 3],
    pub lagging_disconnects: u64,
    pub auth_failures: u64,
    pub active_subscribers: [u64; 3],
    /// Server send time minus slot boundary, per tier.
    pub send_after_boundary: [LogHistogram; 3],
    /// Server send time minus scheduled release, per tier (scheduler slip).
    pub send_after_release: [LogHistogram; 3],
    /// Certification completion minus boundary.
    pub certify_after_boundary: LogHistogram,
    pub bytes_out: u64,
}

impl RelayMetrics {
    pub fn prometheus(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let tiers = ["premium", "intermediate", "standard"];
        for (k, v) in [
            ("published", self.published),
            ("duplicates", self.duplicates),
            ("equivocations", self.equivocations),
            ("gaps", self.gaps),
            ("rejected", self.rejected),
            ("late_certificates", self.late_certificates),
            ("hold_packets", self.hold_packets),
            ("skipped_slots", self.skipped_slots),
            ("lagging_disconnects", self.lagging_disconnects),
            ("auth_failures", self.auth_failures),
            ("bytes_out", self.bytes_out),
        ] {
            let _ = writeln!(s, "shz_relay_{k}_total {v}");
        }
        for (i, t) in tiers.iter().enumerate() {
            let _ = writeln!(s, "shz_relay_deliveries_total{{tier=\"{t}\"}} {}", self.deliveries[i]);
            let _ = writeln!(s, "shz_relay_subscribers{{tier=\"{t}\"}} {}", self.active_subscribers[i]);
            for (name, h) in [("send_after_boundary_us", &self.send_after_boundary[i]), ("send_after_release_us", &self.send_after_release[i])] {
                for (q, label) in [(0.5, "0.5"), (0.95, "0.95"), (0.99, "0.99")] {
                    if let Some(v) = h.quantile(q) {
                        let _ = writeln!(s, "shz_relay_{name}{{tier=\"{t}\",quantile=\"{label}\"}} {v}");
                    }
                }
            }
        }
        if let Some(v) = self.certify_after_boundary.quantile(0.99) {
            let _ = writeln!(s, "shz_relay_certify_after_boundary_us{{quantile=\"0.99\"}} {v}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_quantiles_within_bucket_error() {
        let mut h = LogHistogram::default();
        let mut v: Vec<u64> = (1..=10_000).collect();
        for &x in &v {
            h.record(x);
        }
        let exact = exact_summary(&mut v);
        for (a, b) in [(h.quantile(0.5).unwrap(), exact.p50_us.unwrap()), (h.quantile(0.99).unwrap(), exact.p99_us.unwrap())] {
            assert!(a >= b && (a - b) as f64 <= 0.1 * b as f64, "{a} {b}");
        }
        for i in 24..BUCKETS - 8 {
            assert_eq!(bucket(bucket_upper(i)), i);
        }
    }
}
