//! The member's own reading of the public fast sources (`frost_signer.SourceView`), applying
//! the relay's freshness and dispersion rules (`public_relay.assemble`, fast sources only).

use std::sync::Mutex;
use std::time::Duration;

use crate::json::{self, J, PyErr, R, py_int};

pub const FAST_MAX_AGE_US: i128 = 30_000_000;
pub const MIN_FAST_SOURCES: usize = 3;
pub const MAX_DISPERSION_BPS: i128 = 50;

pub fn now_us() -> i128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as i128).unwrap_or(0)
}

/// A reading: `{"at_us", "status", "fast_sources_used", "median_e8"}`.
#[derive(Clone, Debug, PartialEq)]
pub struct Reading {
    pub at_us: i128,
    pub status: &'static str,
    pub fast_sources_used: usize,
    pub median_e8: Option<i128>,
}

/// Parsed source: (price_e8, source timestamp or None for "use fetch time").
pub type Parsed = (i128, Option<i128>);

/// `public_relay.e8`: `int(Decimal(str(x)) * 100_000_000)`.
pub fn e8(x: &J) -> R<i128> {
    let s = match x {
        J::Str(s) => s.clone(),
        J::Int(i) => i.to_string(),
        J::Float(f) => json::py_float_repr(*f),
        other => return Err(PyErr::type_(format!("conversion from {} to Decimal is not supported", other.type_name()))),
    };
    decimal_e8(&s)
}

fn decimal_e8(s: &str) -> R<i128> {
    let bad = || PyErr::new("InvalidOperation", format!("[<class 'decimal.ConversionSyntax'>] {s}"));
    let t = s.trim();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let (mant, exp) = match t.find(['e', 'E']) {
        Some(p) => (&t[..p], t[p + 1..].parse::<i64>().map_err(|_| bad())?),
        None => (t, 0),
    };
    let (ip, fp) = mant.split_once('.').unwrap_or((mant, ""));
    let ip = ip.replace('_', "");
    let fp = fp.replace('_', "");
    if (ip.is_empty() && fp.is_empty()) || !ip.chars().chain(fp.chars()).all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    let digits = format!("{ip}{fp}");
    // value = digits * 10^(exp - len(fp)); scaled by 1e8 and truncated toward zero.
    let shift = exp + 8 - fp.len() as i64;
    let digits = digits.trim_start_matches('0');
    let v: i128 = if digits.is_empty() {
        0
    } else if shift >= 0 {
        if digits.len() as i64 + shift > 36 {
            return Err(PyErr::new("OverflowError", "price out of range"));
        }
        digits.parse::<i128>().map_err(|_| bad())? * 10i128.pow(shift as u32)
    } else {
        let keep = digits.len() as i64 + shift;
        if keep <= 0 {
            0
        } else {
            let k = &digits[..keep as usize];
            if k.len() > 36 {
                return Err(PyErr::new("OverflowError", "price out of range"));
            }
            k.parse::<i128>().map_err(|_| bad())?
        }
    };
    Ok(if neg { -v } else { v })
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `int(datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp() * 1_000_000)`.
pub fn iso_to_us(t: &str) -> R<i128> {
    let bad = || PyErr::value(format!("Invalid isoformat string: {}", json::py_repr_str(t)));
    let t = t.replace('Z', "+00:00");
    let b = t.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
        return Err(bad());
    }
    let num = |a: usize, z: usize| t.get(a..z).and_then(|s| s.parse::<i64>().ok()).ok_or_else(bad);
    let (y, mo, d, h, mi, s) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let mut p = 19;
    let mut micro: i64 = 0;
    if b.get(p) == Some(&b'.') {
        let start = p + 1;
        p = start;
        while p < b.len() && b[p].is_ascii_digit() {
            p += 1;
        }
        let frac = &t[start..p];
        if frac.is_empty() {
            return Err(bad());
        }
        let f6: String = frac.chars().chain(std::iter::repeat('0')).take(6).collect();
        micro = f6.parse().map_err(|_| bad())?;
    }
    let mut offset_s: i64 = 0;
    if p < b.len() {
        let sign = match b[p] {
            b'+' => 1,
            b'-' => -1,
            _ => return Err(bad()),
        };
        let oh = num(p + 1, p + 3)?;
        let om = num(p + 4, p + 6)?;
        offset_s = sign * (oh * 3600 + om * 60);
    }
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - offset_s;
    let total_us = secs as i128 * 1_000_000 + micro as i128;
    let ts = total_us as f64 / 1e6;
    Ok((ts * 1e6) as i128)
}

pub fn src_coinbase(raw: &[u8]) -> R<Parsed> {
    let j = json::loads_bytes(raw)?;
    let ts = iso_to_us(j.at("time")?.str_or("time")?)?;
    Ok((e8(j.at("price")?)?, Some(ts)))
}

pub fn src_kraken(raw: &[u8]) -> R<Parsed> {
    let j = json::loads_bytes(raw)?;
    if let Some(e) = j.get("error")?
        && e.truthy()
    {
        return Err(PyErr::value(json::dumps(e, json::Style::Default)));
    }
    let res = j.at("result")?.items()?;
    if res.len() != 1 {
        return Err(PyErr::value("not enough values to unpack"));
    }
    Ok((e8(res[0].1.at("c")?.idx(0)?)?, None))
}

pub fn src_bitstamp(raw: &[u8]) -> R<Parsed> {
    let j = json::loads_bytes(raw)?;
    Ok((e8(j.at("last")?)?, Some(py_int(j.at("timestamp")?)? * 1_000_000)))
}

pub fn src_gemini(raw: &[u8]) -> R<Parsed> {
    let j = json::loads_bytes(raw)?;
    Ok((e8(j.at("last")?)?, None))
}

type Parser = fn(&[u8]) -> R<Parsed>;

pub const FAST_SOURCES: [(&str, &str, Parser); 4] = [
    ("coinbase", "https://api.exchange.coinbase.com/products/BTC-USD/ticker", src_coinbase),
    ("kraken", "https://api.kraken.com/0/public/Ticker?pair=XBTUSD", src_kraken),
    ("bitstamp", "https://www.bitstamp.net/api/v2/ticker/btcusd/", src_bitstamp),
    ("gemini", "https://api.gemini.com/v1/pubticker/btcusd", src_gemini),
];

/// One fetch result: fetch completion time and the parse outcome (`None` = fetch/parse error).
pub type FetchResult = (i128, Option<Parsed>);

/// `assemble(...)` restricted to what a reading needs.
pub fn reading_from(results: &[FetchResult], slot_us: i128) -> Reading {
    let mut fast: Vec<i128> = Vec::new();
    for (fetched, res) in results {
        let Some((price, ts)) = res else { continue };
        let src_ts = ts.unwrap_or(*fetched);
        let age = (slot_us - src_ts).max(0);
        let fresh = 0 < *price && *price < 10i128.pow(16) && age <= FAST_MAX_AGE_US && src_ts <= fetched + 5_000_000;
        if fresh {
            fast.push(*price);
        }
    }
    let n = fast.len();
    let hold = Reading { at_us: slot_us, status: "HOLD", fast_sources_used: n, median_e8: None };
    if n < MIN_FAST_SOURCES {
        return hold;
    }
    fast.sort();
    // int(statistics.median(fast)): the mean of the middle pair is a float division.
    let med = if n % 2 == 1 { fast[n / 2] } else { ((fast[n / 2 - 1] + fast[n / 2]) as f64 / 2.0) as i128 };
    if med == 0 {
        return hold;
    }
    let disp = (fast[n - 1] - fast[0]) * 10_000 / med;
    if disp > MAX_DISPERSION_BPS {
        return hold;
    }
    Reading { at_us: slot_us, status: "VALID", fast_sources_used: n, median_e8: Some(med) }
}

pub struct SourceView {
    pub refresh_s: f64,
    pub offset_s: f64,
    reading: Mutex<Option<Reading>>,
    pub failures: Mutex<u64>,
}

impl SourceView {
    pub fn new(refresh_s: f64, offset_s: f64) -> SourceView {
        SourceView { refresh_s, offset_s, reading: Mutex::new(None), failures: Mutex::new(0) }
    }

    pub fn refresh(&self) -> Reading {
        let handles: Vec<_> = FAST_SOURCES
            .iter()
            .map(|&(_, url, parse)| {
                std::thread::spawn(move || {
                    let res = crate::net::get(url, Duration::from_secs(3));
                    let fetched = now_us();
                    (fetched, res.ok().and_then(|raw| parse(&raw).ok()))
                })
            })
            .collect();
        let results: Vec<FetchResult> = handles.into_iter().map(|h| h.join().unwrap_or((now_us(), None))).collect();
        let r = reading_from(&results, now_us());
        *self.reading.lock().unwrap() = Some(r.clone());
        r
    }

    pub fn get(&self) -> Option<Reading> {
        self.reading.lock().unwrap().clone()
    }

    pub fn run(self: std::sync::Arc<Self>) {
        std::thread::sleep(Duration::from_secs_f64(self.offset_s.max(0.0)));
        loop {
            let v = self.clone();
            if std::thread::spawn(move || v.refresh()).join().is_err() {
                *self.failures.lock().unwrap() += 1;
            }
            std::thread::sleep(Duration::from_secs_f64(self.refresh_s.max(0.05)));
        }
    }
}

/// `frost_signer.StaticView` (test hooks and drills).
#[derive(Default)]
pub struct StaticView {
    pub median_e8: Option<i128>,
    pub at_us: Option<i128>,
}

impl StaticView {
    pub fn get(&self, now: i128) -> Reading {
        let valid = self.median_e8.is_some_and(|m| m != 0);
        Reading {
            at_us: self.at_us.unwrap_or(now),
            status: if valid { "VALID" } else { "HOLD" },
            fast_sources_used: if valid { 4 } else { 0 },
            median_e8: self.median_e8,
        }
    }
}

pub enum View {
    /// `NO_PRICE_CHECK`.
    NoCheck,
    /// No view given: every VALID body is refused.
    Missing,
    Source(std::sync::Arc<SourceView>),
    Static(Mutex<StaticView>),
}

impl View {
    pub fn get(&self, now: i128) -> Option<Reading> {
        match self {
            View::NoCheck | View::Missing => None,
            View::Source(v) => v.get(),
            View::Static(v) => Some(v.lock().unwrap().get(now)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e8_truncates_like_decimal() {
        assert_eq!(e8(&J::s("65000.123456789")).unwrap(), 6_500_012_345_678);
        assert_eq!(e8(&J::s("1e3")).unwrap(), 100_000_000_000);
        assert_eq!(e8(&J::s(" 0.5 ")).unwrap(), 50_000_000);
        assert_eq!(e8(&J::Float(97000.5)).unwrap(), 9_700_050_000_000);
        assert!(e8(&J::s("abc")).is_err());
    }

    #[test]
    fn iso_matches_python() {
        // datetime.fromisoformat("2024-01-02T03:04:05.678901+00:00").timestamp() * 1e6
        assert_eq!(iso_to_us("2024-01-02T03:04:05.678901Z").unwrap(), 1_704_164_645_678_901);
        assert_eq!(iso_to_us("2024-01-02T03:04:05Z").unwrap(), 1_704_164_645_000_000);
    }

    #[test]
    fn reading_applies_the_relay_rules() {
        // test_review_hft06 F03_Patched.test_source_view_applies_the_relay_rules, BASE prices.
        let now = 1_800_000_000_000_000;
        let base = [10_000_000_000_000i128, 10_001_000_000_000, 9_999_000_000_000, 10_000_500_000_000];
        let ok: Vec<FetchResult> = base.iter().map(|&p| (now, Some((p, None)))).collect();
        let r = reading_from(&ok, now);
        assert_eq!((r.status, r.fast_sources_used, r.median_e8), ("VALID", 4, Some((10_000_000_000_000 + 10_000_500_000_000) / 2)));
        let mut two_down = ok.clone();
        two_down[0].1 = None;
        two_down[1].1 = None;
        let r = reading_from(&two_down, now);
        assert_eq!((r.status, r.median_e8), ("HOLD", None));
    }
}
