//! Depth-18 structural admission benchmark. Stream witnesses rather than
//! retaining a vector of hundreds of thousands of full frontier states.
#![forbid(unsafe_code)]
use shz_hourly_index_admission_fused_nova as fused;
use shz_hourly_index_admission_packed_nova as packed;
pub use packed::{AdmissionStep, Claim, State, ARITY, CAP, DEPTH, F, RELATION};
use fused::{Action, Op, Record};

pub const BASE_US: u64 = 1_792_800_000_000_000;
pub const PERIOD_US: u64 = 200_000;
pub const MAX_REPORTS: u64 = CAP - 1;

pub fn synthetic_record(source: u8, ordinal: u64) -> Result<Record, String> {
    if !(1..=MAX_REPORTS).contains(&ordinal) || !matches!(source, 1 | 2) {
        return Err("synthetic source/ordinal".into());
    }
    let mut preimage = b"SHZ/ADMIT/SCALE/V1".to_vec();
    preimage.push(source);
    preimage.extend(ordinal.to_le_bytes());
    Ok(Record {
        price_e8: 10_000_000_000_000 + (ordinal % 10_001) * 10_000 + u64::from(source - 1) * 20_000_000_000,
        publish_us: BASE_US + ordinal * PERIOD_US,
        report_hash: fused::hash(&preimage),
    })
}

pub fn expected_folds(reports: u64) -> Result<u64, String> {
    if reports > MAX_REPORTS { return Err("capacity".into()); }
    // Number of merges since sentinel genesis: N+1-popcount(N+1).
    Ok(2 * reports + 2 - u64::from((reports + 1).count_ones()))
}

/// Constant-space generator: only the previous and next frontier plus the
/// current operation are held here. The final independently supplied claim is
/// checked exactly. Nova itself still retains its circuit-specific proving state.
pub fn walk(claim: &Claim, mut visit: impl FnMut(&AdmissionStep) -> Result<(), String>) -> Result<(), String> {
    packed::claim_states(claim)?;
    let (genesis, source) = claim.header.context()?;
    let reports = claim.header.count;
    if expected_folds(reports)? != claim.steps as u64 { return Err("noncanonical benchmark fold count".into()); }
    if claim.header.sealed_through != BASE_US + reports * PERIOD_US { return Err("benchmark seal mismatch".into()); }
    let mut current = State::initial();
    let mut emit = |current: &mut State, action: Action| -> Result<(), String> {
        let after = fused::advance(current, &action)?;
        let step = AdmissionStep { inner: fused::AdmissionStep { before: current.clone(), after: after.clone(), action, genesis, source } };
        visit(&step)?;
        *current = after;
        Ok(())
    };
    for ordinal in 1..=reports {
        emit(&mut current, Action { op: Op::Append, record: synthetic_record(source, ordinal)?, watermark: 0 })?;
        while current.pending {
            emit(&mut current, Action { op: Op::Carry, record: Record::default(), watermark: 0 })?;
        }
    }
    emit(&mut current, Action::seal(claim.header.sealed_through))?;
    if current != claim.final_state { return Err("independently supplied terminal frontier differs".into()); }
    Ok(())
}
