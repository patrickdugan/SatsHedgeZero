//! ADMIT-06: native proof-chain composition over the identical ADMIT-05 circuit.
//! A proof for an arbitrary segment alone does not certify a reachable state.
//! Only the complete verified chain from canonical genesis establishes history.
#![forbid(unsafe_code)]
use serde::{Serialize, Deserialize};
use shz_hourly_index_admission_fused_nova as fused;
use shz_hourly_index_admission_packed_nova as packed;
use shz_hourly_index_admission_scale::{synthetic_record, expected_folds, BASE_US, PERIOD_US};
use fused::{Action, Op, Record};
pub use packed::{AdmissionStep, Claim, State, F, ARITY, RELATION, MAX_STEPS};
pub const SCHEMA: &str = "shz/admission-segment-plan/v1";
pub const MAX_SEGMENTS: usize = 64;
pub const MAX_SEGMENT_STEPS: usize = 8192;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Segment { pub index: usize, pub folds: usize, pub before: State, pub after: State }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan { pub schema: String, pub relation: String, pub snapshot_pin: String, pub segments: Vec<Segment> }
impl Segment {
    pub fn states(&self, claim: &Claim) -> Result<(Vec<F>,Vec<F>),String> {
        let (genesis,source)=claim.header.context()?;
        self.before.validate()?; self.after.validate()?;
        if self.before.pending || self.after.pending {return Err("segment cuts must be idle".into());}
        if self.folds==0 || self.folds>MAX_SEGMENT_STEPS || self.after.operations.checked_sub(self.before.operations)!=Some(self.folds as u64) {
            return Err("segment ordinal interval".into());
        }
        Ok((packed::pack_fields(&self.before.fields(genesis,source)),packed::pack_fields(&self.after.fields(genesis,source))))
    }
}
// Receiver-owned Claim is independent of the untrusted plan and all bundles.
// This is a synthetic benchmark profile with a single final seal, cut only at
// completed appends. The proof-chain theorem also works for other cut policies.
pub fn validate_plan(plan:&Plan, claim:&Claim) -> Result<(),String> {
    let (initial,terminal)=packed::claim_states(claim)?;
    if plan.schema!=SCHEMA || plan.relation!=RELATION || plan.snapshot_pin!=claim.pin || plan.segments.is_empty() || plan.segments.len()>MAX_SEGMENTS {
        return Err("plan schema, context or segment count".into());
    }
    if expected_folds(claim.header.count)?!=claim.steps as u64 || claim.header.sealed_through!=BASE_US+claim.header.count*PERIOD_US {
        return Err("wrong benchmark schedule".into());
    }
    let mut previous=State::initial(); let mut previous_fields=initial; let mut total=0usize;
    for (i,seg) in plan.segments.iter().enumerate() {
        if seg.index!=i || seg.before!=previous {return Err("gap, reorder or mismatched boundary".into());}
        let (a,b)=seg.states(claim)?;
        if a!=previous_fields {return Err("packed boundary mismatch".into());}
        let last=i+1==plan.segments.len();
        let n0=seg.before.leaf_count.checked_sub(1).ok_or("sentinel absent")?;
        let n1=seg.after.leaf_count.checked_sub(1).ok_or("sentinel absent")?;
        if n1<n0 || (n1==n0 && !last) || n1>claim.header.count || seg.before.sealed_through!=0 || seg.after.sealed_through!=(if last{claim.header.sealed_through}else{0}) {
            return Err("report interval or seal schedule".into());
        }
        // Native counts at idle cuts: prefix fold count excluding final seal.
        if seg.before.operations!=expected_folds(n0)?-1 || seg.after.operations!=expected_folds(n1)?-u64::from(!last) {
            return Err("noncanonical idle boundary ordinal".into());
        }
        for (n,state) in [(n0,&seg.before),(n1,&seg.after)] {
            let tail=if n==0{0}else{BASE_US+n*PERIOD_US};
            if state.last_time!=tail {return Err("synthetic tail mismatch".into());}
        }
        total=total.checked_add(seg.folds).ok_or("total overflow")?;
        if total>MAX_STEPS {return Err("total steps cap".into());}
        previous=seg.after.clone(); previous_fields=b;
    }
    if previous!=claim.final_state || previous_fields!=terminal || total!=claim.steps {return Err("wrong terminal frontier or total fold count".into());}
    Ok(())
}
// Each worker gets its initial frontier from the native plan, then streams only
// its own report interval. It never replays the other workers' report intervals.
pub fn walk_segment(seg:&Segment,claim:&Claim,mut visit:impl FnMut(&AdmissionStep)->Result<(),String>)->Result<(),String>{
    seg.states(claim)?;
    let (genesis,source)=claim.header.context()?;
    let mut current=seg.before.clone(); let mut folds=0usize;
    let mut emit=|current:&mut State,action:Action|->Result<(),String>{
        let after=fused::advance(current,&action)?;
        let step=AdmissionStep{inner:fused::AdmissionStep{before:current.clone(),after:after.clone(),action,genesis,source}};
        visit(&step)?; *current=after; folds+=1; Ok(())
    };
    for ordinal in seg.before.leaf_count..seg.after.leaf_count {
        emit(&mut current,Action{op:Op::Append,record:synthetic_record(source,ordinal)?,watermark:0})?;
        while current.pending {emit(&mut current,Action{op:Op::Carry,record:Record::default(),watermark:0})?;}
    }
    if seg.after.sealed_through>current.sealed_through {emit(&mut current,Action::seal(seg.after.sealed_through))?;}
    if current!=seg.after || folds!=seg.folds{return Err("segment does not reach prescribed frontier".into());}
    Ok(())
}
