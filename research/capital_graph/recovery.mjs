// Archival receipt calibration only. This module never authorizes a release.
function normalizeRecovery(r) {
  if(r.schema!=="cbm-shz-01/oracle-dlc-release/v1"||!["testnet4","regtest"].includes(r.chain)||r.passed!==true)throw Error("unsupported or unsuccessful archival receipt");
  for(const k of ["cets_and_refund_signed_before_funding","attestation_matches_announced_point","wrong_outcome_cets_stay_incomplete","cet_confirmed","lp_reimbursed_by_cet","released_outputs_reused"])if(r.checks?.[k]!==true)throw Error("missing recorded check: "+k);
  const tx=x=>{if(typeof x!=="string"||!/^[0-9a-f]{64}$/.test(x))throw Error("missing transaction id");return x;};
  const sat=x=>{if(!Number.isSafeInteger(x)||x<0||x>2100000000000000)throw Error("bad sat amount");return x;};
  const seconds=x=>{if(typeof x!=="number"||!Number.isFinite(x)||x<0||x>1e9)throw Error("bad elapsed time");return x;};
  const h=r.heights;
  if(!h||[h.funding,h.maturity,h.attestation,h.cet].some(x=>!Number.isSafeInteger(x)||x<0)||h.funding>h.maturity||h.maturity>h.attestation||h.attestation>h.cet||r.funding.height!==h.funding)throw Error("inconsistent heights");
  const funded=sat(r.funding.amount_sat),principal=sat(r.cet.lp_sat),a=sat(r.cet.a_sat);
  if(principal<=330||a+principal>funded||!Object.values(r.cet.outputs||{}).includes(principal)||!Object.values(r.cet.outputs||{}).includes(a)||Object.values(r.cet.outputs||{}).reduce((s,x)=>s+sat(x),0)!==a+principal)throw Error("inconsistent CET amounts");
  const reimbursement=seconds(r.timings_s.lp_advance_to_reimbursement_confirmed),reuse=seconds(r.timings_s.cet_confirmed_to_reuse_confirmed),fundToReuse=seconds(r.timings_s.funding_broadcast_to_reuse_confirmed),attestation=seconds(r.timings_s.attestation_to_cet_confirmed);
  if(fundToReuse<reimbursement+reuse||fundToReuse<attestation+reuse)throw Error("inconsistent receipt clocks");
  const clocks={lp_advance_record_to_reimbursement_observed_s:reimbursement,reimbursement_observed_to_all_recorded_reuse_confirmed_s:reuse,lp_advance_record_to_all_recorded_reuse_confirmed_s:reimbursement+reuse,funding_broadcast_record_to_all_recorded_reuse_confirmed_s:fundToReuse};
  const principalClock=(t)=>(BigInt(principal)*BigInt(Math.ceil(t))).toString();
  return {chain:r.chain,prefix:r.prefix,principal_sats:principal,funding_face_sats:funded,txids:{funding:tx(r.funding.txid),cet:tx(r.cet.txid),advance:tx(r.lp_advance_txid),lp_reuse:tx(r.reuse?.lp),a_reuse:tx(r.reuse?.a),b_reuse:tx(r.reuse?.b)},heights:h,clocks,
    rounded_principal_sat_seconds:{through_reimbursement:principalClock(reimbursement),through_all_recorded_reuse:principalClock(reimbursement+reuse)},recorded_checks_only:true,active_chain_independently_verified:false,exact_outpoint_lineage_verified:false,release_authorized:false,production_ready:false};
}

export {normalizeRecovery};
