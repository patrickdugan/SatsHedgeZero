// Aggregate only measured verified proof runs, keep full-size extrapolation separate.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const dir=process.argv[2], cap=Number(process.argv[3]);
if(!dir||![128,512,2048].includes(cap))throw Error('directory and registered cap required');
const read=p=>JSON.parse(readFileSync(resolve(dir,p),'utf8'));
const mem=p=>{const m=readFileSync(resolve(dir,p),'utf8').match(/Maximum resident set size \(kbytes\):\s*(\d+)/);if(!m)throw Error('missing RSS receipt');return Number(m[1]);};
const relation='shz/ordered-admission-frontier-nova/v4-packed-state/depth18';
const reference=read('native-reference.json');const native=read('rust-native-full.json');
const full=reference.metrics.find(m=>m.reports===144000);
if(!full||native.snapshot_pin!==full.snapshot_pin||native.steps!==full.folds||!native.native_trace_verified||native.nova_verified)throw Error('unverified native scale run');
let results=[];let key=null;
for(const n of [16,128,512,2048].filter(x=>x<=cap)){
 const r=read(`proof-${n}/report.json`),v=read(`proof-${n}/verification.json`),c=read(`claims/${n}-expected.json`);
 if(r.relation!==relation||v.relation!==relation||r.tree_depth!==18||r.state_arity!==44||!r.streamed_witness||Number(r.reports)!==n||r.steps!==c.steps||r.snapshot_pin!==c.pin||v.snapshot_pin!==c.pin||!r.compressed_verified||!v.independent_compressed_verified||v.proof_sha256!==r.proof_sha256||v.verifier_key_sha256!==r.verifier_key_sha256)throw Error('proof mismatch '+n);
 for(const k of ['wrong_source_rejected','wrong_sentinel_rejected','wrong_seal_rejected','wrong_step_count_rejected','trailing_proof_rejected'])if(!v[k])throw Error('negative check missing: '+k);
 for(const k of ['source_authentication','near_nova_verified','provider_completeness_proven','can_authorize_dlc_settlement','production_ready'])if(r.flags[k]!==false||v.flags[k]!==false)throw Error('unsafe scope flag: '+k);
 if(key&&key!==r.verifier_key_sha256)throw Error('witness-dependent key');key=r.verifier_key_sha256;
 results.push({reports:n,folds:r.steps,fold_seconds:r.fold_seconds,folds_per_second:r.steps/r.fold_seconds,setup_seconds:r.setup_seconds,compression_seconds:r.compression_seconds,verify_seconds:r.verify_seconds,proof_bytes:r.proof_bytes,vk_bytes:r.verifier_key_bytes,constraints:r.constraints,peak_prove_rss_kib:mem(`prove-${n}-time.txt`),peak_verify_rss_kib:mem(`verify-${n}-time.txt`),verified:true});
}
const last=results.at(-1);const projected=full.folds/last.folds_per_second;
console.log(JSON.stringify({schema:'shz/index-admission-scale/proof-benchmark/v1',relation,depth:18,packed_fields:44,verifier_key_sha256:key,synthetic:true,results,full_native:{reports:144000,folds:full.folds,pin:full.snapshot_pin,verified:true},projection:{basis_reports:last.reports,basis_folds:last.folds,estimated_fold_seconds:projected,estimated_fold_hours:projected/3600,measured:false,excludes_setup_and_compression:true},full_scale_nova_verified:false,source_authentication:false,near_nova_verified:false,provider_completeness_proven:false,production_ready:false},null,2));
