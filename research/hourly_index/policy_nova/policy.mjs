/** INDEX-POLICY-01: receiver-side deterministic admitted-log selection and evidence pinning.
 * A trusted/cryptographically authenticated log root must be obtained independently.
 * This module cannot attest that a provider emitted no unobserved updates.
 */
import {createHash} from 'node:crypto';
import {checkpoint, makeHour, makeHold, sha, shahex, hex32, uint64, u64le, HOURLY_US, MAX_PRICE_E8, MAX_AGE_US, MAX_SOURCE_SKEW_US, MAX_SPREAD_BPS, GENESIS_TESTNET4} from '../index.mjs';
export const POLICY_NAME='SHZ/DUAL-ORACLE-50BPS-5MIN/HOLD-NECESSITY/V2';
export const POLICY_HASH=shahex(Buffer.from(POLICY_NAME));
export const REASON=Object.freeze({MISSING_OR_STALE:1,SPREAD:2,SKEW:3});
const ZERO='00'.repeat(32);
const MAX_LOG=100_000;
const assert=(v,m)=>{if(!v)throw Error(m)};
const abs=(a,b)=>a>b?a-b:b-a;
const ascii=s=>Buffer.from(s,'ascii');
const sameKeys=(x,keys)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join(',')===keys.slice().sort().join(',');
export function empty(){return {present:false,price_e8:'0',publish_us:'0',report_hash:ZERO}}
function admitted(x){
 assert(sameKeys(x,['price_e8','publish_us','report_hash']),'admitted record schema');
 const price=uint64(x.price_e8,'price'),time=uint64(x.publish_us,'publish time');hex32(x.report_hash,'report hash');
 assert(price>0n&&price<=MAX_PRICE_E8&&time>0n&&x.report_hash!==ZERO,'invalid admitted observation');
 return {price,time};
}
function candidate(x,cutoff){
 assert(sameKeys(x,['present','price_e8','publish_us','report_hash'])&&typeof x.present==='boolean','candidate schema');
 if(!x.present){assert(x.price_e8==='0'&&x.publish_us==='0'&&x.report_hash===ZERO,'noncanonical absence');return {eligible:false,p:0n,t:0n};}
 const {price,time}=admitted({price_e8:x.price_e8,publish_us:x.publish_us,report_hash:x.report_hash});
 assert(time<=cutoff,'post-cutoff candidate is malformed');
 return {eligible:cutoff-time<=MAX_AGE_US,p:price,t:time};
}
export function encodeCandidate(x,cutoff){candidate(x,cutoff);return Buffer.concat([Buffer.from([Number(x.present)]),u64le(uint64(x.price_e8,'candidate price')),u64le(uint64(x.publish_us,'candidate time')),hex32(x.report_hash,'candidate digest')]);}
export function validateLog(entries){
 assert(Array.isArray(entries)&&entries.length<=MAX_LOG,'log capacity');
 let prev=0n;const seen=new Set();
 for(const r of entries){let {time}=admitted(r);assert(time>prev,'log publication times must strictly increase (duplicate/conflicting times rejected)');assert(!seen.has(r.report_hash),'replayed report digest');prev=time;seen.add(r.report_hash);}
 return entries;
}
// A streaming digest over an independently pinned, complete admitted-log snapshot.
// The full list is read by the native reference; a future ordered authenticated
// log can replace this with an adjacency proof without changing the evidence leaf.
export function logRoot({genesis,source,entries}){
 assert(source==='pyth'||source==='chainlink','source id');validateLog(entries);
 const h=createHash('sha256');h.update(ascii('SHZ/ADMITTED-LOG/V1'));h.update(hex32(genesis,'genesis'));h.update(hex32(POLICY_HASH,'policy'));h.update(Buffer.from([source==='pyth'?1:2]));h.update(u64le(BigInt(entries.length)));
 for(const e of entries){h.update(u64le(BigInt(e.price_e8)));h.update(u64le(BigInt(e.publish_us)));h.update(hex32(e.report_hash,'log digest'));}
 return h.digest('hex');
}
export function latest(entries,cutoff){
 // Callers validate and pin the entire ordered list first.
 let lo=0,hi=entries.length;while(lo<hi){let mid=(lo+hi)>>1;if(BigInt(entries[mid].publish_us)<=cutoff)lo=mid+1;else hi=mid;}
 return lo===0?empty():{present:true,...entries[lo-1]};
}
export function evidenceLeaf({genesis,hour_id,pyth,chainlink}){
 const hour=uint64(hour_id,'hour');assert(hour<1_000_000_000n,'hour range');const cutoff=(hour+1n)*HOURLY_US;
 return shahex(ascii('SHZ/HOUR/EVIDENCE/V1'),hex32(genesis,'genesis'),hex32(POLICY_HASH,'policy'),u64le(hour),encodeCandidate(pyth,cutoff),encodeCandidate(chainlink,cutoff));
}
export function evidenceRoot({genesis,start_hour,leaves}){
 const start=uint64(start_hour,'start');assert(start%8n===0n&&start<=999999992n,'checkpoint alignment');assert(Array.isArray(leaves)&&leaves.length===8,'exactly eight evidence leaves');
 let layer=leaves.map(v=>hex32(v,'evidence leaf'));while(layer.length>1){let next=[];for(let j=0;j<layer.length;j+=2)next.push(sha(ascii('SHZ/EVIDENCE/NODE/V1'),layer[j],layer[j+1]));layer=next;}
 return shahex(ascii('SHZ/8H/EVIDENCE/V1'),hex32(genesis,'genesis'),hex32(POLICY_HASH,'policy'),u64le(start),layer[0]);
}
// Complete classification relative to the *selected admitted observations*.
// An empty or stale source takes precedence, then skew, then excessive spread.
export function deriveRecord({genesis,hour_id,pyth,chainlink}){
 const hour=uint64(hour_id,'hour'),cutoff=(hour+1n)*HOURLY_US;
 const a=candidate(pyth,cutoff),b=candidate(chainlink,cutoff);
 const common={genesis,policy_hash:POLICY_HASH,hour_id};
 let reason=0;
 if(!a.eligible||!b.eligible)reason=REASON.MISSING_OR_STALE;
 else if(abs(a.t,b.t)>MAX_SOURCE_SKEW_US)reason=REASON.SKEW;
 else if(20000n*abs(a.p,b.p)>MAX_SPREAD_BPS*(a.p+b.p))reason=REASON.SPREAD;
 if(reason)return makeHold({...common,hold_reason:reason});
 return makeHour({...common,pyth_price_e8:pyth.price_e8,chainlink_price_e8:chainlink.price_e8,pyth_publish_us:pyth.publish_us,chainlink_publish_us:chainlink.publish_us,pyth_report_hash:pyth.report_hash,chainlink_report_hash:chainlink.report_hash});
}
// expectedLogRoots MUST come from a receiver-approved authenticated log registry,
// not from the witness package. The synthetic fixture uses locally generated pins.
export function buildFromPinnedLogs({genesis=GENESIS_TESTNET4,start_hour,logs,expectedLogRoots}){
 const start=uint64(start_hour,'start');assert(start%8n===0n&&start<=999999992n,'checkpoint alignment');
 assert(sameKeys(logs,['pyth','chainlink'])&&sameKeys(expectedLogRoots,['pyth','chainlink']),'two source logs/pins required');
 for(const source of ['pyth','chainlink'])assert(logRoot({genesis,source,entries:logs[source]})===expectedLogRoots[source],'source log snapshot differs from independently supplied pin: '+source);
 const evidence=Array.from({length:8},(_,i)=>{const hour=start+BigInt(i),cutoff=(hour+1n)*HOURLY_US;return {hour_id:String(hour),pyth:latest(logs.pyth,cutoff),chainlink:latest(logs.chainlink,cutoff)};});
 const evidence_leaves=evidence.map(e=>evidenceLeaf({genesis,...e}));const evidence_root=evidenceRoot({genesis,start_hour,leaves:evidence_leaves});
 const records=evidence.map(e=>deriveRecord({genesis,...e}));const cp=checkpoint(records);
 const claim={genesis,policy_hash:POLICY_HASH,start_hour,checkpoint_root:cp.checkpoint_root,evidence_root,evidence_leaves};
 return {records,checkpoint:cp,evidence,evidence_root,evidence_leaves,claim};
}
export function verifyEvidenceClaim(claim,{expectedEvidenceRoot}){
 try{assert(claim.policy_hash===POLICY_HASH,'policy version');assert(claim.evidence_root===expectedEvidenceRoot,'receiver root');return evidenceRoot({genesis:claim.genesis,start_hour:claim.start_hour,leaves:claim.evidence_leaves})===expectedEvidenceRoot;}catch{return false;}
}
