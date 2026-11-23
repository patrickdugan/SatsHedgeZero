// Independent, streaming plan for the synthetic ADMIT-05 depth18 benchmark.
// The plan is NOT an authentication oracle. Receiver pins the final claim and
// checks all segment proofs and exact boundary states.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { initial, advance, makeClaim, validateState } from '../admission_fused/frontier.mjs';
import { record, DEPTH, BASE, PERIOD } from '../admission_scale/fixtures/build.mjs';
import { legacy, pack } from '../admission_packed/packing.mjs';
export const SCHEMA='shz/admission-segment-plan/v1';
export const RELATION='shz/ordered-admission-frontier-nova/v4-packed-state/depth18';
export const MAX_SEGMENTS=64, MAX_SEGMENT_STEPS=8192;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const ok=(x,m)=>{if(!x)throw Error(m)};
const prefix=n=>2*n+1-((n+1).toString(2).match(/1/g)||[]).length; // N+merges, excluding seal
export function validatePlan(plan,claim){
 try{
  ok(plan.schema===SCHEMA&&plan.relation===RELATION&&plan.snapshot_pin===claim.pin,'context');
  ok(claim.header.depth===DEPTH&&plan.segments.length>0&&plan.segments.length<=MAX_SEGMENTS,'segment count');
  const count=Number(claim.header.count),src=claim.header.source,g=claim.header.genesis;
  ok(claim.steps===prefix(count)+1&&claim.header.sealed_through===String(BASE+BigInt(count)*PERIOD),'schedule');
  let prev=initial(DEPTH),total=0;
  for(const [i,s] of plan.segments.entries()){
   ok(s.index===i&&same(s.before,prev),'disconnected boundary');
   validateState(s.before,DEPTH);validateState(s.after,DEPTH);ok(!s.before.pending&&!s.after.pending,'pending cut');
   ok(pack(legacy(s.before,g,src,DEPTH),DEPTH).length===44&&pack(legacy(s.after,g,src,DEPTH),DEPTH).length===44,'packed width');
   const a=Number(s.before.leaf_count)-1,b=Number(s.after.leaf_count)-1,last=i===plan.segments.length-1;
   ok(Number.isSafeInteger(s.folds)&&s.folds>0&&s.folds<=MAX_SEGMENT_STEPS&&b>=a&&(b>a||last)&&b<=count,'segment size');
   ok(s.before.sealed_through==='0'&&s.after.sealed_through===(last?claim.header.sealed_through:'0'),'seal schedule');
   ok(Number(s.before.operations)===prefix(a)&&Number(s.after.operations)===prefix(b)+Number(last)&&Number(s.after.operations)-Number(s.before.operations)===s.folds,'ordinals');
   ok(s.before.last_time===(a===0?'0':String(BASE+BigInt(a)*PERIOD))&&s.after.last_time===(b===0?'0':String(BASE+BigInt(b)*PERIOD)),'tail');
   total+=s.folds;prev=s.after;
  }
  return total===claim.steps&&same(prev,claim.final_state)&&same(makeClaim(prev,{genesis:g,source:src,depth:DEPTH}),claim);
 }catch{return false;}
}
export function makePlan(claim,chunk){
 const n=Number(claim.header.count);ok(Number.isSafeInteger(chunk)&&chunk>0&&chunk<=4095&&Math.max(1,Math.ceil(n/chunk))<=MAX_SEGMENTS,'chunk budget');
 let state=initial(DEPTH),before=state,segments=[];
 function emit(){segments.push({index:segments.length,folds:Number(state.operations)-Number(before.operations),before,after:state});before=state;}
 for(let i=1;i<=n;i++){
  state=advance(state,'append',{record:record(i,claim.header.source),depth:DEPTH});while(state.pending)state=advance(state,'carry',{depth:DEPTH});
  if(i<n&&i%chunk===0)emit();
 }
 state=advance(state,'seal',{watermark:claim.header.sealed_through,depth:DEPTH});emit();
 const plan={schema:SCHEMA,relation:RELATION,snapshot_pin:claim.pin,segments};
 ok(validatePlan(plan,claim),'generated plan invalid');return plan;
}
export function replaySegment(s,claim){
 let z=s.before;
 try{
  for(let i=Number(s.before.leaf_count);i<Number(s.after.leaf_count);i++){
   z=advance(z,'append',{record:record(i,claim.header.source),depth:DEPTH});while(z.pending)z=advance(z,'carry',{depth:DEPTH});
  }
  if(BigInt(s.after.sealed_through)>BigInt(z.sealed_through))z=advance(z,'seal',{watermark:s.after.sealed_through,depth:DEPTH});
  return same(z,s.after);
 }catch{return false;}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [claimPath,size,out]=process.argv.slice(2);ok(claimPath&&size&&out,'usage: node plan.mjs EXPECTED.json REPORTS_PER_SEGMENT NEW_PLAN.json');
 const claim=JSON.parse(readFileSync(claimPath,'utf8'));const p=makePlan(claim,Number(size));
 ok(p.segments.every(s=>replaySegment(s,claim)),'native segment replay failed');
 writeFileSync(out,JSON.stringify(p,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({segments:p.segments.length,folds:p.segments.map(s=>s.folds),total:claim.steps,snapshot_pin:claim.pin,source:claim.header.source,native_plan_verified:true,proof_chain_verified:false,recursive_aggregate_verified:false}));
}
