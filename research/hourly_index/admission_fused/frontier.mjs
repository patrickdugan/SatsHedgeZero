/** INDEX-ADMIT-03: eager-placement binary-carry accumulator for the exact MAX-01 ordered
 * SHA256/minimum tree. No provider authentication or watermark authority here. */
import {u64le,uint64,hex32} from '../index.mjs';
import {POLICY_HASH,empty} from '../policy_nova/policy.mjs';
import {leaf,node,defaults,snapshotDigest,MAX} from '../maximality/log.mjs';
const ZERO='00'.repeat(32), MAX_PRICE=10_000_000_000_000_000n;
const ok=(x,m)=>{if(!x)throw Error(m)};
const u=x=>uint64(x,'u64');
export const blankSummary=()=>({min:'0',digest:ZERO});
export const blankSlot=()=>({occupied:false,...blankSummary()});
export const blankRecord=()=>({price_e8:'0',publish_us:'0',report_hash:ZERO});
const summary=x=>({min:x.min,digest:x.digest});
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function depthCheck(d){ok(Number.isInteger(d)&&d>=1&&d<=24,'depth');return 2n**BigInt(d)}
function checkSummary(s){u(s.min);hex32(s.digest,'digest')}
function validateRecord(r){const t=u(r.publish_us),p=u(r.price_e8);hex32(r.report_hash,'report hash');ok(t>0n&&t<MAX&&p>0n&&p<=MAX_PRICE&&r.report_hash!==ZERO,'bad report')}
export function initial(depth=4){depthCheck(depth);const f=Array.from({length:depth+1},blankSlot);f[0]={occupied:true,...leaf(empty())};return {operations:'0',leaf_count:'1',last_time:'0',sealed_through:'0',pending:false,level:0,carry:blankSummary(),frontier:f}}
export function validateState(s,depth){
 const cap=depthCheck(depth),n=u(s.leaf_count);u(s.operations);const last=u(s.last_time),seal=u(s.sealed_through);ok(n>=1n&&n<=cap&&last<MAX&&seal<MAX,'state bounds');ok(typeof s.pending==='boolean'&&Number.isInteger(s.level)&&s.level>=0&&s.level<=depth,'phase');checkSummary(s.carry);ok(s.frontier.length===depth+1,'frontier width');
 for(const x of s.frontier){ok(typeof x.occupied==='boolean','occupied flag');checkSummary(x);if(!x.occupied)ok(eq(summary(x),blankSummary()),'empty slot encoding')}
 if(!s.pending){ok(s.level===0&&eq(s.carry,blankSummary()),'idle carry encoding');for(let i=0;i<=depth;i++)ok(s.frontier[i].occupied===Boolean((n>>BigInt(i))&1n),'idle frontier/count mismatch')}
 else {ok(s.frontier[s.level].occupied,'pending carry must face occupied slot');let mass=1n<<BigInt(s.level);for(let i=0;i<=depth;i++){if(s.frontier[i].occupied){ok(i>=s.level,'unconsumed lower slot');mass+=1n<<BigInt(i)}}ok(mass===n,'carry mass conservation')}
 ok((n===1n)===(last===0n),'tail/genesis mismatch');return true;
}
function installOrCarry(a,i,produced){if(a.frontier[i].occupied){a.pending=true;a.level=i;a.carry=produced;}else{a.frontier[i]={occupied:true,...produced};a.pending=false;a.level=0;a.carry=blankSummary();}}
export function advance(before,op,{record=blankRecord(),watermark='0',depth=4}={}){
 validateState(before,depth);const a=structuredClone(before),cap=depthCheck(depth),n=u(a.leaf_count),last=u(a.last_time),seal=u(a.sealed_through);a.operations=String(u(a.operations)+1n);
 ok((op==='carry')===before.pending,'must resolve carry before another operation');
 if(op==='append'){
   validateRecord(record);const t=u(record.publish_us);ok(watermark==='0'&&n<cap&&t>last&&t>seal,'append capacity or monotone time');
   a.leaf_count=String(n+1n);a.last_time=record.publish_us;installOrCarry(a,0,leaf({present:true,...record}));
 }else if(op==='carry'){
   ok(eq(record,blankRecord())&&watermark==='0','carry dummy fields');const i=a.level,s=a.frontier[i];
   ok(s.occupied&&i<depth&&u(s.min)<u(a.carry.min),'invalid carry merge');const parent=node(summary(s),a.carry);a.frontier[i]=blankSlot();installOrCarry(a,i+1,parent);
 }else if(op==='seal'){
   ok(eq(record,blankRecord()),'seal dummy record');const w=u(watermark);ok(w>seal&&w<MAX,'seal must strictly advance');a.sealed_through=watermark;
 }else throw Error('unknown operation');
 validateState(a,depth);return a;
}
export function transcript({entries,genesis,source,depth=4,watermarks=[]}){
 let s=initial(depth),steps=[],hashes={leaf:0,node:0};const emit=(op,record=blankRecord(),watermark='0')=>{const after=advance(s,op,{record,watermark,depth});steps.push({op,record,watermark,before:s,after});if(op==='append')hashes.leaf++;if(op==='carry')hashes.node++;s=after;};
 const sealAt=new Map();for(const w of watermarks){ok(Number.isInteger(w.after)&&w.after>=0&&w.after<=entries.length,'seal position');const ar=sealAt.get(w.after)??[];ar.push(w.watermark);sealAt.set(w.after,ar);}
 for(const w of sealAt.get(0)??[])emit('seal',blankRecord(),w);
 for(const [i,r] of entries.entries()){emit('append',r);while(s.pending)emit('carry');for(const w of sealAt.get(i+1)??[])emit('seal',blankRecord(),w)}
 return {steps,claim:makeClaim(s,{genesis,source,depth}),hashes};
}
// Native public-output decider: canonical occupied frontier is a partition of
// the admitted prefix. Pad the suffix with the exact MAX-01 defaults.
export function rootFromFrontier(s,depth){
 validateState(s,depth);ok(!s.pending,'cannot snapshot pending carry');const d=defaults(depth);if(s.frontier[depth].occupied)return summary(s.frontier[depth]);let r=d[0];
 for(let i=0;i<depth;i++)r=s.frontier[i].occupied?node(summary(s.frontier[i]),r):node(r,d[i]);return r;
}
export function makeClaim(s,{genesis,source,depth=4}){
 const root=rootFromFrontier(s,depth);const header={genesis,policy_hash:POLICY_HASH,source,depth,count:String(u(s.leaf_count)-1n),last_time:s.last_time,sealed_through:s.sealed_through,root};
 return {header,pin:snapshotDigest(header),steps:Number(u(s.operations)),final_state:s};
}
export function checkTranscript(steps,claim,{expectedPin,source,genesis,depth=4}){
 try{ok(claim.pin===expectedPin&&claim.header.source===source&&claim.header.genesis===genesis&&claim.header.depth===depth,'independent pin/context');ok(steps.length===claim.steps&&steps.length>0,'step count');let s=initial(depth);for(const w of steps){ok(eq(s,w.before),'broken state chain');s=advance(s,w.op,{record:w.record,watermark:w.watermark,depth});ok(eq(s,w.after),'invalid transition')}
 ok(eq(makeClaim(s,{genesis,source,depth}),claim),'final snapshot mismatch');return true}catch{return false}
}
// Model exact fixed-shape hash work, not measured proving time or gas.
export function costModel(reports,depth,seals=1){
 const cap=depthCheck(depth),n=BigInt(reports);ok(n>=0n&&n<cap,'capacity');ok(Number.isSafeInteger(seals)&&seals>=0,'seals');
 const k=Number(n+1n).toString(2).split('1').length-1, merges=n+1n-BigInt(k);
 const old=2n*n+merges+BigInt(seals),fused=n+merges+BigInt(seals);
 return {reports:String(n),depth,seals,merges:String(merges),folds:String(fused),previousFolds:String(old),removedPlacementFolds:String(n),frontierSha256CompressionBlocks:String(2n*fused),previousSharedSha256CompressionBlocks:String(2n*old),oldNewPathCompressionBlocksLowerBound:String(n*BigInt(4*depth+2)),note:'Both circuits use two SHA blocks per fold. Eager placement removes one fold per admitted report. Analytical counts only.'};
}
