// Independent JS byte encoding and composition relation. No proof-verification claim.
import { createHash } from 'node:crypto';
import { initial, validateState, makeClaim } from '../admission_fused/frontier.mjs';
import { validatePlan, replaySegment } from '../admission_segments/plan.mjs';
import { POLICY_HASH } from '../policy_nova/policy.mjs';
const DEPTH=18,CAP=1n<<18n,MAX_STEPS=1n<<20n;
const MAX_U64=(1n<<64n)-1n;
const require=(v,msg)=>{if(!v)throw Error(msg)};
const u64=v=>{let n=BigInt(v);require(n>=0n&&n<=MAX_U64,'u64');let b=Buffer.alloc(8);b.writeBigUInt64LE(n);return b;};
const hash=b=>createHash('sha256').update(b).digest();
const h32=s=>{require(typeof s==='string'&&/^[0-9a-f]{64}$/.test(s),'canonical digest');return Buffer.from(s,'hex')};
export function context(claim,imageId){
 require(Array.isArray(imageId)&&imageId.length===8&&imageId.some(x=>x!==0)&&imageId.every(x=>Number.isInteger(x)&&x>=0&&x<=0xffffffff),'image');
 const h=claim.header;require(h.depth===DEPTH&&h.policy_hash===POLICY_HASH&&['pyth','chainlink'].includes(h.source),'context');
 return {genesis:h.genesis,policy:h.policy_hash,source:h.source==='pyth'?1:2,snapshot_pin:claim.pin,image_id:imageId};
}
function encodeContext(c){
 require(c.policy===POLICY_HASH&&[1,2].includes(c.source),'context');
 require(Array.isArray(c.image_id)&&c.image_id.length===8&&c.image_id.some(x=>x!==0)&&c.image_id.every(x=>Number.isInteger(x)&&x>=0&&x<=0xffffffff),'image');
 const id=Buffer.alloc(32);c.image_id.forEach((x,i)=>id.writeUInt32LE(x,i*4));
 return Buffer.concat([h32(c.genesis),h32(c.policy),Buffer.from([c.source,DEPTH]),h32(c.snapshot_pin),id]);
}
export function stateDigest(c,s){
 validateState(s,DEPTH);const b=[Buffer.from('SHZ/ADMIT/STATE/V1'),encodeContext(c),...['operations','leaf_count','last_time','sealed_through'].map(k=>u64(s[k])),Buffer.from([Number(s.pending),s.level]),u64(s.carry.min),h32(s.carry.digest)];
 for(const x of s.frontier)b.push(Buffer.from([Number(x.occupied)]),u64(x.min),h32(x.digest));return hash(Buffer.concat(b)).toString('hex');
}
const fields=['start_op','end_op','start_reports','end_reports','start_seal','end_seal'];
function validate(j){
 encodeContext(j.ctx);require(Number.isInteger(j.height)&&j.height>=0&&j.height<=6,'height');
 const [a,b,c,d,e,f]=fields.map(k=>BigInt(j[k]));fields.forEach(k=>u64(j[k]));
 require(a<b&&b<=MAX_STEPS&&b-a>=(1n<<BigInt(j.height))&&c<=d&&d<CAP&&e<=f&&f<MAX_U64,'range');h32(j.start);h32(j.end);return j;
}
export function journal(c,height,a,b){
 validateState(a,DEPTH);validateState(b,DEPTH);require(!a.pending&&!b.pending,'pending cut');
 return validate({ctx:c,height,start_op:a.operations,end_op:b.operations,start_reports:String(BigInt(a.leaf_count)-1n),end_reports:String(BigInt(b.leaf_count)-1n),start_seal:a.sealed_through,end_seal:b.sealed_through,start:stateDigest(c,a),end:stateDigest(c,b)});
}
export function encode(j){validate(j);return Buffer.concat([Buffer.from('SHZAGG01'),encodeContext(j.ctx),Buffer.from([j.height]),...fields.map(k=>u64(j[k])),h32(j.start),h32(j.end)]);}
export function join(a,b){
 validate(a);validate(b);require(encodeContext(a.ctx).equals(encodeContext(b.ctx))&&a.height===b.height&&a.height<6&&a.end_op===b.start_op&&a.end_reports===b.start_reports&&a.end_seal===b.start_seal&&a.end===b.start,'disconnected or unequal-height children');
 return validate({...a,height:a.height+1,end_op:b.end_op,end_reports:b.end_reports,end_seal:b.end_seal,end:b.end});
}
export function buildTree(plan,claim,imageId){
 require(validatePlan(plan,claim)&&plan.segments.every(s=>replaySegment(s,claim)),'invalid plan');
 const n=plan.segments.length;require(n>0&&(n&(n-1))===0&&n<=64,'balanced segment count');
 const c=context(claim,imageId);let layer=plan.segments.map(s=>journal(c,0,s.before,s.after));const leaves=layer;let nodes=[];
 while(layer.length>1){let next=[];for(let i=0;i<layer.length;i+=2){const j=join(layer[i],layer[i+1]);next.push(j);nodes.push(j);}layer=next;}
 const root=layer[0],expected=journal(c,Math.log2(n),initial(DEPTH),claim.final_state);
 require(encode(root).equals(encode(expected)),'root mismatch');
 require(makeClaim(claim.final_state,{genesis:claim.header.genesis,source:claim.header.source,depth:DEPTH}).pin===claim.pin,'claim mismatch');
 return {leaves,nodes,root,bytes:encode(root)};
}
