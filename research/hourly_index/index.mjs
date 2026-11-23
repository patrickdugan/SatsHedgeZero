/** SHZ-INDEX-01 canonical public hourly epoch + eight-hour anchor construction.
 * SHA256 is consensus-compatible. This reference proves statement *recomputation*,
 * not private-witness ZK, oracle signature authenticity or a Bitcoin block's finality.
 */
import { createHash } from 'node:crypto';
export const MAGIC = Buffer.from('SHZIDX01'); // 8-byte OP_RETURN protocol discriminator
export const GENESIS_TESTNET4 = '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043';
export const HOURLY_US = 3_600_000_000n;
export const MAX_PRICE_E8 = 10_000_000_000_000_000n;
export const MAX_SPREAD_BPS = 50n;
export const MAX_AGE_US = 300_000_000n;     // within five minutes before the hourly cutoff
export const MAX_SOURCE_SKEW_US = 60_000_000n;
export const HOLD = 2;
export const VALID = 1;
const ASCII = s => Buffer.from(s, 'ascii');
const LEAF_DOMAIN = ASCII('SHZ/HOUR/LEAF/V1');
const NODE_DOMAIN = ASCII('SHZ/HOUR/NODE/V1');
const ROOT_DOMAIN = ASCII('SHZ/8H/ROOT/V1');
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const ZERO32 = '00'.repeat(32);
export const sha = (...args) => createHash('sha256').update(Buffer.concat(args)).digest();
export const shahex = (...args) => sha(...args).toString('hex');
const ensure = (condition, desc) => {if (!condition) throw Error(desc);};
export function hex32(x, name) {
  ensure(typeof x==='string' && /^[0-9a-f]{64}$/.test(x),`invalid ${name}`);
  return Buffer.from(x,'hex');
}
export function uint64(x, name) {
  ensure(typeof x==='string' && /^(0|[1-9][0-9]*)$/.test(x),`${name} canonical decimal string`);
  let v=BigInt(x);ensure(v<=MAX_U64,`${name} overflows u64`);return v;
}
export function u64le(v){ensure(v>=0n && v<=MAX_U64,'out-of-range u64');let b=Buffer.alloc(8);b.writeBigUInt64LE(v);return b;}
const positive = (value,name) => {const x=uint64(value,name);ensure(x>0n && x<=MAX_PRICE_E8,`invalid ${name}`);return x;};
const distance=(a,b)=>a>=b?a-b:b-a;
export function parseRecord(r,{strict=true}={}) {
  ensure(r!==null && typeof r==='object' && !Array.isArray(r),'hour record object');
  const keys=['genesis','policy_hash','hour_id','status','hold_reason','pyth_price_e8','chainlink_price_e8','index_price_e8','pyth_publish_us','chainlink_publish_us','pyth_report_hash','chainlink_report_hash'];
  if(strict)ensure(Object.keys(r).sort().join('|')===keys.sort().join('|'),'hour record keys must match schema');
  const genesis=hex32(r.genesis,'genesis'),policy=hex32(r.policy_hash,'policy_hash');
  const hour=uint64(r.hour_id,'hour_id');
  ensure(hour<1_000_000_000n,'implausible epoch hour');
  ensure(Number.isInteger(r.status) && [VALID,HOLD].includes(r.status),'invalid status');
  ensure(Number.isInteger(r.hold_reason) && r.hold_reason>=0 && r.hold_reason<=3,'hold reason');
  const values=['pyth_price_e8','chainlink_price_e8','index_price_e8','pyth_publish_us','chainlink_publish_us'].map(k=>uint64(r[k],k));
  const [p,c,index,pt,ct]=values;
  const pd=hex32(r.pyth_report_hash,'pyth_report_hash');const cd=hex32(r.chainlink_report_hash,'chainlink_report_hash');
  if(r.status===VALID){
    ensure(r.hold_reason===0,'valid epoch cannot hold');
    positive(r.pyth_price_e8,'pyth_price_e8');positive(r.chainlink_price_e8,'chainlink_price_e8');
    ensure(index>0n && index<=MAX_PRICE_E8,'index range');
    ensure(index===(p+c)/2n,'mean rounding must floor');
    ensure(20_000n*distance(p,c)<=MAX_SPREAD_BPS*(p+c),'spread exceeds tolerance');
    const cutoff=(hour+1n)*HOURLY_US;
    for(const t of [pt,ct])ensure(t<=cutoff && cutoff-t<=MAX_AGE_US,'stale/future source time');
    ensure(distance(pt,ct)<=MAX_SOURCE_SKEW_US,'source timestamps misaligned');
    ensure(r.pyth_report_hash!==ZERO32 && r.chainlink_report_hash!==ZERO32,'missing source digests');
  }else{
    ensure(r.hold_reason>=1,'HOLD requires a reason');
    ensure(values.every(v=>v===0n),'HOLD cannot carry accepted prices or time');
    ensure(r.pyth_report_hash===ZERO32 && r.chainlink_report_hash===ZERO32,'HOLD cannot carry source hash');
  }
  const serialized=Buffer.concat([LEAF_DOMAIN,genesis,policy,u64le(hour),Buffer.from([r.status,r.hold_reason]),...values.map(u64le),pd,cd]);
  return {hour,genesis,policy,serialized,leaf:sha(serialized),status:r.status};
}
export function leafHash(r){return parseRecord(r).leaf.toString('hex');}
export const innerNode=(left,right)=>sha(NODE_DOMAIN,left,right);
export function checkpoint(records){
 ensure(Array.isArray(records)&&records.length===8,'checkpoint requires exactly eight hourly records');
 const parsed=records.map(r=>parseRecord(r));
 const start=parsed[0].hour;
 ensure(start%8n===0n,'checkpoint start hour must align to 8h UTC');
 for(let i=0;i<8;i++){
  ensure(parsed[i].hour===start+BigInt(i),'hourly records nonconsecutive/out of order');
  ensure(parsed[i].genesis.equals(parsed[0].genesis),'genesis changed during checkpoint');
  ensure(parsed[i].policy.equals(parsed[0].policy),'policy changed during checkpoint');
 }
 let layers=[parsed.map(x=>x.leaf)];
 while(layers.at(-1).length>1){let a=layers.at(-1),b=[];for(let j=0;j<a.length;j+=2)b.push(innerNode(a[j],a[j+1]));layers.push(b);}
 const merkleRoot=layers.at(-1)[0];
 const checkpointRoot=sha(ROOT_DOMAIN,parsed[0].genesis,parsed[0].policy,u64le(start),merkleRoot);
 const inclusion=Array.from({length:8},(_,i)=>{
   let idx=i;const siblings=[];
   for(let depth=0;depth<3;depth++){siblings.push(layers[depth][idx^1].toString('hex'));idx=Math.floor(idx/2);}
   return {hour_id:parsed[i].hour.toString(),siblings};
 });
 return {schema:'shz/hourly-checkpoint/v1',start_hour:start.toString(),genesis:parsed[0].genesis.toString('hex'),policy_hash:parsed[0].policy.toString('hex'),merkle_root:merkleRoot.toString('hex'),checkpoint_root:checkpointRoot.toString('hex'),packet_hex:Buffer.concat([MAGIC,checkpointRoot]).toString('hex'),leaves:parsed.map(x=>x.leaf.toString('hex')),inclusion};
}
export function verifyInclusion({record,checkpoint:cp,siblings}){
 try{
  const {leaf,hour,genesis,policy}=parseRecord(record);
  ensure(cp.schema==='shz/hourly-checkpoint/v1','checkpoint schema');
  const start=uint64(cp.start_hour,'start_hour');ensure(start%8n===0n && hour>=start && hour<start+8n,'hour not in 8-hour checkpoint');
  ensure(genesis.equals(hex32(cp.genesis,'cp.genesis')) && policy.equals(hex32(cp.policy_hash,'cp.policy_hash')),'wrong checkpoint network/policy');
  ensure(Array.isArray(siblings)&&siblings.length===3,'exactly 3 Merkle siblings');
  let idx=Number(hour-start),v=leaf;
  for(const [depth,encoded] of siblings.entries()){
   const s=hex32(encoded,`sibling_${depth}`);
   v=(idx&1)?innerNode(s,v):innerNode(v,s);idx>>=1;
  }
  ensure(v.equals(hex32(cp.merkle_root,'cp.merkle_root')),'Merkle inclusion mismatch');
  const root=sha(ROOT_DOMAIN,genesis,policy,u64le(start),v);
  ensure(root.equals(hex32(cp.checkpoint_root,'cp.checkpoint_root')),'checkpoint commitment mismatch');
  ensure(Buffer.concat([MAGIC,root]).toString('hex')===cp.packet_hex,'OP_RETURN packet mismatch');
  return true;
 }catch{return false;}
}
export function opReturnScript(checkpointData){
 let packet=Buffer.from(checkpointData.packet_hex,'hex');ensure(packet.length===40 && packet.subarray(0,8).equals(MAGIC),'invalid SHZ anchor packet');
 return Buffer.concat([Buffer.from([0x6a,40]),packet]);
}
export function makeHour({genesis=GENESIS_TESTNET4,policy_hash,hour_id,pyth_price_e8,chainlink_price_e8,pyth_publish_us,chainlink_publish_us,pyth_report_hash,chainlink_report_hash}){
 const p=uint64(String(pyth_price_e8),'pyth_price_e8'),c=uint64(String(chainlink_price_e8),'chainlink_price_e8');
 const record={genesis,policy_hash,hour_id:String(hour_id),status:VALID,hold_reason:0,pyth_price_e8:p.toString(),chainlink_price_e8:c.toString(),index_price_e8:((p+c)/2n).toString(),pyth_publish_us:String(pyth_publish_us),chainlink_publish_us:String(chainlink_publish_us),pyth_report_hash,chainlink_report_hash};
 parseRecord(record);return record;
}
export function makeHold({genesis=GENESIS_TESTNET4,policy_hash,hour_id,hold_reason=1}){
 const record={genesis,policy_hash,hour_id:String(hour_id),status:HOLD,hold_reason,pyth_price_e8:'0',chainlink_price_e8:'0',index_price_e8:'0',pyth_publish_us:'0',chainlink_publish_us:'0',pyth_report_hash:ZERO32,chainlink_report_hash:ZERO32};
 parseRecord(record);return record;
}
export const domains={leaf:LEAF_DOMAIN.toString(),node:NODE_DOMAIN.toString(),root:ROOT_DOMAIN.toString()};
