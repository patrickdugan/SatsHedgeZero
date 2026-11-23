// Independent JS claims: compare the streaming eager frontier to MAX-01's
// separate full-tree builder. Never use Rust prover output as receiver pins.
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { GENESIS_TESTNET4, shahex, u64le } from '../../index.mjs';
import { buildLog } from '../../maximality/log.mjs';
import { initial, advance, makeClaim, costModel } from '../../admission_fused/frontier.mjs';
import { legacy, pack, unpack } from '../../admission_packed/packing.mjs';
export const DEPTH=18, CAP=2**DEPTH, BASE=1792800000000000n, PERIOD=200000n;
export const LADDER=[0,1,16,128,512,2048,8192,144000];
export function record(ordinal, source='pyth') {
 if(!Number.isSafeInteger(ordinal)||ordinal<1||ordinal>=CAP||!['pyth','chainlink'].includes(source))throw Error('ordinal/source');
 const i=BigInt(ordinal), id=source==='pyth'?1:2;
 return {price_e8:String(10000000000000n+(i%10001n)*10000n+BigInt(id-1)*20000000000n),publish_us:String(BASE+i*PERIOD),report_hash:shahex(Buffer.from('SHZ/ADMIT/SCALE/V1','ascii'),Buffer.from([id]),u64le(i))};
}
export function generate(sizes, source='pyth') {
 if(!Array.isArray(sizes)||sizes.length===0||sizes.some(n=>!Number.isSafeInteger(n)||n<0||n>=CAP))throw Error('ladder bounds');
 let state=initial(DEPTH), entries=[], claims=[], metrics=[], start=performance.now(), elapsed=0;
 const targets=[...new Set(sizes)].sort((a,b)=>a-b);let next=0;
 for(let n=0;n<=targets.at(-1);n++){
   if(n>0){const t=performance.now();const r=record(n,source);entries.push(r);state=advance(state,'append',{record:r,depth:DEPTH});while(state.pending)state=advance(state,'carry',{depth:DEPTH});elapsed+=performance.now()-t;}
   if(n!==targets[next])continue;
   const seal=String(BASE+BigInt(n)*PERIOD);
   const sealed=advance(state,'seal',{watermark:seal,depth:DEPTH});
   const claim=makeClaim(sealed,{genesis:GENESIS_TESTNET4,source,depth:DEPTH});
   const t=performance.now();const independent=buildLog({genesis:GENESIS_TESTNET4,source,depth:DEPTH,entries,sealed_through:seal});const directSeconds=(performance.now()-t)/1000;
   if(claim.pin!==independent.pin||JSON.stringify(claim.header)!==JSON.stringify(independent.header))throw Error('streaming frontier disagrees with full tree');
   const model=costModel(n,DEPTH,1);
   if(claim.steps!==Number(model.folds))throw Error('fold count model');
   const v=legacy(sealed,GENESIS_TESTNET4,source,DEPTH),p=pack(v,DEPTH);
   if(p.length!==44||unpack(p,DEPTH).some((x,i)=>x!==v[i]))throw Error('packed state parity');
   claims.push(claim);metrics.push({reports:n,folds:claim.steps,snapshot_pin:claim.pin,frontier_seconds:elapsed/1000,independent_tree_seconds:directSeconds,packed_fields:p.length,serialized_claim_bytes:Buffer.byteLength(JSON.stringify(claim)),nova_verified:false});
   next++;
 }
 return {claims,metrics,wall_seconds:(performance.now()-start)/1000,source};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const out=process.argv[2];if(!out)throw Error('usage: node build.mjs NEW_OR_EXISTING_OUTPUT_DIR [report counts...]');
 const sizes=process.argv.slice(3).map(Number);const r=generate(sizes.length?sizes:LADDER);
 mkdirSync(out,{recursive:true});for(const c of r.claims)writeFileSync(resolve(out,`${c.header.count}-expected.json`),JSON.stringify(c,null,2)+'\n');
 const report={schema:'shz/index-admission-scale/native/v1',depth:DEPTH,synthetic:true,source:r.source,wall_seconds:r.wall_seconds,metrics:r.metrics,flags:{nova_verified:false,source_authentication:false,provider_completeness_proven:false,production_ready:false}};
 console.log(JSON.stringify(report,null,2));
}
