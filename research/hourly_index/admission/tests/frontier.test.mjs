import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {shahex,HOURLY_US,GENESIS_TESTNET4} from '../../index.mjs';
import {buildLog,select,verifySelection} from '../../maximality/log.mjs';
import {initial,advance,transcript,checkTranscript,rootFromFrontier,makeClaim,costModel,blankRecord,blankSummary,blankSlot} from '../frontier.mjs';
const g=GENESIS_TESTNET4,source='pyth',depth=4;const zero='00'.repeat(32);
const read=p=>JSON.parse(readFileSync(new URL(p,import.meta.url),'utf8'));
const record=(i,t=BigInt(i)*100n)=>({price_e8:String(10000000000000n+BigInt(i)),publish_us:String(t),report_hash:shahex(Buffer.from('record/'+i))});
const entries=Array.from({length:15},(_,i)=>record(i+1));
function make(n,seals=[{after:n,watermark:'2000'}]){return transcript({entries:entries.slice(0,n),genesis:g,source,depth,watermarks:seals})}
function pinned(t){return {expectedPin:t.claim.pin,source,genesis:g,depth}}
function replay(t){return checkTranscript(t.steps,t.claim,pinned(t))}
function altered(t,fn){const a=structuredClone(t);fn(a);return a}
test('all 16 prefix lengths including sentinel-only and full capacity match MAX-01',()=>{for(let n=0;n<=15;n++){const t=make(n);const direct=buildLog({genesis:g,source,entries:entries.slice(0,n),depth,sealed_through:'2000'});assert.equal(t.claim.pin,direct.pin);assert.deepEqual(t.claim.header.root,direct.header.root);assert.ok(replay(t));}});
test('both frozen histories compose exactly with the previous maximality proof',()=>{const {genesis,start_hour,logs}=read('../../policy_nova/fixtures/admitted_logs.json'),max=read('../../maximality/fixtures/expected.json');for(const s of ['pyth','chainlink']){const claim=read('../fixtures/'+s+'-expected.json'),ops=read('../fixtures/'+s+'-steps.json');let state=initial(depth);for(const op of ops)state=advance(state,op.op,{...op,depth});assert.deepEqual(makeClaim(state,{genesis,source:s,depth}),claim);assert.equal(claim.pin,max.pins[s]);const tree=buildLog({genesis,source:s,entries:logs[s],depth,sealed_through:claim.header.sealed_through});for(let i=0;i<8;i++){let cutoff=(BigInt(start_hour)+BigInt(i)+1n)*HOURLY_US;assert.ok(verifySelection(select(tree,cutoff),{pin:claim.pin,cutoff,genesis,source:s}));}}});
test('intermediate seal allows only strictly newer appends',()=>{assert.ok(replay(make(5,[{after:2,watermark:'299'},{after:5,watermark:'2000'}])))});
test('backfill at watermark rejected',()=>assert.throws(()=>make(5,[{after:2,watermark:'300'},{after:5,watermark:'2000'}])));
test('nonmonotone report times rejected',()=>assert.throws(()=>transcript({entries:[record(1),record(2,100n)],genesis:g,source,depth})));
test('zero report hash rejected',()=>assert.throws(()=>advance(initial(), 'append',{record:{...record(1),report_hash:zero}})));
test('zero and above-cap price rejected',()=>{for(const p of ['0','10000000000000001'])assert.throws(()=>advance(initial(),'append',{record:{...record(1),price_e8:p}}))});
test('reserved infinite time rejected',()=>assert.throws(()=>advance(initial(),'append',{record:record(1,2n**64n-1n)})));
test('pending carry cannot seal, append or expose root',()=>{const s=advance(initial(),'append',{record:record(1)});assert.throws(()=>advance(s,'seal',{watermark:'200'}));assert.throws(()=>advance(s,'append',{record:record(2)}));assert.throws(()=>rootFromFrontier(s,4));});
test('idle cannot carry',()=>assert.throws(()=>advance(initial(),'carry')));
test('strict watermark, no equal or backward seal',()=>{const s=advance(initial(),'seal',{watermark:'1'});for(const w of ['0','1','18446744073709551615'])assert.throws(()=>advance(s,'seal',{watermark:w}))});
test('full tree cannot append',()=>assert.throws(()=>advance(make(15).claim.final_state,'append',{record:record(16,3000n)})));
test('carry cannot smuggle record or watermark',()=>{let s=advance(initial(),'append',{record:record(1)});assert.throws(()=>advance(s,'carry',{record:record(2)}));assert.throws(()=>advance(s,'carry',{watermark:'1'}));});
test('skipped fold rejected under retained claim',()=>{let t=make(5);assert.equal(replay(altered(t,a=>a.steps.splice(2,1))),false)});
test('forged slot digest rejected even with recomputed claimed pin',()=>{let t=make(5);const a=altered(t,a=>{let s=a.claim.final_state.frontier.find(s=>s.occupied);s.digest=shahex(Buffer.from('forged'));a.claim=makeClaim(a.claim.final_state,{genesis:g,source,depth});});assert.equal(replay(a),false)});
test('discarding an unfinished carry rejected',()=>{let t=make(5);assert.equal(replay(altered(t,a=>{a.steps[0].after.pending=false;a.steps[0].after.carry=blankSummary()})),false)});
test('empty slot cannot retain a digest',()=>{let s=initial();s.frontier[1].digest=shahex(Buffer.from('hidden'));assert.throws(()=>advance(s,'seal',{watermark:'1'}))});
test('wrong report/root/pin/source/context rejected',()=>{let t=make(3);for(const f of [a=>a.steps[0].record.report_hash=shahex(Buffer.from('other')),a=>a.claim.pin=zero,a=>a.claim.header.source='chainlink',a=>a.claim.header.genesis=zero])assert.equal(replay(altered(t,f)),false)});
test('cost model exact for every prefix of depth 4',()=>{for(let n=0;n<=15;n++){let t=make(n),m=costModel(n,4,1);assert.equal(Number(m.folds),t.steps.length);assert.equal(Number(m.merges),t.hashes.node);assert.equal(Number(m.frontierSha256CompressionBlocks),4*t.steps.length)}});
test('cost model counts real fixed-shape SHA work at depth 18',()=>{const m=costModel(144000,18);assert.ok(BigInt(m.oldNewPathCompressionBlocksLowerBound)>6n*BigInt(m.frontierSha256CompressionBlocks));});
test('differently timed authentic log can only match its own pin',()=>{let t=make(3);let other=transcript({entries:[record(1),record(2,250n),record(3)],genesis:g,source,watermarks:[{after:3,watermark:'2000'}]});assert.equal(checkTranscript(other.steps,other.claim,pinned(t)),false)});
