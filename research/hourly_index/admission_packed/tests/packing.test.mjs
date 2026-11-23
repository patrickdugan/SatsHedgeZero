import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {legacy,layout,pack,unpack} from '../packing.mjs';
import {advance,initial,makeClaim,transcript} from '../../admission_fused/frontier.mjs';
import {buildLog} from '../../maximality/log.mjs';
import {GENESIS_TESTNET4,shahex} from '../../index.mjs';
const read=p=>JSON.parse(readFileSync(new URL(p,import.meta.url),'utf8'));
const genesis=GENESIS_TESTNET4;
const records=Array.from({length:15},(_,i)=>({price_e8:String(10000000000000n+BigInt(i)),publish_us:String(i+1),report_hash:shahex(Buffer.from(`packed/${i}`))}));
const pow=n=>1n<<BigInt(n);
const PALLAS_FR=BigInt('0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001');
for(const depth of [4,18,24])test(`layout depth ${depth}: injective, below field modulus, exact coverage`,()=>{
 const l=layout(depth),seen=new Set();for(const g of l){let bits=new Set(),max=0n;for(const [i,o,w] of g){assert.ok(!seen.has(i));seen.add(i);for(let j=o;j<o+w;j++){assert.ok(!bits.has(j));bits.add(j)}max+=(pow(w)-1n)<<BigInt(o)}assert.ok(max<PALLAS_FR)}
 assert.equal(seen.size,12+4*(depth+1));assert.equal(l.length,6+2*(depth+1));
});
for(const source of ['pyth','chainlink'])test(`all ${source} frozen steps preserve exact fields and MAX-01 pin`,()=>{
 const claim=read(`../../admission_fused/fixtures/${source}-expected.json`),actions=read(`../../admission_fused/fixtures/${source}-steps.json`),max=read('../../maximality/fixtures/expected.json');
 let s=initial(4);for(const a of actions){for(const x of [s,advance(s,a.op,{...a,depth:4})]){const v=legacy(x,genesis,source,4);assert.deepEqual(unpack(pack(v,4),4),v)}s=advance(s,a.op,{...a,depth:4})}assert.deepEqual(makeClaim(s,{genesis,source,depth:4}),claim);assert.equal(claim.pin,max.pins[source]);
});
test('all 16 prefix lengths preserve root and full frontier packing',()=>{for(let n=0;n<=15;n++){const t=transcript({entries:records.slice(0,n),genesis,source:'pyth',depth:4,watermarks:[{after:n,watermark:'20'}]});for(const w of t.steps){for(const s of [w.before,w.after]){const v=legacy(s,genesis,'pyth',4);assert.deepEqual(unpack(pack(v,4),4),v)}}assert.equal(t.claim.pin,buildLog({entries:records.slice(0,n),genesis,source:'pyth',depth:4,sealed_through:'20'}).pin)}});
test('maximal canonical component vector roundtrips without field reduction',()=>{for(const d of [4,18,24]){const l=layout(d),v=Array(12+4*(d+1));for(const g of l)for(const [i,o,w]of g)v[i]=pow(w)-1n;assert.deepEqual(unpack(pack(v,d),d),v);assert.ok(pack(v,d).every(x=>x<PALLAS_FR))}});
test('every component rejects width overflow and negative value',()=>{const v=legacy(initial(4),genesis,'pyth',4);for(const g of layout(4))for(const [i,o,w]of g)for(const x of [pow(w),-1n]){const a=v.slice();a[i]=x;assert.throws(()=>pack(a,4))}});
test('every packed coordinate rejects high bits',()=>{const v=pack(legacy(initial(4),genesis,'pyth',4),4);for(const [j,g] of layout(4).entries()){let a=v.slice();a[j]+=pow(Math.max(...g.map(([i,o,w])=>o+w)));assert.throws(()=>unpack(a,4))}});
test('unchecked linear aliases preserve field but canonical range rejects',()=>{const v=legacy(initial(4),genesis,'pyth',4);const unchecked=a=>layout(4).map(g=>g.reduce((n,[i,o])=>n+(a[i]<<BigInt(o)),0n));for(const [lo,hi,w] of [[0,1,32],[1,2,32],[2,3,64],[3,4,64],[4,5,1],[5,9,8],[6,7,64],[10,11,64]]){let a=v.slice();a[lo]+=pow(w);a[hi]-=1n;assert.deepEqual(unchecked(a),unchecked(v));assert.throws(()=>pack(a,4));}});
test('context and all canonical components are distinguishable',()=>{const v=legacy(initial(4),genesis,'pyth',4),a=pack(v,4);for(const g of layout(4))for(const [i,o,w] of g){let b=v.slice();b[i]=(b[i]+1n)%pow(w);assert.notDeepEqual(pack(b,4),a)}assert.notDeepEqual(pack(legacy(initial(4),genesis,'chainlink',4),4),a)});
test('depth-18 reference initial state uses 44 fields, with headroom',()=>{const v=legacy(initial(18),genesis,'pyth',18);assert.equal(v.length,88);assert.equal(pack(v,18).length,44);assert.deepEqual(unpack(pack(v,18),18),v)});
