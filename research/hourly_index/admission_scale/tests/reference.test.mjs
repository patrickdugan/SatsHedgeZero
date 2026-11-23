import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generate, record, DEPTH, CAP, BASE, PERIOD } from '../fixtures/build.mjs';
import { costModel } from '../../admission_fused/frontier.mjs';
import { GENESIS_TESTNET4 } from '../../index.mjs';
import { buildLog, select, verifySelection } from '../../maximality/log.mjs';
const read=n=>JSON.parse(readFileSync(new URL(`../fixtures/${n}-expected.json`,import.meta.url)));
test('small ladder matches independently committed depth-18 roots and complete states',()=>{
 const ns=[0,1,16,128,512];const r=generate(ns);
 assert.deepEqual(r.claims,ns.map(read));assert.ok(r.metrics.every(x=>x.packed_fields===44&&!x.nova_verified));
});
test('synthetic records have bounded positive values and correct source domain',()=>{
 for(const n of [1,16,144000,CAP-1]){const p=record(n),c=record(n,'chainlink');assert.equal(p.publish_us,String(BASE+BigInt(n)*PERIOD));assert.notEqual(p.report_hash,c.report_hash);assert.notEqual(p.price_e8,c.price_e8);}
 for(const n of [0,CAP,-1,1.5])assert.throws(()=>record(n));
});
test('independent MAX-01 verifier accepts depth18 paths under same streamed pin',()=>{
 const c=read(128),entries=Array.from({length:128},(_,i)=>record(i+1));const tree=buildLog({genesis:GENESIS_TESTNET4,source:'pyth',depth:DEPTH,entries,sealed_through:c.header.sealed_through});
 assert.equal(c.pin,tree.pin);let cutoff=BASE+32n*PERIOD;assert.ok(verifySelection(select(tree,cutoff),{pin:c.pin,genesis:GENESIS_TESTNET4,source:'pyth',cutoff}));
 const early=select(tree,cutoff-PERIOD);assert.equal(verifySelection(early,{pin:c.pin,genesis:GENESIS_TESTNET4,source:'pyth',cutoff}),false);
});
test('full workload and capacity fit explicit operation ceiling',()=>{
 for(const n of [0,1,16,128,512,2048,8192,144000,CAP-1]){const m=costModel(n,DEPTH,1);const folds=2*n+2-Array.from((n+1).toString(2)).filter(c=>c==='1').length;assert.equal(Number(m.folds),folds);assert.ok(folds<2**20);}
 assert.equal(costModel(144000,DEPTH,1).folds,'287996');assert.equal(costModel(144000,DEPTH,1).frontierSha256CompressionBlocks,'575992');
});
test('wrong depth or snapshot context cannot match the independently generated pin',()=>{const c=read(16),entries=Array.from({length:16},(_,i)=>record(i+1));let b=buildLog({genesis:GENESIS_TESTNET4,source:'pyth',entries,depth:17,sealed_through:c.header.sealed_through});assert.notEqual(b.pin,c.pin);b=buildLog({genesis:GENESIS_TESTNET4,source:'chainlink',entries,depth:DEPTH,sealed_through:c.header.sealed_through});assert.notEqual(b.pin,c.pin)});
