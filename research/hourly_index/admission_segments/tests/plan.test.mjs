import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {makePlan,validatePlan,replaySegment} from '../plan.mjs';
import {legacy,pack} from '../../admission_packed/packing.mjs';
const claim=n=>JSON.parse(readFileSync(new URL(`../../admission_scale/fixtures/${n}-expected.json`,import.meta.url),'utf8'));
const c=claim(128), p=makePlan(c,32);
const check=f=>{const q=structuredClone(p);f(q);assert.equal(validatePlan(q,c),false)};
test('four independently replayable segments match frozen plan and complete prefix',()=>{
 const frozen=JSON.parse(readFileSync(new URL('../fixtures/128-plan.json',import.meta.url),'utf8'));
 assert.deepEqual(p,frozen);assert.deepEqual(p.segments.map(s=>s.folds),[63,64,63,66]);
 assert.equal(p.segments.reduce((a,s)=>a+s.folds,0),c.steps);
 assert.ok(p.segments.every(s=>replaySegment(s,c)));assert.ok(validatePlan(p,c));
});
test('all 44 packed boundary coordinates coincide',()=>{
 for(let i=1;i<p.segments.length;i++)assert.deepEqual(pack(legacy(p.segments[i-1].after,c.header.genesis,c.header.source,18),18),pack(legacy(p.segments[i].before,c.header.genesis,c.header.source,18),18));
});
test('zero-report seal, one report, uneven cuts and one segment are supported',()=>{
 for(const [n,k] of [[0,1],[1,1],[16,3],[128,128],[128,29]]){const x=claim(n),q=makePlan(x,k);assert.ok(validatePlan(q,x));assert.ok(q.segments.every(s=>replaySegment(s,x)));}
});
test('gap by deleting middle segment',()=>check(q=>q.segments.splice(1,1)));
test('duplicated segment',()=>check(q=>q.segments.splice(1,0,q.segments[0])));
test('reordering segments',()=>check(q=>[q.segments[0],q.segments[1]]=[q.segments[1],q.segments[0]]));
test('different declared fold count',()=>check(q=>q.segments[1].folds++));
test('noncanonical initial frontier',()=>check(q=>q.segments[0].before.frontier[0].digest='11'.repeat(32)));
test('changed final frontier',()=>check(q=>q.segments.at(-1).after.frontier.find(s=>s.occupied).digest='11'.repeat(32)));
test('different source root or relation',()=>{check(q=>q.snapshot_pin='11'.repeat(32));check(q=>q.relation+='-other');});
test('seal cannot be moved to earlier segment',()=>check(q=>{q.segments[0].after.sealed_through=c.header.sealed_through;q.segments[1].before=structuredClone(q.segments[0].after)}));
test('an arbitrary connected frontier cannot establish reachability: replay must reject',()=>{
 const q=structuredClone(p);const x=q.segments[0].after.frontier.find(s=>s.occupied);x.digest='11'.repeat(32);q.segments[1].before=structuredClone(q.segments[0].after);
 assert.ok(validatePlan(q,c),'a structural plan may have unverified intermediate commitments');
 assert.equal(replaySegment(q.segments[0],c),false);
 assert.equal(replaySegment(q.segments[1],c),false);
});
test('invalid segment size and resource limits fail closed',()=>{for(const k of [0,-1,1.1,4096,1])assert.throws(()=>makePlan(c,k));});
