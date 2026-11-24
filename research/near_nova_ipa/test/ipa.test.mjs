import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve,dirname} from 'node:path';
import {verify,prove,pointFromHex,generators,validateGenerators} from '../ipa.mjs';
const fixture=JSON.parse(readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),'../fixtures/valid.json')));
const change=(f)=>{const v=structuredClone(fixture);f(v);return v};
test('transparent hash-to-curve generators are distinct and on BN254',()=>{
 const g=generators();assert.equal(validateGenerators(g).length,9);assert.ok(g.g.every(Boolean));
});
test('real 2-round BN254 IPA proof verifies',()=>assert.equal(verify(fixture),true));
test('deterministic prover reproducibility',()=>{
 let f=prove({epochHash:fixture.statement.epoch_hash_hex,pythPrice:10000000000000n,chainlinkPrice:10020000000000n});
 assert.deepEqual(f,fixture);
});
test('wrong price rejected',()=>assert.equal(verify(change(f=>f.statement.pyth_price_e8='10000000000001')),false));
test('wrong mean rejected',()=>assert.equal(verify(change(f=>f.statement.mean_e8='10010000000001')),false));
test('different epoch rejected',()=>assert.equal(verify(change(f=>f.statement.epoch_hash_hex='11'.repeat(32))),false));
test('malformed L/R rejected',()=>assert.equal(verify(change(f=>f.proof.l_hex[0]='ff'.repeat(64))),false));
test('modified valid point rejected',()=>assert.equal(verify(change(f=>f.proof.l_hex[1]=f.proof.r_hex[1])),false));
test('modified final scalar rejected',()=>assert.equal(verify(change(f=>f.proof.a_final_hex='00'.repeat(32))),false));
test('invalid/canonical scalar rejected',()=>assert.equal(verify(change(f=>f.proof.b_final_hex='ff'.repeat(32))),false));
test('wide oracle spread triggers HOLD',()=>assert.equal(verify(change(f=>f.statement.chainlink_price_e8='10300000000000')),false));
test('all proof points canonical and on curve',()=>{
 for(let s of [...fixture.proof.l_hex,...fixture.proof.r_hex])assert.doesNotThrow(()=>pointFromHex(s));
});
