import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixture.mjs';
import {verifyJointDollarStatement} from '../src/joint.mjs';
import {encodeHybridAnchor,decodeHybridAnchor,HybridAnchorReplayGate,HYBRID_V1_DATA_BYTES,MINT,BURN} from '../src/op_return.mjs';
const h=c=>c.repeat(64);
function values(){const f=fixture();const r=verifyJointDollarStatement(f,f.policy);return {digest:r.publicStatementDigest,origin:h('1')};}
test('76-byte proof-reference payload roundtrips with minimal OP_PUSHDATA1',()=>{
  const {digest,origin}=values();const hex=encodeHybridAnchor({propertyId:42,operation:MINT,statementDigest:digest,originNullifier:origin});
  assert.equal(hex.length/2,79);assert.equal(HYBRID_V1_DATA_BYTES,76);
  assert.deepEqual(decodeHybridAnchor(hex),{propertyId:42,operation:MINT,statementDigest:digest,originNullifier:origin});
});
test('staged anchor gate binds one proof and consumes one unique nullifier',()=>{
  const {digest,origin}=values();const gate=new HybridAnchorReplayGate({propertyId:42,expectedStatementDigest:digest});
  const hex=encodeHybridAnchor({propertyId:42,operation:MINT,statementDigest:digest,originNullifier:origin});
  assert.equal(gate.observe(hex).tradeLayerSupplyChanged,false);
  assert.throws(()=>gate.observe(hex),/event replay/);
  const next=encodeHybridAnchor({propertyId:42,operation:BURN,statementDigest:digest,originNullifier:h('2')});
  assert.equal(gate.observe(next).operation,BURN);
});
test('OP_RETURN cannot silently change asset property',()=>{
  const {digest,origin}=values();const gate=new HybridAnchorReplayGate({propertyId:42,expectedStatementDigest:digest});
  const hex=encodeHybridAnchor({propertyId:43,operation:MINT,statementDigest:digest,originNullifier:origin});
  assert.throws(()=>gate.observe(hex),/property substitution/);
});
test('OP_RETURN refuses a self-selected different Nova public statement',()=>{
  const {digest,origin}=values();const gate=new HybridAnchorReplayGate({propertyId:42,expectedStatementDigest:digest});
  const hex=encodeHybridAnchor({propertyId:42,operation:MINT,statementDigest:h('a'),originNullifier:origin});
  assert.throws(()=>gate.observe(hex),/statement substitution/);
});
test('OP_RETURN rejects trailing bytes and malleated nonminimal push',()=>{
  const {digest,origin}=values();const hex=encodeHybridAnchor({propertyId:42,operation:MINT,statementDigest:digest,originNullifier:origin});
  assert.throws(()=>decodeHybridAnchor(hex+'00'),/noncanonical/);
  assert.throws(()=>decodeHybridAnchor('6a4c4d'+hex.slice(6)),/noncanonical/);
});
test('OP_RETURN rejects unknown future operation and version until separately activated',()=>{
  const {digest,origin}=values();const hex=encodeHybridAnchor({propertyId:42,operation:MINT,statementDigest:digest,originNullifier:origin});
  const unknown=Buffer.from(hex,'hex');unknown[10]=3;
  assert.throws(()=>decodeHybridAnchor(unknown.toString('hex')),/unknown hybrid/);
  unknown[10]=MINT;unknown[9]=2;
  assert.throws(()=>decodeHybridAnchor(unknown.toString('hex')),/wrong TL-USDC/);
});
