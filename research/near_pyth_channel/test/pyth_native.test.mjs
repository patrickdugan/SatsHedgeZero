import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {verifyPythProSolanaEnvelope} from '../src/pyth_native.mjs';
function sample(){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const der=publicKey.export({format:'der',type:'spki'}),pub=der.subarray(-32);
  // Binary payload is deliberately synthetic; the outer format matches the Pyth Pro wire protocol.
  const payload=Buffer.from('synthetic-price-data-not-a-real-pyth-update');
  const sig=sign(null,payload,privateKey);
  const frame=Buffer.alloc(102+payload.length);
  frame.writeUInt32LE(2182742457,0);sig.copy(frame,4);pub.copy(frame,68);
  frame.writeUInt16LE(payload.length,100);payload.copy(frame,102);
  return {pubHex:pub.toString('hex'),frame};
}
test('verifies native-format Ed25519 signed payload under pinned signer',()=>{
 const x=sample();const got=verifyPythProSolanaEnvelope(x.frame.toString('hex'),[x.pubHex]);
 assert.equal(got.authenticSignedBytes,true);assert.equal(got.priceFieldsParsedAndBound,false);
 assert.equal(got.bitcoinSettlementAuthorized,false);
});
test('rejects signer substitution and unapproved signer',()=>{
 const x=sample();assert.throws(()=>verifyPythProSolanaEnvelope(x.frame.toString('hex'),[]),/untrusted Pyth signer/);
 x.frame[68]^=1;
 assert.throws(()=>verifyPythProSolanaEnvelope(x.frame.toString('hex'),[x.pubHex]),/untrusted Pyth signer/);
});
test('rejects tampered message, wrong envelope length and magic',()=>{
 const x=sample();const raw=x.frame.toString('hex');
 const tampered=Buffer.from(x.frame);tampered[tampered.length-1]^=1;
 assert.throws(()=>verifyPythProSolanaEnvelope(tampered.toString('hex'),[x.pubHex]),/invalid Pyth Ed25519/);
 assert.throws(()=>verifyPythProSolanaEnvelope(raw+'00',[x.pubHex]),/trailing bytes/);
 const bad=Buffer.from(x.frame);bad[0]=0;
 assert.throws(()=>verifyPythProSolanaEnvelope(bad.toString('hex'),[x.pubHex]),/wrong Pyth Pro/);
});
