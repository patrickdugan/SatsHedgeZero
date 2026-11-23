import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {decodePythStandardPayload,verifyNativePythBtcUsd,INNER_MAGIC,PROPERTY} from '../src/pyth_payload.mjs';

// Upstream Pyth Lazer public SDK protocol test `payload/standard.rs::parse_payload`.
// Original message is historical; it serves as wire-parity evidence, NOT live authority.
const OFFICIAL='b9011a82c7887f3aaa5845b20d6bf5ca6609953b57650fa4579a4b4d34a4980ba608a9f76a825a446'+
'f3d6c1fd9daca1c5e3fc46980f14ef89c1a886c6e9e5c510872d30f80efc1f480c5615af3fb673d422'+
'87e993da9fbc3506b6e41dfa32950820c2e6c620075d3c7934077d115064b06000301010000000d009'+
'032fc171b060000014e3a0cff1a06000002bcda8a211b06000003120004f8ff05fc0b7159000000000'+
'600070008000900000aa06616362e0600000b804f93312e0600000c014077d115064b0600';
const sample=Buffer.from(OFFICIAL,'hex').subarray(102);
function fixture({raw=6000000000000n,conf=1200000000n,feed=1,expo=-8,
  timestamp=1795000000000000n,updated=1795000000000000n,channel=3,duplicate=false,
  extraProperty=null}={}) {
  const p=Buffer.alloc(4+8+1+1+4+1+13+3+9+10+(extraProperty?1:0));
  let i=0;p.writeUInt32LE(INNER_MAGIC,i);i+=4;
  p.writeBigUInt64LE(timestamp,i);i+=8;p[i++]=channel;p[i++]=1;
  p.writeUInt32LE(feed,i);i+=4;p[i++]=4+(extraProperty!==null?1:0);
  p[i++]=PROPERTY.Price;p.writeBigInt64LE(raw,i);i+=8;
  p[i++]=PROPERTY.Exponent;p.writeInt16LE(expo,i);i+=2;
  p[i++]=PROPERTY.Confidence;p.writeBigInt64LE(conf,i);i+=8;
  p[i++]=PROPERTY.FeedUpdateTimestamp;p[i++]=1;p.writeBigUInt64LE(updated,i);i+=8;
  if(extraProperty!==null)p[i++]=extraProperty;
  return p.subarray(0,i);
}
function signed(payload){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const pub=publicKey.export({format:'der',type:'spki'}).subarray(-32);
  const frame=Buffer.alloc(102+payload.length);
  frame.writeUInt32LE(2182742457,0);
  sign(null,payload,privateKey).copy(frame,4);pub.copy(frame,68);
  frame.writeUInt16LE(payload.length,100);payload.copy(frame,102);
  return {envelopeHex:frame.toString('hex'),pubkey:pub.toString('hex')};
}
const policy={feedId:1,allowedChannelIds:[3],maxAgeUs:'3000000',maxCarryForwardUs:'2000000',maxFutureSkewUs:'100000',maxConfBps:'100'};
const now='1795000001000000';
function verify(opts={},data={}){
 const x=signed(fixture(data));
 return verifyNativePythBtcUsd({envelopeHex:x.envelopeHex,signerKeys:[x.pubkey],policy:{...policy,...opts},nowUs:now});
}
test('upstream standard.rs signed sample decodes exact channel, 13 tags, BTC/USD and microseconds',()=>{
 const d=decodePythStandardPayload(sample);
 assert.equal(d.timestampUs,1771339368200000n);
 assert.equal(d.channelId,3);
 assert.equal(d.feeds.length,1);
 assert.equal(d.feeds[0].feedId,1);
 assert.equal(Object.keys(d.feeds[0].properties).length,13);
 assert.equal(d.feeds[0].properties.Price,6713436287632n);
 assert.equal(d.feeds[0].properties.Exponent,-8);
 assert.equal(d.feeds[0].properties.Confidence,1500580860n);
 assert.equal(d.feeds[0].properties.FeedUpdateTimestamp,1771339368200000n);
});
test('signed fixture authenticates BTC/USD numeric ID and exact signed price, confidence, time',()=>{
 const q=verify();
 assert.equal(q.priceE8,'6000000000000');
 assert.equal(q.nativePythSignatureVerified,true);
 assert.equal(q.priceFieldsParsedAndBound,true);
 assert.equal(q.provenanceGrade,'NATIVE_PYTH_ED25519_WITH_SIGNED_PRICE');
 assert.equal(q.nearFinalityVerified,false);
 assert.equal(q.bitcoinSpendEnforced,false);
 assert.match(q.receiptHash,/^[a-f0-9]{64}$/);
});
test('untrusted signer fails closed',()=>{
 const x=signed(fixture());assert.throws(()=>verifyNativePythBtcUsd({envelopeHex:x.envelopeHex,signerKeys:['bb'.repeat(32)],policy,nowUs:now}),/untrusted Pyth signer/);
});
test('tampered signed price fails Ed25519 verification',()=>{
 const x=signed(fixture());const tampered=Buffer.from(x.envelopeHex,'hex');tampered[120]^=1;
 assert.throws(()=>verifyNativePythBtcUsd({envelopeHex:tampered.toString('hex'),signerKeys:[x.pubkey],policy,nowUs:now}),/invalid Pyth Ed25519/);
});
test('wrong signed feed ID is never treated as BTC/USD',()=>assert.throws(()=>verify({},{feed:2}),/BTC\/USD feed is absent/));
test('wrong signed channel ID violates immutable policy',()=>assert.throws(()=>verify({},{channel:1}),/channel policy mismatch/));
test('publisher confidence over threshold blocks a signed observation',()=>assert.throws(()=>verify({},{conf:100000000000n}),/confidence wider/));
test('signed carried-forward price is rejected after allowed window',()=>assert.throws(()=>verify({},{updated:1794999990000000n}),/carried-forward/));
test('signed future timestamp rejected',()=>assert.throws(()=>verify({},{timestamp:1795000002000000n,updated:1795000002000000n}),/future native Pyth/));
test('stale signed publish timestamp rejected',()=>assert.throws(()=>verify({},{timestamp:1794999980000000n,updated:1794999980000000n}),/stale native Pyth/));
test('signed zero price and absent confidence fail closed',()=>assert.throws(()=>verify({},{raw:0n}),/missing valid signed BTC/));
test('duplicate property tag cannot shadow verified price',()=>assert.throws(()=>decodePythStandardPayload(fixture({extraProperty:0})),/duplicate Pyth property tag/));
test('unknown property tag is rejected even after signed known fields',()=>assert.throws(()=>decodePythStandardPayload(fixture({extraProperty:255})),/unknown Pyth property tag/));
test('truncation and trailing data are both rejected',()=>{
 const raw=fixture();assert.throws(()=>decodePythStandardPayload(raw.subarray(0,-1)),/truncated/);
 assert.throws(()=>decodePythStandardPayload(Buffer.concat([raw,Buffer.from([0])])),/trailing bytes/);
});
test('wrong payload magic and unsupported channel fail',()=>{
 const p=fixture(),q=Buffer.from(p);q[0]^=1;assert.throws(()=>decodePythStandardPayload(q),/inner payload magic/);
 const r=Buffer.from(p);r[12]=0;assert.throws(()=>decodePythStandardPayload(r),/channel ID/);
});
test('policy requires pinned signer registry and numeric BTC/USD 1',()=>{
 const x=signed(fixture());
 assert.throws(()=>verifyNativePythBtcUsd({envelopeHex:x.envelopeHex,signerKeys:[],policy,nowUs:now}),/pinned Pyth signer/);
 assert.throws(()=>verifyNativePythBtcUsd({envelopeHex:x.envelopeHex,signerKeys:[x.pubkey],policy:{...policy,feedId:2},nowUs:now}),/unexpected Pyth BTC/);
});
