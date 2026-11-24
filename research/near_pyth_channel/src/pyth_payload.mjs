/**
 * Strict, dependency-free decoder of Pyth Pro/Lazer *standard* little-endian
 * PayloadData from sdk/rust/protocol/src/payload/standard.rs.
 * Parsing is only safe after the outer Solana Ed25519 signature verifies.
 * Deliberately rejects unknown/duplicate properties and trailing bytes.
 * Pyth Pro numeric feed IDs differ from Pyth Core 32-byte Hermes IDs.
 */
import {createHash} from 'node:crypto';
import {verifyPythProSolanaEnvelope} from './pyth_native.mjs';
import {normalizePoint} from './oracle.mjs';

export const INNER_MAGIC = 2479346549;
export const BTC_USD_PYTH_PRO_FEED_ID = 1;
export const PROPERTY = Object.freeze({
  Price:0, BestBidPrice:1, BestAskPrice:2, PublisherCount:3, Exponent:4,
  Confidence:5, FundingRate:6, FundingTimestamp:7, FundingRateInterval:8,
  MarketSession:9, EmaPrice:10, EmaConfidence:11, FeedUpdateTimestamp:12,
});
const propertyNames=Object.keys(PROPERTY);
const err=x=>{throw new Error(x)};
const isHex=h=>typeof h==='string' && /^(?:[0-9a-f]{2})+$/.test(h);
const u64=v=>BigInt(v);

export function decodePythStandardPayload(signedPayload) {
  const buf=Buffer.from(signedPayload);
  if(buf.length<14 || buf.length>8192)err('invalid Pyth PayloadData length');
  let p=0;
  function read(n){if(n<0||p+n>buf.length)err('truncated Pyth PayloadData');const o=p;p+=n;return o;}
  const read8=()=>buf.readUInt8(read(1));
  const readU16=()=>buf.readUInt16LE(read(2));
  const readI16=()=>buf.readInt16LE(read(2));
  const readU32=()=>buf.readUInt32LE(read(4));
  const readI64=()=>buf.readBigInt64LE(read(8));
  const readU64=()=>buf.readBigUInt64LE(read(8));
  if(readU32()!==INNER_MAGIC)err('wrong Pyth inner payload magic');
  const timestampUs=readU64();
  const channelId=read8(),count=read8();
  if(channelId<1||channelId>4)err('invalid Pyth channel ID');
  if(count===0||count>32)err('invalid Pyth feed count');
  const feeds=[],seenFeeds=new Set();
  for(let i=0;i<count;i++) {
    const feedId=readU32(),propertiesCount=read8();
    if(seenFeeds.has(feedId))err('duplicate Pyth feed ID');
    seenFeeds.add(feedId);
    if(propertiesCount===0||propertiesCount>13)err('invalid property count');
    const properties={},seenTags=new Set();
    for(let j=0;j<propertiesCount;j++) {
      const tag=read8();
      if(tag>12)err('unknown Pyth property tag');
      if(seenTags.has(tag))err('duplicate Pyth property tag');
      seenTags.add(tag);
      let value;
      if([0,1,2,5,10,11].includes(tag)){
        const v=readI64();value=v===0n?null:v;
      } else if(tag===3) value=readU16();
      else if(tag===4) value=readI16();
      else if([6,7,8,12].includes(tag)) {
        const present=read8();
        if(present!==0&&present!==1)err('invalid Pyth optional property presence flag');
        value=present===0?null:(tag===6?readI64():readU64());
      } else if(tag===9) { value=readI16(); if(value<0||value>4)err('invalid Pyth market session'); }
      properties[propertyNames[tag]]=value;
    }
    feeds.push(Object.freeze({feedId,properties:Object.freeze(properties)}));
  }
  if(p!==buf.length)err('trailing bytes after Pyth PayloadData');
  return Object.freeze({timestampUs,channelId,feeds:Object.freeze(feeds)});
}

const dec=(v,field)=>{if(typeof v!=='bigint'&&typeof v!=='number'&&typeof v!=='string')err(`invalid ${field}`);const s=String(v);if(!/^(0|[1-9][0-9]*)$/.test(s))err(`invalid ${field}`);return BigInt(s)};
/**
 * Verify the native signed binary and decode its BTC/USD price from those same
 * authenticated bytes. `signerKeys` must be independently pinned by governance.
 * This outputs a PROVENANCE receipt, not a live NEAR inclusion or BTC spend proof.
 */
export function verifyNativePythBtcUsd({envelopeHex,signerKeys,policy,nowUs}) {
  if(!policy || policy.feedId!==BTC_USD_PYTH_PRO_FEED_ID)err('unexpected Pyth BTC/USD feed policy');
  if(!Array.isArray(signerKeys)||signerKeys.length===0)err('missing independently pinned Pyth signer registry');
  const verified=verifyPythProSolanaEnvelope(envelopeHex,signerKeys);
  const raw=Buffer.from(envelopeHex,'hex');
  const decoded=decodePythStandardPayload(raw.subarray(102));
  const feed=decoded.feeds.find(x=>x.feedId===policy.feedId);
  if(!feed)err('BTC/USD feed is absent from signed Pyth payload');
  const p=feed.properties;
  if(typeof p.Price!=='bigint'||p.Price<=0n||!Number.isInteger(p.Exponent)||
     typeof p.Confidence!=='bigint'||p.Confidence<0n || typeof p.FeedUpdateTimestamp!=='bigint') {
    err('missing valid signed BTC/USD price, exponent, confidence or feed-update time');
  }
  if(Array.isArray(policy.allowedChannelIds) && !policy.allowedChannelIds.includes(decoded.channelId))err('Pyth channel policy mismatch');
  const normalized=normalizePoint({feedId:feed.feedId,rawPrice:String(p.Price),
    conf:String(p.Confidence),expo:p.Exponent,publishTimeUs:decoded.timestampUs.toString(),
    feedUpdateTimeUs:p.FeedUpdateTimestamp.toString()});
  const now=dec(nowUs,'nowUs'),age=dec(policy.maxAgeUs,'maxAgeUs'),carry=dec(policy.maxCarryForwardUs,'maxCarryForwardUs'),
    future=dec(policy.maxFutureSkewUs??0,'maxFutureSkewUs'),maxConf=dec(policy.maxConfBps,'maxConfBps');
  if(normalized.publishTimeUs>now+future)err('future native Pyth update');
  if(now>normalized.publishTimeUs&&now-normalized.publishTimeUs>age)err('stale native Pyth update');
  if(normalized.publishTimeUs-normalized.feedUpdateTimeUs>carry)err('carried-forward Pyth feed too old');
  if(BigInt(normalized.confBps)>maxConf)err('Pyth confidence wider than policy');
  const domain='SHZ/PYTH-NATIVE-PRICE-IMPORT/V2';
  const sourceCommitment=createHash('sha256').update(JSON.stringify([
     domain,verified.signerKeyHex,verified.signedPayloadSha256,
     decoded.channelId,feed.feedId,p.Price.toString(),p.Exponent,p.Confidence.toString(),
     normalized.publishTimeUs.toString(),normalized.feedUpdateTimeUs.toString(),
  ])).digest('hex');
  return Object.freeze({
    priceE8:normalized.priceE8,confBps:normalized.confBps,
    publishTimeUs:normalized.publishTimeUs.toString(),feedUpdateTimeUs:normalized.feedUpdateTimeUs.toString(),
    rawPrice:p.Price.toString(),expo:p.Exponent,confidence:String(p.Confidence),
    feedId:feed.feedId,channelId:decoded.channelId,
    signerKeyHex:verified.signerKeyHex,signedPayloadSha256:verified.signedPayloadSha256,
    receiptHash:sourceCommitment,sourceCommitment,
    provenanceGrade:'NATIVE_PYTH_ED25519_WITH_SIGNED_PRICE',
    nativePythSignatureVerified:true,priceFieldsParsedAndBound:true,
    nearContractVerified:false,nearFinalityVerified:false,bitcoinSpendEnforced:false,productionReady:false,
  });
}
