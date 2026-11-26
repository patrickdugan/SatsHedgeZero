import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPublicKey, sign as edSign, verify } from 'node:crypto';
import { replay } from './recovery-model.mjs';
import {
  verifyWithdrawalReceipt,
  verifyConversionQuote,
  rejectExplorerOrSimulated,
} from './withdrawal-receipt.mjs';

const MAX_BYTES = 4 * 1024 * 1024, MAX_LINE = 16384;
const roles = ['reserve', 'btc', 'rgb', 'conflict'];
const fields = {
  reserve: ['type','id','withdrawalId','network','assetId','units','sats','carrierMsat','payee','batchDigest','paymentHash','at','expiresAt'],
  submit: ['type','id','at'], ambiguous: ['type','id','at'],
  observe: ['type','id','at','paymentHash'],
  reconcile: ['type','id','at','network','assetId','units','sats','carrierMsat','payee','paymentHash','btcEvidence','rgbEvidence'],
  chain_conflict: ['type','id','at','conflictEvidence']
};
const authRoles = { reserve:['reserve'], submit:[], ambiguous:[], observe:[], reconcile:['btc','rgb'], chain_conflict:['conflict'] };
const requireThat = (v,m) => { if (!v) throw new Error(m); };
const hash = v => createHash('sha256').update(v).digest('hex');
const hex = v => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && !/^0+$/.test(v);
function shape(o, keys) {
  requireThat(o && Object.getPrototypeOf(o) === Object.prototype && Object.keys(o).length === keys.length && keys.every(k => Object.hasOwn(o,k)), 'unexpected object fields');
}
function canonical(o) {
  if (Array.isArray(o)) return o.map(canonical);
  if (o && typeof o === 'object') return Object.fromEntries(Object.keys(o).sort().map(k => [k, canonical(o[k])]));
  requireThat(typeof o === 'string' || (typeof o === 'number' && Number.isSafeInteger(o)), 'unsupported canonical value');
  return o;
}
const encode = o => JSON.stringify(canonical(o));
function normalizePolicy(policy) {
  shape(policy, roles);
  const keys = {}, fingerprints = {};
  for (const role of roles) {
    const key = createPublicKey(policy[role]);
    requireThat(key.asymmetricKeyType === 'ed25519','Ed25519 required');
    keys[role] = key; fingerprints[role] = hash(key.export({type:'spki',format:'der'}));
  }
  requireThat(new Set(Object.values(fingerprints)).size === roles.length,'independent keys required');
  return {keys,fingerprints};
}
function receiptMessage(journalId, role, reservation, event) {
  requireThat(hex(journalId) && roles.includes(role),'invalid signing domain');
  shape(event, fields[event.type] || []);
  requireThat(authRoles[event.type]?.includes(role),'unexpected signer role');
  shape(reservation, fields.reserve);
  return Buffer.from(encode(['SHZ/RGB/JOURNAL/ATTEST/V1',journalId,role,reservation,event]));
}
function validate(records, id, keys, receiptPolicy = null) {
  const events = [], reserves = new Map(), evidence = new Set(), consumedReceipts = new Set(), consumedLanes = new Set();
  for (const record of records) {
    const hasReceiptAuth = Object.hasOwn(record, 'receipt') || Object.hasOwn(record, 'quote') || Object.hasOwn(record, 'providerSig');
    if (hasReceiptAuth) {
      shape(record, ['event', 'auth', 'receipt', 'quote', 'providerSig']);
    } else {
      shape(record, ['event', 'auth']);
    }
    const e = record.event;
    requireThat(e && Object.hasOwn(fields, e.type), 'unknown event type');
    shape(e, fields[e.type]); shape(record.auth, authRoles[e.type]);
    for (const value of Object.values(e)) requireThat(typeof value === 'string' || Number.isSafeInteger(value), 'invalid event scalar');
    const reservation = e.type === 'reserve' ? e : reserves.get(e.id);
    requireThat(reservation, 'missing reservation');
    if (e.type === 'reserve' && (receiptPolicy || hasReceiptAuth)) {
      requireThat(receiptPolicy && hasReceiptAuth, 'durable Rust withdrawal receipt and conversion quote required');
      const rv = verifyWithdrawalReceipt(record.receipt, {
        network: receiptPolicy.network ?? 'regtest',
        routerConfig: receiptPolicy.routerConfig,
        routerSigner: receiptPolicy.routerSigner,
        routerId: receiptPolicy.routerId,
        requireState: 'reserved',
      });
      requireThat(!consumedReceipts.has(rv.receiptDigest) && !consumedLanes.has(rv.laneKey), 'duplicate withdrawal receipt consumption');
      verifyConversionQuote(record.quote, record.providerSig, record.receipt, {
        network: receiptPolicy.network ?? 'regtest',
        providerKeys: receiptPolicy.providerKeys,
        assetAllowlist: receiptPolicy.assetAllowlist,
        maxFeeCeilingSats: receiptPolicy.maxFeeCeilingSats,
        maxOracleAgeUs: receiptPolicy.maxOracleAgeUs,
        nowSec: e.at,
      });
      requireThat(
        e.withdrawalId === record.receipt.withdrawal_id &&
        e.sats === record.receipt.amount_sats &&
        e.network === record.receipt.network &&
        e.assetId === record.quote.assetId &&
        e.units === record.quote.assetUnits &&
        e.carrierMsat === record.quote.carrierMsat &&
        e.payee === record.quote.destination &&
        e.paymentHash === record.quote.paymentHash &&
        e.expiresAt === record.quote.expiresAt &&
        BigInt(e.at) * 1000000n >= BigInt(record.receipt.reserved_at_us) &&
        BigInt(e.at) * 1000000n < BigInt(record.receipt.expires_us),
        'reservation does not match verified withdrawal receipt and conversion quote'
      );
      if (!/^0+$/.test(record.receipt.batch_digest)) {
        requireThat(e.batchDigest === record.receipt.batch_digest, 'reservation batchDigest does not match withdrawal receipt');
      }
      consumedReceipts.add(rv.receiptDigest);
      consumedLanes.add(rv.laneKey);
    }
    for (const role of authRoles[e.type]) {
      const sig = record.auth[role];
      requireThat(typeof sig === 'string' && /^[0-9a-f]{128}$/.test(sig), 'invalid signature encoding');
      requireThat(verify(null, receiptMessage(id, role, reservation, e), keys[role], Buffer.from(sig, 'hex')), 'attestation signature rejected');
    }
    if (e.type === 'reserve') reserves.set(e.id, e);
    if (e.type === 'reconcile') {
      // A stable external proof ID may not fund multiple obligations, even across roles.
      for (const ref of [e.btcEvidence, e.rgbEvidence]) {
        requireThat(hex(ref) && !evidence.has(ref), 'reused external evidence'); evidence.add(ref);
      }
    }
    events.push(e);
  }
  return replay(events);
}
const frameHash = (seq,prev,record) => hash(encode(['SHZ/RGB/JOURNAL/FRAME/V1',seq,prev,record]));
const syncDir = dir => { const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY); try {fs.fsyncSync(fd);} finally {fs.closeSync(fd);} };
function exactPin(pin, actual) {
  shape(pin,['seq','digest']);
  requireThat(pin.seq === actual.seq && pin.digest === actual.digest,'external tip mismatch: stop and investigate');
}
function load(fd, header, pin, keys, receiptPolicy = null) {
  const stat=fs.fstatSync(fd);
  requireThat(stat.isFile() && stat.size>0 && stat.size<=MAX_BYTES,'journal size/type invalid');
  const buf=Buffer.alloc(stat.size);let offset=0;
  while(offset<buf.length){const n=fs.readSync(fd,buf,offset,buf.length-offset,offset);requireThat(n>0,'short journal read');offset+=n;}
  const raw=new TextDecoder('utf-8',{fatal:true}).decode(buf);
  requireThat(raw.endsWith('\n'),'torn journal: refuse reopen');
  const lines=raw.slice(0,-1).split('\n');
  requireThat(lines[0]===encode(header),'journal header/policy mismatch');
  let tip={seq:0,digest:hash(lines[0])};const records=[];
  for(const line of lines.slice(1)){
    requireThat(Buffer.byteLength(line)<=MAX_LINE,'oversized frame');
    const f=JSON.parse(line);shape(f,['seq','prev','record','digest']);
    requireThat(line===encode(f) && f.seq===tip.seq+1 && f.prev===tip.digest && f.digest===frameHash(f.seq,f.prev,f.record),'invalid hash chain');
    records.push(f.record);tip={seq:f.seq,digest:f.digest};
  }
  exactPin(pin,tip);
  return {tip,records,state:validate(records,header.journalId,keys,receiptPolicy),bytes:buf.length};
}
function receiptPolicyPin(receiptPolicy) {
  if (!receiptPolicy) return null;
  requireThat(hex(receiptPolicy.routerConfig) && hex(receiptPolicy.routerSigner), 'invalid receiptPolicy pin');
  return {
    network: receiptPolicy.network ?? 'regtest',
    routerConfig: receiptPolicy.routerConfig,
    routerSigner: receiptPolicy.routerSigner,
  };
}
function journal(dir, policy, journalId, expectedPin, create=false, opts={}) {
  requireThat(process.platform==='linux','Linux local filesystem qualification only');
  requireThat(hex(journalId),'invalid journal ID');
  const {keys,fingerprints}=normalizePolicy(policy);
  const receiptPolicy = opts?.receiptPolicy ?? null;
  const rpPin = receiptPolicyPin(receiptPolicy);
  const header = rpPin
    ? {schema:'SHZ/RGB/JOURNAL/V2',journalId,fingerprints,receiptPolicy:rpPin}
    : {schema:'SHZ/RGB/JOURNAL/V1',journalId,fingerprints};
  dir=path.resolve(dir);const lock=path.join(dir,'.writer'),filename=path.join(dir,'events.jsonl');
  if(create){requireThat(expectedPin===undefined,'create cannot accept an existing pin');fs.mkdirSync(dir,{mode:0o700});syncDir(path.dirname(dir));}
  const ds=fs.lstatSync(dir);requireThat(ds.isDirectory() && (ds.mode&0o077)===0,'private real journal directory required');
  fs.mkdirSync(lock,{mode:0o700}); // exclusive, no stale-lock takeover
  let fd, data, closed=false, poisoned=false;
  const release=()=>{ if(fd!==undefined){fs.closeSync(fd);fd=undefined;} fs.rmdirSync(lock);syncDir(dir); };
  try{
    syncDir(dir);
    const flags=fs.constants.O_RDWR|fs.constants.O_APPEND|fs.constants.O_NOFOLLOW;
    fd=fs.openSync(filename,flags|(create?fs.constants.O_CREAT|fs.constants.O_EXCL:0),0o600);
    requireThat((fs.fstatSync(fd).mode&0o077)===0,'private journal file required');
    if(create){const line=encode(header)+'\n';fs.writeFileSync(fd,line);fs.fsyncSync(fd);syncDir(dir);expectedPin={seq:0,digest:hash(encode(header))};}
    data=load(fd,header,expectedPin,keys,receiptPolicy);
  }catch(e){release();throw e;}
  const usable=()=>requireThat(!closed&&!poisoned,'journal closed or poisoned');
  return Object.freeze({
    tip(){usable();return {...data.tip};},
    snapshot(){usable();return structuredClone(data.state);},
    append(record){
      usable();record=structuredClone(record);
      requireThat(Buffer.byteLength(encode(record))<=MAX_LINE,'oversized record');
      const records=[...data.records,record];const state=validate(records,journalId,keys,receiptPolicy);
      const seq=data.tip.seq+1,prev=data.tip.digest,digest=frameHash(seq,prev,record);
      const line=encode({seq,prev,record,digest})+'\n';const size=Buffer.byteLength(line);
      requireThat(size<=MAX_LINE && data.bytes+size<=MAX_BYTES,'journal limit');
      try{fs.writeFileSync(fd,line);fs.fsyncSync(fd);}catch(e){poisoned=true;throw e;}
      data={tip:{seq,digest},records,state,bytes:data.bytes+size};return {...data.tip};
    },
    close(){if(!closed){closed=true;release();}}
  });
}
function createReserveAuthorizer({ journalId, reservePrivateKey, receiptPolicy }) {
  requireThat(hex(journalId) && reservePrivateKey && receiptPolicy, 'invalid reserve authorizer config');
  const consumedReceipts = new Set(), consumedLanes = new Set();
  return Object.freeze({
    authorize({ id, receipt, quote, providerSig, at, batchDigest }) {
      rejectExplorerOrSimulated(receipt);
      const rv = verifyWithdrawalReceipt(receipt, { ...receiptPolicy, requireState: 'reserved', nowUs: BigInt(at) * 1000000n });
      requireThat(!consumedReceipts.has(rv.receiptDigest) && !consumedLanes.has(rv.laneKey), 'duplicate withdrawal receipt consumption');
      verifyConversionQuote(quote, providerSig, receipt, { ...receiptPolicy, nowSec: at });
      const effectiveBatch = !/^0+$/.test(receipt.batch_digest) ? receipt.batch_digest : batchDigest;
      requireThat(hex(effectiveBatch), 'non-zero batchDigest required');
      const event = {
        type: 'reserve', id, withdrawalId: receipt.withdrawal_id, network: receipt.network,
        assetId: quote.assetId, units: quote.assetUnits, sats: receipt.amount_sats,
        carrierMsat: quote.carrierMsat, payee: quote.destination, batchDigest: effectiveBatch,
        paymentHash: quote.paymentHash, at, expiresAt: quote.expiresAt,
      };
      const sig = edSign(null, receiptMessage(journalId, 'reserve', event, event), reservePrivateKey).toString('hex');
      consumedReceipts.add(rv.receiptDigest);
      consumedLanes.add(rv.laneKey);
      return { event, auth: { reserve: sig }, receipt: structuredClone(receipt), quote: structuredClone(quote), providerSig };
    },
  });
}
const createJournal=(dir,policy,id,opts)=>journal(dir,policy,id,undefined,true,opts);
const openJournal=(dir,policy,id,pin,opts)=>journal(dir,policy,id,pin,false,opts);
export {createJournal,openJournal,receiptMessage,createReserveAuthorizer};
