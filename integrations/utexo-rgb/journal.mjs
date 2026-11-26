import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { replay } from './recovery-model.mjs';

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
function validate(records, id, keys) {
  const events = [], reserves = new Map(), evidence = new Set();
  for (const record of records) {
    shape(record,['event','auth']);
    const e = record.event;
    requireThat(e && Object.hasOwn(fields,e.type),'unknown event type');
    shape(e,fields[e.type]); shape(record.auth,authRoles[e.type]);
    // Only canonical primitive values enter the event; no opaque SDK blobs or secrets.
    for (const value of Object.values(e)) requireThat(typeof value === 'string' || Number.isSafeInteger(value),'invalid event scalar');
    const reservation = e.type === 'reserve' ? e : reserves.get(e.id);
    requireThat(reservation,'missing reservation');
    for (const role of authRoles[e.type]) {
      const sig = record.auth[role];
      requireThat(typeof sig === 'string' && /^[0-9a-f]{128}$/.test(sig),'invalid signature encoding');
      requireThat(verify(null,receiptMessage(id,role,reservation,e),keys[role],Buffer.from(sig,'hex')),'attestation signature rejected');
    }
    if (e.type === 'reserve') reserves.set(e.id,e);
    if (e.type === 'reconcile') {
      // A stable external proof ID may not fund multiple obligations, even across roles.
      for (const ref of [e.btcEvidence,e.rgbEvidence]) {
        requireThat(hex(ref) && !evidence.has(ref),'reused external evidence'); evidence.add(ref);
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
function load(fd, header, pin, keys) {
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
  return {tip,records,state:validate(records,header.journalId,keys),bytes:buf.length};
}
function journal(dir, policy, journalId, expectedPin, create=false) {
  requireThat(process.platform==='linux','Linux local filesystem qualification only');
  requireThat(hex(journalId),'invalid journal ID');
  const {keys,fingerprints}=normalizePolicy(policy);
  const header={schema:'SHZ/RGB/JOURNAL/V1',journalId,fingerprints};
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
    data=load(fd,header,expectedPin,keys);
  }catch(e){release();throw e;}
  const usable=()=>requireThat(!closed&&!poisoned,'journal closed or poisoned');
  return Object.freeze({
    tip(){usable();return {...data.tip};},
    snapshot(){usable();return structuredClone(data.state);},
    append(record){
      usable();record=structuredClone(record);
      requireThat(Buffer.byteLength(encode(record))<=MAX_LINE,'oversized record');
      const records=[...data.records,record];const state=validate(records,journalId,keys);
      const seq=data.tip.seq+1,prev=data.tip.digest,digest=frameHash(seq,prev,record);
      const line=encode({seq,prev,record,digest})+'\n';const size=Buffer.byteLength(line);
      requireThat(size<=MAX_LINE && data.bytes+size<=MAX_BYTES,'journal limit');
      try{fs.writeFileSync(fd,line);fs.fsyncSync(fd);}catch(e){poisoned=true;throw e;}
      data={tip:{seq,digest},records,state,bytes:data.bytes+size};return {...data.tip};
    },
    close(){if(!closed){closed=true;release();}}
  });
}
const createJournal=(dir,policy,id)=>journal(dir,policy,id,undefined,true);
const openJournal=(dir,policy,id,pin)=>journal(dir,policy,id,pin,false);
export {createJournal,openJournal,receiptMessage};
