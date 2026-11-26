import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign, randomBytes } from 'node:crypto';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createJournal, openJournal, receiptMessage } from './journal.mjs';

const h = c => c.repeat(64);
const makeFixture = t => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'shz-rgb-journal-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const dir=path.join(root,'book'),id=randomBytes(32).toString('hex'),keys={},policy={};
  for(const role of ['reserve','btc','rgb','conflict']){
    keys[role]=generateKeyPairSync('ed25519');
    policy[role]=keys[role].publicKey.export({type:'spki',format:'pem'});
  }
  const r={type:'reserve',id:'a',withdrawalId:'w1',network:'regtest',assetId:'rgb:fixture',units:'25',sats:'1000',carrierMsat:'3000000',payee:'02'+h('a'),batchDigest:h('b'),paymentHash:h('c'),at:1,expiresAt:10};
  const sub={type:'submit',id:'a',at:2},amb={type:'ambiguous',id:'a',at:3};
  const done={type:'reconcile',id:'a',at:11,network:r.network,assetId:r.assetId,units:r.units,sats:r.sats,carrierMsat:r.carrierMsat,payee:r.payee,paymentHash:r.paymentHash,btcEvidence:h('d'),rgbEvidence:h('e')};
  const conflict={type:'chain_conflict',id:'a',at:12,conflictEvidence:h('f')};
  const signed=(event,roles,reservation=r,domain=id)=>({event,auth:Object.fromEntries(roles.map(role=>[role,sign(null,receiptMessage(domain,role,reservation,event),keys[role].privateKey).toString('hex')]))});
  return {dir,id,policy,r,sub,amb,done,conflict,signed,open:pin=>openJournal(dir,policy,id,pin),create:()=>createJournal(dir,policy,id)};
};
const local=event=>({event,auth:{}});

test('durable signed reconciliation, exact tip and conflict freeze',t=>{
  const f=makeFixture(t),j=f.create();const genesis=j.tip();
  const p1=j.append(f.signed(f.r,['reserve']));
  j.append(local(f.sub));j.append(local(f.amb));
  assert.throws(()=>j.append(local({...f.sub,at:4})),/invalid or expired submit/);
  const p=j.append(f.signed(f.done,['btc','rgb']));
  assert.equal(j.snapshot()[0].credited,true);j.close();
  assert.throws(()=>f.open(genesis),/external tip mismatch/);
  assert.throws(()=>f.open(p1),/external tip mismatch/);
  const k=f.open(p);assert.equal(k.snapshot()[0].state,'reconciled');
  assert.throws(()=>k.append(f.signed(f.done,['btc','rgb'])),/reused external evidence/);
  const pin=k.append(f.signed(f.conflict,['conflict']));k.close();
  const v=f.open(pin);assert.equal(v.snapshot()[0].frozen,true);assert.equal(v.snapshot()[0].credited,true);v.close();
});

test('wrong role/domain, altered amount, unsigned and opaque data rejected without append',t=>{
  const f=makeFixture(t),j=f.create(),gen=j.tip();
  assert.throws(()=>j.append(local(f.r)),/unexpected object fields/);
  assert.throws(()=>j.append(f.signed(f.r,['reserve'],f.r,h('9'))),/signature rejected/);
  const rec=f.signed(f.r,['reserve']);rec.event={...f.r,units:'26'};
  assert.throws(()=>j.append(rec),/signature rejected/);assert.deepEqual(j.tip(),gen);
  j.append(f.signed(f.r,['reserve']));j.append(local(f.sub));const pin=j.tip();
  const d=f.signed(f.done,['btc','rgb']);[d.auth.btc,d.auth.rgb]=[d.auth.rgb,d.auth.btc];
  assert.throws(()=>j.append(d),/signature rejected/);
  assert.throws(()=>j.append(f.signed({...f.done,units:'26'},['btc','rgb'])),/wrong reconciliation/);
  assert.throws(()=>j.append({event:{...f.done,raw:'opaque'},auth:{}}),/unexpected object fields/);
  assert.throws(()=>j.append(local(f.conflict)),/unexpected object fields/);
  assert.deepEqual(j.tip(),pin);j.close();
});

test('cross-role proof reuse, duplicate withdrawal and payment hash',t=>{
  const f=makeFixture(t),j=f.create();j.append(f.signed(f.r,['reserve']));j.append(local(f.sub));j.append(f.signed(f.done,['btc','rgb']));
  const b={...f.r,id:'b',withdrawalId:'w2',paymentHash:h('1')};
  assert.throws(()=>j.append(f.signed({...b,withdrawalId:f.r.withdrawalId},['reserve'],{...b,withdrawalId:f.r.withdrawalId})),/duplicate reserve/);
  assert.throws(()=>j.append(f.signed({...b,paymentHash:f.r.paymentHash},['reserve'],{...b,paymentHash:f.r.paymentHash})),/reused hash/);
  j.append(f.signed(b,['reserve'],b));j.append(local({...f.sub,id:b.id}));
  const d={...f.done,id:b.id,paymentHash:b.paymentHash,btcEvidence:f.done.rgbEvidence,rgbEvidence:h('2')};
  assert.throws(()=>j.append(f.signed(d,['btc','rgb'],b)),/reused external evidence/);j.close();
});

test('single writer, policy pin, immutable snapshots',t=>{
  const f=makeFixture(t),j=f.create(),gen=j.tip();
  assert.throws(()=>f.open(gen),/EEXIST/);
  const pin=j.append(f.signed(f.r,['reserve']));const snapshot=j.snapshot();snapshot[0].state='reconciled';
  assert.equal(j.snapshot()[0].state,'reserved');j.close();
  assert.throws(()=>openJournal(f.dir,{...f.policy,rgb:f.policy.btc},f.id,pin),/independent keys/);
  assert.throws(()=>openJournal(f.dir,{...f.policy,btc:f.policy.rgb,rgb:f.policy.btc},f.id,pin),/header\/policy mismatch/);
  assert.throws(()=>openJournal(f.dir,f.policy,h('9'),pin),/header\/policy mismatch/);
  const k=f.open(pin);k.close();assert.throws(()=>k.tip(),/closed/);
});

test('torn tail and complete-frame mutation are never silently repaired',t=>{
  const f=makeFixture(t),j=f.create();const p=j.append(f.signed(f.r,['reserve']));j.close();
  const file=path.join(f.dir,'events.jsonl'),original=fs.readFileSync(file);
  fs.appendFileSync(file,'{"partial":');assert.throws(()=>f.open(p),/torn journal/);
  fs.writeFileSync(file,original);fs.writeFileSync(file,original.toString().replace('"units":"25"','"units":"26"'));
  assert.throws(()=>f.open(p),/invalid hash chain/);
  fs.writeFileSync(file,original);const k=f.open(p);assert.equal(k.snapshot()[0].units,'25');k.close();
});

test('SIGKILL after fsynced submit: stale lock and old pin fence retry',async t=>{
  const f=makeFixture(t),j=f.create();const before=j.append(f.signed(f.r,['reserve']));j.close();
  const child=fork(fileURLToPath(new URL('./journal-crash-worker.mjs',import.meta.url)),[],{stdio:['ignore','ignore','inherit','ipc']});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
  const exited=once(child,'exit');
  const received=once(child,'message');child.send({dir:f.dir,policy:f.policy,id:f.id,pin:before,record:local(f.sub)});
  const [after]=await Promise.race([received,exited.then(()=>{throw new Error('child exited before durable append');})]);
  child.kill('SIGKILL');await exited;
  assert.throws(()=>f.open(after),/EEXIST/);
  // Test operator verifies the dead child and removes only the stale lock. Production needs external review.
  fs.rmdirSync(path.join(f.dir,'.writer'));
  assert.throws(()=>f.open(before),/external tip mismatch/);
  const recovered=f.open(after);assert.equal(recovered.snapshot()[0].state,'submitted');
  assert.throws(()=>recovered.append(local(f.sub)),/invalid or expired submit/);recovered.close();
});
