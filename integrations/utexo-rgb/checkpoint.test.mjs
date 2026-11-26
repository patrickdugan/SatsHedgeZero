import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createCoordinator,openCoordinator,checkpointStore,coordinator } from './checkpoint.mjs';
import { openJournal,receiptMessage } from './journal.mjs';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
const h=c=>c.repeat(64);
function fixture(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'shz-cas-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const dir=path.join(root,'journal'),pins=path.join(root,'pins'),id=h('a'),policy={},keys={};
  for(const role of ['reserve','btc','rgb','conflict']){keys[role]=generateKeyPairSync('ed25519');policy[role]=keys[role].publicKey.export({type:'spki',format:'pem'})}
  const r={type:'reserve',id:'a',withdrawalId:'w1',network:'regtest',assetId:'rgb:fixture',units:'25',sats:'1000',carrierMsat:'3000000',payee:'02'+h('b'),batchDigest:h('c'),paymentHash:h('d'),at:1,expiresAt:10};
  const record={event:r,auth:{reserve:sign(null,receiptMessage(id,'reserve',r,r),keys.reserve.privateKey).toString('hex')}};
  const sub={event:{type:'submit',id:'a',at:2},auth:{}};
  return {dir,pins,id,policy,record,sub,create:()=>createCoordinator(dir,pins,policy,id),open:()=>openCoordinator(dir,pins,policy,id),store:()=>checkpointStore(pins,id)};
}
test('exact CAS, persistent reopen and monotone pin',t=>{
  const f=fixture(t),j=f.create(),gen=j.tip();const p=j.append(f.record);
  assert.deepEqual(f.store().read(),p);assert.equal(p.seq,1);
  assert.throws(()=>f.store().compareAndSwap(gen,{seq:1,digest:h('2')}),/CAS mismatch/);
  assert.throws(()=>f.store().compareAndSwap(p,{seq:3,digest:h('3')}),/advance/);
  assert.throws(()=>checkpointStore(f.pins,h('b')),/identity/);
  j.close();const k=f.open();assert.equal(k.snapshot()[0].state,'reserved');assert.equal(k.append(f.sub).seq,2);k.close();
});
test('CAS error after journal fsync fences and cannot silently roll back',t=>{
  const f=fixture(t),j=f.create(),gen=j.append(f.record);j.close();
  const raw=openJournal(f.dir,f.policy,f.id,gen);const store=f.store();const c=coordinator(raw,{read:store.read,compareAndSwap(){throw Error('injected CAS outage')}});
  assert.throws(()=>c.append(f.sub),/CAS outage/);assert.throws(()=>c.tip(),/fenced/);assert.throws(()=>c.append(f.sub),/fenced/);c.close();
  assert.deepEqual(store.read(),gen);assert.throws(()=>f.open(),/external tip mismatch/);
});
test('lost CAS acknowledgement fences writer; verified matching tip can reopen',t=>{
  const f=fixture(t),j=f.create(),gen=j.append(f.record);j.close();const store=f.store();
  const c=coordinator(openJournal(f.dir,f.policy,f.id,gen),{read:store.read,compareAndSwap(a,b){store.compareAndSwap(a,b);throw Error('lost response')}});
  assert.throws(()=>c.append(f.sub),/lost response/);assert.throws(()=>c.snapshot(),/fenced/);c.close();const k=f.open();assert.equal(k.snapshot()[0].state,'submitted');assert.throws(()=>k.append(f.sub));k.close();
});
for(const mode of ['before-cas','after-cas'])test('SIGKILL '+mode+' leaves no redispatch path',async t=>{
  const f=fixture(t),j=f.create(),before=j.append(f.record);j.close();
  const child=fork(fileURLToPath(new URL('./checkpoint-crash-worker.mjs',import.meta.url)),[],{stdio:['ignore','ignore','inherit','ipc']});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL')});
  const exited=once(child,'exit'),message=once(child,'message');child.send({dir:f.dir,pins:f.pins,policy:f.policy,id:f.id,record:f.sub,mode});
  const [after]=await Promise.race([message,exited.then(()=>{throw Error('child exited early')})]);child.kill('SIGKILL');await exited;
  assert.throws(()=>f.open(),/EEXIST/);fs.rmdirSync(path.join(f.dir,'.writer'));
  if(mode==='before-cas'){assert.deepEqual(f.store().read(),before);assert.throws(()=>f.open(),/external tip mismatch/)}
  else{assert.deepEqual(f.store().read(),after);const k=f.open();assert.equal(k.snapshot()[0].state,'submitted');assert.throws(()=>k.append(f.sub));k.close()}
});
