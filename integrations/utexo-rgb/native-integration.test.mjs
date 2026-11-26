import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { qualifyNativePair,observeAuthorizedNativeRgb } from './native-peer.mjs';
import { fundingMessage } from './evidence.mjs';
import { inspectCandidate } from './shz-candidate.mjs';
const h=c=>c.repeat(64);
function native(){
  const preimage=h('1'),paymentHash=createHash('sha256').update(Buffer.from(preimage,'hex')).digest('hex'),payerNode='02'+h('2'),payee='03'+h('3'),assetId='rgb:fixture',assetUnits='25',carrierMsat='3000000',invoice='fixture';
  const d={network:'Regtest',payment_hash:paymentHash,payee_pubkey:payee,asset_id:assetId,asset_amount:25,amt_msat:'3000000',timestamp:100,expiry_sec:600};
  const p={payment_hash:paymentHash,payment_type:'Outbound',status:'Succeeded',payee_pubkey:payee,asset_id:assetId,asset_amount:'25',amt_msat:3000000,preimage};
  const q={...p,payment_type:'InboundAutoClaim'};
  const maps=[payerNode,payee].map((pubkey,i)=>({getNetwork:'regtest',getCapabilities:{lightning:true},getAddressState:{status:'ready'},getNetworkInfo:{network:'Regtest'},getNodeInfo:{pubkey},decodeInvoice:d,getPayment:i?q:p,getInvoiceStatus:{status:'Succeeded'}}));
  const calls=maps.map(m=>async method=>{assert.ok(Object.hasOwn(m,method));return structuredClone(m[method])});
  const options={payerCall:calls[0],receiverCall:calls[1],payerNode,payee,invoice,paymentHash,assetId,assetUnits,carrierMsat};
  const reserve={type:'reserve',id:'a',withdrawalId:'w',network:'regtest',assetId,units:assetUnits,sats:'1000',carrierMsat,payee,batchDigest:h('4'),paymentHash,at:101,expiresAt:700};
  const journalId=h('5'),binding={payer:payerNode,scriptPubKey:'5120'+h('6')};
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const auth={journalId,reserve,binding,authorizer:publicKey.export({type:'spki',format:'pem'}),signature:sign(null,fundingMessage(journalId,reserve,binding),privateKey).toString('hex'),payerCall:calls[0],receiverCall:calls[1],invoice};
  return {options,auth,maps,preimage,privateKey};
}
test('pinned native shape maps both peer histories without leaking preimage',async()=>{
  const f=native(),r=await qualifyNativePair(f.options),a=await observeAuthorizedNativeRgb(f.auth);
  assert.equal(r.assetUnits,'25');assert.equal(r.scope,'native-history-observation-only');assert.equal(a.kind,'rgb-ln-observation');assert.equal(a.paymentHash,r.paymentHash);
  assert.ok(!JSON.stringify([r,a]).includes(f.preimage));
});
test('refuse wrong peer, capabilities, envelope, pending, preimage and unsafe integers',async()=>{
  for(const [i,method,patch] of [[0,'getNetwork','mainnet'],[0,'getCapabilities',{lightning:false}],[1,'getAddressState',{status:'locked'}],[0,'getNodeInfo',{pubkey:'02'+h('7')}],[1,'getNetworkInfo',{network:'signet'}],[1,'getInvoiceStatus',{status:'Pending'}]]){
    const f=native();f.maps[i][method]=patch;await assert.rejects(qualifyNativePair(f.options));
  }
  for(const patch of [{payment_type:'InboundHodl'},{status:'Pending'},{asset_amount:26},{amt_msat:9007199254740992},{amt_msat:'03000000'},{preimage:null},{preimage:h('7')},{asset_id:'rgb:other'},{payee_pubkey:'02'+h('7')}]){
    const f=native();Object.assign(f.maps[1].getPayment,patch);await assert.rejects(qualifyNativePair(f.options));
  }
  const f=native();f.maps[0].getPayment={payment:f.maps[0].getPayment};await assert.rejects(qualifyNativePair(f.options));
});
test('native history cannot override signed reservation or invoice expiry',async()=>{
  const f=native();await assert.rejects(observeAuthorizedNativeRgb({...f.auth,signature:'0'.repeat(128)}),/signature rejected/);
  const reserve={...f.auth.reserve,expiresAt:701};const signature=sign(null,fundingMessage(f.auth.journalId,reserve,f.auth.binding),f.privateKey).toString('hex');
  await assert.rejects(observeAuthorizedNativeRgb({...f.auth,reserve,signature}),/expiry mismatch/);
  await assert.rejects(qualifyNativePair({...f.options,assetUnits:'26'}),/amount mismatch/);
});
function shz(){
  const owner=h('a'),channel={txid:h('b'),vout:0},other={txid:h('c'),vout:1};
  const raw=o=>({txid:[...Buffer.from(o.txid,'hex')],vout:o.vout});
  const j={journal:{config_hash:h('d'),tip:{records:50,digest:h('e')},next_resolution:2}};
  const b={seq:1,digest:h('f'),phase:'committed',ledger_state:'Committed',committed_us:1000,accounts:[{channel,owner,approved:true},{channel:other,owner:h('9'),approved:true}],acks:[{channel,owner_signed:true,evidence:h('8')}],settlements:[{channel,owner,released_margin_sats:500,payout_sats:1500,realized_pnl_sats:1000}],clearing:{rows:[{channel:raw(channel),paid:1000,collected:0,net:1000},{channel:raw(other),paid:0,collected:1000,net:-1000}],cash_before:0,cash_after:0}};
  const accounts=[{owner,outpoint:channel,kind:'utxo',balance:{free:800,realized_pnl:900}}];
  const get=async p=>structuredClone(p.endsWith('/journal')?j:p.endsWith('/accounts')?accounts:{batch:b});
  return {options:{get,sequence:1,owner,channel},j,b,accounts};
}
test('actual explorer shape screens positive cash net capped by current free and realized balance',async()=>{
  const f=shz(),r=await inspectCandidate(f.options);assert.equal(r.candidateSats,'800');assert.equal(r.withdrawalAuthorized,false);assert.equal(r.proofOfFunding,false);assert.equal(r.simulatedChannel,true);
  assert.equal((await inspectCandidate(f.options)).observationDigest,r.observationDigest);
  f.accounts[0].balance.realized_pnl=-1;assert.equal((await inspectCandidate(f.options)).candidateSats,'0');
});
test('reject uncommitted batch, absent V3, duplicated lanes, wrong owner, unfunded cash and unsafe values',async()=>{
  for(const mutate of [f=>f.b.phase='prepared',f=>f.b.ledger_state='Reversed',f=>f.b.clearing=null,f=>f.b.acks[0].owner_signed=false,f=>f.b.accounts[0].approved=false,f=>f.b.settlements[0].owner=h('1'),f=>f.b.clearing.rows[1].net=-999,f=>f.b.clearing.rows[1].channel=f.b.clearing.rows[0].channel,f=>f.b.clearing.cash_after=1,f=>f.b.settlements[0].payout_sats=1501,f=>f.accounts[0].owner=h('1'),f=>f.accounts[0].balance.free=Number.MAX_SAFE_INTEGER+1]){
    const f=shz();mutate(f);await assert.rejects(inspectCandidate(f.options));
  }
});
test('moving explorer tip fences inconsistent snapshot',async()=>{
  const f=shz();let reads=0;const get=async p=>{const x=await f.options.get(p);if(p.endsWith('/journal')&&++reads===2)x.journal.tip.records++;return x};
  await assert.rejects(inspectCandidate({...f.options,get}),/changed during read/);
});
