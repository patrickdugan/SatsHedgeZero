import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { fundingMessage, verifyBtcFunding, verifyRgbLightning, reconciliationEvent } from './evidence.mjs';
const h=c=>c.repeat(64);
function fixture(){
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const journalId=h('1'),preimage=h('2'),paymentHash=createHash('sha256').update(Buffer.from(preimage,'hex')).digest('hex');
  const reserve={type:'reserve',id:'a',withdrawalId:'w1',network:'regtest',assetId:'rgb:fixture',units:'25',sats:'1000',carrierMsat:'3000000',payee:'02'+h('3'),batchDigest:h('4'),paymentHash,at:1,expiresAt:10};
  const binding={payer:'03'+h('5'),scriptPubKey:'5120'+h('6')};
  const signature=sign(null,fundingMessage(journalId,reserve,binding),privateKey).toString('hex');
  const base={journalId,reserve,binding,signature,authorizer:publicKey.export({type:'spki',format:'pem'})};
  const txid=h('7'),blockHash=h('8'),tip=h('9'),chain={chain:'regtest',bestblockhash:tip,blocks:110};
  const data={getblockchaininfo:chain,getblockheader:{hash:blockHash,height:105},getblockhash:blockHash,getblock:{hash:blockHash,tx:[txid]},getrawtransaction:{txid,blockhash:blockHash,in_active_chain:true,vout:[{n:0,value:0.00001,scriptPubKey:{hex:binding.scriptPubKey}}]}};
  const rpc=async method=>structuredClone(data[method]);
  const p={network:'regtest',direction:'Outbound',node:binding.payer,status:'Succeeded',paymentHash,assetId:reserve.assetId,assetUnits:reserve.units,carrierMsat:reserve.carrierMsat,payee:reserve.payee,preimage};
  const q={...p,node:reserve.payee,direction:'InboundAutoClaim'};delete q.preimage;
  const btc={...base,rpc,txid,vout:0,blockHash};const rgb={...base,payer:async()=>p,receiver:async()=>q};
  return {base,btc,rgb,p,q,data,privateKey};
}
test('funding and RGB peer evidence combine without exposing preimage',async()=>{
  const f=fixture(),b=await verifyBtcFunding(f.btc),r=await verifyRgbLightning(f.rgb);
  const event=reconciliationEvent(f.base.journalId,f.base.reserve,f.base.binding,b,r,11);
  assert.equal(event.btcEvidence,b.evidenceId);assert.equal(event.rgbEvidence,r.evidenceId);assert.equal(event.units,'25');
  assert.equal(JSON.stringify(r).includes(f.p.preimage),false);
  assert.equal((await verifyBtcFunding(f.btc)).evidenceId,b.evidenceId);
  assert.equal((await verifyRgbLightning(f.rgb)).evidenceId,r.evidenceId);
  assert.throws(()=>reconciliationEvent(f.base.journalId,f.base.reserve,{...f.base.binding,payer:'02'+h('a')},b,r,11),/observation mismatch/);
});
test('signed recipient binding and authorization cannot be altered',async()=>{
  const f=fixture();
  for(const patch of [{binding:{...f.base.binding,scriptPubKey:'5120'+h('a')}},{journalId:h('a')},{reserve:{...f.base.reserve,sats:'1001'}},{signature:'0'.repeat(128)}])await assert.rejects(verifyBtcFunding({...f.btc,...patch}),/signature rejected/);
  await assert.rejects(verifyRgbLightning({...f.rgb,binding:{...f.base.binding,payer:'02'+h('a')}}),/signature rejected/);
});
test('BTC checks chain, confirmations, active membership, amount and script',async()=>{
  for(const [method,patch] of [['getblockchaininfo',{chain:'main'}],['getblockheader',{height:106}],['getblock',{tx:[]}],['getrawtransaction',{in_active_chain:false}],['getrawtransaction',{vout:[{n:0,value:0.00001001,scriptPubKey:{hex:'5120'+h('6')}}]}],['getrawtransaction',{vout:[{n:0,value:0.00001,scriptPubKey:{hex:'5120'+h('a')}}]}]]){
    const f=fixture();Object.assign(f.data[method],patch);await assert.rejects(verifyBtcFunding(f.btc));
  }
  const f=fixture();f.data.getblockhash=h('a');await assert.rejects(verifyBtcFunding(f.btc),/inactive/);
  const g=fixture();let n=0;await assert.rejects(verifyBtcFunding({...g.btc,rpc:async(method,args)=>method==='getblockchaininfo'&&++n===2?{...g.data[method],bestblockhash:h('a')}:g.btc.rpc(method,args)}),/chain changed/);
  await assert.rejects(verifyBtcFunding({...g.btc,minConfirmations:1}),/locator\/policy/);
});
test('Lightning fails closed on incomplete or mismatched peer observations',async()=>{
  for(const patch of [{status:'Pending'},{assetUnits:'26'},{assetId:'rgb:other'},{carrierMsat:'3000001'},{paymentHash:h('a')},{network:'signet'},{node:'02'+h('a')},{payee:'02'+h('a')},{direction:'Outbound'}]){
    const f=fixture();Object.assign(f.q,patch);await assert.rejects(verifyRgbLightning(f.rgb),/record mismatch/);
  }
  const f=fixture();f.p.preimage=h('a');await assert.rejects(verifyRgbLightning(f.rgb),/preimage/);
  await assert.rejects(verifyRgbLightning({...f.rgb,receiver:f.rgb.payer}),/separate peer/);
});
test('canonical identifiers do not depend on confirmation block or peer response decoration',async()=>{
  const f=fixture(),b=await verifyBtcFunding(f.btc),r=await verifyRgbLightning(f.rgb),other=h('a');
  f.data.getblockheader.hash=other;f.data.getblockhash=other;f.data.getblock.hash=other;f.data.getrawtransaction.blockhash=other;
  assert.equal((await verifyBtcFunding({...f.btc,blockHash:other})).evidenceId,b.evidenceId);
  f.p.extra='metadata';assert.equal((await verifyRgbLightning(f.rgb)).evidenceId,r.evidenceId);
});
