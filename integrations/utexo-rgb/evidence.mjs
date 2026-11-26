import { createHash, createPublicKey, verify } from 'node:crypto';
const check=(ok,msg)=>{if(!ok)throw new Error(msg)};
const hash=b=>createHash('sha256').update(b).digest('hex');
const hex=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s)&&!/^0+$/.test(s);
const node=s=>typeof s==='string'&&/^(02|03)[0-9a-f]{64}$/.test(s);
const uint=s=>typeof s==='string'&&/^[1-9][0-9]{0,19}$/.test(s)&&BigInt(s)<=18446744073709551615n;
const canon=o=>Array.isArray(o)?o.map(canon):o&&typeof o==='object'?Object.fromEntries(Object.keys(o).sort().map(k=>[k,canon(o[k])])):o;
const bytes=o=>Buffer.from(JSON.stringify(canon(o)));
const id=(...parts)=>hash(bytes(parts));
const fields=['type','id','withdrawalId','network','assetId','units','sats','carrierMsat','payee','batchDigest','paymentHash','at','expiresAt'];
function validateReserve(r){
  check(r&&Object.keys(r).sort().join(',')===fields.slice().sort().join(',')&&r.type==='reserve'&&r.network==='regtest','invalid reserve');
  check([r.id,r.withdrawalId,r.assetId].every(x=>typeof x==='string'&&x.length>0&&x.length<=256)&&r.assetId.startsWith('rgb:')&&[r.units,r.sats,r.carrierMsat].every(uint)&&node(r.payee)&&hex(r.paymentHash)&&hex(r.batchDigest)&&Number.isSafeInteger(r.at)&&r.at>=0&&Number.isSafeInteger(r.expiresAt)&&r.expiresAt>r.at,'invalid reservation fields');
}
function fundingMessage(journalId,r,binding){
  validateReserve(r);
  check(hex(journalId)&&binding&&Object.keys(binding).sort().join(',')==='payer,scriptPubKey'&&node(binding.payer)&&typeof binding.scriptPubKey==='string'&&/^(0014[0-9a-f]{40}|0020[0-9a-f]{64}|5120[0-9a-f]{64})$/.test(binding.scriptPubKey),'invalid funding binding');
  return bytes(['SHZ/RGB/FUNDING-BINDING/V1',journalId,r,binding]);
}
function authorize(journalId,r,binding,sig,publicKey){
  const key=createPublicKey(publicKey);
  check(key.asymmetricKeyType==='ed25519'&&typeof sig==='string'&&/^[0-9a-f]{128}$/.test(sig)&&verify(null,fundingMessage(journalId,r,binding),key,Buffer.from(sig,'hex')),'funding binding signature rejected');
  return structuredClone(binding);
}
function btcToSats(v){
  check(typeof v==='number'&&Number.isFinite(v)&&v>0&&v<=21000000,'invalid Core BTC value');
  const n=Math.round(v*100000000);check(Number.isSafeInteger(n)&&n/100000000===v,'inexact BTC amount');return String(n);
}
// Trusted, independent regtest Core RPC. Never accept a caller-supplied confirmation count.
async function verifyBtcFunding({rpc,journalId,reserve:r,binding,signature,authorizer,txid,vout,blockHash,minConfirmations=6}){
  const b=authorize(journalId,r,binding,signature,authorizer);
  check(hex(txid)&&hex(blockHash)&&Number.isInteger(vout)&&vout>=0&&vout<=0xffffffff&&Number.isSafeInteger(minConfirmations)&&minConfirmations>=6,'invalid locator/policy');
  const before=await rpc('getblockchaininfo',[]);check(before.chain==='regtest'&&hex(before.bestblockhash)&&Number.isSafeInteger(before.blocks),'wrong Core chain');
  const header=await rpc('getblockheader',[blockHash,true]);
  check(header.hash===blockHash&&Number.isSafeInteger(header.height)&&header.height>=0&&before.blocks-header.height+1>=minConfirmations,'insufficient confirmations');
  check(await rpc('getblockhash',[header.height])===blockHash,'inactive funding block');
  const block=await rpc('getblock',[blockHash,1]);check(block.hash===blockHash&&Array.isArray(block.tx)&&block.tx.includes(txid),'transaction absent from block');
  const tx=await rpc('getrawtransaction',[txid,true,blockHash]);
  check(tx.txid===txid&&tx.blockhash===blockHash&&tx.in_active_chain===true&&Array.isArray(tx.vout),'wrong transaction');
  const matches=tx.vout.filter(x=>x.n===vout);check(matches.length===1,'wrong output locator');
  const output=matches[0];check(output.scriptPubKey?.hex===b.scriptPubKey&&btcToSats(output.value)===r.sats,'wrong BTC script or value');
  const after=await rpc('getblockchaininfo',[]);check(after.chain==='regtest'&&after.bestblockhash===before.bestblockhash&&after.blocks===before.blocks,'chain changed during observation');
  return {kind:'btc-observation',reservationDigest:id(journalId,r),bindingDigest:id(journalId,r,b),evidenceId:id('SHZ/RGB/BTC-OUTPOINT/V1','regtest',txid,vout),txid,vout,blockHash,tip:after.bestblockhash};
}
// Normalized records from independently provisioned authenticated peer observers.
// The native beta.5 object-to-record mapping is deliberately not implemented here.
async function verifyRgbLightning({payer,receiver,journalId,reserve:r,binding,signature,authorizer}){
  const b=authorize(journalId,r,binding,signature,authorizer);
  check(payer!==receiver,'separate peer observers required');
  const [p,q]=await Promise.all([payer(r.paymentHash),receiver(r.paymentHash)]);
  for(const [record,direction,identity] of [[p,'Outbound',b.payer],[q,'InboundAutoClaim',r.payee]]){
    check(record&&record.network==='regtest'&&record.direction===direction&&record.node===identity&&record.status==='Succeeded'&&record.paymentHash===r.paymentHash&&record.assetId===r.assetId&&record.assetUnits===r.units&&record.carrierMsat===r.carrierMsat&&record.payee===r.payee,'RGB peer record mismatch');
  }
  check(b.payer!==r.payee&&typeof p.preimage==='string'&&/^[0-9a-f]{64}$/.test(p.preimage)&&hash(Buffer.from(p.preimage,'hex'))===r.paymentHash,'invalid payment preimage or peer identity');
  return {kind:'rgb-ln-observation',reservationDigest:id(journalId,r),bindingDigest:id(journalId,r,b),evidenceId:id('SHZ/RGB/LN-PAYMENT/V1','regtest',r.paymentHash),paymentHash:r.paymentHash};
}
// Observations are local trust-bound values, not portable authenticated receipts.
// Independent observers must recompute and sign the journal event themselves.
function reconciliationEvent(journalId,r,binding,btc,rgb,at){
  validateReserve(r);fundingMessage(journalId,r,binding);
  const digest=id(journalId,r),bindingDigest=id(journalId,r,binding);
  check(btc.kind==='btc-observation'&&rgb.kind==='rgb-ln-observation'&&btc.reservationDigest===digest&&rgb.reservationDigest===digest&&btc.bindingDigest===bindingDigest&&rgb.bindingDigest===bindingDigest&&hex(btc.evidenceId)&&hex(rgb.evidenceId)&&btc.evidenceId!==rgb.evidenceId&&rgb.paymentHash===r.paymentHash&&Number.isSafeInteger(at)&&at>=r.at,'observation mismatch');
  return {type:'reconcile',id:r.id,at,network:r.network,assetId:r.assetId,units:r.units,sats:r.sats,carrierMsat:r.carrierMsat,payee:r.payee,paymentHash:r.paymentHash,btcEvidence:btc.evidenceId,rgbEvidence:rgb.evidenceId};
}
export { fundingMessage, verifyBtcFunding, verifyRgbLightning, reconciliationEvent };
