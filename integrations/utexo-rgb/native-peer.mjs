import { createHash } from 'node:crypto';
import { verifyRgbLightning } from './evidence.mjs';

const check=(v,m)=>{if(!v)throw Error(m)};
const hex=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s);
const node=s=>typeof s==='string'&&/^(02|03)[0-9a-f]{64}$/.test(s);
function exact(v){
  const s=typeof v==='number'&&Number.isSafeInteger(v)?String(v):v;
  check(typeof s==='string'&&/^[1-9][0-9]{0,19}$/.test(s)&&BigInt(s)<=18446744073709551615n,'invalid exact positive native integer');return s;
}
const network=s=>typeof s==='string'&&s.toLowerCase()==='regtest';
const sha=s=>createHash('sha256').update(Buffer.from(s,'hex')).digest('hex');
// The WDK facade is query-only. `call` must target an authenticated pinned peer;
// a method name or returned pubkey alone is not peer authentication.
async function readNativePeer(call, expected, direction, invoice, hash){
  check(typeof call==='function'&&node(expected)&&hex(hash)&&['Outbound','InboundAutoClaim'].includes(direction),'invalid peer policy');
  check(await call('getNetwork')==='regtest'&&(await call('getCapabilities'))?.lightning===true,'native capability mismatch');
  check((await call('getAddressState'))?.status==='ready','native wallet locked');
  check(network((await call('getNetworkInfo'))?.network)&&(await call('getNodeInfo'))?.pubkey===expected,'native peer identity/network mismatch');
  const d=await call('decodeInvoice',invoice),p=await call('getPayment',hash,direction);
  check(d&&p&&network(d.network)&&d.payment_hash===hash&&p.payment_hash===hash&&p.payment_type===direction&&p.status==='Succeeded','native payment mismatch');
  check(node(d.payee_pubkey)&&p.payee_pubkey===d.payee_pubkey&&typeof d.asset_id==='string'&&d.asset_id.startsWith('rgb:')&&p.asset_id===d.asset_id,'native asset/payee mismatch');
  const units=exact(p.asset_amount),carrier=exact(p.amt_msat);
  check(units===exact(d.asset_amount)&&carrier===exact(d.amt_msat)&&BigInt(carrier)>=3000000n,'native amount mismatch');
  check(Number.isSafeInteger(d.timestamp)&&d.timestamp>=0&&Number.isSafeInteger(d.expiry_sec)&&d.expiry_sec>0&&Number.isSafeInteger(d.timestamp+d.expiry_sec),'invalid native invoice expiry');
  if(direction==='InboundAutoClaim')check(expected===d.payee_pubkey&&(await call('getInvoiceStatus',invoice))?.status==='Succeeded','receiver invoice not settled');
  check(hex(p.preimage)&&sha(p.preimage)===hash,'native preimage unavailable or invalid');
  return {network:'regtest',direction,node:expected,status:p.status,paymentHash:hash,assetId:d.asset_id,assetUnits:units,carrierMsat:carrier,payee:d.payee_pubkey,preimage:p.preimage,issuedAt:d.timestamp,expiresAt:d.timestamp+d.expiry_sec};
}
async function pair({payerCall,receiverCall,payerNode,payee,invoice,paymentHash,assetId,assetUnits,carrierMsat}){
  check(payerCall!==receiverCall&&payerNode!==payee&&typeof invoice==='string'&&invoice.length>0&&invoice.length<=65536,'invalid independent peer inputs');
  const p=await readNativePeer(payerCall,payerNode,'Outbound',invoice,paymentHash);
  const q=await readNativePeer(receiverCall,payee,'InboundAutoClaim',invoice,paymentHash);
  for(const x of [p,q])check(x.payee===payee&&x.assetId===assetId&&x.assetUnits===assetUnits&&x.carrierMsat===carrierMsat,'authorized native amount mismatch');
  check(p.preimage===q.preimage&&p.issuedAt===q.issuedAt&&p.expiresAt===q.expiresAt,'native peers disagree');
  return {p,q};
}
// Benchmark-only: no signed withdrawal, no preimage/raw response in public receipt.
async function qualifyNativePair(options){const {p}=await pair(options);return {paymentHash:p.paymentHash,assetId:p.assetId,assetUnits:p.assetUnits,carrierMsat:p.carrierMsat,expiresAt:p.expiresAt,scope:'native-history-observation-only'};}
async function observeAuthorizedNativeRgb({payerCall,receiverCall,invoice,...auth}){
  const {reserve:r,binding:b}=auth;
  const {p,q}=await pair({payerCall,receiverCall,payerNode:b.payer,payee:r.payee,invoice,paymentHash:r.paymentHash,assetId:r.assetId,assetUnits:r.units,carrierMsat:r.carrierMsat});
  check(p.issuedAt<=r.at&&r.at<p.expiresAt&&r.expiresAt===p.expiresAt,'reservation invoice expiry mismatch');
  return verifyRgbLightning({...auth,payer:async()=>p,receiver:async()=>q});
}
export { qualifyNativePair,observeAuthorizedNativeRgb };
