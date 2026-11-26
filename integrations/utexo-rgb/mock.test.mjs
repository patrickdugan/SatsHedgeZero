import { quoteConversion, checkDecoded, createDevelopmentAdapter } from './adapter.mjs';

async function runMockTests(){
  let n=0;
  function eq(a,b){if(a!==b)throw new Error("assertion failed: "+String(a)+" != "+String(b));n++;}
  async function rejects(fn){let failed=false;try{await fn();}catch{failed=true;}eq(failed,true);}
  const payee="02"+"a".repeat(64),hash="b".repeat(64),id="rgb:Test_Contract~1";
  const q={network:"regtest",assetId:id,payee,assetUnits:"12500000",carrierMsat:"3000000",expiresAt:1100,obligationId:"batch:1:row:2"};
  const d={network:"regtest",asset_id:id,payee_pubkey:payee,asset_amount:"12500000",amt_msat:3000000,timestamp:1000,expiry_sec:100,payment_hash:hash};
  let calls=0;const read={getAddressState:async()=>({status:"ready"}),getAssetMetadata:async()=>({fixture:true}),getAssetBalance:async()=>({fixture:true}),decodeInvoice:async()=>d,getInvoiceStatus:async()=>({status:"Succeeded"}),getPayment:async(h,t)=>({h,t})};
  const account={getNetwork:()=>"regtest",getCapabilities:()=>({lightning:true}),toReadOnlyAccount:async()=>read,createLightningInvoice:async req=>{calls++;return req;}};
  eq(quoteConversion({sats:"100000",btcUsdCents:"10000000",assetUsdCents:100,decimals:6}).assetUnits,100000000n);
  const r=quoteConversion({sats:1,btcUsdCents:12345,assetUsdCents:99,decimals:6});
  eq(r.assetUnits*r.denominator+r.remainder,12345000000n);
  eq(quoteConversion({sats:100000,btcUsdCents:10000000,assetUsdCents:80,decimals:6}).assetUnits,125000000n);
  await rejects(()=>quoteConversion({sats:1,btcUsdCents:1,assetUsdCents:0,decimals:6}));
  await rejects(()=>createDevelopmentAdapter(account,"mainnet"));
  await rejects(()=>createDevelopmentAdapter(account,"testnet4"));
  await rejects(()=>createDevelopmentAdapter(account,"signet"));
  await rejects(()=>createDevelopmentAdapter({...account,getCapabilities:()=>({lightning:false})},"regtest"));
  const a=await createDevelopmentAdapter(account,"regtest");
  eq((await a.inspect(id)).state,"ready");
  await rejects(()=>a.inspect("USDT"));
  const req=await a.createReceiveInvoice(q,1000);
  eq(req.assetAmount,12500000);eq(req.amountMsat,3000000);eq(req.expirySec,100);
  await rejects(()=>a.createReceiveInvoice({...q,network:"signet"},1000));
  await rejects(()=>a.createReceiveInvoice({...q,assetUnits:"9007199254740992"},1000));
  await rejects(()=>a.createReceiveInvoice({...q,carrierMsat:2999999},1000));
  await rejects(()=>a.createReceiveInvoice(q,1100));eq(calls,1);
  const c=await a.inspectInvoice(q,"fixture",1000);eq(c.paymentHash,hash);eq(c.kind,"invoice_candidate");
  for(const patch of [{network:"signet"},{asset_id:"rgb:wrong"},{asset_amount:1},{amt_msat:null},{payee_pubkey:"03"+"a".repeat(64)},{expiry_sec:101},{timestamp:1001},{payment_hash:"bad"}]){
    await rejects(()=>checkDecoded(q,{...d,...patch},1000));
  }
  const o=await a.observe(c,"fixture");eq(o.kind,"unverified_observation");eq(o.inbound.t,"InboundAutoClaim");
  await rejects(()=>a.observe({...c,paymentHash:"c".repeat(64)},"fixture"));
  eq(typeof a.pay,"undefined");eq(typeof a.credit,"undefined");
  return n;
}

console.log('Mock assertions passed:', await runMockTests());
