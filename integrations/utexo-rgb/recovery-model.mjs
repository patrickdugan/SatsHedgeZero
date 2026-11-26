function replay(events) {
  const obligations=new Map(), withdrawals=new Set(), hashes=new Set(), btcProofs=new Set(), rgbProofs=new Set();
  const positive=s=>typeof s==="string"&&/^[1-9][0-9]*$/.test(s);
  const hex=s=>typeof s==="string"&&/^[0-9a-f]{64}$/.test(s)&&!/^0+$/.test(s);
  const text=s=>typeof s==="string"&&s.length>0&&s.length<=256;
  const must=(v,m)=>{if(!v)throw new Error(m)};
  for(const e of events){
    must(e&&text(e.id),"event identity");
    const old=obligations.get(e.id);
    if(e.type==="reserve"){
      must(!old&&text(e.withdrawalId)&&!withdrawals.has(e.withdrawalId),"duplicate reserve");
      must(e.network==="regtest"&&text(e.assetId)&&e.assetId.startsWith("rgb:")&&positive(e.units)&&positive(e.sats)&&positive(e.carrierMsat)&&BigInt(e.carrierMsat)>=3000000n&&hex(e.batchDigest)&&hex(e.paymentHash)&&!hashes.has(e.paymentHash),"invalid reservation or reused hash");
      must(typeof e.payee==="string"&&/^(02|03)[0-9a-f]{64}$/.test(e.payee)&&Number.isSafeInteger(e.expiresAt)&&Number.isSafeInteger(e.at)&&e.at>=0&&e.at<e.expiresAt,"invalid reservation expiry/payee");
      withdrawals.add(e.withdrawalId);hashes.add(e.paymentHash);
      obligations.set(e.id,{...e,state:"reserved",lastAt:e.at,credited:false,frozen:false});
      continue;
    }
    must(old&&Number.isSafeInteger(e.at)&&e.at>=old.lastAt,"unknown or out-of-order event");
    const s=old.state;
    must(!old.frozen,"frozen obligation");
    switch(e.type){
      case "submit":
        must(s==="reserved"&&e.at<old.expiresAt,"invalid or expired submit");
        old.state="submitted";break;
      case "ambiguous":
        must(s==="submitted"||s==="observed","invalid ambiguity");
        old.state="ambiguous";break;
      case "observe":
        must(["submitted","ambiguous","observed"].includes(s)&&e.paymentHash===old.paymentHash,"invalid observation");
        old.state="observed";break;
      case "reconcile":
        // This is a transition model, not a proof verifier: identifiers are inputs
        // from independent verification, never SDK status alone.
        must(["submitted","ambiguous","observed"].includes(s)&&!old.credited&&e.paymentHash===old.paymentHash&&e.assetId===old.assetId&&e.units===old.units&&e.sats===old.sats&&e.carrierMsat===old.carrierMsat&&e.payee===old.payee&&e.network===old.network,"wrong reconciliation");
        must(hex(e.btcEvidence)&&hex(e.rgbEvidence)&&e.btcEvidence!==e.rgbEvidence&&!btcProofs.has(e.btcEvidence)&&!rgbProofs.has(e.rgbEvidence),"missing/reused leg evidence");
        btcProofs.add(e.btcEvidence);rgbProofs.add(e.rgbEvidence);
        old.state="reconciled";old.credited=true;break;
      case "chain_conflict":
        // Evidence invalidation is an alert/freeze, not an automatic reversal or refund.
        must(["submitted","ambiguous","observed","reconciled"].includes(s)&&hex(e.conflictEvidence),"invalid conflict");
        old.frozen=true;old.state="frozen";break;
      default:throw new Error("unknown event");
    }
    old.lastAt=e.at;
  }
  return [...obligations.values()].map(o=>({...o}));
}

export { replay };
