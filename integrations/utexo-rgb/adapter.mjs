function devNetwork(network) {
  if (!["regtest","signet","testnet"].includes(network)) throw new Error("RGB Lightning is development-only");
  return network;
}

function uint(value, name) {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
  throw new Error("Invalid integer: " + name);
}

function exactNumber(value, name) {
  const n=uint(value,name);
  if(n>BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("SDK unsafe integer: "+name);
  return Number(n);
}

function assetId(id) {
  if(typeof id!=="string" || !/^rgb:[A-Za-z0-9_~\-]+$/.test(id)) throw new Error("Expected explicit RGB contract ID");
  return id;
}

function hash32(h) {
  if(typeof h!=="string" || !/^[0-9a-f]{64}$/.test(h) || /^0+$/.test(h)) throw new Error("Invalid payment hash");
  return h;
}

function pubkey(k) {
  if(typeof k!=="string" || !/^(02|03)[0-9a-f]{64}$/.test(k)) throw new Error("Invalid recipient node ID");
  return k;
}

function quoteConversion({sats,btcUsdCents,assetUsdCents,decimals}) {
  const s=uint(sats,"sats"),p=uint(btcUsdCents,"BTC cents"),a=uint(assetUsdCents,"asset cents");
  if(!s||!p||!a||!Number.isInteger(decimals)||decimals<0||decimals>18) throw new Error("Invalid quote");
  const numerator=s*p*10n**BigInt(decimals),denominator=100000000n*a;
  return {assetUnits:numerator/denominator,remainder:numerator%denominator,denominator};
}

function validateQuote(q,now) {
  devNetwork(q.network);assetId(q.assetId);pubkey(q.payee);
  if(typeof q.obligationId!=="string" || !q.obligationId.trim()) throw new Error("Missing obligation ID");
  const assetUnits=exactNumber(q.assetUnits,"assetUnits"), carrierMsat=exactNumber(q.carrierMsat,"carrierMsat");
  if(assetUnits<=0||carrierMsat<3000000) throw new Error("Zero asset or below RGB HTLC minimum");
  if(!Number.isSafeInteger(now)||now<0||!Number.isSafeInteger(q.expiresAt)||q.expiresAt<=now||q.expiresAt-now>3600) throw new Error("Invalid or expired quote");
  return {assetUnits,carrierMsat,expirySec:q.expiresAt-now};
}

function checkDecoded(q,decoded,now) {
  const v=validateQuote(q,now);
  if(String(decoded.network).toLowerCase()!==q.network||decoded.asset_id!==q.assetId||decoded.payee_pubkey!==q.payee||
     uint(decoded.asset_amount,"decoded asset")!==BigInt(v.assetUnits)||uint(decoded.amt_msat,"decoded carrier")!==BigInt(v.carrierMsat))
    throw new Error("Invoice binding mismatch");
  if(!Number.isSafeInteger(decoded.timestamp)||!Number.isSafeInteger(decoded.expiry_sec)||decoded.timestamp<0||decoded.expiry_sec<=0||
     decoded.timestamp>now||!Number.isSafeInteger(decoded.timestamp+decoded.expiry_sec)||
     decoded.timestamp+decoded.expiry_sec<=now||decoded.timestamp+decoded.expiry_sec>q.expiresAt)
    throw new Error("Invoice expiry mismatch");
  return Object.freeze({obligationId:q.obligationId,network:q.network,assetId:q.assetId,assetUnits:String(v.assetUnits),carrierMsat:String(v.carrierMsat),payee:q.payee,paymentHash:hash32(decoded.payment_hash),expiresAt:decoded.timestamp+decoded.expiry_sec,kind:"invoice_candidate"});
}

async function createDevelopmentAdapter(account,network) {
  devNetwork(network);
  if(!account||typeof account.toReadOnlyAccount!=="function") throw new Error("Expected unlocked WDK account");
  if (account.getNetwork?.() !== network || account.getCapabilities?.().lightning !== true) throw new Error("Account capability/network mismatch");
  const read=await account.toReadOnlyAccount();
  function local(q){if(q.network!==network) throw new Error("Account network mismatch");}
  return Object.freeze({
    async inspect(id){
      assetId(id);
      const state=await read.getAddressState();
      if(state.status!=="ready") throw new Error("Wallet is locked");
      return {network,state:state.status,metadata:await read.getAssetMetadata(id),balance:await read.getAssetBalance(id)};
    },
    async createReceiveInvoice(q,now){
      local(q);const v=validateQuote(q,now);
      // The native return is deliberately opaque until package-specific capture.
      return account.createLightningInvoice({amountMsat:v.carrierMsat,expirySec:v.expirySec,assetId:q.assetId,assetAmount:v.assetUnits});
    },
    async inspectInvoice(q,invoice,now){
      local(q);validateQuote(q,now);
      if(typeof invoice!=="string"||!invoice.trim()) throw new Error("Missing invoice");
      return checkDecoded(q,await read.decodeInvoice(invoice),now);
    },
    async observe(candidate,invoice){
      if(candidate.network!==network||candidate.kind!=="invoice_candidate") throw new Error("Candidate mismatch");
      const d=await read.decodeInvoice(invoice);
      if(d.payment_hash!==candidate.paymentHash||String(d.network).toLowerCase()!==candidate.network||d.asset_id!==candidate.assetId||
         uint(d.asset_amount,"asset")!==uint(candidate.assetUnits,"candidate asset")||
         uint(d.amt_msat,"carrier")!==uint(candidate.carrierMsat,"candidate carrier")||d.payee_pubkey!==candidate.payee) throw new Error("Observation invoice mismatch");
      return {kind:"unverified_observation",paymentHash:hash32(candidate.paymentHash),
        invoiceStatus:await read.getInvoiceStatus(invoice),
        inbound:await read.getPayment(candidate.paymentHash,"InboundAutoClaim")};
    }
  });
}

export { quoteConversion, checkDecoded, createDevelopmentAdapter };
