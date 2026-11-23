import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {
 PYTH_PRO_BTC_USD_FEED_ID,digestHex, canonicalSource, canonicalRelay,
 verifySourceReceipt,verifyNearImport,proveEquivocation,proveSourceSubstitution,normalizePoint,
} from '../src/oracle.mjs';

function fixture(){
 const vk=generateKeyPairSync('ed25519'),rk=generateKeyPairSync('ed25519');
 const policy={feedId:PYTH_PRO_BTC_USD_FEED_ID,maxFutureSkewUs:'1000000',maxAgeUs:'60000000',
 maxCarryForwardUs:'15000000',maxConfBps:'100',nearChainId:'near:testnet',nearContract:'shz-oracle.testnet',
 independentVerifierKeys:{independent:vk.publicKey.export({type:'spki',format:'pem'})},
 relayerKeys:{bonded:rk.publicKey.export({type:'spki',format:'pem'})}};
 const signedPayloadHex=Buffer.from('FICTIONAL SIGNED PYTH UPDATE: payload authenticity is NOT checked by this fixture','utf8').toString('hex');
 const receipt={verifierId:'independent',requestId:'shz-event-1',signedPayloadSha256:digestHex(Buffer.from(signedPayloadHex,'hex')),
 point:{feedId:PYTH_PRO_BTC_USD_FEED_ID,rawPrice:'8000000000000',conf:'1200000000',expo:-8,publishTimeUs:'1795000000000000',feedUpdateTimeUs:'1794999999000000'}};
 receipt.signatureHex=sign(null,canonicalSource(receipt),vk.privateKey).toString('hex');
 const src=verifySourceReceipt({receipt,signedPayloadHex,policy,nowUs:'1795000001000000'});
 const relay={nearChainId:'near:testnet',nearContract:'shz-oracle.testnet',relayerId:'bonded',
 requestId:receipt.requestId,eventId:'BTCUSD/2026-11-23',round:7,receiptHash:src.receiptHash,
 claimedPriceE8:src.priceE8,publishTimeUs:receipt.point.publishTimeUs,precommitRoot:'12'.repeat(32)};
 relay.signatureHex=sign(null,canonicalRelay(relay),rk.privateKey).toString('hex');
 return {policy,receipt,relay,signedPayloadHex,src,vk,rk};
}
test('independent verifier signed import has explicit non-native provenance grade',()=>{
 const f=fixture();const res=verifyNearImport({...f,nowUs:'1795000001000000'});
 assert.equal(res.priceE8,(80000n*100000000n).toString());
 assert.equal(res.nativePythSignatureVerified,false);
 assert.equal(res.nearFinalityVerified,false);
 assert.equal(res.bitcoinSpendEnforced,false);
 assert.equal(res.productionReady,false);
});
test('rejects altered original source payload even when relayer signs',()=>{
 const f=fixture();assert.throws(()=>verifyNearImport({...f,signedPayloadHex:'beef',nowUs:'1795000001000000'}),/payload hash mismatch/);
});
test('rejects forged upstream verifier signature',()=>{
 const f=fixture();f.receipt.point.rawPrice='6000000000000';
 assert.throws(()=>verifyNearImport({...f,nowUs:'1795000001000000'}),/invalid signer signature/);
});
test('rejects unregistered upstream verifier or relayer',()=>{
 const f=fixture();delete f.policy.independentVerifierKeys.independent;
 assert.throws(()=>verifyNearImport({...f,nowUs:'1795000001000000'}),/unregistered signer/);
 const g=fixture();delete g.policy.relayerKeys.bonded;
 assert.throws(()=>verifyNearImport({...g,nowUs:'1795000001000000'}),/unregistered signer/);
});
test('rejects stale prices and carried-forward stale feed update timestamps',()=>{
 const f=fixture();assert.throws(()=>verifyNearImport({...f,nowUs:'1795000120000000'}),/stale price/);
 const g=fixture();g.receipt.point.feedUpdateTimeUs='1794999900000000';
 g.receipt.signatureHex=sign(null,canonicalSource(g.receipt),g.vk.privateKey).toString('hex');
 assert.throws(()=>verifyNearImport({...g,nowUs:'1795000001000000'}),/stale carried-forward/);
});
test('rejects wrong network, contract and unsigned price substitution',()=>{
 const f=fixture();f.relay.nearChainId='near:mainnet';assert.throws(()=>verifyNearImport({...f,nowUs:'1795000001000000'}),/NEAR domain mismatch/);
 const g=fixture();g.relay.claimedPriceE8='1';assert.throws(()=>verifyNearImport({...g,nowUs:'1795000001000000'}),/relay price substitution/);
});
test('rejects excessive confidence and invalid exponent without float arithmetic',()=>{
 const f=fixture();f.policy.maxConfBps='1';assert.throws(()=>verifyNearImport({...f,nowUs:'1795000001000000'}),/confidence interval/);
 assert.throws(()=>normalizePoint({...f.receipt.point,expo:-90}),/unsupported exponent/);
});
test('two conflicting authorized relay messages prove objective double-signing',()=>{
 const f=fixture();const conflict={...f.relay,precommitRoot:'34'.repeat(32)};
 conflict.signatureHex=sign(null,canonicalRelay(conflict),f.rk.privateKey).toString('hex');
 const evidence=proveEquivocation(f.relay,conflict,f.policy);
 assert.equal(evidence.fraudType,'RELAY_EQUIVOCATION');
 assert.equal(evidence.nearSlashExecuted,false);
 assert.throws(()=>proveEquivocation(f.relay,f.relay,f.policy),/identical relay claims/);
});
test('fraud evidence cannot use unverified forged relay signature',()=>{
 const f=fixture();const other={...f.relay,claimedPriceE8:'1'};
 assert.throws(()=>proveEquivocation(f.relay,other,f.policy),/invalid signer signature/);
});
test('source substitution is independently provable and does not pretend NEAR has slashed',()=>{
 const f=fixture();f.relay.claimedPriceE8='9000000000000';
 f.relay.signatureHex=sign(null,canonicalRelay(f.relay),f.rk.privateKey).toString('hex');
 const proof=proveSourceSubstitution({...f,nowUs:'1795000001000000'});
 assert.equal(proof.fraudType,'RELAY_SOURCE_SUBSTITUTION');assert.equal(proof.nearSlashExecuted,false);
});
