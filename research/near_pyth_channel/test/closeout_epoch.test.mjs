import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {buildCloseoutProposal} from '../src/channels.mjs';
import {openClearingEpoch,approveChannel,canonicalWalletApproval,requestChannelCloseout,canonicalNearObservation} from '../src/closeout_epoch.mjs';
import {INNER_MAGIC} from '../src/pyth_payload.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
const hex=s=>hash(s);
const P='aa'.repeat(32);
function signedPythPrice(){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const signer=publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
 const b=Buffer.alloc(4+8+1+1+4+1+9+3+9+10);let i=0;
 b.writeUInt32LE(INNER_MAGIC,i);i+=4;b.writeBigUInt64LE(1795000000000000n,i);i+=8;
 b[i++]=3;b[i++]=1;b.writeUInt32LE(1,i);i+=4;b[i++]=4;
 b[i++]=0;b.writeBigInt64LE(12500000000000n,i);i+=8;
 b[i++]=4;b.writeInt16LE(-8,i);i+=2;
 b[i++]=5;b.writeBigInt64LE(1500000000n,i);i+=8;
 b[i++]=12;b[i++]=1;b.writeBigUInt64LE(1795000000000000n,i);i+=8;
 const payload=b.subarray(0,i),outer=Buffer.alloc(payload.length+102);
 outer.writeUInt32LE(2182742457);sign(null,payload,privateKey).copy(outer,4);
 Buffer.from(signer,'hex').copy(outer,68);outer.writeUInt16LE(payload.length,100);payload.copy(outer,102);
 return {envelopeHex:outer.toString('hex'),signerKeys:[signer],policy:{feedId:1,allowedChannelIds:[3],
  maxAgeUs:'4000000',maxCarryForwardUs:'1000000',maxFutureSkewUs:'0',maxConfBps:'100'},nowUs:'1795000001000000'};
}
function fixture(){
 const trades=[
  {id:'AB',long:'Alice',short:'Bob',notionalUsd:'1',entryUsd:'80000',longMarginSats:'625',shortMarginSats:'1000',fundingTxid:'01'.repeat(32),fundingVout:0},
  {id:'BC',long:'Bob',short:'Carol',notionalUsd:'1',entryUsd:'100000',longMarginSats:'500',shortMarginSats:'625',fundingTxid:'02'.repeat(32),fundingVout:1},
  {id:'CA',long:'Carol',short:'Alice',notionalUsd:'1',entryUsd:'125000',longMarginSats:'400',shortMarginSats:'400',fundingTxid:'03'.repeat(32),fundingVout:2},
 ];
 const vaults=[{id:'bob',owner:'Bob',nettingSetId:'btc',fundedSats:'1500',protectedSats:'0'},
   {id:'carol',owner:'Carol',nettingSetId:'btc',fundedSats:'1025',protectedSats:'0'}];
 const routes=[{fromVaultId:'bob',toParty:'Alice',capacitySats:'250',policyDigest:P},
  {fromVaultId:'carol',toParty:'Alice',capacitySats:'200',policyDigest:P}];
 const channelHops=[
  {channelId:'AB',commitmentTxid:hex('AB'),timeoutHeight:240,originalPeerOffline:true,authorizationMode:'mnr02-0x83-at-maturity',preauthorizationPackageDigest:hex('AB preauth')},
  {channelId:'BC',commitmentTxid:hex('BC'),timeoutHeight:220,originalPeerOffline:true,authorizationMode:'mnr02-0x83-at-maturity',preauthorizationPackageDigest:hex('BC preauth')},
  {channelId:'CA',commitmentTxid:hex('CA'),timeoutHeight:200,authorizationMode:'interactive-bilateral'},
 ];
 const pythSignedUpdate=signedPythPrice();
 // Compute native source receipt independently by re-verifying the same signed bytes.
 // The epoch coordinator will also re-verify; the earlier proposal needs its hash.
 const oracleImport=verifyNativeFromFixture(pythSignedUpdate);
 const proposal=buildCloseoutProposal({routeId:'triangle',markUsd:'125000',oracleImport,
   trades,vaults,routes,channelHops,currentHeight:120});
 const channelPolicies=channelHops.map(h=>({channelId:h.channelId,authorizationMode:h.authorizationMode,
   cetPackageDigest:hex(h.channelId+' cet'),refundPackageDigest:hex(h.channelId+' refund'),
   revocationPackageDigest:hex(h.channelId+' revocation'),routePolicyDigest:hex(h.channelId+' policy'),
   activationHeight:119,expiryHeight:h.timeoutHeight,
   requiredWalletIds:h.channelId==='AB'?['Alice','Guard']:h.channelId==='BC'?['Carol','Guard']:['Alice','Carol'],
   ...(h.originalPeerOffline?{originationPreauthorizationDigest:h.preauthorizationPackageDigest,
    bobPinnedOutputDigest:hex(h.channelId+' Bob output'),sighashType:131,
    l1MaturityHeight:175,graceEndHeight:205,refundHeight:245}:{})}));
 const policy={bitcoinNetwork:'bitcoin-testnet4',genesisHash:hex('testnet4 genesis'),previousLedgerRoot:hex('prior state'),
   nearChainId:'near:testnet',nearContractId:'shz-guard.testnet',
   eventId:'SHZ/BTCUSD/TESTNET4/177',oracleEpoch:177,currentHeight:120,challengeEndHeight:125,channels:channelPolicies};
 const keyIds=['Alice','Bob','Carol','Guard'];
 const keys=Object.fromEntries(keyIds.map(id=>[id,generateKeyPairSync('ec',{namedCurve:'secp256k1'})]));
 const pubkeys=Object.fromEntries(keyIds.map(id=>[id,keys[id].publicKey.export({format:'pem',type:'spki'})]));
 return {proposal,pythSignedUpdate,policy,keys,pubkeys};
}
import {verifyNativePythBtcUsd} from '../src/pyth_payload.mjs';
const verifyNativeFromFixture=x=>verifyNativePythBtcUsd(x);
function allApprovals(f){
 let state=openClearingEpoch(f);
 for(const c of state.channels)for(const walletId of c.requiredWalletIds){
  const m={sessionHash:state.sessionHash,proposalHash:state.proposalHash,channelId:c.channelId,walletId,
   commitmentTxid:c.commitmentTxid,cetPackageDigest:c.cetPackageDigest,refundPackageDigest:c.refundPackageDigest,
   revocationPackageDigest:c.revocationPackageDigest,oracleReceiptHash:state.oracleReceiptHash,
   routePolicyDigest:c.routePolicyDigest,activationHeight:c.activationHeight,expiryHeight:c.expiryHeight,
   authorizationMode:c.authorizationMode};
  m.signatureHex=sign('sha256',canonicalWalletApproval(m),f.keys[walletId].privateKey).toString('hex');
  state=approveChannel(state,m,f.pubkeys);
 }
 return state;
}
function observe(s){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const receipt={observerId:'IndependentNearNode',nearChainId:s.nearChainId,
   nearContractId:s.nearContractId,sessionHash:s.sessionHash,eventId:s.eventId,
   oracleEpoch:s.oracleEpoch,signedPayloadSha256:s.oraclePayloadSha256,
   stateRoot:hex('NEAR finalized state'),blockHash:hex('NEAR finalized block'),
   blockHeight:1000000,challengeWindowClosed:true};
 receipt.signatureHex=sign(null,canonicalNearObservation(receipt),privateKey).toString('hex');
 return {nearObservation:receipt,observerKeys:{IndependentNearNode:publicKey.export({format:'pem',type:'spki'})}};
}
test('native-signed oracle epoch + complete multi-channel wallet approvals stay non-spending',()=>{
 const f=fixture(),s=allApprovals(f);
 assert.equal(s.approvals.length,6);
 assert.equal(s.phase,'APPROVED_FOR_WALLET_VERIFICATION');
 assert.equal(s.bitcoinSpendEnforced,false);
 assert.equal(s.collateralReleased,false);
 assert.match(s.sessionHash,/^[0-9a-f]{64}$/);
});
test('offline Bob cannot trigger premature BTC release before L1 maturity',()=>{
 const s=allApprovals(fixture());
 const waiting=requestChannelCloseout(s,{height:150,externalCommitmentVerifierReady:true,...observe(s)});
 assert.equal(waiting.phase,'AWAITING_MNR02_L1_MATURITY');
 assert.equal(waiting.collateralReleased,false);
 const requested=requestChannelCloseout(s,{height:180,externalCommitmentVerifierReady:true,...observe(s)});
 assert.equal(requested.phase,'WALLET_SETTLEMENT_REQUESTED');
 assert.equal(requested.readyForBitcoinBroadcast,false);
 assert.equal(requested.bitcoinSpendEnforced,false);
});
test('challenge window, NEAR finality, Bitcoin wallet adapter gate all prevent requesting closeout',()=>{
 const s=allApprovals(fixture());
 assert.throws(()=>requestChannelCloseout(s,{height:120,...observe(s),externalCommitmentVerifierReady:true}),/challenge window/);
 assert.throws(()=>requestChannelCloseout(s,{height:180,nearObservation:null,externalCommitmentVerifierReady:true}),/unbound or unfinalized NEAR/);
 assert.throws(()=>requestChannelCloseout(s,{height:180,...observe(s),externalCommitmentVerifierReady:false}),/Bitcoin channel commitment verifier/);
});
test('offline L1 route loses priority at grace end and cannot unlock collateral',()=>{
 const s=allApprovals(fixture());
 assert.throws(()=>requestChannelCloseout(s,{height:199,...observe(s),externalCommitmentVerifierReady:true}),/priority confirmation window exhausted/);
 assert.throws(()=>requestChannelCloseout(s,{height:220,...observe(s),externalCommitmentVerifierReady:true}),/channel lock has expired/);
});
test('wallet approval cannot replay across sessions or against a different oracle price',()=>{
 const f=fixture();const s=openClearingEpoch(f),c=s.channels[0],id=c.requiredWalletIds[0];
 const a={sessionHash:s.sessionHash,proposalHash:s.proposalHash,channelId:c.channelId,walletId:id,
   commitmentTxid:c.commitmentTxid,cetPackageDigest:c.cetPackageDigest,refundPackageDigest:c.refundPackageDigest,
   revocationPackageDigest:c.revocationPackageDigest,oracleReceiptHash:s.oracleReceiptHash,
   routePolicyDigest:c.routePolicyDigest,activationHeight:c.activationHeight,expiryHeight:c.expiryHeight,
   authorizationMode:c.authorizationMode};
 a.signatureHex=sign('sha256',canonicalWalletApproval(a),f.keys[id].privateKey).toString('hex');
 assert.equal(approveChannel(s,a,f.pubkeys).phase,'AWAITING_APPROVALS');
 assert.throws(()=>approveChannel(s,{...a,oracleReceiptHash:hex('changed oracle')},f.pubkeys),/not bound to exact/);
 assert.throws(()=>approveChannel(s,{...a,signatureHex:a.signatureHex.slice(0,-2)+'ab'},f.pubkeys),/invalid wallet approval signature/);
 const ns=openClearingEpoch({...f,policy:{...f.policy,oracleEpoch:f.policy.oracleEpoch+1}});
 assert.throws(()=>approveChannel(ns,a,f.pubkeys),/not bound to exact/);
});
test('full wallet approvals require every named channel and signer, duplicate rejected',()=>{
 const f=fixture(),s=openClearingEpoch(f),c=s.channels[0],id=c.requiredWalletIds[0];
 const a={sessionHash:s.sessionHash,proposalHash:s.proposalHash,channelId:c.channelId,walletId:id,
   commitmentTxid:c.commitmentTxid,cetPackageDigest:c.cetPackageDigest,refundPackageDigest:c.refundPackageDigest,
   revocationPackageDigest:c.revocationPackageDigest,oracleReceiptHash:s.oracleReceiptHash,
   routePolicyDigest:c.routePolicyDigest,activationHeight:c.activationHeight,expiryHeight:c.expiryHeight,
   authorizationMode:c.authorizationMode};
 a.signatureHex=sign('sha256',canonicalWalletApproval(a),f.keys[id].privateKey).toString('hex');
 const one=approveChannel(s,a,f.pubkeys);
 assert.throws(()=>approveChannel(one,a,f.pubkeys),/duplicate channel wallet approval/);
 assert.throws(()=>requestChannelCloseout(one,{height:180,...observe(s),externalCommitmentVerifierReady:true}),/incomplete bilateral/);
});
test('missing Bob origination 0x83 preauth and unsafe fallback heights fail',()=>{
 const f=fixture();f.policy.channels[0].originationPreauthorizationDigest=hex('changed');
 assert.throws(()=>openClearingEpoch(f),/unverifiable Bob-offline/);
 const g=fixture();g.policy.channels[0].graceEndHeight=175;
 assert.throws(()=>openClearingEpoch(g),/unverifiable Bob-offline/);
});
test('oracle object with fabricated provenance cannot bypass signed-envelope verification',()=>{
 const f=fixture();
 assert.throws(()=>openClearingEpoch({...f,pythSignedUpdate:{nativePythSignatureVerified:true,priceFieldsParsedAndBound:true,receiptHash:P}}));
});
test('unfunded or nonflat closeout never opens a clearing epoch',()=>{
 const f=fixture();
 assert.throws(()=>openClearingEpoch({...f,proposal:{...f.proposal,funding:{feasible:false}}}),/unfunded/);
 assert.throws(()=>openClearingEpoch({...f,proposal:{...f.proposal,accounting:{...f.proposal.accounting,allPartiesFlat:false}}}),/residual USD exposure/);
});
test('session hash commits to every bilateral CET/refund/revocation and required wallet ID',()=>{
 const f=fixture(),base=openClearingEpoch(f);
 const g=fixture();g.policy.channels[0].cetPackageDigest=hex('different CET');
 assert.notEqual(openClearingEpoch(g).sessionHash,base.sessionHash);
 const h=fixture();h.policy.channels[0].requiredWalletIds.push('Bob');
 assert.notEqual(openClearingEpoch(h).sessionHash,base.sessionHash);
});
test('adversarial caller mutation after epoch open cannot rewrite pinned channel keys',()=>{
 const f=fixture(),s=openClearingEpoch(f);
 const before=s.sessionHash;
 f.policy.channels[0].requiredWalletIds.push('Mallory');
 f.policy.channels[0].cetPackageDigest=hex('changed');
 assert.equal(s.channels[0].requiredWalletIds.includes('Mallory'),false);
 assert.equal(s.sessionHash,before);
 assert.throws(()=>s.channels[0].requiredWalletIds.push('Mallory'),TypeError);
});

test('NEAR observer cannot spoof finalized state root or reuse a different epoch',()=>{
 const f=fixture(),s=allApprovals(f),o=observe(s);
 assert.throws(()=>requestChannelCloseout(s,{height:180,externalCommitmentVerifierReady:true,
   nearObservation:{...o.nearObservation,stateRoot:hex('forged')},observerKeys:o.observerKeys}),/invalid independent NEAR observer signature/);
 assert.throws(()=>requestChannelCloseout(s,{height:180,externalCommitmentVerifierReady:true,
   nearObservation:{...o.nearObservation,oracleEpoch:s.oracleEpoch+1},observerKeys:o.observerKeys}),/unbound or unfinalized/);
 assert.throws(()=>requestChannelCloseout(s,{height:180,externalCommitmentVerifierReady:true,
   nearObservation:{...o.nearObservation,challengeWindowClosed:false},observerKeys:o.observerKeys}),/unbound or unfinalized/);
});
