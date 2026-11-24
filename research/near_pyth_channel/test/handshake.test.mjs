import test from 'node:test';
import assert from 'node:assert/strict';
import {newCloseoutSession,addPreparedPackage,lockChannel,simulatePreimageReveal,demoPreimage} from '../src/handshake.mjs';
const a='aa'.repeat(32),b='bb'.repeat(32);
function setup(){const secret=demoPreimage(),plan={status:'PROPOSED_ONLY',proposalHash:a,
 funding:{feasible:true},channelHops:[{channelId:'AB'},{channelId:'AC'}]};
 return {secret,state:newCloseoutSession(plan,secret.hashlockHex,200)};}
const prep=id=>({channelId:id,proposalHash:a,offerDigest:b,refundDigest:b,penaltyDigest:b,authorizationDigest:b});
const ack=id=>({channelId:id,proposalHash:a,signedCommitmentDigest:b,revokedOldStateDigest:b,verifierReceiptDigest:b});
test('two-phase channel preparation requires every channel before lock',()=>{
 let {state}=setup();state=addPreparedPackage(state,prep('AB'));assert.equal(state.phase,'PROPOSED');
 assert.throws(()=>lockChannel(state,ack('AB')),/all exit packages/);
 state=addPreparedPackage(state,prep('AC'));assert.equal(state.phase,'PREPARED');
 state=lockChannel(state,ack('AB'));assert.equal(state.phase,'PREPARED');
 state=lockChannel(state,ack('AC'));assert.equal(state.phase,'LOCKED');
});
test('revocation package required and repeated channel approvals rejected',()=>{
 let {state}=setup();state=addPreparedPackage(state,prep('AB'));
 assert.throws(()=>addPreparedPackage(state,prep('AB')),/duplicate preparation/);
 state=addPreparedPackage(state,prep('AC'));
 assert.throws(()=>lockChannel(state,{...ack('AB'),revokedOldStateDigest:''}),/missing signed commitment/);
});
test('hash preimage disclosure stays simulated and requires both channel locks',()=>{
 let {state,secret}=setup();state=addPreparedPackage(state,prep('AB'));state=addPreparedPackage(state,prep('AC'));
 assert.throws(()=>simulatePreimageReveal(state,secret.preimageHex,150),/missing locked channel/);
 state=lockChannel(state,ack('AB'));state=lockChannel(state,ack('AC'));
 assert.throws(()=>simulatePreimageReveal(state,a,150),/incorrect preimage/);
 assert.throws(()=>simulatePreimageReveal(state,secret.preimageHex,201),/expired/);
 const receipt=simulatePreimageReveal(state,secret.preimageHex,150);
 assert.equal(receipt.preimageReleased,true);assert.equal(receipt.bitcoinSpendEnforced,false);
 assert.equal(receipt.collateralReleased,false);
});
