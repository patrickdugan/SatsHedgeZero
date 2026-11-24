/**
 * SHZ-CHANNEL-01 conditional multi-channel closeout handshake scaffold.
 * This is an off-chain PREPARATION AUDIT, not a Lightning channel engine.
 * Native wallet verification, revocations, penalty scripts, BIP341 signatures,
 * and SPV/Bitcoin chain status MUST be provided by independent adapters.
 */
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
const h = x=>createHash('sha256').update(x).digest('hex');
function check(cond,message){if(!cond)throw new Error(message)}
const H = v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
export function newCloseoutSession(proposal,hashlockHex,expiryHeight){
 check(proposal?.status==='PROPOSED_ONLY'&&H(proposal.proposalHash),'invalid closeout proposal');
 check(H(hashlockHex),'invalid hashlock');
 check(Number.isSafeInteger(expiryHeight)&&expiryHeight>0,'invalid expiry');
 check(proposal.funding.feasible,'underfunded closeout');
 return Object.freeze({
   proposalHash:proposal.proposalHash,hashlockHex,expiryHeight,
   expectedChannelIds:[...new Set(proposal.channelHops?.map(x=>x.channelId)||[])].sort(),
   phase:'PROPOSED',prepared:[],locked:[],
   preimageReleased:false,bitcoinSpendEnforced:false,collateralReleased:false,
 });
}
/** Each verified package must be checked by an actual channel adaptor. Here we only
 * pin its hashes and record acknowledgement for an external validator to audit.
 */
export function addPreparedPackage(state,receipt){
 check(state.phase==='PROPOSED'||state.phase==='PREPARED','preparation phase closed');
 check(state.expectedChannelIds.includes(receipt?.channelId),'unrecognized channel');
 check(!state.prepared.some(x=>x.channelId===receipt.channelId),'duplicate preparation');
 check(H(receipt?.offerDigest)&&H(receipt?.refundDigest)&&H(receipt?.penaltyDigest)&&H(receipt?.authorizationDigest),
   'missing signed exit or penalty package commitment');
 check(receipt.proposalHash===state.proposalHash,'wrong closeout proposal');
 const prepared=[...state.prepared,{...receipt}].sort((a,b)=>a.channelId.localeCompare(b.channelId));
 return Object.freeze({...state,prepared,phase:prepared.length===state.expectedChannelIds.length?'PREPARED':'PROPOSED'});
}
/** Record native external verifier evidence of signed commitments AND old-state revocations.
 * A hash of a verification report is bookkeeping, not an independent proof here.
 */
export function lockChannel(state,ack){
 check(state.phase==='PREPARED'||state.phase==='LOCKED','all exit packages must be prepared first');
 check(state.expectedChannelIds.includes(ack?.channelId),'unrecognized channel');
 check(!state.locked.some(x=>x.channelId===ack.channelId),'duplicate commitment lock');
 check(H(ack?.signedCommitmentDigest)&&H(ack?.revokedOldStateDigest)&&H(ack?.verifierReceiptDigest),
    'missing signed commitment, revocation or independent verifier receipt');
 check(ack.proposalHash===state.proposalHash,'proposal mismatch');
 const locked=[...state.locked,{...ack}].sort((a,b)=>a.channelId.localeCompare(b.channelId));
 return Object.freeze({...state,locked,phase:locked.length===state.expectedChannelIds.length?'LOCKED':'PREPARED'});
}
/** Hashlock disclosure must occur only AFTER all channel signatures and revocations
 * have been independently checked. This function only makes a simulation receipt.
 */
export function simulatePreimageReveal(state,preimageHex,currentHeight){
 check(state.phase==='LOCKED','missing locked channel commitments');
 check(Number.isSafeInteger(currentHeight)&&currentHeight<state.expiryHeight,'expired condition');
 check(typeof preimageHex==='string'&&H(preimageHex),'invalid preimage');
 const got=Buffer.from(h(Buffer.from(preimageHex,'hex')),'hex');
 if(!timingSafeEqual(got,Buffer.from(state.hashlockHex,'hex')))throw new Error('incorrect preimage');
 return Object.freeze({...state,phase:'SIMULATED_REVEAL',preimageReleased:true,
   bitcoinSpendEnforced:false,collateralReleased:false,
   warning:'Use on-chain channel engine to publish preimage; this record authorizes no Bitcoin spend.'});
}
export function demoPreimage(){const s=randomBytes(32);return {preimageHex:s.toString('hex'),hashlockHex:h(s)};}
