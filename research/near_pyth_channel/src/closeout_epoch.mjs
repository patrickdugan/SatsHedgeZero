/**
 * SHZ-ORACLE-02 / CHANNEL-02: cryptographic *intent* binding for multi-channel
 * economic closeout. Wallet approval signatures authenticate the exact clearing
 * epoch; they are NOT Bitcoin signatures, revocations, nor channel commitments.
 * All actual collateral remains under its original bilateral DLC until Bitcoin
 * settlement or LN commitment updates are independently enforced.
 */
import {createHash,createPublicKey,verify} from 'node:crypto';
import {verifyNativePythBtcUsd} from './pyth_payload.mjs';
const H=x=>createHash('sha256').update(x).digest('hex');
const hex32=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const fail=x=>{throw new Error(x)};
const U=n=>typeof n==='number'&&Number.isSafeInteger(n)&&n>=0;
const str=x=>typeof x==='string'&&x.length>0&&x.length<=128;
const bound=(value,name)=>{if(!str(value))fail(`invalid ${name}`);return value};
function unique(xs,name){const s=new Set(xs);if(s.size!==xs.length)fail(`duplicate ${name}`);}

export function canonicalWalletApproval(a){
  return Buffer.from(JSON.stringify([
    'SHZ/MULTILATERAL-CHANNEL-WALLET-APPROVAL/V2',a.sessionHash,a.proposalHash,
    a.channelId,a.walletId,a.commitmentTxid,a.cetPackageDigest,a.refundPackageDigest,
    a.revocationPackageDigest,a.oracleReceiptHash,a.routePolicyDigest,
    a.activationHeight,a.expiryHeight,a.authorizationMode,
  ]));
}
function verifyWalletSig(receipt,walletKeys){
  if(typeof receipt.signatureHex!=='string'||!/^(?:[0-9a-f]{2})+$/.test(receipt.signatureHex)||receipt.signatureHex.length>512)fail('invalid wallet signature');
  if(!Object.hasOwn(walletKeys,receipt.walletId))fail('unregistered wallet signer');
  const key=createPublicKey(walletKeys[receipt.walletId]);
  if(key.asymmetricKeyType!=='ec' || key.asymmetricKeyDetails?.namedCurve!=='secp256k1')fail('expected secp256k1 wallet signer');
  if(!verify('sha256',canonicalWalletApproval(receipt),key,Buffer.from(receipt.signatureHex,'hex')))fail('invalid wallet approval signature');
}
/**
 * Bilateral channel IDs are retained. The route closes economic exposure across
 * counterparties, with a separate authorization for every affected channel.
 */
export function openClearingEpoch({proposal,pythSignedUpdate,policy}) {
  // The caller supplies the original signed bytes. Re-verify them here rather
  // than trusting a plain object with self-declared provenance flags.
  const pythPrice=verifyNativePythBtcUsd(pythSignedUpdate);
  if(proposal?.status!=='PROPOSED_ONLY'||!hex32(proposal.proposalHash)||!proposal.funding?.feasible)fail('unfunded or invalid closeout proposal');
  if(!proposal.accounting?.allPartiesFlat)fail('unmatched residual USD exposure');
  if(!pythPrice?.nativePythSignatureVerified||!pythPrice?.priceFieldsParsedAndBound||!hex32(pythPrice.receiptHash))fail('native signed Pyth price proof required');
  if((BigInt(proposal.accounting.markUsd)*100000000n).toString()!==pythPrice.priceE8)fail('oracle price does not match clearing mark');
  if(policy?.bitcoinNetwork!=='bitcoin-testnet4'&&policy?.bitcoinNetwork!=='bitcoin-regtest')fail('invalid Bitcoin network');
  if(!hex32(policy.genesisHash)||!hex32(policy.previousLedgerRoot)||!str(policy.eventId)||
    !str(policy.nearChainId)||!str(policy.nearContractId)||!U(policy.oracleEpoch)||
    !U(policy.currentHeight)||!U(policy.challengeEndHeight)||policy.challengeEndHeight<=policy.currentHeight)fail('invalid oracle epoch or challenge window');
  if(!Array.isArray(proposal.channelHops)||proposal.channelHops.length===0||proposal.channelHops.length>32)fail('missing bilateral channels');
  if(!Array.isArray(policy.channels)||policy.channels.length!==proposal.channelHops.length)fail('incomplete per-channel recovery policy');
  const hopMap=new Map(proposal.channelHops.map(h=>[h.channelId,h]));
  unique(proposal.channelHops.map(h=>h.channelId),'channel route');
  unique(policy.channels.map(p=>p.channelId),'channel recovery policy');
  const channels=[];
  for(const item of policy.channels){
    const hop=hopMap.get(item.channelId);
    if(!hop||!hex32(hop.commitmentTxid)||!hex32(item.cetPackageDigest)||!hex32(item.refundPackageDigest)||
       !hex32(item.revocationPackageDigest)||!hex32(item.routePolicyDigest))fail('missing exact bilateral package hashes');
    if(!U(item.activationHeight)||!U(item.expiryHeight)||item.activationHeight>=item.expiryHeight ||
       item.expiryHeight!==hop.timeoutHeight || item.activationHeight>policy.currentHeight)fail('invalid per-channel height policy');
    if(!Array.isArray(item.requiredWalletIds)||item.requiredWalletIds.length===0||item.requiredWalletIds.length>4)fail('missing channel signers');
    item.requiredWalletIds.forEach(id=>bound(id,'wallet ID'));unique(item.requiredWalletIds,'wallet signer');
    if(item.authorizationMode!==hop.authorizationMode)fail('channel authorization mismatch');
    if(hop.originalPeerOffline){
      if(item.authorizationMode!=='mnr02-0x83-at-maturity'||!hex32(item.originationPreauthorizationDigest)||
         item.originationPreauthorizationDigest!==hop.preauthorizationPackageDigest||
         !hex32(item.bobPinnedOutputDigest)||item.sighashType!==131||
         !U(item.l1MaturityHeight)||!U(item.graceEndHeight)||!U(item.refundHeight)||
         !(item.l1MaturityHeight<item.graceEndHeight&&item.graceEndHeight<item.refundHeight))fail('unverifiable Bob-offline MNR02 fallback policy');
    } else if(item.authorizationMode!=='interactive-bilateral')fail('unexpected noninteractive channel');
    channels.push(Object.freeze({...item,requiredWalletIds:Object.freeze([...item.requiredWalletIds].sort()),
      commitmentTxid:hop.commitmentTxid,originalPeerOffline:!!hop.originalPeerOffline}));
  }
  channels.sort((a,b)=>a.channelId.localeCompare(b.channelId));
  Object.freeze(channels);
  const immutable=Object.freeze({
    network:policy.bitcoinNetwork,genesisHash:policy.genesisHash,eventId:policy.eventId,
    nearChainId:policy.nearChainId,nearContractId:policy.nearContractId,
    oracleEpoch:policy.oracleEpoch,challengeEndHeight:policy.challengeEndHeight,
    previousLedgerRoot:policy.previousLedgerRoot,
    oracleSourceHash:pythPrice.receiptHash,oraclePayloadSha256:pythPrice.signedPayloadSha256,
    oracleTimestampUs:pythPrice.publishTimeUs,
    oracleFeedUpdateTimeUs:pythPrice.feedUpdateTimeUs,oraclePriceE8:pythPrice.priceE8,
    proposalHash:proposal.proposalHash,
    channelPolicies:channels.map(c=>({id:c.channelId,mode:c.authorizationMode,txid:c.commitmentTxid,
      routePolicyDigest:c.routePolicyDigest,cetPackageDigest:c.cetPackageDigest,
      refundPackageDigest:c.refundPackageDigest,revocationPackageDigest:c.revocationPackageDigest,
      activationHeight:c.activationHeight,expiryHeight:c.expiryHeight,
      requiredWalletIds:c.requiredWalletIds,preauthDigest:c.originationPreauthorizationDigest||null,
      bobPinnedOutputDigest:c.bobPinnedOutputDigest||null,sighashType:c.sighashType||null,
      maturity:c.l1MaturityHeight||null,grace:c.graceEndHeight||null,refund:c.refundHeight||null})),
  });
  const sessionHash=H(Buffer.from(JSON.stringify(['SHZ/MNR-CLEARING-EPOCH/V2',immutable])));
  return Object.freeze({sessionHash,proposalHash:proposal.proposalHash,
    oracleReceiptHash:pythPrice.receiptHash,oraclePayloadSha256:pythPrice.signedPayloadSha256,
    oracleEpoch:policy.oracleEpoch,eventId:policy.eventId,
    nearChainId:policy.nearChainId,nearContractId:policy.nearContractId,
    challengeEndHeight:policy.challengeEndHeight,channels,approvals:Object.freeze([]),phase:'AWAITING_APPROVALS',
    bitcoinSpendEnforced:false,collateralReleased:false,nearFinalityVerified:false,
    readyForBitcoinBroadcast:false,
  });
}

export function approveChannel(state,approval,walletKeys){
  if(state?.phase!=='AWAITING_APPROVALS'&&state?.phase!=='APPROVED_FOR_WALLET_VERIFICATION')fail('channel approval phase closed');
  const channel=state.channels.find(c=>c.channelId===approval?.channelId);
  if(!channel)fail('unknown bilateral channel');
  if(!channel.requiredWalletIds.includes(approval.walletId))fail('wallet does not control this channel');
  if(state.approvals.some(a=>a.channelId===approval.channelId&&a.walletId===approval.walletId))fail('duplicate channel wallet approval');
  if(approval.sessionHash!==state.sessionHash||approval.proposalHash!==state.proposalHash||
     approval.oracleReceiptHash!==state.oracleReceiptHash||approval.commitmentTxid!==channel.commitmentTxid||
     approval.routePolicyDigest!==channel.routePolicyDigest||
     approval.cetPackageDigest!==channel.cetPackageDigest||approval.refundPackageDigest!==channel.refundPackageDigest||
     approval.revocationPackageDigest!==channel.revocationPackageDigest||
     approval.activationHeight!==channel.activationHeight||approval.expiryHeight!==channel.expiryHeight||
     approval.authorizationMode!==channel.authorizationMode)fail('wallet approval not bound to exact channel/epoch');
  verifyWalletSig(approval,walletKeys);
  const approvals=Object.freeze([...state.approvals,{channelId:approval.channelId,walletId:approval.walletId,
      signatureDigest:H(Buffer.from(approval.signatureHex,'hex'))}].sort((a,b)=>
      a.channelId.localeCompare(b.channelId)||a.walletId.localeCompare(b.walletId))
      .map(a=>Object.freeze(a)));
  const complete=state.channels.every(c=>c.requiredWalletIds.every(id=>
      approvals.some(a=>a.channelId===c.channelId&&a.walletId===id)));
  return Object.freeze({...state,approvals,phase:complete?'APPROVED_FOR_WALLET_VERIFICATION':'AWAITING_APPROVALS'});
}
/** Independent NEAR RPC/state observer's *attestation*, a weaker trust tier
 * than a verified NEAR light-client finality proof. The observer key must be
 * pinned outside the relayer and different from the Pyth price signer.
 */
export function canonicalNearObservation(o){
  return Buffer.from(JSON.stringify([
    'SHZ/NEAR-FINALIZED-STATE-OBSERVER/V1',o.observerId,o.nearChainId,
    o.nearContractId,o.sessionHash,o.eventId,o.oracleEpoch,
    o.signedPayloadSha256,o.stateRoot,o.blockHash,o.blockHeight,
    o.challengeWindowClosed,
  ]));
}
function verifyNearObservation(state,receipt,observerKeys){
  if(!receipt||receipt.sessionHash!==state.sessionHash||receipt.eventId!==state.eventId||
    receipt.nearChainId!==state.nearChainId||receipt.nearContractId!==state.nearContractId||
    receipt.oracleEpoch!==state.oracleEpoch||receipt.signedPayloadSha256!==state.oraclePayloadSha256||
    !hex32(receipt.stateRoot)||!hex32(receipt.blockHash)||!U(receipt.blockHeight)||
    receipt.challengeWindowClosed!==true)fail('unbound or unfinalized NEAR observer receipt');
  if(!observerKeys||!Object.hasOwn(observerKeys,receipt.observerId))fail('unregistered NEAR observer');
  const key=createPublicKey(observerKeys[receipt.observerId]);
  if(key.asymmetricKeyType!=='ed25519'||typeof receipt.signatureHex!=='string'||
    !/^[0-9a-f]{128}$/.test(receipt.signatureHex)||
    !verify(null,canonicalNearObservation(receipt),key,Buffer.from(receipt.signatureHex,'hex')))
      fail('invalid independent NEAR observer signature');
  return H(canonicalNearObservation(receipt));
}
/**
 * An observer signature is an accountable external statement, not a NEAR
 * light-client proof. This method returns a settlement *request*, never
 * spend authorization or a collateral-release receipt.
 */
export function requestChannelCloseout(state,{height,externalCommitmentVerifierReady=false,nearObservation,observerKeys}={}){
  if(state?.phase!=='APPROVED_FOR_WALLET_VERIFICATION')fail('incomplete bilateral authorizations');
  if(!U(height)||height<state.challengeEndHeight)fail('oracle challenge window still open');
  const observerStatementHash=verifyNearObservation(state,nearObservation,observerKeys);
  if(!externalCommitmentVerifierReady)fail('missing independent Bitcoin channel commitment verifier');
  const l1Offline=state.channels.filter(c=>c.originalPeerOffline);
  if(state.channels.some(c=>height>=c.expiryHeight))fail('channel lock has expired');
  if(l1Offline.some(c=>height+6>=c.graceEndHeight))fail('MNR02 priority confirmation window exhausted');
  if(l1Offline.some(c=>height<c.l1MaturityHeight)){
    return Object.freeze({...state,observerStatementHash,nearObserverAttested:true,phase:'AWAITING_MNR02_L1_MATURITY',
      readyForBitcoinBroadcast:false,collateralReleased:false,bitcoinSpendEnforced:false});
  }
  return Object.freeze({...state,observerStatementHash,nearObserverAttested:true,phase:'WALLET_SETTLEMENT_REQUESTED',
      readyForBitcoinBroadcast:false,collateralReleased:false,bitcoinSpendEnforced:false,
      requiredExternalChecks:[
        'independent BIP341 sighash authorization for each bilateral outpoint',
        'on-chain or channel-state commitment signatures and revocation ordering',
        'HTLC/PTLC timeout safety and watchtower recovery',
        'Bitcoin Core confirmation + reorg-safe ledger transition',
      ]});
}
