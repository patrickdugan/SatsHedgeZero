import { authSigned, demand, digest, hex32, positive, u64 } from './common.mjs';
export const BRIDGE_BOOK_DOMAIN = 'TL/USD/USDC-BRIDGE-BOOK/V1';
const DEPOSIT='TL/USD/USDC-DEPOSIT-ATTESTATION/V1';
const RELEASE='TL/USD/USDC-RELEASE-ATTESTATION/V1';
const LIABILITY='TL/USD/BRIDGE-LIABILITY-ATTESTATION/V1';

function bridgeDeposit(evidence, policy) {
  const p=authSigned(evidence,policy.sourceObservers,DEPOSIT,'USDC source deposit');
  demand(p.sourceChain===policy.sourceChain && p.tokenContract===policy.sourceTokenContract && p.escrowAddress===policy.sourceEscrowAddress, 'USDC source token/escrow substitution');
  demand(p.finalized===true && Number.isSafeInteger(p.confirmations) && p.confirmations>=policy.minConfirmations, 'USDC deposit lacks independently attested finality');
  hex32(p.sourceBlockHash,'USDC source block hash');
  demand(p.destinationChain===policy.destinationChain && p.destinationPropertyId===policy.destinationPropertyId, 'USDC destination substitution');
  demand(typeof p.beneficiary==='string' && p.beneficiary.length>0 && p.beneficiary.length<=128, 'invalid beneficiary');
  hex32(p.txid,'source transaction');
  demand(Number.isSafeInteger(p.logIndex) && p.logIndex>=0 && p.logIndex<=0xffffffff,'invalid log index');
  const id=`usdc:${p.sourceChain}:${p.tokenContract}:${p.txid}:${p.logIndex}`;
  // A bridge can also encumber a Bitcoin outpoint, but it MUST identify it to prevent double-pledge.
  const resources=[id];
  if(p.additionalBitcoinBackingResourceId) {
    demand(typeof p.additionalBitcoinBackingResourceId==='string' && /^bitcoin:bitcoin-(?:regtest|testnet4|mainnet):[a-f0-9]{64}:\d+$/.test(p.additionalBitcoinBackingResourceId), 'invalid cross-bridge Bitcoin backing resource');
    resources.push(p.additionalBitcoinBackingResourceId);
  }
  return {id,resources,amount:positive(p.amountMicros,'deposited USDC')};
}
export function checkUsdcBridgeBook(book,policy) {
  demand(book?.assetId===policy.assetId && book.issuer===policy.issuer && book.epoch===policy.epoch, 'wrong USDC issuer/epoch');
  demand(Array.isArray(book.deposits) && book.deposits.length<=256 && Array.isArray(book.releases) && book.releases.length<=256, 'bridge batch oversized');
  const bookHash = digest(BRIDGE_BOOK_DOMAIN,book);
  hex32(policy.expectedBookHash,'pinned bridge book');
  demand(bookHash===policy.expectedBookHash,'bridge book root differs from independently pinned root');
  const liab=authSigned(book.liability,policy.liabilityAuditors,LIABILITY,'TL-USDC issued supply');
  demand(liab.assetId===book.assetId && liab.issuer===book.issuer && liab.epoch===book.epoch && liab.destinationPropertyId===policy.destinationPropertyId, 'bridge liability domain substitution');
  hex32(liab.oracleEpochDigest,'authenticated price epoch');
  demand(liab.oracleEpochDigest === policy.oracleEpochDigest,'bridge oracle epoch substitution');
  hex32(liab.liabilityRoot,'TL-USDC holder root');
  demand(liab.liabilityRoot===policy.expectedLiabilityRoot,'TL-USDC holder root differs from pinned ledger');
  const resources=new Set(),depositIDs=new Set();
  let deposited=0n,released=0n;
  for(const e of book.deposits){
    const d=bridgeDeposit(e,policy);
    demand(!depositIDs.has(d.id),'replayed USDC deposit event');
    depositIDs.add(d.id);
    for(const id of d.resources){demand(!resources.has(id),'duplicated bridge backing resource');resources.add(id)}
    deposited+=d.amount;
  }
  const releaseIDs=new Set();
  for(const r of book.releases){
    const p=authSigned(r,policy.sourceObservers,RELEASE,'USDC redemption release');
    demand(p.sourceChain===policy.sourceChain && p.tokenContract===policy.sourceTokenContract && p.escrowAddress===policy.sourceEscrowAddress && p.finalized===true, 'unauthenticated USDC release');
    demand(Number.isSafeInteger(p.confirmations)&&p.confirmations>=policy.minConfirmations, 'unfinalized release');
    hex32(p.txid,'release txid');
    demand(Number.isSafeInteger(p.logIndex)&&p.logIndex>=0,'release logIndex');
    const id=`release:${p.sourceChain}:${p.txid}:${p.logIndex}`;
    demand(!releaseIDs.has(id),'replayed redemption release');
    releaseIDs.add(id); released+=positive(p.amountMicros,'released USDC');
  }
  const minted = u64(liab.mintedMicros,'total minted');
  const burned = u64(liab.burnedMicros,'total burned');
  const outstanding = u64(liab.outstandingMicros,'outstanding USDC');
  const pending=u64(liab.pendingRedemptionMicros,'unpaid USDC burns');
  demand(burned<=minted && released<=burned && released<=deposited,'invalid USDC supply/reserve history');
  demand(outstanding===minted-burned && pending===burned-released,'USDC burn or supply conservation failure');
  demand(u64(liab.releasedMicros,'ledger recorded USDC releases')===released,'signed supply ledger release total differs from source escrow');
  const reserve=deposited-released;
  demand(reserve>=outstanding+pending, 'unbacked TL-USDC supply and pending redemption');
  return {issuer:book.issuer,assetId:book.assetId,epoch:book.epoch,bookHash,liabilityRoot:liab.liabilityRoot,
    depositedMicros:deposited.toString(),mintedMicros:minted.toString(),burnedMicros:burned.toString(),
    releasedMicros:released.toString(),outstandingMicros:outstanding.toString(),pendingRedemptionMicros:pending.toString(),
    reserveMicros:reserve.toString(),excessReserveMicros:(reserve-outstanding-pending).toString(),
    resourceIds:[...resources].sort(),verificationTier:'PINNED_SIGNED_USDC_ESCROW_ATTESTATION',
    nearFinalityLightClientVerified:false,tradeLayerConsensusMintVerified:false};
}
