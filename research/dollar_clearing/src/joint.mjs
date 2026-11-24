/**
 * SHZ/TL cross-domain reference statement. An actual Nova circuit must constrain
 * chain proofs, economic transitions, and the exact statement before this can
 * authorize a token mint, BTC spend, TL opcode, or BitVM3 challenge.
 */
import { assertDistinctRoles, demand, digest, hex32 } from './common.mjs';
import { checkHedgeBook } from './hedge.mjs';
import { checkUsdcBridgeBook } from './usdc_bridge.mjs';
import { verifyBtcUsdcVwap } from './vwap.mjs';
export const JOINT_DOMAIN='SHZ/TL/JOINT-DOLLAR-LIABILITIES/V1';
export function verifyJointDollarStatement({shzBook,tlUsdcBook,spotWindow},policy) {
  hex32(policy.expectedOracleEpochDigest,'independently pinned price epoch');
  hex32(policy.expectedVerifierProgramDigest,'future Nova verifier program identity');
  assertDistinctRoles({
    shzCoin:policy.shz.coinObservers,
    shzLiability:policy.shz.liabilityAuditors,
    tlSource:policy.tlUsdc.sourceObservers,
    tlLiability:policy.tlUsdc.liabilityAuditors,
    tlSpot:policy.spot.indexerObservers,
  });
  demand(policy.shz.oracleEpochDigest===policy.expectedOracleEpochDigest &&
    policy.tlUsdc.oracleEpochDigest===policy.expectedOracleEpochDigest, 'different price epochs in shared statement');
  demand(policy.shz.assetId!==policy.tlUsdc.assetId,'duplicate liability asset identity');
  const shz=checkHedgeBook(shzBook,policy.shz);
  const tlUsdc=checkUsdcBridgeBook(tlUsdcBook,policy.tlUsdc);
  const spot=verifyBtcUsdcVwap(spotWindow,policy.spot);
  const idSet=new Set();
  for(const id of [...shz.resourceIds,...tlUsdc.resourceIds]) {
    demand(!idSet.has(id),`collateral double-counting: ${id}`);
    idSet.add(id);
  }
  const statement={
    scheme:'SHZ_TL_JOINT_DOLLARS_V1',
    shzAssetId:shz.assetId, tlUsdcAssetId:tlUsdc.assetId,
    shzBookHash:shz.bookHash,tlUsdcBookHash:tlUsdc.bookHash,
    shzLiabilityRoot:shz.liabilityRoot,tlUsdcLiabilityRoot:tlUsdc.liabilityRoot,
    spotWindowRoot:spot.executionRoot,spotPriceUsdE8:spot.priceUsdE8,
    oracleEpochDigest:policy.expectedOracleEpochDigest,
    verifierProgramDigest:policy.expectedVerifierProgramDigest,
    shzOutstandingMicros:shz.outstandingMicros,tlUsdcOutstandingMicros:tlUsdc.outstandingMicros,
    shzPendingRedemptionMicros:shz.pendingRedemptionMicros,
    tlUsdcPendingRedemptionMicros:tlUsdc.pendingRedemptionMicros,
    backingResourcesSorted:[...idSet].sort(),
  };
  return {
    statement,
    publicStatementDigest:digest(JOINT_DOMAIN,statement),
    shz,tlUsdc,spot,
    referenceArithmeticAndSignerChecksPassed:true,
    disjointBackingResourcesChecked:true,
    acceptedProofSystem:'REFERENCE_ONLY',
    novaProofVerified:false,bitvm3OnchainEnforced:false,
    nativeTapAssetProofVerified:false,nearUsdcLightClientVerified:false,
    tradeLayerStateTransitionVerified:false,
    mintAuthorized:false,
    redeemAuthorized:false,
    productionReady:false,
  };
}
