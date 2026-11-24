import {generateKeyPairSync, sign} from 'node:crypto';
import {makeCertificate,digest,bitcoinOutpoint} from '../src/common.mjs';
import {HEDGE_BOOK_DOMAIN} from '../src/hedge.mjs';
import {BRIDGE_BOOK_DOMAIN} from '../src/usdc_bridge.mjs';
import {TL_SPOT_WINDOW} from '../src/vwap.mjs';
const h = c => c.repeat(64);
export const epochHash=h('e');
const roleTag={
  shzCoin:'SHZ/USD/COIN-ATTESTATION/V1',
  shzLiability:'SHZ/USD/LIABILITY-ATTESTATION/V1',
  tlSourceDeposit:'TL/USD/USDC-DEPOSIT-ATTESTATION/V1',
  tlSourceRelease:'TL/USD/USDC-RELEASE-ATTESTATION/V1',
  tlLiability:'TL/USD/BRIDGE-LIABILITY-ATTESTATION/V1',
  spot:'TL/USD/SPOT-WINDOW-ATTESTATION/V1'
};
export function fixture() {
  const keyPairs={};
  for(const role of Object.keys(roleTag))keyPairs[role]=generateKeyPairSync('ed25519');
  function attest(role,payload){return makeCertificate(payload,role,keyPairs[role].privateKey,roleTag[role],sign);}
  const key = role => keyPairs[role].publicKey.export({format:'pem',type:'spki'});
  const network='bitcoin-testnet4';
  const pricePolicy={
    expectedOracleEpochDigest:epochHash,
    expectedVerifierProgramDigest:h('d'),
  };
  const c1={network,asset:'BTC',purpose:'SHZ_DLC',owner:'shz-hedge-vault',unspent:true,
    confirmations:12,tipBlockHash:h('1'),spendingPolicyDigest:h('2'),txid:h('3'),vout:0,valueSats:'250000330'};
  const c2={...c1,purpose:'SHZ_RESERVE',spendingPolicyDigest:h('4'),txid:h('5'),vout:1,valueSats:'10000000'};
  const shzBook={issuer:'shz-hedge-vault',assetId:'SHZ-USD',network,epoch:42,
    positions:[{id:'short-hedge-1',notionalUsd:'60000',entryPriceUsd:'60000',shortMarginSats:'100000000',counterpartyMarginSats:'150000000',fundingOverheadSats:'330',spendPolicyDigest:h('2'),attestation:attest('shzCoin',c1)}],
    reserves:[{spendPolicyDigest:h('4'),attestation:attest('shzCoin',c2)}],
    liability:attest('shzLiability',{
      issuer:'shz-hedge-vault',assetId:'SHZ-USD',bitcoinNetwork:network,epoch:42,
      oracleEpochDigest:epochHash,taprootAssetGenesis:h('6'),liabilityRoot:h('7'),
      outstandingMicros:'60000000000',pendingRedemptionMicros:'0',
    })};
  const usdcChain='base-mainnet';const token='0x'+('a'.repeat(40));const escrow='0x'+('b'.repeat(40));
  const d1={sourceChain:usdcChain,tokenContract:token,escrowAddress:escrow,finalized:true,confirmations:22,
    sourceBlockHash:h('8'),destinationChain:network,destinationPropertyId:'TL-USDC-42',beneficiary:'alice-tl',
    txid:h('9'),logIndex:0,amountMicros:'70000000000'};
  const release={sourceChain:usdcChain,tokenContract:token,escrowAddress:escrow,finalized:true,confirmations:20,
    txid:h('a'),logIndex:1,amountMicros:'3000000000'};
  const tlUsdcBook={issuer:'tl-usdc-procedural',assetId:'TL-USDC',epoch:42,
    deposits:[attest('tlSourceDeposit',d1)],releases:[attest('tlSourceRelease',release)],
    liability:attest('tlLiability',{
      assetId:'TL-USDC',issuer:'tl-usdc-procedural',epoch:42,destinationPropertyId:'TL-USDC-42',
      oracleEpochDigest:epochHash,liabilityRoot:h('b'),mintedMicros:'70000000000',
      burnedMicros:'5000000000',releasedMicros:'3000000000',
      outstandingMicros:'65000000000',pendingRedemptionMicros:'2000000000',
    })};
  const spotWindow={network,baseAsset:'BTC',quoteAsset:'TL-USDC',executions:[
    {tradeId:h('c'),height:2500,maker:'market-A',taker:'trader-A',btcSats:'100000000',usdcMicros:'60000000000'},
    {tradeId:h('d'),height:2501,maker:'market-B',taker:'trader-B',btcSats:'200000000',usdcMicros:'119000000000'},
    {tradeId:h('e'),height:2502,maker:'market-C',taker:'trader-C',btcSats:'100000000',usdcMicros:'60500000000'},
  ]};
  const windowRoot=digest(TL_SPOT_WINDOW,spotWindow);
  spotWindow.indexerCheckpoint=attest('spot', {executionRoot:windowRoot,network,quoteAsset:'TL-USDC',blockHash:h('f'),height:2502,finalizedHeight:2522});
  const policy={...pricePolicy,
    shz:{issuer:'shz-hedge-vault',assetId:'SHZ-USD',epoch:42,bitcoinNetwork:network,minConfirmations:6,
      expectedTipBlockHash:h('1'),oracleEpochDigest:epochHash,expectedLiabilityRoot:h('7'),
      expectedBookHash:digest(HEDGE_BOOK_DOMAIN,shzBook),coinObservers:{shzCoin:key('shzCoin')},
      liabilityAuditors:{shzLiability:key('shzLiability')},
      stressPricesUsd:['30000','40000','60000','100000'],estimatedExitFeesSats:'10000',insolvencyHaircutSats:'100000'},
    tlUsdc:{issuer:'tl-usdc-procedural',assetId:'TL-USDC',epoch:42,sourceChain:usdcChain,sourceTokenContract:token,
      sourceEscrowAddress:escrow,destinationChain:network,destinationPropertyId:'TL-USDC-42',minConfirmations:12,
      oracleEpochDigest:epochHash,expectedLiabilityRoot:h('b'),expectedBookHash:digest(BRIDGE_BOOK_DOMAIN,tlUsdcBook),
      sourceObservers:{tlSourceDeposit:key('tlSourceDeposit'),tlSourceRelease:key('tlSourceRelease')},
      liabilityAuditors:{tlLiability:key('tlLiability')}},
    spot:{network,quoteAssetId:'TL-USDC',maxLookbackBlocks:24,minTrades:3,minDistinctMakers:3,
      minBtcVolumeSats:'100000000',maxMakerShareBps:'7000',independentPythPriceUsdE8:'6000000000000',maxDeviationBps:'400',
      expectedTipBlockHash:h('f'),expectedWindowRoot:windowRoot,indexerObservers:{spot:key('spot')}},
  };
  const repin=()=>{
    policy.shz.expectedBookHash=digest(HEDGE_BOOK_DOMAIN,shzBook);
    policy.tlUsdc.expectedBookHash=digest(BRIDGE_BOOK_DOMAIN,tlUsdcBook);
    policy.spot.expectedWindowRoot=digest(TL_SPOT_WINDOW,{network:spotWindow.network,baseAsset:spotWindow.baseAsset,
      quoteAsset:spotWindow.quoteAsset,executions:spotWindow.executions});
    spotWindow.indexerCheckpoint=attest('spot',{executionRoot:policy.spot.expectedWindowRoot,network,
      quoteAsset:'TL-USDC',blockHash:h('f'),height:2502,finalizedHeight:2522});
  };
  return {shzBook,tlUsdcBook,spotWindow,policy,attest,repin,
    sourceCoinId:bitcoinOutpoint(network,c1.txid,c1.vout)};
}
