/** Source-oriented TL BTC/USDC VWAP: trade receipts, not pair-key snapshots.
 * A pinned event-root and signed window close supply the external trust context.
 */
import { authSigned, demand, digest, hex32, positive, u64 } from './common.mjs';
export const TL_SPOT_WINDOW = 'TL/USD/SPOT-EXECUTION-WINDOW/V1';
const SPOT_ATTEST='TL/USD/SPOT-WINDOW-ATTESTATION/V1';
const SATS=100000000n, MICROS=1000000n, E8=100000000n;
export function verifyBtcUsdcVwap(window,policy) {
  demand(window?.network===policy.network && window.baseAsset==='BTC' && window.quoteAsset===policy.quoteAssetId, 'wrong VWAP spot pair');
  demand(Array.isArray(window.executions)&&window.executions.length>0&&window.executions.length<=4096, 'invalid VWAP execution count');
  const root=digest(TL_SPOT_WINDOW,{network:window.network,baseAsset:window.baseAsset,quoteAsset:window.quoteAsset,executions:window.executions});
  hex32(policy.expectedWindowRoot,'independently pinned TL execution window root');
  demand(root===policy.expectedWindowRoot,'TL execution window root mismatch');
  const meta=authSigned(window.indexerCheckpoint,policy.indexerObservers,SPOT_ATTEST,'TL execution indexer');
  demand(meta.executionRoot===root && meta.network===policy.network && meta.quoteAsset===policy.quoteAssetId, 'spot window checkpoint binding mismatch');
  hex32(meta.blockHash,'chain block hash');
  if(policy.expectedTipBlockHash) demand(meta.blockHash===policy.expectedTipBlockHash,'untrusted VWAP tip');
  demand(Number.isSafeInteger(meta.height)&&meta.height>0 && Number.isSafeInteger(meta.finalizedHeight)&&meta.finalizedHeight>=meta.height, 'unfinalized VWAP index window');
  const seen=new Set(),makers=new Set(),volByMaker=new Map();
  let satSum=0n,usdMicrosSum=0n;
  for (const e of window.executions) {
    demand(typeof e.tradeId==='string' && /^[a-f0-9]{64}$/.test(e.tradeId)&&!seen.has(e.tradeId),'replayed trade ID');
    seen.add(e.tradeId);
    demand(typeof e.maker==='string'&&e.maker.length>0&&typeof e.taker==='string'&&e.taker.length>0&&e.maker!==e.taker,'wash/self-cross trade');
    demand(Number.isSafeInteger(e.height)&&e.height<=meta.height&&e.height>meta.height-policy.maxLookbackBlocks,'outside VWAP time window');
    const sats=positive(e.btcSats,'BTC executed sats');
    const micro=positive(e.usdcMicros,'USDC quote micros');
    // One recorded execution is a trade, not an arbitrary candle, pair volume, or order placement.
    makers.add(e.maker);volByMaker.set(e.maker,(volByMaker.get(e.maker)||0n)+sats);
    satSum+=sats;usdMicrosSum+=micro;
  }
  demand(seen.size>=policy.minTrades && makers.size>=policy.minDistinctMakers, 'insufficient independent spot executions');
  demand(satSum>=positive(policy.minBtcVolumeSats,'minimum BTC spot volume'), 'insufficient executable BTC liquidity');
  for(const vol of volByMaker.values()) demand(vol*10000n<=satSum*u64(policy.maxMakerShareBps,'max maker share'),'maker concentration exceeds policy');
  const priceE8=(usdMicrosSum*SATS*E8 + satSum*MICROS/2n)/(satSum*MICROS); // exact rounded USD/BTC
  const anchor=positive(policy.independentPythPriceUsdE8,'Pyth independent mark');
  const diff=priceE8>anchor?priceE8-anchor:anchor-priceE8;
  demand(diff*10000n<=anchor*u64(policy.maxDeviationBps,'max spot divergence'),'TL VWAP deviates from independent reference');
  return {executionRoot:root,priceUsdE8:priceE8.toString(),totalBtcSats:satSum.toString(),totalUsdcMicros:usdMicrosSum.toString(),tradeCount:seen.size,
    distinctMakers:makers.size,concentrationChecked:true,provenance:'PINNED_SIGNED_EXECUTION_WINDOW',
    tradeLayerConsensusInclusionVerified:false};
}
