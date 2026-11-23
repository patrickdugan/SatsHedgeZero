/**
 * Research-only adapter for patrickdugan/TradeLayer-Rust VolumeHistory::sample_range.
 * VolumeRecord alone has no executed quote quantity or maker/taker identity.
 * Require independently supplied matched execution rows. Never infer them.
 */
import { demand, positive, u64 } from './common.mjs';
const E8=100000000n, SATS=100000000n, MICRO=1000000n;
export function convertVolumeHistoryWindow({volumeRecords,matchedExecutions,btcProperty,usdcProperty}) {
  demand(Array.isArray(volumeRecords)&&Array.isArray(matchedExecutions)&&volumeRecords.length>0&&volumeRecords.length<=4096,'invalid TL rust volume export');
  demand(Number.isSafeInteger(btcProperty)&&btcProperty>=0&&Number.isSafeInteger(usdcProperty)&&usdcProperty>0,'invalid TL pair IDs');
  const detailById=new Map();
  for(const e of matchedExecutions){
    demand(typeof e.tradeId==='string'&&/^[a-f0-9]{64}$/.test(e.tradeId),'invalid TradeLayer execution ID');
    demand(!detailById.has(e.tradeId),'duplicate TradeLayer execution details');
    detailById.set(e.tradeId,e);
  }
  const seen=new Set(),out=[];
  for(const v of volumeRecords){
    demand(typeof v.event_id==='string'&&/^[a-f0-9]{64}$/.test(v.event_id)&&!seen.has(v.event_id),'duplicate volume observation');
    seen.add(v.event_id);
    demand(v.pair?.first===btcProperty&&v.pair?.second===usdcProperty,'incorrect directional BTC/USDC pair');
    demand(v.kind==='Token' || v.kind==='Utxo','derivative contract volume cannot drive spot VWAP');
    const d=detailById.get(v.event_id);
    demand(d,'missing matched underlying spot execution');
    demand(v.block_height===d.height,'volume observation height mismatch');
    const sats=positive(d.btcSats,'BTC settlement quantity');
    const usdMicro=positive(d.usdcMicros,'USDC settlement quantity');
    demand(u64(v.raw_volume_atoms,'Rust volume atoms')===sats,'volume history quantity differs from trade receipt');
    const priceAtoms=(usdMicro*SATS*E8 + sats*MICRO/2n)/(sats*MICRO);
    demand(u64(v.price_atoms,'Rust q8 price atoms')===priceAtoms,'Rust recorded price diverges from exact trade amount');
    out.push({tradeId:v.event_id,height:v.block_height,maker:d.maker,taker:d.taker,
      btcSats:sats.toString(),usdcMicros:usdMicro.toString()});
  }
  demand(out.length===detailById.size,'unmatched external trade detail');
  out.sort((a,b)=>a.height-b.height||a.tradeId.localeCompare(b.tradeId));
  return out;
}
