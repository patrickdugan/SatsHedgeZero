import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture} from './fixture.mjs';
import {convertVolumeHistoryWindow} from '../src/tl_volume_adapter.mjs';
function sources(){
 const f=fixture();const details=f.spotWindow.executions;
 const volumeRecords=details.map(x=>({event_id:x.tradeId,source_id:'BTC-TL-USDC',pair:{first:0,second:42},kind:'Token',
   block_height:x.height,raw_volume_atoms:x.btcSats,
   price_atoms:((BigInt(x.usdcMicros)*100000000n*100000000n+BigInt(x.btcSats)*1000000n/2n)/(BigInt(x.btcSats)*1000000n)).toString()}));
 return {volumeRecords,matchedExecutions:details,btcProperty:0,usdcProperty:42};
}
test('exact TL VolumeHistory data plus original trade quantities produce canonical BTC/USDC executions',()=>{
 const s=sources();const rows=convertVolumeHistoryWindow(s);
 assert.equal(rows.length,3);assert.equal(rows[1].usdcMicros,'119000000000');
});
test('VolumeRecord alone is insufficient to determine a genuine spot execution',()=>{
 const s=sources();s.matchedExecutions=[];
 assert.throws(()=>convertVolumeHistoryWindow(s),/missing matched underlying spot execution/);
});
test('reject direction reversal until price and quantities are inverted explicitly',()=>{
 const s=sources();s.volumeRecords[0].pair.first=42;s.volumeRecords[0].pair.second=0;
 assert.throws(()=>convertVolumeHistoryWindow(s),/incorrect directional/);
});
test('reject misreported q8 price copied from different fill',()=>{
 const s=sources();s.volumeRecords[0].price_atoms='5555555555555';
 assert.throws(()=>convertVolumeHistoryWindow(s),/recorded price diverges/);
});
test('reject a forged partial snapshot with an orphan trade detail',()=>{
 const s=sources();s.volumeRecords.pop();
 assert.throws(()=>convertVolumeHistoryWindow(s),/unmatched external trade detail/);
});
test('reject a derivative fill passed into spot pricing',()=>{
 const s=sources();s.volumeRecords[0].kind='Contract';
 assert.throws(()=>convertVolumeHistoryWindow(s),/derivative contract volume/);
});
