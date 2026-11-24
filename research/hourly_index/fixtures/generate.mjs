import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {writeFileSync} from 'node:fs';
import {makeHour,makeHold,checkpoint,HOURLY_US,verifyInclusion} from '../index.mjs';
const hour=498_000n; // 8-hour aligned, UTC hour index; deterministic test hours
const policy=createHash('sha256').update('SHZ/DUAL-ORACLE-50BPS-5MIN/V1').digest('hex');
const records=Array.from({length:8},(_,i)=>{
 const h=hour+BigInt(i);
 if(i===4)return makeHold({policy_hash:policy,hour_id:h,hold_reason:2});
 const p=(100_000n+BigInt(i*10))*100_000_000n;
 const c=(100_200n+BigInt(i*10))*100_000_000n;
 const cutoff=(h+1n)*HOURLY_US;
 return makeHour({policy_hash:policy,hour_id:h,pyth_price_e8:p,chainlink_price_e8:c,pyth_publish_us:cutoff-5_000_000n,chainlink_publish_us:cutoff-20_000_000n,
  pyth_report_hash:createHash('sha256').update(`fixture/pyth/${i}`).digest('hex'),chainlink_report_hash:createHash('sha256').update(`fixture/chainlink/${i}`).digest('hex')});
});
const cp=checkpoint(records);
for(let i=0;i<8;i++)if(!verifyInclusion({record:records[i],checkpoint:cp,siblings:cp.inclusion[i].siblings}))throw Error('unverifiable fixture');
const filename=resolve(dirname(fileURLToPath(import.meta.url)),'checkpoint.json');
writeFileSync(filename,JSON.stringify({records,checkpoint:cp},null,2)+'\n');
console.log(cp.checkpoint_root,cp.packet_hex);
