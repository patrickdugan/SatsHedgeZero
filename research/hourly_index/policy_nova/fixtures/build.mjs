import {writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {GENESIS_TESTNET4,HOURLY_US,shahex} from '../../index.mjs';
import {buildFromPinnedLogs,logRoot} from '../policy.mjs';
const genesis=GENESIS_TESTNET4,start=498000n,start_hour=String(start),S=100000000n;
const logs={pyth:[],chainlink:[]};
function add(source,i,seconds,price,label){const cutoff=(start+BigInt(i)+1n)*HOURLY_US;logs[source].push({price_e8:String(BigInt(price)*S),publish_us:String(cutoff-BigInt(seconds)*1000000n),report_hash:shahex(Buffer.from(`synthetic/${source}/${i}/${label}`))});}
// hour 0 missing Chainlink; hours 1-4 valid; 5 spread; 6 skew; 7 stale.
add('pyth',0,5,100000,'only');
for(let i=1;i<=4;i++){
 add('pyth',i,50,99900+i,'earlier');add('pyth',i,i===4?300:5,100000+i,'latest');
 // Hour 4: both exactly at the freshness boundary; ensure chronological order.
 add('chainlink',i,i===4?300:20,100200+i,'latest');
}
// For hour 4 move the earlier update before the freshness boundary.
logs.pyth.find(x=>x.report_hash===shahex(Buffer.from('synthetic/pyth/4/earlier'))).publish_us=String((start+5n)*HOURLY_US-301000000n);
add('pyth',5,5,100000,'latest');add('chainlink',5,20,103000,'wide');
add('pyth',6,5,100000,'latest');add('chainlink',6,90,100200,'skew');
// Include a future observation beyond this checkpoint, proving it cannot be selected.
add('pyth',8,5,110000,'future');add('chainlink',8,20,110000,'future');
for(const source of ['pyth','chainlink'])logs[source].sort((a,b)=>BigInt(a.publish_us)<BigInt(b.publish_us)?-1:1);
const expectedLogRoots=Object.fromEntries(Object.entries(logs).map(([source,entries])=>[source,logRoot({genesis,source,entries})]));
const fixture=buildFromPinnedLogs({genesis,start_hour,logs,expectedLogRoots});
const dir=dirname(fileURLToPath(import.meta.url));
const out=(name,value)=>writeFileSync(resolve(dir,name),JSON.stringify(value,null,2)+'\n');
out('checkpoint.json',{records:fixture.records,checkpoint:fixture.checkpoint,evidence:fixture.evidence,evidence_root:fixture.evidence_root,evidence_leaves:fixture.evidence_leaves});out('expected.json',fixture.claim);out('admitted_logs.json',{schema:'shz/synthetic-admitted-logs/v1',genesis,start_hour,logs,expectedLogRoots,source_authenticated:false,completeness_verified:false});
console.log(JSON.stringify({evidence_root:fixture.evidence_root,checkpoint_root:fixture.checkpoint.checkpoint_root,states:fixture.records.map(x=>x.hold_reason),packet:fixture.checkpoint.packet_hex}));
