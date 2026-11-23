import {readFileSync,writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {HOURLY_US} from '../../index.mjs';
import {buildLog} from '../../maximality/log.mjs';
import {transcript,checkTranscript,costModel} from '../frontier.mjs';
const here=dirname(fileURLToPath(import.meta.url));
const read=p=>JSON.parse(readFileSync(resolve(here,p),'utf8'));
const {genesis,start_hour,logs}=read('../../policy_nova/fixtures/admitted_logs.json');
const expected=read('../../maximality/fixtures/expected.json');
const cutoff=String((BigInt(start_hour)+8n)*HOURLY_US);
for(const source of ['pyth','chainlink']){
 const entries=logs[source];
 // An intermediate real watermark, one microsecond before the next report.
 const middle=Math.min(3,entries.length-1),watermarks=[{after:middle,watermark:String(BigInt(entries[middle].publish_us)-1n)},{after:entries.length,watermark:cutoff}];
 const t=transcript({entries,genesis,source,watermarks});
 if(t.claim.pin!==expected.pins[source]||t.claim.pin!==buildLog({genesis,source,entries,depth:4,sealed_through:cutoff}).pin)throw Error('MAX-01 pin mismatch');
 if(!checkTranscript(t.steps,t.claim,{expectedPin:expected.pins[source],source,genesis}))throw Error('transcript');
 writeFileSync(resolve(here,source+'-steps.json'),JSON.stringify(t.steps.map(({op,record,watermark})=>({op,record,watermark})),null,2)+'\n');
 writeFileSync(resolve(here,source+'-expected.json'),JSON.stringify(t.claim,null,2)+'\n');
 console.log(source,t.claim.steps,t.claim.pin,t.hashes);
}
const costs=[costModel(12,4,2),costModel(7,4,2),costModel(144000,18,1),costModel(262143,18,1)];
writeFileSync(resolve(here,'../evidence/hash-work-model.json'),JSON.stringify({schema:'shz/admission-eager-placement-work-model/v1',measured:false,models:costs},null,2)+'\n');
