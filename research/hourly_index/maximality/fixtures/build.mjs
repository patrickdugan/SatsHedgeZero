import {readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {HOURLY_US} from '../../index.mjs';
import {buildLog,select,verifyEight,verifyGenesis,verifyAppend,verifySeal} from '../log.mjs';
const here=dirname(fileURLToPath(import.meta.url));
const read=f=>JSON.parse(readFileSync(resolve(here,'../../policy_nova/fixtures',f),'utf8'));
const {genesis,start_hour,logs}=read('admitted_logs.json'),policy=read('expected.json');
const sealed_through=String((BigInt(start_hour)+8n)*HOURLY_US),depth=4;
const trees={},transitions={};
for(const source of ['pyth','chainlink']){
 let old=buildLog({genesis,source,entries:[],depth});if(!verifyGenesis(old.header,old.pin))throw Error('genesis');
 let seq=[];for(let i=0;i<logs[source].length;i++){let next=buildLog({genesis,source,entries:logs[source].slice(0,i+1),depth});let w={oldHeader:old.header,newHeader:next.header,record:logs[source][i],siblings:old.path(i+1)};if(!verifyAppend(w,{oldPin:old.pin,newPin:next.pin}))throw Error('append');seq.push(w);old=next;}
 const next=buildLog({genesis,source,entries:logs[source],depth,sealed_through});if(!verifySeal(old.header,next.header,{oldPin:old.pin,newPin:next.pin}))throw Error('seal');trees[source]=next;transitions[source]=seq.length;
}
const pins={pyth:trees.pyth.pin,chainlink:trees.chainlink.pin};const openings=Array.from({length:8},(_,i)=>{let h=BigInt(start_hour)+BigInt(i),cutoff=(h+1n)*HOURLY_US;return {hour_id:String(h),pyth:select(trees.pyth,cutoff),chainlink:select(trees.chainlink,cutoff)}});
const fixture={genesis,start_hour,openings},expected={genesis,policy_hash:policy.policy_hash,start_hour,pins,evidence_root:policy.evidence_root,evidence_leaves:policy.evidence_leaves};
let check=verifyEight(fixture,{pins,expectedEvidenceRoot:policy.evidence_root});if(!check||JSON.stringify(check.evidence_leaves)!==JSON.stringify(policy.evidence_leaves))throw Error('policy bridge');
writeFileSync(resolve(here,'openings.json'),JSON.stringify(fixture,null,2)+'\n');writeFileSync(resolve(here,'expected.json'),JSON.stringify(expected,null,2)+'\n');
console.log(JSON.stringify({depth,transitions,pins,evidence_root:policy.evidence_root,sourceAuthenticated:false,providerCompletenessProven:false}));
// Independent negative vector: valid membership path for the previous Pyth
// observation in hour 1. Recompute only the evidence leaf for this attack.
const attack=structuredClone(openings[1]);const prior=Number(attack.pyth.index)-1;
attack.pyth={header:trees.pyth.header,index:String(prior),candidate:trees.pyth.candidates[prior],siblings:trees.pyth.path(prior)};
writeFileSync(resolve(here,'earlier.json'),JSON.stringify(attack,null,2)+'\n');
