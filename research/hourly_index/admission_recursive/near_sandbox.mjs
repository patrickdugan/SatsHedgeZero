/** Actual gas, receipt and failure reporting. This never deploys to a public chain. */
import {Sandbox} from 'near-sandbox';
import {Account,JsonRpcProvider,teraToGas} from 'near-api-js';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const here=dirname(fileURLToPath(import.meta.url)), [dir,out]=process.argv.slice(2);
if(!dir||!out)throw Error('usage: near_sandbox.mjs PROOF_ARTIFACT_DIR REPORT.json');
const read=p=>readFileSync(resolve(dir,p));
const pins=JSON.parse(read('expected.json')), independent=JSON.parse(read('independent.json')), profile=JSON.parse(read('verifier-profile.json'));
assert.ok(independent.independent_succinct_verified&&profile.actual_succinct_verified&&profile.tampered_seal_rejected);
assert.deepEqual(pins.image_id_words,independent.image_id_words);
assert.equal(pins.snapshot_pin,independent.snapshot_pin);
assert.equal(profile.sdk,'3.1.0');
const wasm=readFileSync(resolve(here,'near_verifier/target/wasm32-unknown-unknown/release/shz_near_stark_probe.wasm'));
const valid=read('proof/root.bin'), altered=read('proof/mutated-seal.bin');
const report={schema:'shz/near-succinct-stark-probe/v1',sdk:'3.1.0',wasm_bytes:wasm.length,receipt_bytes:valid.length,image_id_words:pins.image_id_words,snapshot_pin:pins.snapshot_pin,verifier_control_root:profile.control_root,gas_limit_TGas:300,near_verified:false,source_authentication:false,production_ready:false,can_authorize_dlc_settlement:false,cases:[]};
const save=()=>writeFileSync(out,JSON.stringify(report,null,2)+'\n');
save();
const sandbox=await Sandbox.start({});
try{
 const provider=new JsonRpcProvider({url:sandbox.rpcUrl});
 const acct=new Account('sandbox',provider,'ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB');
 await acct.deployContract(new Uint8Array(wasm));
 const init=await acct.callFunctionRaw({contractId:'sandbox',methodName:'new',args:{image:pins.image_id_words,expected:Buffer.from(pins.journal_hex,'hex').toString('base64')},gas:teraToGas('60')});
 assert.ok(Object.hasOwn(init.status??{},'SuccessValue'),'research initialization failed');
 for(const [name,b] of [['valid',valid],['mutated_seal',altered],['truncated',valid.subarray(0,Math.floor(valid.length/2))],['trailing',Buffer.concat([valid,Buffer.from([0])])]]){
  let row={name,accepted:false,executed:false};
  try{
   const r=await acct.callFunctionRaw({contractId:'sandbox',methodName:'verify_receipt',args:{receipt:b.toString('base64')},gas:teraToGas('300')});
   const status=r.status??{};
   const gas=(r.receipts_outcome??r.receipts_outcomes??[]).reduce((a,x)=>a+BigInt(x?.outcome?.gas_burnt??0),0n);
   row={...row,executed:true,status,receipt_gas_burnt:gas.toString(),receipt_TGas:Number(gas)/1e12};
   if(Object.hasOwn(status,'SuccessValue'))row.accepted=JSON.parse(Buffer.from(status.SuccessValue,'base64').toString('utf8'))===true;
  }catch(e){row.error=String(e);}
  report.cases.push(row);save();
  if(name==='valid'&&(!row.accepted||!(row.receipt_TGas>0&&row.receipt_TGas<=300)))throw Error('valid receipt did not verify under the gas limit; see saved receipt');
  if(name!=='valid'&&row.accepted)throw Error('tampered receipt accepted: '+name);
 }
 for(const method of ['can_authorize_dlc_settlement','production_ready'])assert.equal(await provider.callFunction({contractId:'sandbox',method,args:{}}),false);
 report.near_verified=true;save();console.log(JSON.stringify(report));
}catch(e){report.failure=String(e);save();throw e;}
finally{await sandbox.tearDown()}
