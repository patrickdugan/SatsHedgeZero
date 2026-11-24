/** Replay only: use exact frozen proof, compare identical hash work on NEAR.
 * Continue recording after gas failures, never treat a failure as verification.
 */
import {Sandbox} from 'near-sandbox';
import {Account,JsonRpcProvider,teraToGas} from 'near-api-js';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const here=dirname(fileURLToPath(import.meta.url)),[dir,out]=process.argv.slice(2);
if(!dir||!out)throw Error('usage: fast_sandbox.mjs ARCHIVE_DIR REPORT.json');
const pins=JSON.parse(readFileSync(resolve(here,'evidence/admit08-frozen-pins.json')));
const valid=readFileSync(resolve(dir,'proof/root.bin')),bad=readFileSync(resolve(dir,'proof/mutated-seal.bin'));
assert.equal(createHash('sha256').update(valid).digest('hex'),pins.receipt_sha256);
const wasm=readFileSync(resolve(here,'near_verifier/target/wasm32-unknown-unknown/release/shz_near_stark_probe.wasm'));
const report={schema:'shz/admit09-fast-stark-near/v1',wasm_bytes:wasm.length,receipt_sha256:pins.receipt_sha256,control_root:pins.control_root,hash_cases:[],proof_cases:[],near_verified:false,production_ready:false,can_authorize_dlc_settlement:false,source_authentication:false};
const save=()=>writeFileSync(out,JSON.stringify(report,null,2)+'\n');
save();
const sandbox=await Sandbox.start({});
try{
 const provider=new JsonRpcProvider({url:sandbox.rpcUrl});
 const acct=new Account('sandbox',provider,'ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB');
 await acct.deployContract(new Uint8Array(wasm));
 await acct.callFunctionRaw({contractId:'sandbox',methodName:'new',args:{image:pins.image_id_words,expected:Buffer.from(pins.journal_hex,'hex').toString('base64')},gas:teraToGas('60')});
 async function call(method,args){
  try{
   const r=await acct.callFunctionRaw({contractId:'sandbox',methodName:method,args,gas:teraToGas('300')});
   const status=r.status??{};
   const gas=(r.receipts_outcome??r.receipts_outcomes??[]).reduce((a,x)=>a+BigInt(x?.outcome?.gas_burnt??0),0n);
   return {executed:true,status,receipt_gas_burnt:String(gas),receipt_TGas:Number(gas)/1e12,value:Object.hasOwn(status,'SuccessValue')?JSON.parse(Buffer.from(status.SuccessValue,'base64').toString('utf8')):null};
  }catch(e){return {executed:false,error:String(e)};}
 }
 for(const n of [0,32,128,512]){
  const a=await call('hash_pairs',{n,fast:false});const b=await call('hash_pairs',{n,fast:true});
  report.hash_cases.push({n,upstream:a,fast:b});save();
  if(a.executed&&b.executed){assert.ok(Array.isArray(a.value)&&Array.isArray(b.value));assert.deepEqual(a.value,b.value,'hash digest mismatch');}
 }
 for(const fast of [false,true]){
  const method=fast?'verify_receipt_fast':'verify_receipt';
  for(const [name,bytes] of [['valid',valid],['mutated_seal',bad],['truncated',valid.subarray(0,valid.length>>1)],['trailing',Buffer.concat([valid,Buffer.from([0])])]]){
   const r=await call(method,{receipt:bytes.toString('base64')});
   report.proof_cases.push({fast,name,...r});save();
   if(name!=='valid'&&r.value===true)throw Error('accepted corrupt proof');
  }
 }
 for(const method of ['production_ready','can_authorize_dlc_settlement'])assert.equal(await provider.callFunction({contractId:'sandbox',method,args:{}}),false);
 const good=report.proof_cases.find(r=>r.fast&&r.name==='valid');
 const negatives=report.proof_cases.filter(r=>r.fast&&r.name!=='valid');
 report.near_verified=good.value===true&&good.receipt_TGas>0&&good.receipt_TGas<=300&&negatives.length===3&&negatives.every(r=>r.value!==true);
 report.outcome=report.near_verified?'VERIFIED':'GAS_OR_EXECUTION_GATE_NOT_MET';
 save();console.log(JSON.stringify(report));
} catch(e){report.failure=String(e);save();throw e;}finally{await sandbox.tearDown();}
