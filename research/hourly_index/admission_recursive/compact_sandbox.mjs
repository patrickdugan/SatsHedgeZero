/** Compare three immutable gas-work profiles on the same genuine STARK.
 * Receipt outputs alone never authorize acceptance: final replay opens the
 * actually validated commitment from the original verifier's real inputs. */
import {Sandbox} from 'near-sandbox';
import {Account,JsonRpcProvider,teraToGas} from 'near-api-js';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const here=dirname(fileURLToPath(import.meta.url)),[archive,traceDir,out]=process.argv.slice(2);
if(!out)throw Error('usage: compact_sandbox.mjs ARCHIVE PLAN_DIR REPORT.json');
const pins=JSON.parse(readFileSync(resolve(here,'evidence/admit08-frozen-pins.json')));
const plan=JSON.parse(readFileSync(resolve(traceDir,'manifest.json')));
const proof=readFileSync(resolve(archive,'proof/root.bin')),bad=readFileSync(resolve(archive,'proof/mutated-seal.bin'));
const wasm=readFileSync(resolve(here,'near_compact/target/wasm32-unknown-unknown/release/shz_near_stark_compact.wasm'));
const b64=b=>Buffer.from(b).toString('base64');
assert.equal(createHash('sha256').update(proof).digest('hex'),pins.receipt_sha256);
assert.deepEqual(plan.profiles.map(x=>x.cap),[512,2048,3072]);
const report={schema:'shz/admit12-sandbox/v1',receipt_sha256:pins.receipt_sha256,wasm_bytes:wasm.length,profiles:[],near_verified:false,production_ready:false,source_authentication:false,provider_completeness:false,can_authorize_dlc_settlement:false};
const save=()=>writeFileSync(out,JSON.stringify(report,null,2)+'\n');save();
for(const p of plan.profiles){
 const row={cap:p.cap,frame_count:p.frame_count,tape_bytes:p.tape_bytes,full_transcript_bytes:p.full_transcript_bytes,verified:false,cases:[]};
 report.profiles.push(row);save();
 const read=n=>readFileSync(resolve(traceDir,String(p.cap),n));
 const tape=read('tape.bin'),altTape=read('alternate-tape.bin'),first=read(p.frames[0].file);
 assert.ok(p.native_verified&&p.upstream_pass_wrong_root_rejected&&p.wrong_boundary_rejected);
 const rpc=16*1024*1024;
 const sandbox=await Sandbox.start({config:{additionalConfig:{rpc:{limits_config:{json_payload_max_size:rpc}}}}});
 try{
  const provider=new JsonRpcProvider({url:sandbox.rpcUrl});
  const acct=new Account('sandbox',provider,'ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB');
  const dump=await sandbox.dump();assert.equal(dump.config?.rpc?.limits_config?.json_payload_max_size,rpc);
  await acct.deployContract(new Uint8Array(wasm));
  const init=await acct.callFunctionRaw({contractId:'sandbox',methodName:'new',args:{image:pins.image_id_words,expected:b64(Buffer.from(pins.journal_hex,'hex')),receipt_sha256:pins.receipt_sha256,call_count:p.calls,cap:p.cap},gas:teraToGas('60')});
  assert.ok(Object.hasOwn(init.status??{},'SuccessValue'));
  const status=()=>provider.callFunction({contractId:'sandbox',method:'status',args:{}});
  async function call(label,method,args){
   let r={label,method,executed:false,value:null};
   try{
    const tx=await acct.callFunctionRaw({contractId:'sandbox',methodName:method,args,gas:teraToGas('300')});
    const s=tx.status??{};
    const gas=(tx.receipts_outcome??tx.receipts_outcomes??[]).reduce((a,x)=>a+BigInt(x?.outcome?.gas_burnt??0),0n);
    r={...r,executed:true,receipt_TGas:Number(gas)/1e12,value:Object.hasOwn(s,'SuccessValue')?JSON.parse(Buffer.from(s.SuccessValue,'base64').toString('utf8')):null,status:s};
   }catch(e){r.error=String(e);}
   r.after=await status();row.cases.push(r);save();console.log(JSON.stringify({cap:p.cap,...r}));return r;
  }
  const yes=async(label,method,args)=>{const r=await call(label,method,args);assert.equal(r.value,true,label);assert.ok(r.receipt_TGas>0&&r.receipt_TGas<=300,label+' gas');return r};
  const no=async(label,method,args)=>{const before=await status();const r=await call(label,method,args);assert.equal(r.value,false,label);assert.deepEqual(r.after,before,label+' state changed');return r};
  const finish=(receipt,t)=>({receipt:b64(receipt),tape:b64(t)});
  const initial=await status();assert.equal(initial.commitment,p.initial_commitment);assert.equal(initial.offset,0);assert.equal(initial.cap,p.cap);
  await no('premature','finish',finish(proof,tape));
  await no('wrong_offset','append_batch',{offset:1,frame:b64(first)});
  await no('forged_output','append_batch',{offset:0,frame:b64(read('forged-output.bin'))});
  await no('trailing_frame','append_batch',{offset:0,frame:b64(Buffer.concat([first,Buffer.from([0])]))});
  // Fully validated wrong-input commitment, then an honest output tape.
  for(const f of p.frames){
   const r=await yes('alt_'+f.index,'append_batch',{offset:f.offset,frame:b64(read(f.index===0?'alternate-first.bin':f.file))});
   assert.equal(r.after.verified,false);assert.equal(r.after.offset,f.offset+f.calls);
  }
  const alt=await status();assert.equal(alt.commitment,p.alternate_terminal_commitment);
  await no('upstream_pass_wrong_root','finish',finish(proof,tape));
  // This tape may fail the verifier early; a trap must not mutate the state.
  const a=await call('alternate_tape','finish',finish(proof,altTape));assert.notEqual(a.value,true);assert.deepEqual(a.after,alt);
  await yes('reset','reset',{});assert.equal((await status()).commitment,p.initial_commitment);
  for(const f of p.frames){
   const r=await yes('batch_'+f.index,'append_batch',{offset:f.offset,frame:b64(read(f.file))});
   assert.equal(r.after.offset,f.offset+f.calls);assert.equal(r.after.commitment,f.commitment);assert.equal(r.after.verified,false);
   if(f.index===0)await no('duplicate_batch','append_batch',{offset:0,frame:b64(first)});
  }
  await no('wrong_proof','finish',finish(bad,tape));
  await no('wrong_boundary','finish',finish(proof,read('wrong-boundary.bin')));
  await no('truncated_tape','finish',finish(proof,tape.subarray(0,tape.length-1)));
  await no('trailing_tape','finish',finish(proof,Buffer.concat([tape,Buffer.from([0])])));
  const final=await yes('valid_final','finish',finish(proof,tape));assert.equal(final.after.verified,true);
  await no('repeated_finish','finish',finish(proof,tape));await no('reset_after_accept','reset',{});
  for(const method of ['production_ready','can_authorize_dlc_settlement'])assert.equal(await provider.callFunction({contractId:'sandbox',method,args:{}}),false);
  const rows=row.cases.filter(x=>/^batch_\d+$/.test(x.label));
  assert.equal(rows.length,p.frame_count);
  row.honest_batch_TGas=rows.reduce((n,x)=>n+x.receipt_TGas,0);row.max_batch_TGas=Math.max(...rows.map(x=>x.receipt_TGas));
  row.final_TGas=final.receipt_TGas;row.honest_total_TGas=row.honest_batch_TGas+row.final_TGas;
  row.verification_transactions=rows.length+1;row.verified=true;row.strong_wrong_commitment_rejected=true;
 }catch(e){row.failure=String(e);console.error(JSON.stringify({cap:p.cap,failure:row.failure}));}
 finally{save();await sandbox.tearDown();}
}
const passed=report.profiles.filter(p=>p.verified).sort((a,b)=>a.verification_transactions-b.verification_transactions||a.honest_total_TGas-b.honest_total_TGas);
report.near_verified=passed.length>0;report.best=passed.length?{cap:passed[0].cap,transactions:passed[0].verification_transactions,total_TGas:passed[0].honest_total_TGas,final_TGas:passed[0].final_TGas,max_batch_TGas:passed[0].max_batch_TGas}:null;
save();console.log(JSON.stringify({schema:report.schema,profiles:report.profiles.map(({cases,...r})=>r),best:report.best,near_verified:report.near_verified}));
if(!report.profiles.find(p=>p.cap===512)?.verified||!passed.some(p=>p.cap>=2048))throw Error('compact replay baseline or larger-batch gate failed');
