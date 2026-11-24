/** ADMIT-11: real NEAR transactions; immutable pinned proof, validated hash
 * frames, exact final upstream replay. No execution or contract size override. */
import {Sandbox} from 'near-sandbox';
import {Account,JsonRpcProvider,teraToGas} from 'near-api-js';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const here=dirname(fileURLToPath(import.meta.url));
const [archive,traceDir,out]=process.argv.slice(2);
if(!archive||!traceDir||!out)throw Error('usage: replay_sandbox.mjs ARCHIVE TRACE_DIR REPORT.json');
const pins=JSON.parse(readFileSync(resolve(here,'evidence/admit08-frozen-pins.json')));
const m=JSON.parse(readFileSync(resolve(traceDir,'manifest.json')));
const proof=readFileSync(resolve(archive,'proof/root.bin')),bad=readFileSync(resolve(archive,'proof/mutated-seal.bin'));
const trace=readFileSync(resolve(traceDir,'transcript.bin')),altTrace=readFileSync(resolve(traceDir,'alternate-transcript.bin'));
const wasm=readFileSync(resolve(here,'near_resumable/target/wasm32-unknown-unknown/release/shz_near_stark_resumable.wasm'));
const b64=b=>Buffer.from(b).toString('base64');
assert.equal(createHash('sha256').update(proof).digest('hex'),pins.receipt_sha256);
assert.ok(m.native_actual_receipt_verified&&m.wrong_input_with_valid_hash_rejected&&m.forged_output_rejected);
assert.equal(m.calls,4630);assert.equal(m.permutations,5661);
const report={schema:'shz/admit11-near-replay/v1',receipt_sha256:pins.receipt_sha256,wasm_bytes:wasm.length,transcript_bytes:trace.length,expected_calls:m.calls,expected_batches:m.frame_count,gas_limit_TGas:300,stage:'start',cases:[],near_verified:false,production_ready:false,source_authentication:false,provider_completeness:false,can_authorize_dlc_settlement:false};
const save=()=>writeFileSync(out,JSON.stringify(report,null,2)+'\n');
save();
const rpcLimit=16*1024*1024;
const sandbox=await Sandbox.start({config:{additionalConfig:{rpc:{limits_config:{json_payload_max_size:rpcLimit}}}}});
try{
 const provider=new JsonRpcProvider({url:sandbox.rpcUrl});
 const acct=new Account('sandbox',provider,'ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB');
 const dump=await sandbox.dump();assert.equal(dump.config?.rpc?.limits_config?.json_payload_max_size,rpcLimit);
 await acct.deployContract(new Uint8Array(wasm));
 const init=await acct.callFunctionRaw({contractId:'sandbox',methodName:'new',args:{image:pins.image_id_words,expected:b64(Buffer.from(pins.journal_hex,'hex')),receipt_sha256:pins.receipt_sha256,call_count:m.calls},gas:teraToGas('60')});
 assert.ok(Object.hasOwn(init.status??{},'SuccessValue'));
 async function status(){return provider.callFunction({contractId:'sandbox',method:'status',args:{}});}
 async function call(label,method,args){
  let row={label,method,executed:false,value:null};
  try{
   const r=await acct.callFunctionRaw({contractId:'sandbox',methodName:method,args,gas:teraToGas('300')});
   const s=r.status??{};
   const gas=(r.receipts_outcome??r.receipts_outcomes??[]).reduce((a,x)=>a+BigInt(x?.outcome?.gas_burnt??0),0n);
   row={...row,executed:true,status:s,receipt_TGas:Number(gas)/1e12,value:Object.hasOwn(s,'SuccessValue')?JSON.parse(Buffer.from(s.SuccessValue,'base64').toString('utf8')):null};
  }catch(e){row.error=String(e);}
  row.after=await status();report.cases.push(row);save();console.log(JSON.stringify(row));return row;
 }
 const same=(a,b)=>assert.deepEqual(a,b,'failed attempt changed contract state');
 const no=async(label,method,args)=>{
  const before=await status();const r=await call(label,method,args);assert.equal(r.value,false,label);same(before,r.after);return r;
 };
 const yes=async(label,method,args)=>{
  const r=await call(label,method,args);assert.equal(r.value,true,label);assert.ok(r.receipt_TGas>0&&r.receipt_TGas<=300,label+' gas');return r;
 };
 const finish=(receipt,transcript)=>({receipt:b64(receipt),transcript:b64(transcript)});
 let st=await status();assert.equal(st.commitment,m.initial_commitment);assert.equal(st.offset,0);assert.equal(st.verified,false);
 report.stage='negative_prefix';save();
 const first=readFileSync(resolve(traceDir,m.frames[0].file));
 await no('premature','finish',finish(proof,trace));
 await no('wrong_offset','append_batch',{offset:1,frame:b64(first)});
 await no('forged_output','append_batch',{offset:0,frame:b64(readFileSync(resolve(traceDir,'forged-output.bin')))});
 await no('trailing_frame','append_batch',{offset:0,frame:b64(Buffer.concat([first,Buffer.from([0])]))});
 // Every hash of this alternate transcript is correct, but its first input
 // differs from the actual upstream verifier call. Test a fully committed
 // wrong transcript before the honest session; only replay can reject it.
 report.stage='alternate_session';save();
 for(const f of m.frames){
  const bytes=readFileSync(resolve(traceDir,f.index===0?'alternate-first.bin':f.file));
  const r=await yes('alt_batch_'+f.index,'append_batch',{offset:f.offset,frame:b64(bytes)});
  assert.equal(r.after.offset,f.offset+f.calls);assert.equal(r.after.verified,false);
 }
 st=await status();assert.equal(st.commitment,m.alternate_terminal_commitment);
 const alternate=await call('valid_hash_wrong_input','finish',finish(proof,altTrace));
 assert.notEqual(alternate.value,true);same(st,alternate.after);
 // Treat only explicit false as a completed negative control; gas failure
 // remains a separate unresolved verifier workload.
 report.alternate_rejected_explicitly=alternate.executed&&alternate.value===false;
 await yes('reset','reset',{});
 report.stage='honest_session';save();
 for(const f of m.frames){
  const bytes=readFileSync(resolve(traceDir,f.file));
  const r=await yes('batch_'+f.index,'append_batch',{offset:f.offset,frame:b64(bytes)});
  assert.equal(r.after.offset,f.offset+f.calls);assert.equal(r.after.batches,f.index+1);assert.equal(r.after.commitment,f.commitment);assert.equal(r.after.verified,false);
  if(f.index===0)await no('duplicate_batch','append_batch',{offset:0,frame:b64(bytes)});
 }
 st=await status();assert.equal(st.commitment,m.terminal_commitment);assert.equal(st.offset,m.calls);
 await no('wrong_proof','finish',finish(bad,trace));
 await no('wrong_committed_transcript','finish',finish(proof,altTrace));
 await no('truncated_transcript','finish',finish(proof,trace.subarray(0,trace.length-1)));
 const final=await call('valid_final','finish',finish(proof,trace));
 const rows=report.cases.filter(r=>/^batch_\d+$/.test(r.label));
 report.honest_batch_TGas=rows.reduce((n,r)=>n+r.receipt_TGas,0);
 report.max_batch_TGas=Math.max(...rows.map(r=>r.receipt_TGas));
 report.final_TGas=final.receipt_TGas??null;
 report.honest_total_TGas=final.value===true?report.honest_batch_TGas+report.final_TGas:null;
 report.near_verified=final.value===true&&final.after.verified===true&&report.alternate_rejected_explicitly&&final.receipt_TGas>0&&final.receipt_TGas<=300;
 report.outcome=report.near_verified?'VERIFIED':'FINAL_REPLAY_OR_NEGATIVE_GATE_NOT_MET';
 report.stage='complete';save();console.log(JSON.stringify({schema:report.schema,near_verified:report.near_verified,outcome:report.outcome,frame_count:m.frame_count,max_batch_TGas:report.max_batch_TGas,honest_batch_TGas:report.honest_batch_TGas,final_TGas:report.final_TGas,honest_total_TGas:report.honest_total_TGas,alternate_rejected_explicitly:report.alternate_rejected_explicitly,wasm_bytes:report.wasm_bytes}));
 assert.equal(await provider.callFunction({contractId:'sandbox',method:'production_ready',args:{}}),false);
 assert.equal(await provider.callFunction({contractId:'sandbox',method:'can_authorize_dlc_settlement',args:{}}),false);
 if(!report.near_verified)throw Error('actual multi-transaction application gate did not pass');
 await no('repeated_finish','finish',finish(proof,trace));await no('reset_after_accept','reset',{});
}catch(e){report.failure=String(e);save();throw e;}finally{await sandbox.tearDown();}
