/** ADMIT-14: actual distinct receipt with independently pinned statement. */
import {Sandbox} from 'near-sandbox';
import {Account,JsonRpcProvider,teraToGas} from 'near-api-js';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const here=dirname(fileURLToPath(import.meta.url)),[archive,traceDir,fixture,original,out]=process.argv.slice(2);
if(!out)throw Error('usage: generalize_sandbox.mjs ARCHIVE PLAN_DIR RECEIVER_FIXTURE ORIGINAL_ARCHIVE REPORT.json');
const pins=JSON.parse(readFileSync(resolve(fixture,'expected.json')));
const approved=JSON.parse(readFileSync(resolve(here,'evidence/admit08-frozen-pins.json')));
const plan=JSON.parse(readFileSync(resolve(traceDir,'manifest.json')));
const proof=readFileSync(resolve(archive,'proof/root.bin')),bad=readFileSync(resolve(archive,'proof/mutated-seal.bin')),old=readFileSync(resolve(original,'proof/root.bin'));
const wasm=readFileSync(resolve(here,'near_fused/target/wasm32-unknown-unknown/release/shz_near_stark_fused.wasm'));
const b64=b=>Buffer.from(b).toString('base64');
assert.equal(createHash('sha256').update(proof).digest('hex'),plan.receipt_sha256);
assert.equal(createHash('sha256').update(old).digest('hex'),approved.receipt_sha256);
assert.equal(plan.case_id,pins.id);assert.equal(plan.journal_hex,pins.journal_hex);assert.equal(plan.snapshot_pin,pins.snapshot_pin);
assert.deepEqual(plan.image_id_words,approved.image_id_words);assert.deepEqual(pins.image_id_words,approved.image_id_words);
assert.ok(plan.native_actual_receipt_verified&&plan.mutated_seal_rejected);
if(plan.fresh_receipt){assert.notEqual(plan.receipt_sha256,approved.receipt_sha256);assert.ok(plan.cross_journal_substitution_rejected);}
assert.deepEqual(plan.profiles.map(x=>x.cap),[3072,3456,3584]);
const report={schema:'shz/admit14-sandbox/v1',case_id:pins.id,source:pins.source,reports:pins.reports,leaves:pins.leaves,folds:pins.folds,snapshot_pin:pins.snapshot_pin,receipt_bytes:proof.length,calls:plan.calls,permutations:plan.permutations,fresh_receipt:plan.fresh_receipt,receipt_sha256:plan.receipt_sha256,wasm_bytes:wasm.length,profiles:[],near_verified:false,production_ready:false,source_authentication:false,provider_completeness:false,can_authorize_dlc_settlement:false};
const save=()=>writeFileSync(out,JSON.stringify(report,null,2)+'\n');save();
for(const p of plan.profiles){
 const row={cap:p.cap,frame_count:p.frame_count,tape_bytes:p.tape_bytes,verified:false,cases:[]};
 report.profiles.push(row);save();
 assert.ok(p.frame_count>=2);assert.ok(p.native_verified&&p.upstream_pass_wrong_root_rejected&&p.wrong_boundary_rejected);
 const read=n=>readFileSync(resolve(traceDir,String(p.cap),n));
 const tape=read('tape.bin'),first=read(p.frames[0].file),last=read(p.frames.at(-1).file),offset=p.frames.at(-1).offset;
 const rpc=16*1024*1024;
 const sandbox=await Sandbox.start({config:{additionalConfig:{rpc:{limits_config:{json_payload_max_size:rpc}}}}});
 try{
  const provider=new JsonRpcProvider({url:sandbox.rpcUrl});
  const acct=new Account('sandbox',provider,'ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB');
  const dump=await sandbox.dump();assert.equal(dump.config?.rpc?.limits_config?.json_payload_max_size,rpc);
  await acct.deployContract(new Uint8Array(wasm));
  const init=await acct.callFunctionRaw({contractId:'sandbox',methodName:'new',args:{image:pins.image_id_words,expected:b64(Buffer.from(pins.journal_hex,'hex')),receipt_sha256:plan.receipt_sha256,call_count:p.calls,cap:p.cap},gas:teraToGas('60')});
  assert.ok(Object.hasOwn(init.status??{},'SuccessValue'));
  const status=()=>provider.callFunction({contractId:'sandbox',method:'status',args:{}});
  async function call(label,method,args){
   let r={label,method,executed:false,value:null};
   try{
    const tx=await acct.callFunctionRaw({contractId:'sandbox',methodName:method,args,gas:teraToGas('300')});
    const s=tx.status??{};const gas=(tx.receipts_outcome??tx.receipts_outcomes??[]).reduce((a,x)=>a+BigInt(x?.outcome?.gas_burnt??0),0n);
    r={...r,executed:true,receipt_TGas:Number(gas)/1e12,value:Object.hasOwn(s,'SuccessValue')?JSON.parse(Buffer.from(s.SuccessValue,'base64').toString('utf8')):null,status:s};
   }catch(e){r.error=String(e);}
   r.after=await status();row.cases.push(r);save();console.log(JSON.stringify({cap:p.cap,...r}));return r;
  }
  const yes=async(label,method,args)=>{const r=await call(label,method,args);assert.equal(r.value,true,label);assert.ok(r.receipt_TGas>0&&r.receipt_TGas<=300,label+' gas');return r};
  const no=async(label,method,args,explicit=true)=>{const before=await status();const r=await call(label,method,args);if(explicit)assert.equal(r.value,false,label);else assert.notEqual(r.value,true,label);assert.deepEqual(r.after,before,label+' state changed');return r};
  const finish=(frame=last,receipt=proof,t=tape,at=offset)=>({offset:at,frame:b64(frame),receipt:b64(receipt),tape:b64(t)});
  const initial=await status();assert.equal(initial.commitment,p.initial_commitment);assert.equal(initial.offset,0);
  await no('premature','finish_with_batch',finish(last,proof,tape,0));
  await no('forged_prefix','append_batch',{offset:0,frame:b64(read('forged-output.bin'))});
  for(const f of p.frames.slice(0,-1))await yes('alternate_prefix_'+f.index,'append_batch',{offset:f.offset,frame:b64(read(f.index===0?'alternate-first.bin':f.file))});
  // All committed hash computations are valid; the honest proof/tape alone
  // passes the upstream equations, but the candidate root must differ.
  await no('wrong_prefix_valid_hash','finish_with_batch',finish());
  await yes('reset','reset',{});assert.equal((await status()).commitment,p.initial_commitment);
  const prefix=[];
  for(const f of p.frames.slice(0,-1)){
   const a=await yes('honest_prefix_'+f.index,'append_batch',{offset:f.offset,frame:b64(read(f.file))});
   assert.equal(a.after.offset,f.offset+f.calls);assert.equal(a.after.commitment,f.commitment);assert.equal(a.after.verified,false);
   prefix.push(a);
  }
  assert.equal((await status()).offset,offset);
  await no('duplicate_prefix','append_batch',{offset:0,frame:b64(first)});
  await no('terminal_requires_finish','append_batch',{offset,frame:b64(last)});
  await no('wrong_proof','finish_with_batch',finish(last,bad));
  if(plan.fresh_receipt)await no('prior_genuine_receipt','finish_with_batch',finish(last,old));
  await no('wrong_offset','finish_with_batch',finish(last,proof,tape,offset+1));
  await no('forged_last','finish_with_batch',finish(read('forged-last.bin')));
  await no('valid_wrong_last','finish_with_batch',finish(read('valid-wrong-last.bin')));
  await no('truncated_tape','finish_with_batch',finish(last,proof,tape.subarray(0,tape.length-1)));
  await no('wrong_boundary','finish_with_batch',finish(last,proof,read('wrong-boundary.bin')),false);
  const final=await yes('honest_terminal','finish_with_batch',finish());
  assert.equal(final.after.offset,p.calls);assert.equal(final.after.batches,p.frame_count);assert.equal(final.after.commitment,p.terminal_commitment);assert.equal(final.after.verified,true);
  await no('repeated_finish','finish_with_batch',finish());await no('reset_after_accept','reset',{});
  for(const method of ['production_ready','can_authorize_dlc_settlement'])assert.equal(await provider.callFunction({contractId:'sandbox',method,args:{}}),false);
  row.prefix_TGas=prefix.reduce((n,r)=>n+r.receipt_TGas,0);row.terminal_TGas=final.receipt_TGas;row.max_transaction_TGas=Math.max(...prefix.map(r=>r.receipt_TGas),row.terminal_TGas);
  row.honest_total_TGas=row.prefix_TGas+row.terminal_TGas;row.verification_transactions=prefix.length+1;row.verified=true;row.atomic_failure_controls_passed=true;
 }catch(e){row.failure=String(e);console.error(JSON.stringify({cap:p.cap,failure:row.failure}));}
 finally{save();await sandbox.tearDown();}
}
const passed=report.profiles.filter(p=>p.verified).sort((a,b)=>a.verification_transactions-b.verification_transactions||a.max_transaction_TGas-b.max_transaction_TGas||a.honest_total_TGas-b.honest_total_TGas);
report.near_verified=passed.length>0;report.best=passed.length?{cap:passed[0].cap,transactions:passed[0].verification_transactions,total_TGas:passed[0].honest_total_TGas,max_transaction_TGas:passed[0].max_transaction_TGas,terminal_TGas:passed[0].terminal_TGas}:null;
save();console.log(JSON.stringify({schema:report.schema,case_id:report.case_id,source:report.source,reports:report.reports,folds:report.folds,fresh_receipt:report.fresh_receipt,snapshot_pin:report.snapshot_pin,receipt_bytes:report.receipt_bytes,calls:report.calls,permutations:report.permutations,profiles:report.profiles.map(({cases,...r})=>r),best:report.best,near_verified:report.near_verified}));
if(!passed.length)throw Error('no generalization profile passed');
