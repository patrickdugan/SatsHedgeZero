/** Executes the SHZ hourly public checkpoint verifier inside an ephemeral NEAR sandbox.
 * Does not submit or prove a real Bitcoin transaction, ZK private witness or oracle signatures.
 */
import {Sandbox} from 'near-sandbox';
import {Account,JsonRpcProvider,teraToGas} from 'near-api-js';
import {readFileSync,writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {strict as assert} from 'node:assert';
const dir=dirname(fileURLToPath(import.meta.url));
const {records,checkpoint:original}=JSON.parse(readFileSync(resolve(dir,'fixtures/checkpoint.json'),'utf8'));
const {schema,start_hour,genesis,policy_hash,merkle_root,checkpoint_root,packet_hex,inclusion}=original;
const cp={schema,start_hour,genesis,policy_hash,merkle_root,checkpoint_root,packet_hex};
const wasm=new Uint8Array(readFileSync(resolve(dir,'near_contract/target/wasm32-unknown-unknown/release/shz_near_hourly_checkpoint.wasm')));
const genesisPrivateKey='ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB';
const sandbox=await Sandbox.start({});
try {
 const provider=new JsonRpcProvider({url:sandbox.rpcUrl});
 const acct=new Account('sandbox',provider,genesisPrivateKey);
 await acct.deployContract(wasm);
 const init=await acct.callFunction({contractId:'sandbox',methodName:'new',args:{},gas:teraToGas('60')});
 assert.equal(Boolean(init?.status?.Failure),false,'initialize checkpoint registry');
 const staged=await acct.callFunction({contractId:'sandbox',methodName:'stage_checkpoint',args:{cp},gas:teraToGas('60')});
 assert.equal(Boolean(staged?.status?.Failure),false,'stage research root');
 for(let i=0;i<8;i++){
  const args={record:records[i],start_hour, siblings:inclusion[i].siblings};
  assert.equal(await provider.callFunction({contractId:'sandbox',method:'verify_hour_inclusion',args}),true);
  assert.equal(await provider.callFunction({contractId:'sandbox',method:'verify_qualified_hour',args}),i!==4);
 }
 const good={record:records[3],start_hour,siblings:inclusion[3].siblings};
 const altered=structuredClone(good);altered.record.pyth_report_hash='ff'.repeat(32);
 assert.equal(await provider.callFunction({contractId:'sandbox',method:'verify_hour_inclusion',args:altered}),false);
 const status=['bitcoin_anchor_finality_verified','pyth_chainlink_sources_authenticated','zk_private_hourly_witness_verified','nova_verified','can_authorize_dlc_settlement'];
 for(const method of status){assert.equal(await provider.callFunction({contractId:'sandbox',method,args:{}}),false,`unsafe state gate: ${method}`)}
 const receipt=await acct.callFunctionRaw({contractId:'sandbox',methodName:'verify_hour_inclusion',args:good,gas:teraToGas('300')});
 assert.equal(Boolean(receipt?.status?.Failure),false);
 const receipts=receipt?.receipts_outcome??receipt?.receipts_outcomes??[];
 const receiptGas=receipts.reduce((a,x)=>a+BigInt(x?.outcome?.gas_burnt??x?.gas_burnt??0),0n);
 assert.ok(receiptGas>0n,'measurable receipt gas');
 const report={schema:'shz/near-8h-public-checkpoint-sandbox/v1',network:'near-sandbox',checkpoint_root,packet_hex,authenticated_sources:false,bitcoin_header_finality:false,zk_witness_verified:false,nova_verified:false,dlc_authorized:false,valid_inclusion_checks:8,qualified_hours:7,hold_hours:1,tampered_report_rejected:true,receipt_gas_burnt:receiptGas.toString(),receipt_TGas:Number(receiptGas)/1e12};
 console.log(JSON.stringify(report,null,2));
 if(process.env.SHZ_HOURLY_SANDBOX_REPORT)writeFileSync(process.env.SHZ_HOURLY_SANDBOX_REPORT,JSON.stringify(report,null,2)+'\n');
} finally {await sandbox.tearDown()}
