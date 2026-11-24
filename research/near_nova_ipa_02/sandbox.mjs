// Live NEAR-sandbox WASM execution of IPA proof sizes 8,16,32 and a tampered control.
// No real onchain funds, no production proof authorizations.
import {Sandbox} from 'near-sandbox';
import {Account,JsonRpcProvider,teraToGas} from 'near-api-js';
import {readFileSync,writeFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {strict as assert} from 'node:assert';
const here=dirname(fileURLToPath(import.meta.url));
const wasm=new Uint8Array(readFileSync(resolve(here,'near_contract/target/wasm32-unknown-unknown/release/shz_near_transparent_ipa_mnr03_state.wasm')));
const sandboxGenesisKey='ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB';
const sandbox=await Sandbox.start({});
try {
 const provider=new JsonRpcProvider({url:sandbox.rpcUrl});
 const account=new Account('sandbox',provider,sandboxGenesisKey);
 await account.deployContract(wasm);
 const init=await account.callFunction({contractId:'sandbox',methodName:'new',args:{},gas:teraToGas('50')});
 assert.equal(Boolean(init?.status?.Failure),false,'contract initialization');
 const canNova=await provider.callFunction({contractId:'sandbox',method:'can_authorize_nova',args:{}});
 const canDlc=await provider.callFunction({contractId:'sandbox',method:'can_authorize_dlc_settlement',args:{}});
 assert.equal(canNova,false);assert.equal(canDlc,false);
 const measurements=[];
 for(const n of [8,16,32]){
  const fixture=JSON.parse(readFileSync(resolve(here,`fixtures/mnr03-${n}.json`),'utf8'));
  const args={statement:fixture.statement,proof:fixture.proof};
  const good=await provider.callFunction({contractId:'sandbox',method:'verify_frozen_mnr03_public_state',args});
  assert.equal(good,true,`${n}-dim proof must verify`);
  const bad=structuredClone(args);bad.statement.collateral_sats+=1;
  const rejected=await provider.callFunction({contractId:'sandbox',method:'verify_frozen_mnr03_public_state',args:bad});
  assert.equal(rejected,false,`${n}-dim forged accounting must fail`);
  const wrong=structuredClone(args);wrong.proof.a_final_hex='00'.repeat(32);
  assert.equal(await provider.callFunction({contractId:'sandbox',method:'verify_frozen_mnr03_public_state',args:wrong}),false,'modified proof must fail');
  const raw=await account.callFunctionRaw({contractId:'sandbox',methodName:'verify_frozen_mnr03_public_state',args,gas:teraToGas('300')});
  assert.equal(Boolean(raw?.status?.Failure),false,`${n}-dim receipt must execute`);
  const receipts=raw?.receipts_outcome??raw?.receipts_outcomes??[];
  const gas=receipts.reduce((s,r)=>s+BigInt(r?.outcome?.gas_burnt??r?.gas_burnt??0),0n);
  assert.ok(gas>0n,`${n}-dim gas measured`);
  measurements.push({dimension:n,rounds:Math.log2(n),receiptGasBurnt:gas.toString(),receiptTGas:Number(gas)/1e12,validAccepted:good,accountingTamperRejected:rejected===false,proofTamperRejected:true});
  console.log(JSON.stringify(measurements.at(-1)));
 }
 const result={schema:'shz/near-ipa02-sandbox/v1',researchOnly:true,transparent:true,relation:'shz/near-ipa02-frozen-mnr03-state/v2',frozenMnr03SourceCommitmentBound:true,fullNovaPallasVerifierConstrained:false,sourceAuthenticated:false,bitcoinWitnessProved:false,canAuthorizeNova:canNova,canAuthorizeDlcSettlement:canDlc,productionReady:false,measurements};
 console.log(JSON.stringify(result,null,2));
 if(process.env.SHZ_IPA02_SANDBOX_RECEIPT)writeFileSync(process.env.SHZ_IPA02_SANDBOX_RECEIPT,JSON.stringify(result,null,2)+'\n');
}finally {await sandbox.tearDown()}
