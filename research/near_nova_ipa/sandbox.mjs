// Real NEAR sandbox execution/gas receipt, requires near-workspaces 5 and a built WASM.
import {Worker} from 'near-workspaces';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {strict as assert} from 'node:assert';
const here=dirname(fileURLToPath(import.meta.url));
const proof=JSON.parse(readFileSync(resolve(here,'fixtures/valid.json'),'utf8'));
const wasm=resolve(here,'near_contract/target/wasm32-unknown-unknown/release/shz_near_transparent_ipa_pilot.wasm');
const worker=await Worker.init({network:'sandbox'});
try {
 const root=worker.rootAccount;
 const contract=await root.devDeploy(wasm);
 await root.call(contract,'new',{});
 const ok=await contract.view('verify_ipa',{statement:proof.statement,proof:proof.proof});
 assert.equal(ok,true,'valid proof must verify in sandbox');
 const bad=structuredClone(proof);bad.proof.a_final_hex='00'.repeat(32);
 assert.equal(await contract.view('verify_ipa',{statement:bad.statement,proof:bad.proof}),false,
   'tampered scalar must be rejected inside sandbox');
 assert.equal(await contract.view('can_authorize_nova',{}),false);
 // Function-call transaction measures receipt gas; view gas is not a transaction benchmark.
 const result=await root.callRaw(contract,'verify_ipa',
   {statement:proof.statement,proof:proof.proof},{gas:'300000000000000'});
 assert.equal(result.succeeded,true,'valid proof function call must succeed');
 const receipts=result.receipts_outcomes||[];
 const receiptGas=receipts.reduce((acc,o)=>acc+Number(o.outcome?.gas_burnt??o.gas_burnt??0),0);
 const record={schema:'shz/near-transparent-ipa-sandbox/v1',network:'near-sandbox',
   relation:'shz/near-transparent-bn254-ipa/v1',transparent:true,epoch:proof.statement.epoch_hash_hex,
   validProofAccepted:ok,tamperedProofRejected:true,canAuthorizeNova:false,
   receiptGasBurnt:receiptGas,receiptGasTgas:receiptGas/1e12,
   totalReportedGasBurnt:result.gas_burnt??null,
   verifierVersion:'near-sdk=5.17.2',sourceVerified:false,novaVerified:false,bitcoinEnforced:false};
 console.log(JSON.stringify(record,null,2));
 const out=process.env.SHZ_IPA_SANDBOX_RECEIPT;
 if(out)writeFileSync(out,JSON.stringify(record,null,2)+'\n');
} finally {await worker.tearDown()}
