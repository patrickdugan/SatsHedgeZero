// Current NEAR sandbox + near-api-js v7 integration. Zero externally funded accounts.
// Tests a real WASM module with native BN254 G1 multiexp in NEAR execution.
import {Sandbox} from 'near-sandbox';
import {Account, JsonRpcProvider, teraToGas} from 'near-api-js';
import {readFileSync, writeFileSync} from 'node:fs';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {strict as assert} from 'node:assert';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(resolve(here, 'fixtures/valid.json'), 'utf8'));
const wasm = new Uint8Array(readFileSync(resolve(here,
  'near_contract/target/wasm32-unknown-unknown/release/shz_near_transparent_ipa_pilot.wasm')));
// This is the publicly documented default development-only genesis key of near-sandbox-js.
// NEVER use this key outside ephemeral local sandboxes.
const sandboxGenesisKey = 'ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB';
const sandbox = await Sandbox.start({});
try {
  const provider = new JsonRpcProvider({url:sandbox.rpcUrl});
  const account = new Account('sandbox', provider, sandboxGenesisKey);
  await account.deployContract(wasm);
  const init = await account.callFunction({contractId:'sandbox', methodName:'new', args:{}, gas:teraToGas('50')});
  assert.equal(Boolean(init?.status?.Failure), false, 'NEAR contract initialization must succeed');
  const params = {statement:fixture.statement, proof:fixture.proof};
  const good = await provider.callFunction({contractId:'sandbox', method:'verify_ipa', args:params});
  assert.equal(good, true, 'valid transparent IPA must verify in NEAR sandbox');
  const tampered = structuredClone(params);
  tampered.proof.a_final_hex = '00'.repeat(32);
  const bad = await provider.callFunction({contractId:'sandbox', method:'verify_ipa', args:tampered});
  assert.equal(bad, false, 'modified proof must be rejected by NEAR sandbox');
  const canAuthorize = await provider.callFunction({contractId:'sandbox', method:'can_authorize_nova', args:{}});
  assert.equal(canAuthorize, false, 'no live Nova authorization');
  const receipt = await account.callFunctionRaw({contractId:'sandbox', methodName:'verify_ipa', args:params, gas:teraToGas('300')});
  assert.equal(Boolean(receipt?.status?.Failure), false, 'valid proof transaction must succeed');
  const outcomes = receipt?.receipts_outcome ?? receipt?.receipts_outcomes ?? [];
  const receiptGasBurnt = outcomes.reduce((sum,r) => sum + BigInt(r?.outcome?.gas_burnt ?? r?.gas_burnt ?? 0), 0n);
  assert.ok(receiptGasBurnt > 0n, 'real transaction must return receipt gas');
  const report = {
    schema:'shz/near-transparent-ipa-sandbox/v1',
    network:'near-sandbox',
    relation:'shz/near-transparent-bn254-ipa/v1',
    sandboxRuntime:'near-sandbox@0.3.5',
    transparent:true,
    validProofAccepted:good,
    tamperedProofRejected:bad === false,
    canAuthorizeNova:canAuthorize,
    receiptGasBurnt:receiptGasBurnt.toString(),
    receiptGasTgas:Number(receiptGasBurnt)/1e12,
    sourceVerified:false,
    novaVerified:false,
    bitcoinEnforced:false,
    productionReady:false
  };
  console.log(JSON.stringify(report,null,2));
  if(process.env.SHZ_IPA_SANDBOX_RECEIPT){
    writeFileSync(process.env.SHZ_IPA_SANDBOX_RECEIPT, JSON.stringify(report,null,2)+'\n');
  }
} finally {
  await sandbox.tearDown();
}
