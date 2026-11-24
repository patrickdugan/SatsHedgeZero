import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {FROZEN,FROZEN_ROOT,snapshotHash,generators,prove,verify,fromHex} from '../ipa_state.mjs';
const here=dirname(fileURLToPath(import.meta.url));
const fx=n=>JSON.parse(readFileSync(resolve(here,`../fixtures/mnr03-${n}.json`),'utf8'));
const mutate=(n,fn)=>{const f=fx(n);fn(f);return verify(f)};
for(const n of [8,16,32]){
  test(`genuine ${n}-dim transparent IPA checks pinned MNR-03 public tuple`,()=>assert.equal(verify(fx(n)),true));
  test(`${n}-dim deterministic prover reproducible`,()=>assert.deepEqual(prove(n),fx(n)));
  test(`${n}-dim rejects altered final scalar`,()=>assert.equal(mutate(n,x=>x.proof.a_final_hex='00'.repeat(32)),false));
  test(`${n}-dim rejects corrupted L point`,()=>assert.equal(mutate(n,x=>x.proof.l_hex[0]='ff'.repeat(64)),false));
  test(`${n}-dim rejects altered proof R point`,()=>assert.equal(mutate(n,x=>x.proof.r_hex[0]=x.proof.l_hex[0]),false));
  test(`${n}-dim rejects truncated proof`,()=>assert.equal(mutate(n,x=>x.proof.r_hex.pop()),false));
  test(`${n}-dim rejects 1-sat escrow fraud`,()=>assert.equal(mutate(n,x=>x.statement.collateral_sats+=1),false));
  test(`${n}-dim rejects forged public Nova journal commitment`,()=>assert.equal(mutate(n,x=>x.statement.nova_journal_sha256_hex='aa'.repeat(32)),false));
  test(`${n}-dim rejects substitution of actual Bitcoin settlement TXID`,()=>assert.equal(mutate(n,x=>x.statement.bitcoin_assertion_txid_hex=FROZEN.nova_batch_txid_hex),false));
  test(`${n}-dim rejects wrong oracle epoch`,()=>assert.equal(mutate(n,x=>x.statement.epoch_id+=1),false));
  test(`${n}-dim rejects modified proof hash`,()=>assert.equal(mutate(n,x=>x.statement.nova_proof_sha256_hex='bb'.repeat(32)),false));
  test(`${n}-dim rejects incorrect generator dimension`,()=>assert.equal(mutate(n,x=>x.statement.dimension=4),false));
}
test('frozen snapshot commits all public pins, not just total collateral',()=>{
 assert.equal(FROZEN_ROOT,snapshotHash(FROZEN));
 assert.notEqual(FROZEN_ROOT,snapshotHash({...FROZEN,final_poseidon_hex:'00'.repeat(32)}));
 assert.notEqual(FROZEN_ROOT,snapshotHash({...FROZEN,nova_batch_txid_hex:FROZEN.bitcoin_assertion_txid_hex}));
});
test('frozen accounting conserves independently of native Bitcoin transaction fee',()=>{
 assert.equal(FROZEN.collateral_sats,FROZEN.payout_sats+FROZEN.fee_sats);
 assert.notEqual(FROZEN.bitcoin_assertion_txid_hex,FROZEN.nova_batch_txid_hex);
 assert.equal(FROZEN.fee_sats,450);
});
test('generators have no repeated G/H/U points at dimension 32',()=>{
 const g=generators(32);const unique=[...g.g,...g.h,g.u].map(p=>`${p.x}/${p.y}`);
 assert.equal(new Set(unique).size,65);
});
test('proof L and R points decode canonically for all dimensions',()=>{
 for(const n of [8,16,32])for(const p of [...fx(n).proof.l_hex,...fx(n).proof.r_hex])assert.doesNotThrow(()=>fromHex(p));
});
