import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectMnr03Receipt,NOVA_VK_PIN,NOVA_RELATION} from '../receipt_gate.mjs';
const a='ab'.repeat(32),b='cd'.repeat(32),c='ef'.repeat(32);
const fixture=()=>({bob_online_during_clearing_or_proving:false,production_ready:false,bitvm3_onchain_verified:false,
  bob_offline_atomic_clearing_txid:a,oracle_bound_nova_report:{bitvm3_statement:{assertion_txid_hex:a},journal:{batch_txid_hex:b},
  nova_expected_statement:{relation_version:NOVA_RELATION},pyth_pro_epoch:{session_hash_hex:c},
  external_nova_snark_receipt:{verifier_key_sha256_hex:NOVA_VK_PIN,proof_sha256_hex:b,nova_compressed_verified:true}}});
test('native Nova receipt stays explicitly unwrapped',()=>{
 const r=inspectMnr03Receipt(fixture());assert.equal(r.bitcoinAndJournalSameTx,false);
 assert.equal(r.nativeNovaReceiptClaimsVerified,true);assert.equal(r.novaVerifiedInsideGroth16Circuit,false);
 assert.equal(r.productionReady,false);assert.equal(r.gate,'BLOCKED_FULL_NOVA_WRAP');
});
test('reject altered verifier key',()=>{
 const r=fixture();r.oracle_bound_nova_report.external_nova_snark_receipt.verifier_key_sha256_hex=a;
 assert.throws(()=>inspectMnr03Receipt(r),/wrong Nova verifier key/);
});
test('reject changed actual Bitcoin clearing TXID',()=>{
 const r=fixture();r.oracle_bound_nova_report.bitvm3_statement.assertion_txid_hex=b;
 assert.throws(()=>inspectMnr03Receipt(r),/Bitcoin txid missing/);
});
test('reject purported onchain Nova verification',()=>{
 const r=fixture();r.bitvm3_onchain_verified=true;
 assert.throws(()=>inspectMnr03Receipt(r),/unexpected on-chain/);
});
test('reject unsafely promoted production claim',()=>{
 const r=fixture();r.production_ready=true;
 assert.throws(()=>inspectMnr03Receipt(r),/unexpected production/);
});
