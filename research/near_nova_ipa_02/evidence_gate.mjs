// Read-only verification of the archived MNR-03 receipt, actual Bitcoin TXID, and Nova proof bytes.
// The archive records native/Spartan verification performed elsewhere. This code does NOT
// cryptographically verify the Pallas/Vesta Nova proof; it prevents untrusted receipt substitution.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {FROZEN,FROZEN_ROOT,snapshotHash} from './ipa_state.mjs';
const hash=(b)=>createHash('sha256').update(b).digest();
const sha256hex=(b)=>hash(b).toString('hex');
const fail=(x)=>{throw Error(`MNR-03 archive mismatch: ${x}`)};
const eq=(a,b,label)=>{if(a!==b)fail(label)};
const checkedDigest=x=>{if(typeof x!=='string'||!/^[a-f0-9]{64}$/.test(x))fail('noncanonical digest');return x};
const json=(p)=>JSON.parse(readFileSync(p,'utf8').replace(/^\uFEFF/,''));
function varint(raw,p){if(p>=raw.length)fail('varint truncation');const h=raw[p];if(h<253)return{v:h,p:p+1};const size=h===253?2:h===254?4:8;if(p+1+size>raw.length)fail('varint overrun');let v=0n;for(let i=0;i<size;i++)v+=BigInt(raw[p+1+i])<<BigInt(8*i);if(v>1000000n)fail('varint too large');return{v:Number(v),p:p+size+1}}
function skip(raw,p,n){if(n<0||p+n>raw.length)fail('transaction truncated');return p+n}
export function txidFromSegwitHex(s){
 if(typeof s!=='string'||s.length>100000||s.length%2||!/^[a-f0-9]+$/.test(s))fail('transaction encoding');
 const raw=Buffer.from(s,'hex');if(raw.length<12)fail('transaction too small');
 let p=4;const wit=raw[p]===0&&raw[p+1]!==0;if(wit)p+=2;
 const base=[raw.subarray(0,4)];let k=varint(raw,p);const vinStart=p;p=k.p;
 if(k.v<1||k.v>100)fail('input count');const inputCount=k.v;
 for(let i=0;i<inputCount;i++){p=skip(raw,p,36);k=varint(raw,p);p=skip(raw,k.p,k.v);p=skip(raw,p,4)}
 base.push(raw.subarray(vinStart,p));const voutStart=p;k=varint(raw,p);p=k.p;
 if(k.v<1||k.v>100)fail('output count');const outputCount=k.v;
 for(let i=0;i<outputCount;i++){p=skip(raw,p,8);k=varint(raw,p);p=skip(raw,k.p,k.v)}
 base.push(raw.subarray(voutStart,p));
 if(wit){for(let i=0;i<inputCount;i++){k=varint(raw,p);p=k.p;if(k.v>100)fail('witness item count');const witnessItems=k.v;for(let j=0;j<witnessItems;j++){k=varint(raw,p);p=skip(raw,k.p,k.v)}}}
 const lock=raw.subarray(p,skip(raw,p,4));p+=4;if(p!==raw.length)fail('trailing tx bytes');base.push(lock);
 const tx=Buffer.concat(base);return Buffer.from(hash(hash(tx))).reverse().toString('hex');
}
export function checkReceipt(receipt,manifest,proofBytes,{checkActualTx=true}={}){
 const report=receipt?.oracle_bound_nova_report;
 if(!report)fail('missing oracle-bound report');const expected=report.nova_expected_statement;
 if(!expected)fail('missing Nova public state');
 const stmt=report.bitvm3_statement;
 if(!stmt)fail('missing Bitcoin assertion');
 const proofHash=sha256hex(proofBytes);
 const observed={
  epoch_id:report.journal.epoch,
  count:expected.final_state.count,
  collateral_sats:expected.final_state.total_collateral,
  payout_sats:expected.final_state.total_payout,
  fee_sats:expected.final_state.total_fee,
  oracle_receipt_hash_hex:checkedDigest(report.pyth_pro_epoch.receipt_hash_hex),
  bitcoin_assertion_txid_hex:checkedDigest(receipt.bob_offline_atomic_clearing_txid),
  nova_batch_txid_hex:checkedDigest(report.journal.batch_txid_hex),
  nova_journal_sha256_hex:checkedDigest(report.journal.journal_sha256_hex),
  nova_proof_sha256_hex:proofHash,
  nova_vk_sha256_hex:checkedDigest(report.external_nova_snark_receipt?.verifier_key_sha256_hex),
  init_poseidon_hex:checkedDigest(expected.initial_state.transcript_chain_digest_hex),
  final_poseidon_hex:checkedDigest(expected.final_state.transcript_chain_digest_hex),
 };
 for(const [k,v]of Object.entries(FROZEN))eq(observed[k],v,k);
 eq(snapshotHash(observed),FROZEN_ROOT,'snapshot state hash');
 eq(expected.relation_version,'lnmarkets/sha256-transcript-accounting/v2','Nova relation');
 eq(stmt.assertion_txid_hex,observed.bitcoin_assertion_txid_hex,'BitVM assertion txid');
 eq(expected.journal_sha256_hex,observed.nova_journal_sha256_hex,'Nova expected journal');
 eq(manifest.claim.journal_sha256,observed.nova_journal_sha256_hex,'manifest journal');
 eq(manifest.claim.relation,'lnmarkets/sha256-transcript-accounting/v2','manifest relation');
 eq(manifest.proof_sha256,proofHash,'manifest proof hash');
 eq(manifest.claim.verifier_key_sha256,observed.nova_vk_sha256_hex,'manifest verifier key');
 eq(expected.final_state.count,3,'expected count');
 eq(expected.final_state.total_collateral,expected.final_state.total_payout+expected.final_state.total_fee,'Nova conservation');
 eq(manifest.claim.steps,3,'manifest steps');
 eq(report.mnr03_clearing.atomic_clearing_txid_hex,observed.bitcoin_assertion_txid_hex,'real TXID');
 eq(report.mnr03_clearing.miner_fee_sats,610,'actual Bitcoin miner fee');
 if(checkActualTx){const txid=txidFromSegwitHex(report.mnr03_atomic_clearing_raw_segwit_tx_hex);eq(txid,observed.bitcoin_assertion_txid_hex,'raw Bitcoin TXID reconstruction')}
 if(observed.nova_batch_txid_hex===observed.bitcoin_assertion_txid_hex)fail('legacy journal TXID unexpectedly identical; check fixture migration');
 return {
  schema:'shz/ipa02-mnr03-archive-gate/v1',snapshot_root_hex:FROZEN_ROOT,
  originalNovaProofSha256:proofHash,archiveHashPinned:true,rawBitcoinTxidVerified:checkActualTx,
  journalTxidDiffersFromActualBitcoinTxid:true,bitcoinMinerFeeSats:610,novaJournalFeeSats:450,
  transparentIpaProvedNovaValidity:false,fullNovaCircuitVerifiedOnNear:false,
  sourceAuthenticated:false,settlementAuthorized:false,productionReady:false
 };
}
const script=fileURLToPath(import.meta.url);
if(process.argv[1]===script){
 const root=resolve(dirname(script),'../../');
 const receipt=json(process.argv[2]||resolve(root,'evidence/mnr03_testnet4_bob_offline_receipt.json'));
 const manifest=json(process.argv[3]||resolve(root,'evidence/mnr03_testnet4_nova_bundle/manifest.json'));
 const proof=readFileSync(process.argv[4]||resolve(root,'evidence/mnr03_testnet4_nova_bundle/proof.bin'));
 console.log(JSON.stringify(checkReceipt(receipt,manifest,proof),null,2));
}
