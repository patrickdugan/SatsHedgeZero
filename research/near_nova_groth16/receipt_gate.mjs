/** SHZ-NOVA-G16-01: evidence inventory and forced honest gates. NOT a ZK verifier. */
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
export const NOVA_RELATION='lnmarkets/sha256-transcript-accounting/v2';
export const G16_PRICE_RELATION='shz/dual-price-groth16-arithmetic/v1';
export const NOVA_VK_PIN='4eafbd223936cc3c1e9b16e750f1946a57cd5413f86578f6f1d37d9abb53e38b';
const h=v=>createHash('sha256').update(v).digest('hex');
const is32=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
function must(ok,error){if(!ok)throw new Error(error)}

export function inspectMnr03Receipt(receipt){
 const r=receipt?.oracle_bound_nova_report;
 must(r&&receipt?.bob_online_during_clearing_or_proving===false,'missing Bob-offline evidence');
 must(receipt?.production_ready===false,'unexpected production flag');
 must(receipt?.bitvm3_onchain_verified===false,'unexpected on-chain verification');
 const nativeTx=receipt.bob_offline_atomic_clearing_txid;
 const assertedTx=r?.bitvm3_statement?.assertion_txid_hex;
 const journalTx=r?.journal?.batch_txid_hex;
 must(is32(nativeTx)&&is32(assertedTx)&&is32(journalTx),'missing transaction hashes');
 must(nativeTx===assertedTx,'Bitcoin txid missing from BitVM3 assertion');
 must(r?.nova_expected_statement?.relation_version===NOVA_RELATION,'unexpected Nova relation');
 must(r?.external_nova_snark_receipt?.verifier_key_sha256_hex===NOVA_VK_PIN,'wrong Nova verifier key');
 const sess=r.pyth_pro_epoch?.session_hash_hex;
 must(is32(sess),'missing oracle session hash');
 const statement={relation:'shz/nova-groth16-decider/v1',bitcoin_txid:nativeTx,nova_journal_txid:journalTx,
   oracle_session_hash:sess,nova_proof_sha256:r.external_nova_snark_receipt.proof_sha256_hex,
   nova_vk_sha256:NOVA_VK_PIN,bitvm3_assertion_txid:assertedTx};
 return Object.freeze({statement,statementSha256:h(Buffer.from(JSON.stringify(statement))),
   bitcoinAndJournalSameTx:nativeTx===journalTx,
   nativeNovaReceiptClaimsVerified:r.external_nova_snark_receipt.nova_compressed_verified===true,
   novaVerifiedInsideGroth16Circuit:false,groth16NovaDeciderProofPresent:false,
   nearPairingVerified:false,bitcoinSpendEnforcedByGroth16:false,productionReady:false,
   gate:'BLOCKED_FULL_NOVA_WRAP'});
}
if(process.argv[1]?.endsWith('receipt_gate.mjs')){
 const p=process.argv[2];if(!p){console.error('usage: node receipt_gate.mjs evidence/mnr03_testnet4_bob_offline_receipt.json');process.exit(2)}
 const receipt=JSON.parse(readFileSync(p,'utf8').replace(/^\uFEFF/,''));console.log(JSON.stringify(inspectMnr03Receipt(receipt),null,2));
}
