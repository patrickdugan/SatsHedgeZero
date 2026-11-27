import {readFileSync} from "node:fs";
import {normalizeRecovery} from "./recovery.mjs";
const {entries}=JSON.parse(readFileSync(new URL("./recovery_receipt.json",import.meta.url),"utf8"));
for(const {input,expected} of entries)if(JSON.stringify(normalizeRecovery(input))!==JSON.stringify(expected))throw Error("archival receipt projection mismatch");
let rejected=0;
for(const mutate of [r=>r.passed=false,r=>r.checks.released_outputs_reused=false,r=>r.timings_s.lp_advance_to_reimbursement_confirmed=-1,r=>r.reuse.lp="",r=>r.cet.lp_sat=0,r=>r.heights.attestation=1]){
 const r=JSON.parse(JSON.stringify(entries[0].input));mutate(r);try{normalizeRecovery(r);}catch{rejected++;}
}
if(rejected!==6)throw Error("fail-closed receipt checks");
console.log(JSON.stringify({archival_receipts:entries.length,invalid_rejected:rejected,release_authorized:false}));
