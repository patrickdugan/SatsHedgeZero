/** ADMIT-14: receiver-owned independent case registry. Freeze expected
 * statement before building or running the prover. All source reports are synthetic. */
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {generate} from '../admission_scale/fixtures/build.mjs';
import {makePlan} from '../admission_segments/plan.mjs';
import {buildTree} from './reference.mjs';
const here=dirname(fileURLToPath(import.meta.url)),out=process.argv[2];
if(!out)throw Error('usage: generalize_fixtures.mjs NEW_OUTPUT_DIR');
const registry=JSON.parse(readFileSync(resolve(here,'evidence/admit14-cases.json')));
const approved=JSON.parse(readFileSync(resolve(here,'evidence/admit08-frozen-pins.json')));
assert.deepEqual(registry.approved_image_id_words,approved.image_id_words);
const image=registry.approved_image_id_words;
const hash=b=>createHash('sha256').update(b).digest('hex');
mkdirSync(out,{recursive:false});
for(const source of ['pyth','chainlink']){
 const cases=registry.cases.filter(x=>x.source===source);
 const {claims}=generate([...new Set(cases.map(x=>x.reports))],source);
 for(const c of cases){
  const claim=claims.find(x=>Number(x.header.count)===c.reports);
  assert.ok(claim);assert.equal(claim.pin,c.snapshot_pin);assert.equal(claim.steps,c.folds);
  const plan=makePlan(claim,c.reports/c.leaves);
  assert.equal(plan.segments.length,c.leaves);assert.deepEqual(plan.segments.map(s=>s.folds),c.segment_folds);
  const tree=buildTree(plan,claim,image);
  assert.equal(tree.bytes.length,251);assert.equal(hash(tree.bytes),c.journal_sha256);
  const expected={...c,sdk:registry.sdk,image_id_words:image,journal_hex:tree.bytes.toString('hex'),synthetic:true};
  if(c.id==='pyth4-two')assert.equal(expected.journal_hex,approved.journal_hex);
  const dest=resolve(out,c.id);mkdirSync(dest);
  for(const [name,obj] of [['claim.json',claim],['plan.json',plan],['expected.json',expected]])writeFileSync(resolve(dest,name),JSON.stringify(obj,null,2)+'\n',{flag:'wx'});
 }
}
console.log(JSON.stringify({schema:registry.schema,cases:registry.cases,reference_verified:true,nova_verified:false,fresh_stark_verified:false,near_verified:false,production_ready:false}));
