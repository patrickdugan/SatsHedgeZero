import {writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,resolve} from 'node:path';
import {generators,pb,prove,verify,FROZEN_ROOT} from '../ipa_state.mjs';
const dir=dirname(fileURLToPath(import.meta.url));
for (const n of [8,16,32]) {const f=prove(n);if(!verify(f))throw Error(`IPA-${n} self-test failed`);writeFileSync(resolve(dir,`mnr03-${n}.json`),JSON.stringify(f,null,2)+'\n');}
const g=generators(32);
const text=`// Generated from transparent SHA256 hash-to-curve generator rule.\n// 32 G, 32 H and one U points; every string is x||y little-endian BN254.\n// The first four match SHZ-IPA-01 exactly. No trusted setup.\npub const G_HEX: [&str;32] = [\n${g.g.map(p=>'"'+pb(p).toString('hex')+'"').join(',\n')}\n];\npub const H_HEX: [&str;32] = [\n${g.h.map(p=>'"'+pb(p).toString('hex')+'"').join(',\n')}\n];\npub const U_HEX: &str = "${pb(g.u).toString('hex')}";\npub const FROZEN_ROOT_HEX: &str = "${FROZEN_ROOT}";\n`;
writeFileSync(resolve(dir,'../near_contract/src/generators.rs'),text);
console.log(JSON.stringify({generated:[8,16,32],frozenRoot:FROZEN_ROOT,generators:65}));
