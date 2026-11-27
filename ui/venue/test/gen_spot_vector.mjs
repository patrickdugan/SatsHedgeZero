// Writes spot_vector.json: SpotIntent ids and signatures from the JS encoder and signer, which
// the Rust test (crates/shz-venue/src/core/spot.rs) and spot.test.mjs check.
// Run: node ui/venue/test/gen_spot_vector.mjs
import { writeFileSync, readFileSync } from 'node:fs';
import { hex, pubkey, sha256, signSpotIntent } from '../crypto.js';

const O = JSON.parse(readFileSync(new URL('./options_vector.json', import.meta.url), 'utf8'));
const template = { scope: O.scope, router: O.router };
const sk = await sha256(new TextEncoder().encode('shz-spot-vector/owner/v1'));
const owner = hex(pubkey(sk));
const channel = { txid: '97145b7b36d33006ba687dabc9e44f1f381690a6607845be1e54703fde9ba0b1', vout: 3 };
const pair = 'c4f1a6b0d2e38957a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718';
const base = { owner, channel, pair, expires_us: 1800000000000000 };
const cases = [
  ['post: sell 0.01 BTC at 90,000.0 USDT', { ...base, sequence: 1764000000000001, action: 'post', buy: false, qty_sats: 1000000, price: 90000000000 }],
  ['take: buy 0.004 BTC up to 90,050.5 USDT', { ...base, sequence: 1764000000000002, action: 'take', buy: true, qty_sats: 400000, price: 90050500000 }],
  ['cancel a resting order', { ...base, sequence: 1764000000000003, action: 'cancel', cancel_target: '2e6e314e196f35cfc9e7bdd2d5489268f222f147ab0b4ee26f44477789989095' }],
];
const intents = [];
for (const [name, i] of cases) {
  const { id, intent } = await signSpotIntent(i, template, sk);
  intents.push({ name, intent, id });
}
const out = { note: 'Shared Rust/JS vector: SpotIntent ids (shz_dex SpotIntent::id, tag SHZ/HFT06/SPOT-INTENT/V8). Test key: sha256("shz-spot-vector/owner/v1").',
  scope: O.scope, router: O.router, intents };
writeFileSync(new URL('./spot_vector.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(intents.map((x) => x.id).join('\n'));
