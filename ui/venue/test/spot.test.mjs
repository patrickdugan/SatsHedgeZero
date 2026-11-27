import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex, unhex, bip340Verify, spotIntentId, signSpotIntent, sha256, pubkey } from '../crypto.js';
import { priceToBase, baseToPrice, satsFromBtc, quoteUnits, walk, marketLimit, depthRows } from '../spot.js';

const V = JSON.parse(readFileSync(new URL('./spot_vector.json', import.meta.url), 'utf8'));
const template = { scope: V.scope, router: V.router };
const pair = { pair: 'c4'.repeat(32), lot_sats: 1000, tick: 100000, quote: { decimals: 6, code: 'USDT' } };

test('SpotIntent ids match the shared Rust vector (shz_dex SpotIntent::id)', async () => {
  for (const c of V.intents) {
    const id = await spotIntentId(c.intent, template);
    assert.equal(hex(id), c.id, c.name);
    assert.ok(await bip340Verify(id, unhex(c.intent.owner), unhex(c.intent.signature)), c.name + ': signature');
  }
});

test('signSpotIntent fills defaults and re-signs to the same id', async () => {
  const sk = await sha256(new TextEncoder().encode('shz-spot-vector/owner/v1'));
  const c = V.intents[2];
  const { signature, version, qty_sats, price, buy, ...unsigned } = c.intent;
  const { id, intent } = await signSpotIntent(unsigned, template, sk);
  assert.equal(id, c.id);
  assert.equal(intent.owner, hex(pubkey(sk)));
  assert.deepEqual([intent.version, intent.qty_sats, intent.price, intent.buy], [8, 0, 0, false]);
  await assert.rejects(spotIntentId({ ...c.intent, action: 'swap' }, template), /bad action/);
});

test('prices round to the tick and sizes down to the lot; fills are exact', () => {
  assert.equal(priceToBase('90000', pair), 90_000_000_000);
  assert.equal(priceToBase(90000.04, pair), 90_000_000_000);
  assert.equal(priceToBase(90000.06, pair), 90_000_100_000);
  assert.equal(baseToPrice(90_050_500_000, pair), 90050.5);
  assert.throws(() => priceToBase(0, pair), /positive/);
  assert.equal(satsFromBtc('0.0012345', pair), 123_000);
  assert.throws(() => satsFromBtc('0.0000009', pair), /at least/);
  assert.equal(quoteUnits(400_000, 90_000_000_000), 360_000_000);
  // lot x tick is a multiple of 1e8: every on-lot, on-tick fill is an integer
  for (const [q, p] of [[1000, 100000], [7000, 90_000_300_000], [123_000, 61_234_500_000]]) assert.equal((BigInt(q) * BigInt(p)) % 100_000_000n, 0n);
});

test('walk and marketLimit price an IOC take against the book', () => {
  const asks = [[90_000_000_000, 600_000, 1], [90_100_000_000, 500_000, 1]];
  assert.deepEqual(walk(asks, 1_000_000, true, 90_100_000_000), { sats: 1_000_000, quote: 540_000_000 + 360_400_000, avg: 90_040_000_000, levels: 2 });
  assert.equal(walk(asks, 1_000_000, true, 90_050_000_000).sats, 600_000, 'the limit stops the walk');
  const bids = [[89_000_000_000, 300_000, 2]];
  assert.equal(walk(bids, 500_000, false, 88_000_000_000).sats, 300_000, 'IOC fills what crosses');
  assert.equal(marketLimit(asks, true, pair), 90_450_000_000);
  assert.equal(marketLimit(bids, false, pair), 88_555_000_000);
  assert.equal(marketLimit([], true, pair), null);
  assert.deepEqual(depthRows(asks).map((r) => r[3]), [600_000, 1_100_000]);
});
