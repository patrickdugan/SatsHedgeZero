import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex, unhex, bip340Verify, intentV7Id, transferDigest, signIntentV7, sha256, pubkey } from '../crypto.js';
import { buildChain, presetLegs, takeLimits, milliFromHuman, perContractBase, human, worstCaseUpper } from '../options.js';

const V = JSON.parse(readFileSync(new URL('./options_vector.json', import.meta.url), 'utf8'));
const template = { scope: V.scope, router: V.router };

test('IntentV7 ids match the shared Rust vector (shz_dex IntentV7::id)', async () => {
  for (const c of V.intents) {
    const id = await intentV7Id(c.intent, template);
    assert.equal(hex(id), c.id, c.name);
    assert.ok(await bip340Verify(id, unhex(c.intent.owner), unhex(c.intent.signature)), c.name + ': signature');
  }
});

test('option transfer digests match the shared Rust vector (shz-venue transfer_digest)', async () => {
  for (const t of V.transfers) assert.equal(hex(await transferDigest(t.op, t.owner, t.asset, t.amount, t.expires_us)), t.digest, t.op);
});

test('signIntentV7 drops empty other_limits and re-signs to the same id', async () => {
  const sk = await sha256(new TextEncoder().encode('shz-options-vector/owner/v1'));
  const c = V.intents[0];
  const { signature, ...unsigned } = c.intent;
  const { id, intent } = await signIntentV7({ ...unsigned, other_limits: [] }, template, sk);
  assert.equal(id, c.id);
  assert.equal(intent.other_limits, undefined);
  assert.equal(intent.owner, hex(pubkey(sk)));
});

test('IntentV7 encoder rejects out-of-range premiums and bad assets', async () => {
  const base = { ...V.intents[1].intent };
  await assert.rejects(intentV7Id({ ...base, premium_milli: 2n ** 63n }, template), /out of range/);
  await assert.rejects(intentV7Id({ ...base, other_limits: [{ asset: { kind: 'gold' }, premium_milli: 1 }] }, template), /bad asset/);
});

// ---------------------------------------------------------------- chain, presets, limits
const btc = { kind: 'btc', code: 'BTC' };
const usdt = { kind: 'stable', protocol: 'rgb', id: 'ab'.repeat(32), decimals: 6, code: 'USDT' };
const mk = (kind, asset, k, o = {}) => ({ id: `${kind}-${asset.code}-${k}`, kind, asset, asset_code: asset.code, strike_usd: k, event_id: 'E1', maturity_unix: 1_800_000_000,
  contract_qty: asset.kind === 'btc' ? 100 : 1_000_000, bid: null, ask: null, worst_case_per_contract: { short: asset.kind === 'btc' ? (kind === 'call' ? 90_000 : 9_999_000_000) : k * 10_000 - 10_000, long: 0 }, settled_price_usd: null, ...o });
const strikes = [98_000, 99_000, 100_000, 101_000, 102_000];
const series = strikes.flatMap((k) => [mk('call', btc, k), mk('put', btc, k), mk('put', usdt, k)]);
series.find((s) => s.id === 'call-BTC-100000').ask = { premium_milli: 3000, qty: 100 };
series.find((s) => s.id === 'call-BTC-101000').bid = { premium_milli: 1000, qty: 100 };
series.find((s) => s.id === 'call-BTC-101000').ask = { premium_milli: 1200, qty: 50 };
series.find((s) => s.id === 'put-USDT-99000').ask = { premium_milli: 15_000, qty: 1_000_000 };
const view = { mark_usd: 100_200, events: [{ event_id: 'E1', maturity_unix: 1_800_000_000, status: 'announced' }], series };
const byId = new Map(series.map((s) => [s.id, s]));

test('buildChain lays out one expiry as a strike ladder with calls and puts per asset', () => {
  const c = buildChain(view);
  assert.equal(c.events.length, 1);
  assert.deepEqual(c.events[0].rows.map((r) => r.strike), strikes);
  assert.deepEqual(c.putAssets, ['BTC', 'USDT']);
  const r = c.events[0].rows[2];
  assert.equal(r.call.id, 'call-BTC-100000');
  assert.equal(r.puts.USDT.id, 'put-USDT-100000');
  assert.equal(r.puts.BTC.id, 'put-BTC-100000');
});

test('presets: call spread, collar (USDT put below, BTC call above), covered call', () => {
  const ev = buildChain(view).events[0];
  assert.deepEqual(presetLegs('spread', ev, 100_200, 2), [{ series: 'call-BTC-100000', long: true, qty: 200 }, { series: 'call-BTC-101000', long: false, qty: 200 }]);
  assert.deepEqual(presetLegs('spread', ev, 100_200, 1, byId.get('call-BTC-98000'))[1], { series: 'call-BTC-99000', long: false, qty: 100 });
  assert.deepEqual(presetLegs('collar', ev, 100_200, 1), [{ series: 'put-USDT-99000', long: true, qty: 1_000_000 }, { series: 'call-BTC-101000', long: false, qty: 100 }]);
  assert.deepEqual(presetLegs('covered', ev, 100_200, 3), [{ series: 'call-BTC-101000', long: false, qty: 300 }]);
  assert.throws(() => presetLegs('spread', ev, 100_200, 1, byId.get('call-BTC-102000')), /strike above/);
});

test('takeLimits: first leg asset in premium_milli, the other asset once in other_limits, with slippage room', () => {
  const ev = buildChain(view).events[0];
  const legs = presetLegs('collar', ev, 100_200, 1);
  const l = takeLimits(legs, byId, 500);
  // pays 15 USDT (15e6 base, 15e9 milli) for the put; receives 100 sats for the call (-100,000 milli)
  assert.equal(l.nets.USDT, 15_000_000);
  assert.equal(l.nets.BTC, -100);
  assert.equal(l.premium_milli, 15_000_000_000 + 750_000_000);
  assert.deepEqual(l.other_limits, [{ asset: { kind: 'btc' }, premium_milli: -100_000 + 5_000 }]);
  assert.deepEqual(l.missing, []);
  assert.equal(l.thin, false);
  const big = takeLimits([{ series: 'call-BTC-101000', long: true, qty: 100 }], byId);
  assert.equal(big.thin, true); // best ask has 50 of the 100 asked
  assert.deepEqual(takeLimits([{ series: 'call-BTC-99000', long: true, qty: 100 }], byId).missing, ['call-BTC-99000']);
});

test('premium units: per-contract sats for BTC series, USDT for stable series, round trip', () => {
  const c = byId.get('call-BTC-100000'), p = byId.get('put-USDT-99000');
  assert.equal(perContractBase(c, 3000), 300); // 300 sats per 100 USD
  assert.equal(milliFromHuman(c, 300), 3000);
  assert.equal(human(p, perContractBase(p, 15_000)), 15); // 15 USDT per 0.01 BTC
  assert.equal(milliFromHuman(p, 15), 15_000);
  assert.throws(() => milliFromHuman(c, 0), /positive/);
  assert.deepEqual(worstCaseUpper([{ series: 'call-BTC-101000', long: false, qty: 200 }, { series: 'put-USDT-99000', long: true, qty: 1_000_000 }], byId), { BTC: 180_000 });
});
