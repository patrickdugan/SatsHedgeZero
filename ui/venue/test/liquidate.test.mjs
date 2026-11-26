import test from 'node:test';
import assert from 'node:assert/strict';
import { planTakes, describe } from '../liquidate.js';

const risk = (over = {}) => ({
  state: 'maintenance', reduce_only: true, margin_bps: 480, notional_usd: 40,
  params: { maintenance_bps: 500 },
  liquidation: { reduce_side: 'short', tranche_usd: 12, limit_usd: 94_000, auction_discount_bps: 50 },
  ...over,
});
const book = { bids: [[94_500, 10, 2], [94_100, 10, 2], [93_900, 50, 1]], asks: [[95_000, 10, 2]] };

test('a long sells the tranche into bids at or above the auction limit, one quote per take', () => {
  assert.deepEqual(planTakes(risk(), book), [
    { side: 'short', quantity: 5, limit_usd: 94_500 },
    { side: 'short', quantity: 5, limit_usd: 94_500 },
    { side: 'short', quantity: 2, limit_usd: 94_100 },
  ]);
});

test('bids below the limit are never hit', () => {
  const r = risk({ liquidation: { reduce_side: 'short', tranche_usd: 40, limit_usd: 94_000 } });
  const takes = planTakes(r, book);
  assert.equal(takes.reduce((s, t) => s + t.quantity, 0), 20);
  assert.ok(takes.every((t) => t.limit_usd >= 94_000));
});

test('a short buys asks at or below the limit', () => {
  const r = risk({ liquidation: { reduce_side: 'long', tranche_usd: 7, limit_usd: 95_100 } });
  assert.deepEqual(planTakes(r, book), [{ side: 'long', quantity: 5, limit_usd: 95_000 }, { side: 'long', quantity: 2, limit_usd: 95_000 }]);
});

test('healthy accounts and empty books produce nothing; takes are capped', () => {
  assert.deepEqual(planTakes({ state: 'ok', reduce_only: false }, book), []);
  assert.deepEqual(planTakes(risk(), { bids: [], asks: [] }), []);
  assert.equal(planTakes(risk({ liquidation: { reduce_side: 'short', tranche_usd: 1000, limit_usd: 1 } }), { bids: [[90_000, 100, 100]] }, 3).length, 3);
});

test('never closes more than the position', () => {
  const r = risk({ notional_usd: 6, liquidation: { reduce_side: 'short', tranche_usd: 50, limit_usd: 1 } });
  assert.equal(planTakes(r, book).reduce((s, t) => s + t.quantity, 0), 6);
});

test('banner text by state', () => {
  assert.equal(describe({ state: 'ok' }), null);
  assert.equal(describe(risk()).level, 'danger');
  assert.match(describe(risk()).text, /only position-reducing/);
  assert.equal(describe({ state: 'warning', margin_bps: 700, params: { maintenance_bps: 500 }, liquidation_price_usd: 95_000 }).level, 'warn');
});
