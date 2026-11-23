'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { inverseLongPnlSats, buildMatchedCloseout, obligationsForOutcome, netObligations, routePayouts } = require('../src');

const original = Object.freeze({
  id: 'dlc:alice-bob', long: 'Alice', short: 'Bob', notionalUsd: '50000',
  entryPriceUsd: '50000', oracleEventId: 'BTCUSD:epoch7',
  nettingSetId: 'BTC:SHZ:inverse', maturityHeight: '1000'
});
const quote = Object.freeze({
  id: 'quote:carol-01', closePriceUsd: '55000', notionalUsd: '50000',
  oracleEventId: 'BTCUSD:epoch7', nettingSetId: 'BTC:SHZ:inverse', expiryHeight: '920'
});
const prices = ['45000', '50000', '55000', '60000', '70000'];
function close(extra = {}) { return buildMatchedCloseout({ original, closingParty: 'Alice', liquidityProvider: 'Carol', quote, outcomePricesUsd: prices, currentHeight: 900, ...extra }); }
function source(owner, available, extra = {}) {
  return { id: `vault:${owner.toLowerCase()}`, owner, nettingSetId: original.nettingSetId,
    fundingSats: String(BigInt(available) + 1_000_000n), retainedSats: '500000',
    protectedSats: '400000', feeSats: '100000', ...extra };
}
function routes(from, to, cap) { return { fromVaultId: `vault:${from.toLowerCase()}`, toAccountId: to, nettingSetId: original.nettingSetId, capacitySats: String(cap) }; }

test('inverse BTC formula telescopes as exact rationals and is bounded to 1 sat after bilateral truncation', () => {
  assert.equal(inverseLongPnlSats('50000','50000','60000'), 16666666n);
  const plan = close();
  assert.equal(plan.offsetContract.short, 'Alice');
  assert.equal(plan.offsetContract.long, 'Carol');
  assert.equal(plan.markPnlSats, '9090909');
  for (const row of plan.payoffGrid) {
    assert.ok(BigInt(row.roundingResidualSats) >= -1n && BigInt(row.roundingResidualSats) <= 1n);
    assert.ok(BigInt(row.combinedPnlSats) - BigInt(row.markPnlSats) === BigInt(row.roundingResidualSats));
  }
  assert.equal(plan.execution.originalCollateralReleased, false);
  assert.equal(plan.execution.productionReady, false);
});

test('opposite direction: existing short closes with new long against unrelated liquidity provider', () => {
  const plan = close({ closingParty: 'Bob' });
  assert.equal(plan.offsetContract.long, 'Bob');
  assert.equal(plan.offsetContract.short, 'Carol');
  assert.equal(plan.markPnlSats, '-9090909');
  assert.ok(plan.payoffGrid.every(row => BigInt(row.roundingResidualSats) >= -1n && BigInt(row.roundingResidualSats) <= 1n));
});

test('positive-outcome routing: Bob pays net realized profit to Alice and residual to Carol', () => {
  const plan = close();
  const obligations = obligationsForOutcome(plan, '60000');
  assert.deepEqual(obligations.map(o => `${o.from}->${o.to}`), ['Bob->Alice', 'Alice->Carol']);
  const netting = netObligations(obligations, original.nettingSetId);
  assert.equal(netting.balancesSats.Alice, '9090909');
  assert.equal(netting.balancesSats.Carol, '7575757');
  assert.equal(netting.balancesSats.Bob, '-16666666');
  const result = routePayouts({ netting, vaults: [source('Bob', '16666666')],
    routes: [routes('Bob', 'Alice', 10_000_000), routes('Bob', 'Carol', 10_000_000)] });
  assert.equal(result.status, 'CAPACITY_FEASIBLE_PROPOSAL');
  assert.equal(result.routedSats, '16666666');
  assert.equal(result.shortfallSats, '0');
  assert.equal(result.routeConsentVerified, false);
  assert.equal(result.bitcoinSpendEnforced, false);
  assert.deepEqual(result.allocations, [
    { fromVaultId:'vault:bob', toAccountId:'Alice', amountSats:'9090909' },
    { fromVaultId:'vault:bob', toAccountId:'Carol', amountSats:'7575757' }
  ]);
});

test('negative-outcome routing: Carol pays Alice and Bob, retaining original DLC counterparties', () => {
  const plan = close();
  const netting = netObligations(obligationsForOutcome(plan, '45000'), original.nettingSetId);
  assert.ok(BigInt(netting.balancesSats.Carol) < 0n);
  assert.ok(BigInt(netting.balancesSats.Bob) > 0n);
  const owed = -BigInt(netting.balancesSats.Carol);
  const result = routePayouts({ netting, vaults: [source('Carol', owed)], routes: [routes('Carol', 'Alice', owed), routes('Carol', 'Bob', owed)] });
  assert.equal(result.status, 'CAPACITY_FEASIBLE_PROPOSAL');
  assert.equal(result.routedSats, owed.toString());
});

test('missing alternate-counterparty funding edge produces exact shortfall', () => {
  const plan = close();
  const netting = netObligations(obligationsForOutcome(plan, '60000'), original.nettingSetId);
  const result = routePayouts({netting, vaults:[source('Bob','16666666')], routes:[routes('Bob','Alice',10_000_000)]});
  assert.equal(result.status, 'UNFUNDED_PROPOSAL');
  assert.equal(result.routedSats, '9090909');
  assert.deepEqual(result.unfunded, [{accountId:'Carol', shortfallSats:'7575757'}]);
});

test('insufficient unencumbered collateral creates a capacity cut', () => {
  const netting = netObligations(obligationsForOutcome(close(), '60000'), original.nettingSetId);
  const result = routePayouts({netting, vaults:[source('Bob','12000000')], routes:[routes('Bob','Alice','16666666'), routes('Bob','Carol','16666666')]});
  assert.equal(result.status, 'UNFUNDED_PROPOSAL');
  assert.equal(result.routedSats, '12000000');
  assert.equal(result.shortfallSats, '4666666');
});

test('deterministic routing independent of route or obligation input order', () => {
  const obligations = obligationsForOutcome(close(), '60000');
  const a = netObligations(obligations, original.nettingSetId);
  const b = netObligations([...obligations].reverse(), original.nettingSetId);
  assert.deepEqual(a.balancesSats, b.balancesSats);
  assert.deepEqual(a.netEdges, b.netEdges);
  const rr = [routes('Bob','Carol',10_000_000), routes('Bob','Alice',10_000_000)];
  const r1 = routePayouts({netting:a, vaults:[source('Bob','16666666')], routes:rr});
  const r2 = routePayouts({netting:a, vaults:[source('Bob','16666666')], routes:[...rr].reverse()});
  assert.equal(r1.routeDigest, r2.routeDigest);
});

test('settlement zero-outcome leaves original and offset nominally live with no net routing requirement', () => {
  const noLeg = [{id:'x',from:'A',to:'B',amountSats:'100',nettingSetId:original.nettingSetId}, {id:'y',from:'B',to:'A',amountSats:'100',nettingSetId:original.nettingSetId}];
  const n = netObligations(noLeg, original.nettingSetId);
  assert.equal(n.netRequiredSats, '0');
  const r = routePayouts({netting:n,vaults:[],routes:[]});
  assert.equal(r.status, 'CAPACITY_FEASIBLE_PROPOSAL');
  assert.equal(r.routedSats, '0');
  assert.equal(r.bitcoinSpendEnforced, false);
});

test('rejects mismatched events, expiries, partial matching, and reused counterparties', () => {
  assert.throws(() => close({quote: {...quote, oracleEventId:'OTHER'}}), /oracle event mismatch/);
  assert.throws(() => close({quote: {...quote, nettingSetId:'WRONG'}}), /netting domain mismatch/);
  assert.throws(() => close({quote: {...quote, expiryHeight:'890'}}), /expired/);
  assert.throws(() => close({quote: {...quote, notionalUsd:'49999'}}), /partial close/);
  assert.throws(() => close({liquidityProvider:'Bob'}), /distinct third party/);
  assert.throws(() => close({outcomePricesUsd:['60000','50000']}), /ascending/);
  assert.throws(() => obligationsForOutcome(close(),'52000'), /outside/);
});

test('rejects unauthorized domain crossover, replayed obligation ID, duplicate route and unrelated payout', () => {
  const n = netObligations(obligationsForOutcome(close(), '60000'), original.nettingSetId);
  assert.throws(() => netObligations([{id:'x',from:'A',to:'B',amountSats:1,nettingSetId:'other'}], original.nettingSetId), /cross-netting/);
  assert.throws(() => netObligations([{id:'x',from:'A',to:'B',amountSats:1,nettingSetId:original.nettingSetId}, {id:'x',from:'B',to:'A',amountSats:1,nettingSetId:original.nettingSetId}], original.nettingSetId), /duplicate obligation/);
  assert.throws(() => routePayouts({netting:n,vaults:[source('Bob','16666666')],routes:[routes('Bob','Carol',10),routes('Bob','Carol',10)]}), /duplicate vault-to-recipient/);
  assert.throws(() => routePayouts({netting:n,vaults:[source('Bob','16666666')],routes:[routes('Bob','Eve',10)]}), /non-creditor/);
  assert.throws(() => routePayouts({netting:n,vaults:[source('Bob','16666666')],routes:[{...routes('Bob','Carol',10), nettingSetId:'another'}]}), /cross-domain/);
});

test('rejects encumbered reserves and stale netting digests; no caller can set production status', () => {
  const n = netObligations(obligationsForOutcome(close(), '60000'), original.nettingSetId);
  assert.throws(() => routePayouts({netting:n,vaults:[source('Bob',1000,{fundingSats:'200',retainedSats:'201'})],routes:[]}), /reserve backing/);
  assert.throws(() => routePayouts({netting:{...n, balancesSats:{...n.balancesSats, Alice:'999'}},vaults:[],routes:[]}), /digest mismatch/);
  const result = routePayouts({ netting:n, vaults:[source('Bob','16666666')], routes:[routes('Bob','Alice',10_000_000), routes('Bob','Carol',10_000_000)], productionReady:true });
  assert.equal(result.productionReady, false);
  assert.equal(result.proofVerified, false);
});

test('max-flow matches independent exhaustive 2x2 integer allocation for 81 route-capacity graphs', () => {
  const domain = original.nettingSetId;
  const fixedNetting = netObligations([
    {id:'obligation:d1', from:'D1', to:'C1', amountSats:'2', nettingSetId:domain},
    {id:'obligation:d2', from:'D2', to:'C2', amountSats:'2', nettingSetId:domain}
  ],domain);
  const vaults = [source('D1','2'),source('D2','2')];
  const pairs = [['D1','C1'],['D1','C2'],['D2','C1'],['D2','C2']];
  let checked = 0;
  for (let a=0; a<=2; a++) for (let b=0; b<=2; b++) for (let c=0; c<=2; c++) for (let d=0; d<=2; d++) {
    const caps=[a,b,c,d];
    const declared = pairs.flatMap(([from,to],i) => caps[i] === 0 ? [] : [routes(from,to,caps[i])]);
    const got = routePayouts({netting:fixedNetting,vaults,routes:declared});
    let expected=0;
    for (let x=0; x<=a; x++) for(let y=0; y<=b; y++) for(let z=0; z<=c; z++) for(let w=0; w<=d; w++) {
      if (x+y<=2 && z+w<=2 && x+z<=2 && y+w<=2) expected=Math.max(expected,x+y+z+w);
    }
    assert.equal(BigInt(got.routedSats),BigInt(expected),`caps ${caps}`);
    assert.equal(BigInt(got.shortfallSats),4n-BigInt(expected),`caps ${caps}`);
    checked++;
  }
  assert.equal(checked,81);
});

test('strict canonical amounts reject floats, negative inputs, oversized Bitcoin funds', () => {
  assert.throws(() => inverseLongPnlSats(1.25,50000,60000), /canonical nonnegative/);
  assert.throws(() => inverseLongPnlSats(10,0,60000), /range/);
  const n=netObligations(obligationsForOutcome(close(),'60000'), original.nettingSetId);
  assert.throws(() => routePayouts({netting:n,vaults:[source('Bob',10,{fundingSats:'2100000000000001'})],routes:[]}), /range/);
  assert.throws(() => netObligations([{id:'oversize',nettingSetId:original.nettingSetId,from:'A',to:'B',amountSats:'2100000000000001'}],original.nettingSetId), /range/);
});
