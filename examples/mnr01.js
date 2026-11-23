'use strict';

const { buildMatchedCloseout, obligationsForOutcome, netObligations, routePayouts } = require('../src');
const domain = 'BTC:SHZ:inverse';
const plan = buildMatchedCloseout({
  original: { id: 'dlc:alice-bob', long: 'Alice', short: 'Bob', notionalUsd: '50000', entryPriceUsd: '50000', oracleEventId: 'BTCUSD:epoch7', nettingSetId: domain, maturityHeight: 1000 },
  closingParty: 'Alice', liquidityProvider: 'Carol',
  quote: { id: 'quote:carol-01', closePriceUsd: '55000', notionalUsd: '50000', oracleEventId: 'BTCUSD:epoch7', nettingSetId: domain, expiryHeight: 920 },
  currentHeight: 900,
  outcomePricesUsd: ['45000','50000','55000','60000','70000']
});
const netting = netObligations(obligationsForOutcome(plan, '60000'), domain);
const routing = routePayouts({
  netting,
  vaults: [{id:'vault:bob',owner:'Bob',nettingSetId:domain,fundingSats:'17666666',retainedSats:'500000',protectedSats:'400000',feeSats:'100000'}],
  routes: [
    {fromVaultId:'vault:bob',toAccountId:'Alice',capacitySats:'10000000',nettingSetId:domain},
    {fromVaultId:'vault:bob',toAccountId:'Carol',capacitySats:'10000000',nettingSetId:domain}
  ]
});
console.log(JSON.stringify({
  description: 'Synthetic Alice/Bob DLC offset by Alice/Carol at $55,000; routed BTC PnL if the oracle settles at $60,000',
  original: plan.originalContract,
  newOffsettingDlc: plan.offsetContract,
  markPnlSats: plan.markPnlSats,
  maxRoundingResidualSats: plan.maxRoundingResidualSats,
  netting,
  routing,
  enforcementWarning: 'Accounting feasibility only. No signatures, UTXOs, Lightning channels, Bitcoin spends or cryptographic proofs were verified.'
}, null, 2));
