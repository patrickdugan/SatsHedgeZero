'use strict';

const { integer, identifier, commitment, MAX_SATS, compareIds } = require('./core');

// Proposal algebra only. Netting changes the payee relationship and requires
// prior route authority or a freshly signed, Bitcoin-enforceable transaction.
function netObligations(obligations, nettingSetId) {
  const domain = identifier(nettingSetId, 'nettingSetId');
  if (!Array.isArray(obligations) || obligations.length > 4096) throw new Error('bounded obligations array required');
  const seen = new Set();
  const balances = new Map();
  let gross = 0n;
  const consumed = [];
  for (const o of obligations) {
    if (!o || typeof o !== 'object') throw new Error('invalid obligation');
    const id = identifier(o.id, 'obligation.id');
    if (seen.has(id)) throw new Error('duplicate obligation id');
    seen.add(id);
    const from = identifier(o.from, 'obligation.from');
    const to = identifier(o.to, 'obligation.to');
    if (from === to) throw new Error('self-payment is invalid');
    if (o.nettingSetId !== domain) throw new Error('cross-netting-domain obligation');
    const amount = integer(o.amountSats, 'obligation.amountSats', { zero: false, max: MAX_SATS });
    balances.set(from, (balances.get(from) || 0n) - amount);
    balances.set(to, (balances.get(to) || 0n) + amount);
    gross += amount;
    consumed.push(id);
  }
  if (gross > (1n << 100n)) throw new Error('aggregate obligation exceeds prototype bound');
  const debtors = [...balances.entries()].filter(([, v]) => v < 0n).map(([id, v]) => ({ id, remaining: -v })).sort((a, b) => compareIds(a.id, b.id));
  const creditors = [...balances.entries()].filter(([, v]) => v > 0n).map(([id, v]) => ({ id, remaining: v })).sort((a, b) => compareIds(a.id, b.id));
  const netEdges = [];
  let di = 0, ci = 0, net = 0n;
  while (di < debtors.length && ci < creditors.length) {
    const debtor = debtors[di], creditor = creditors[ci];
    const amount = debtor.remaining < creditor.remaining ? debtor.remaining : creditor.remaining;
    netEdges.push({ from: debtor.id, to: creditor.id, amountSats: amount.toString() });
    net += amount;
    debtor.remaining -= amount;
    creditor.remaining -= amount;
    if (debtor.remaining === 0n) di++;
    if (creditor.remaining === 0n) ci++;
  }
  if (di !== debtors.length || ci !== creditors.length) throw new Error('netting conservation failure');
  const orderedBalances = Object.fromEntries([...balances].sort(([a], [b]) => compareIds(a, b)).map(([k, v]) => [k, v.toString()]));
  const result = {
    protocol: 'SHZ/MNR-01/netting/v1',
    nettingSetId: domain,
    consumedObligationIds: consumed.sort(),
    balancesSats: orderedBalances,
    grossObligationsSats: gross.toString(),
    netRequiredSats: net.toString(),
    netEdges,
    settlementAuthorityVerified: false,
    spendEnforced: false
  };
  return { ...result, nettingDigest: commitment('SHZ.MNR01.NETTING.v1', result) };
}

module.exports = { netObligations };
