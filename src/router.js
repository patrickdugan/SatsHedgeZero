'use strict';

const { integer, identifier, commitment, MAX_SATS, compareIds } = require('./core');

// Maximum flow proves capacity feasibility relative to supplied vaults and
// routes. Neither vault existence nor route signatures are authenticated here.
function routePayouts({ netting, vaults, routes }) {
  if (!netting || netting.protocol !== 'SHZ/MNR-01/netting/v1') throw new Error('invalid netting proposal');
  const { nettingDigest, ...nettingStatement } = netting;
  if (commitment('SHZ.MNR01.NETTING.v1', nettingStatement) !== nettingDigest) throw new Error('netting digest mismatch');
  if (!Array.isArray(vaults) || vaults.length > 256 || !Array.isArray(routes) || routes.length > 4096) {
    throw new Error('invalid or unbounded vault/route set');
  }
  const domain = netting.nettingSetId;
  const balances = Object.entries(netting.balancesSats);
  const debtorAmounts = new Map(balances.filter(([, x]) => BigInt(x) < 0n).map(([id, v]) => [id, -BigInt(v)]));
  const creditorAmounts = new Map(balances.filter(([, x]) => BigInt(x) > 0n).map(([id, v]) => [id, BigInt(v)]));
  const byVault = new Map();
  for (const v of vaults) {
    const id = identifier(v.id, 'vault.id');
    const owner = identifier(v.owner, 'vault.owner');
    if (v.nettingSetId !== domain) throw new Error('cross-domain vault');
    if (!debtorAmounts.has(owner)) throw new Error(`vault ${id} does not belong to a net debtor`);
    if (byVault.has(id)) throw new Error('duplicate vault id');
    const funding = integer(v.fundingSats, 'vault.fundingSats', { max: MAX_SATS });
    const retained = integer(v.retainedSats, 'vault.retainedSats', { max: MAX_SATS });
    const protectedSats = integer(v.protectedSats, 'vault.protectedSats', { max: MAX_SATS });
    const fee = integer(v.feeSats, 'vault.feeSats', { max: MAX_SATS });
    const free = funding - retained - protectedSats - fee;
    if (free < 0n) throw new Error(`vault ${id} violates retained-claim or protected reserve backing`);
    byVault.set(id, { id, owner, free });
  }
  const sortedOwners = [...debtorAmounts.keys()].sort(compareIds);
  const sortedVaults = [...byVault.values()].sort((a, b) => compareIds(a.id, b.id));
  const sortedCreditors = [...creditorAmounts.keys()].sort(compareIds);
  const nodes = ['source', ...sortedOwners.map(id => `account:${id}`), ...sortedVaults.map(v => `vault:${v.id}`), ...sortedCreditors.map(id => `payout:${id}`), 'sink'];
  const source = 0, sink = nodes.length - 1;
  const nodeIndex = new Map(nodes.map((key, index) => [key, index]));
  const adjacency = Array.from({ length: nodes.length }, () => []);
  function addEdge(from, to, capacity, label = null) {
    const f = { to, rev: adjacency[to].length, cap: capacity, initial: capacity, label };
    const r = { to: from, rev: adjacency[from].length, cap: 0n, initial: 0n, label: null };
    adjacency[from].push(f);
    adjacency[to].push(r);
    return f;
  }
  for (const id of sortedOwners) addEdge(source, nodeIndex.get(`account:${id}`), debtorAmounts.get(id));
  for (const v of sortedVaults) addEdge(nodeIndex.get(`account:${v.owner}`), nodeIndex.get(`vault:${v.id}`), v.free);
  for (const id of sortedCreditors) addEdge(nodeIndex.get(`payout:${id}`), sink, creditorAmounts.get(id));
  const routeKeys = new Set();
  const routeEdges = [];
  const sortedRoutes = [...routes].sort((a, b) => compareIds(String(a.fromVaultId), String(b.fromVaultId)) || compareIds(String(a.toAccountId), String(b.toAccountId)));
  for (const r of sortedRoutes) {
    const vaultId = identifier(r.fromVaultId, 'route.fromVaultId');
    const accountId = identifier(r.toAccountId, 'route.toAccountId');
    if (r.nettingSetId !== domain) throw new Error('cross-domain route');
    if (!byVault.has(vaultId)) throw new Error(`unknown route source ${vaultId}`);
    if (!creditorAmounts.has(accountId)) throw new Error(`route targets non-creditor ${accountId}`);
    const key = `${vaultId}\0${accountId}`;
    if (routeKeys.has(key)) throw new Error('duplicate vault-to-recipient route');
    routeKeys.add(key);
    const capacity = integer(r.capacitySats, 'route.capacitySats', { zero: false, max: MAX_SATS });
    routeEdges.push({ fromVaultId: vaultId, toAccountId: accountId, edge: addEdge(nodeIndex.get(`vault:${vaultId}`), nodeIndex.get(`payout:${accountId}`), capacity) });
  }
  let flow = 0n;
  while (true) {
    const parentNode = Array(nodes.length).fill(-1), parentEdge = Array(nodes.length).fill(-1);
    const queue = [source];
    parentNode[source] = source;
    for (let head = 0; head < queue.length && parentNode[sink] < 0; head++) {
      const u = queue[head];
      for (let i = 0; i < adjacency[u].length; i++) {
        const e = adjacency[u][i];
        if (e.cap > 0n && parentNode[e.to] < 0) {
          parentNode[e.to] = u;
          parentEdge[e.to] = i;
          queue.push(e.to);
        }
      }
    }
    if (parentNode[sink] < 0) break;
    let pushed = null;
    for (let node = sink; node !== source; node = parentNode[node]) {
      const e = adjacency[parentNode[node]][parentEdge[node]];
      pushed = pushed === null || e.cap < pushed ? e.cap : pushed;
    }
    for (let node = sink; node !== source; node = parentNode[node]) {
      const e = adjacency[parentNode[node]][parentEdge[node]];
      e.cap -= pushed;
      adjacency[node][e.rev].cap += pushed;
    }
    flow += pushed;
  }
  const totalDemand = [...creditorAmounts.values()].reduce((a, b) => a + b, 0n);
  const allocations = routeEdges.map(({ fromVaultId, toAccountId, edge }) => ({
    fromVaultId, toAccountId, amountSats: (edge.initial - edge.cap).toString()
  })).filter(a => a.amountSats !== '0');
  const fundedRecipient = new Map(sortedCreditors.map(id => [id, 0n]));
  for (const a of allocations) fundedRecipient.set(a.toAccountId, fundedRecipient.get(a.toAccountId) + BigInt(a.amountSats));
  const unfunded = sortedCreditors.map(id => ({
    accountId: id, shortfallSats: (creditorAmounts.get(id) - fundedRecipient.get(id)).toString()
  })).filter(v => v.shortfallSats !== '0');
  const result = {
    protocol: 'SHZ/MNR-01/route/v1',
    nettingSetId: domain,
    nettingDigest: netting.nettingDigest,
    status: flow === totalDemand ? 'CAPACITY_FEASIBLE_PROPOSAL' : 'UNFUNDED_PROPOSAL',
    requiredSats: totalDemand.toString(),
    routedSats: flow.toString(),
    shortfallSats: (totalDemand - flow).toString(),
    allocations,
    unfunded,
    fundingOutpointsVerified: false,
    routeConsentVerified: false,
    stateRootVerified: false,
    bitcoinSpendEnforced: false,
    proofVerified: false,
    productionReady: false
  };
  return { ...result, routeDigest: commitment('SHZ.MNR01.ROUTE.v1', result) };
}

module.exports = { routePayouts };
