// Markdown tables from a drill JSONL: node summarize.mjs ../results/liq-drill-fund.jsonl
import { readFileSync } from 'node:fs';
const rows = readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const of = (k) => rows.filter((r) => r.kind === k);
const out = [];
const table = (head, body) => { out.push('| ' + head.join(' | ') + ' |', '|' + head.map(() => '---').join('|') + '|'); for (const r of body) out.push('| ' + r.join(' | ') + ' |'); out.push(''); };
const fmt = (n) => (n == null ? '-' : typeof n === 'number' ? n.toLocaleString('en-US') : String(n));

out.push('#### Assertions', '');
table(['', 'assertion'], of('assert').map((a) => [a.ok ? 'PASS' : '**FAIL**', a.name]));

out.push('#### Risk state transitions', '');
table(['t (s)', 'account', 'from', 'to', 'mark', 'margin bps', 'net USD'], of('risk_transition').filter((r) => !r.acct.startsWith('MM') || r.to !== 'ok').map((r) => [r.t, r.acct, r.from, r.to, fmt(r.mark_usd), fmt(r.margin_bps), fmt(r.net_usd)]));

out.push('#### Auction plan (first and last sample per account and mark)', '');
const groups = new Map();
for (const p of of('auction_plan')) { const k = p.acct + '@' + p.mark_usd; (groups.get(k) || groups.set(k, []).get(k)).push(p); }
table(['account', 'mark', 'samples', 'first: t / discount / limit / tranche', 'last: t / discount / limit / tranche', 'post_margin_bps (plan)', 'margin_bps (observed)'],
  [...groups.values()].map((g) => { const a = g[0], z = g[g.length - 1]; return [a.acct, fmt(a.mark_usd), g.length, `${a.t} s / ${a.discount} bps / ${fmt(a.limit_usd)} / ${a.tranche_usd}`, `${z.t} s / ${z.discount} bps / ${fmt(z.limit_usd)} / ${z.tranche_usd}`, fmt(z.post_margin_bps), fmt(z.margin_bps)]; }));

out.push('#### Client liquidation takes (planTakes from ui/venue/liquidate.js)', '');
const results = of('liq_result');
const takes = of('liq_take');
table(['t (s)', 'account', 'mark', 'net before', 'free before', 'plan tranche / limit / discount', 'takes (qty@limit)', 'outcome'],
  takes.map((tk, i) => { const rs = results.find((r) => r.acct === tk.acct && r.t >= tk.t && r.t - tk.t < 15); return [tk.t, tk.acct, fmt(tk.mark_usd), fmt(tk.net_before), fmt(tk.free_before),
    `${tk.plan.tranche_usd} / ${fmt(tk.plan.limit_usd)} / ${tk.plan.auction_discount_bps} bps`, tk.takes.map((x) => `${x.quantity}@${fmt(x.limit_usd)}`).join(', '),
    rs ? rs.results.map((r) => `${r.status}${r.reason ? ' (' + r.reason + ')' : ''}${r.price ? ' @' + fmt(r.price) : ''}`).join(', ') : '?']; }));
const idle = of('liq_idle');
out.push(`${idle.length} further plan evaluations found no bid inside the auction limit (client waits for the discount to grow).`, '');

out.push('#### Reduce-only gate probes', '');
table(['account', 'state', 'held USD', 'increase', 'flip', 'new increasing quote'], of('gate_probe').map((g) => [g.acct, g.state, g.held, `${g.increase.status} ${g.increase.error || ''}`, `${g.flip.status} ${g.flip.error || ''}`, `${g.post.status} ${g.post.error || ''}`]));

out.push('#### Batches with a clearing shortfall', '');
table(['t (s)', 'batch', 'layer', 'shortfall', 'fund absorbed', 'haircut', 'carry after', 'fund after', 'claims after', 'rows (who: pnl / released / collected / shortfall / paid / claim after)'],
  of('batch').filter((b) => b.clearing && (b.clearing.shortfall > 0 || b.clearing.haircut > 0 || b.clearing.carry_after > 0)).map((b) => [b.t, b.seq, b.clearing.layer, fmt(b.clearing.shortfall), fmt(b.clearing.fund_absorbed), fmt(b.clearing.haircut), fmt(b.clearing.carry_after), fmt(b.clearing.fund_after), fmt(b.clearing.claims_after),
    b.clearing.rows.map((r, i) => ({ ...r, who: (b.settlements[i] || {}).who || r.who })).filter((r) => r.pnl || r.shortfall || r.paid || r.claim_after).map((r) => `${r.who}: ${fmt(r.pnl)} / ${fmt(r.released)} / ${fmt(r.collected)} / ${fmt(r.shortfall)} / ${fmt(r.paid)} / ${fmt(r.claim_after)}`).join('<br>')]));

const b = of('batch');
const lay = {}; for (const x of b) if (x.clearing) lay[x.clearing.layer] = (lay[x.clearing.layer] || 0) + 1;
out.push(`${b.length} batches settled; clearing layers reached: ${Object.entries(lay).map(([k, v]) => `${k} ${v}`).join(', ')}.`, '');

const sol = of('solvency').filter((s) => !s.skipped);
out.push('#### Solvency identity', '');
out.push(`${sol.length} snapshots (one per committed batch, journal digest unchanged across the read): identity == 0 in ${sol.filter((s) => s.identity_zero).length}; sum(realized_pnl) + pool cash == fund0 in ${sol.filter((s) => s.realized_plus_cash_eq_fund0).length}.`, '');
const last = sol[sol.length - 1];
if (last) out.push(`Last snapshot (after batch ${last.after_batch}): identity ${last.identity}, sum realized ${fmt(last.sum_realized_pnl)}, pool cash ${fmt(last.cash)}, fund0 ${fmt(last.fund0)}, fund ${fmt(last.fund)}, carry ${fmt(last.carry)}, claims ${fmt(last.claims)}, open book ${fmt(last.book)}.`, '');

const fin = of('final_accounts')[0];
if (fin) { out.push('#### Final accounts (demo cap 200,000 sats each)', ''); table(['account', 'free', 'committed', 'realized pnl', 'equity', 'net USD', 'claim'], Object.entries(fin).filter(([n]) => n !== 't' && n !== 'kind').map(([n, a]) => [n, fmt(a.free), fmt(a.committed), fmt(a.realized_pnl), fmt(a.equity), fmt(a.net_usd), fmt(a.claim)])); }
console.log(out.join('\n'));
