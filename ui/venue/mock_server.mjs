#!/usr/bin/env node
// Zero-dependency mock of the shz-venue API (docs/SHZ_VENUE_API.md) with synthetic data.
// Usage: node ui/venue/mock_server.mjs [port]   (default 8095, binds 127.0.0.1)
// Verifies real BIP340 signatures with crypto.js, so the UI's signing path is exercised.
// Unspecified-by-contract object shapes (open_orders, fills, explorer objects) are the guesses
// the UI reads; the UI tolerates missing fields.
import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { hex, unhex, intentId, bip340Verify, taggedHash, sha256 } from './crypto.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.argv[2] || process.env.PORT || 8095);
const MARKET = 'SHZ-BTCUSD-INV';
const ZERO32 = '0'.repeat(64);
const h32 = () => randomBytes(32).toString('hex');
const sha = (s) => createHash('sha256').update(s).digest('hex');
const nowUs = () => Date.now() * 1000;

const template = {
  scope: { network: sha('testnet4'), epoch: 1, policy: sha('policy') },
  router: 1, tariff_version: 1, execution_policy: sha('exec-policy'),
  tariff: { maker_ppm: [200, 150, 100], taker_ppm: [500, 400, 300] },
  max_mark_age_us: 10_000_000, leverage_bps: { min: 10000, max: 100000 }, collar_bps: 200, market: MARKET,
};
const TIERS = ['standard', 'intermediate', 'premium'];
const tariffId = sha('tariff'), policyId = sha('exec-policy');

// ---------- state ----------
const S = {
  mark: 95000, markSeq: 1000, markAt: Date.now(), packets: [], trades: [], tradeSeq: 0,
  resting: [], // user + bot resting orders {id, owner, side, tier, qty, limit, ts_us, bot}
  accounts: new Map(), fills: new Map(), batches: new Map(), batchSeq: 0, entitlements: new Map(),
  drafts: new Map(), journalRecords: 0, journalDigest: ZERO32, pending: new Map(), // owner -> items
  candles: new Map(), // minute ms -> candle
};
const dlcEvents = [
  { event_id: 'shz-btcusd-20261125-1200', state: 'announced', maturity: '2026-11-25T12:00:00Z' },
  { event_id: 'shz-btcusd-20261125-0600', state: 'attested', outcome: 94871, maturity: '2026-11-25T06:00:00Z' },
  { event_id: 'shz-btcusd-20261124-1800', state: 'unattestable', reason: 'quorum below 3-of-5', maturity: '2026-11-24T18:00:00Z' },
  { event_id: 'shz-btcusd-20261124-1200', state: 'setup_abandoned', reason: 'no counterparty', maturity: '2026-11-24T12:00:00Z' },
];

function journal(kind) { S.journalRecords++; S.journalDigest = sha(S.journalDigest + kind + S.journalRecords); }

function newPacket() {
  S.markSeq++;
  const p = { seq: S.markSeq, slot_us: Math.floor(nowUs() / 5e6) * 5e6, status: 'ok', price_usd: Math.round(S.mark),
    median_usd: Math.round(S.mark), digest: h32(), signers: [1, 2, 3, 4, 5].slice(0, 3 + (S.markSeq % 3)), threshold: '3-of-5', verified: true };
  S.packets.unshift(p); S.packets.length = Math.min(S.packets.length, 200);
  S.markAt = Date.now();
  return p;
}
const curPacket = () => S.packets[0];
const markView = () => ({ seq: S.markSeq, status: 'ok', price_usd: Math.round(S.mark), slot_us: curPacket().slot_us,
  packet_digest: curPacket().digest, age_s: +((Date.now() - S.markAt) / 1000).toFixed(1), verified: true });

// ---------- candles ----------
const minuteOf = (ms) => Math.floor(ms / 60000) * 60000;
function addToCandle(ms, price, vol) {
  const m = minuteOf(ms), c = S.candles.get(m);
  if (!c) S.candles.set(m, { time: m, open: price, high: price, low: price, close: price, volume: vol });
  else { c.high = Math.max(c.high, price); c.low = Math.min(c.low, price); c.close = price; c.volume += vol; }
  return S.candles.get(m);
}
(function seedHistory() {
  let p = 94200; const end = minuteOf(Date.now());
  for (let m = end - 900 * 60000; m < end; m += 60000) {
    const o = p; p += (Math.random() - 0.48) * 25; const hi = Math.max(o, p) + Math.random() * 12, lo = Math.min(o, p) - Math.random() * 12;
    S.candles.set(m, { time: m, open: o, high: hi, low: lo, close: p, volume: Math.random() < 0.15 ? 0 : +(Math.random() * 40000).toFixed(0) });
  }
  S.mark = p;
})();
function aggregate(interval, limit) {
  const step = { '1m': 1, '5m': 5, '15m': 15, '1h': 60 }[interval];
  if (!step) return null;
  const mins = [...S.candles.values()].sort((a, b) => a.time - b.time), out = [];
  for (const c of mins) {
    const b = Math.floor(c.time / (step * 60000)) * step * 60000, last = out[out.length - 1];
    if (last && last.time === b) { last.high = Math.max(last.high, c.high); last.low = Math.min(last.low, c.low); last.close = c.close; last.volume += c.volume; }
    else out.push({ ...c, time: b });
  }
  return out.slice(-limit).map((c) => ({ ...c, open: r2(c.open), high: r2(c.high), low: r2(c.low), close: r2(c.close) }));
}
const r2 = (x) => Math.round(x * 100) / 100;

// ---------- book ----------
function botBook() {
  // deterministic synthetic ladder around the mark (rounded to $1), plus resting user orders
  const m = Math.round(S.mark), bids = new Map(), asks = new Map();
  for (let i = 1; i <= 30; i++) {
    const q = 2000 + ((i * 7919 + Math.floor(Date.now() / 3000) * 31) % 18000);
    bids.set(m - i, { qty: q, n: 1 + (i % 4) }); asks.set(m + i, { qty: q + (i * 311) % 4000, n: 1 + (i % 3) });
  }
  return { bids, asks };
}
function bookView(depth = 25) {
  const { bids, asks } = botBook();
  for (const o of S.resting) {
    const side = o.side === 'long' ? bids : asks, x = side.get(o.limit) || { qty: 0, n: 0 };
    side.set(o.limit, { qty: x.qty + o.qty, n: x.n + 1 });
  }
  const fmt = (mp, desc) => [...mp.entries()].sort((a, b) => (desc ? b[0] - a[0] : a[0] - b[0])).slice(0, depth).map(([p, v]) => [p, v.qty, v.n]);
  return { bids: fmt(bids, true), asks: fmt(asks, false), mark: markView() };
}

// ---------- accounts / orders / fills ----------
function acct(owner) { return S.accounts.get(owner); }
function accountView(owner) {
  const a = acct(owner); if (!a) return null;
  const mine = S.resting.filter((o) => o.owner === owner);
  const resting = mine.reduce((s, o) => s + marginSats(o.qty, o.limit, o.lev), 0);
  const pend = S.pending.get(owner) || [];
  const un = a.net_usd && a.avg ? Math.round(a.net_usd * (1 / a.avg - 1 / S.mark) * 1e8) : 0;
  return { owner, label: a.label, outpoint: a.outpoint,
    balance: { cap: a.cap, free: Math.max(0, a.cap - resting - a.committed - a.paid_fees), resting, pending: 0, committed: a.committed, paid_fees: a.paid_fees },
    position: { net_usd: a.net_usd, avg_entry_usd: a.avg || 0, unrealized_sats: un, deferred_claim_sats: Math.abs(a.net_usd) >= 20 ? 1500 : 0 },
    open_orders: mine.map((o) => ({ id: o.id, side: o.side, tier: o.tier, quantity: o.qty, limit_usd: o.limit, leverage_bps: o.lev, ts_us: o.ts_us })),
    fills: a.fills.slice(0, 100), pending_signatures: pend.map(({ id, kind, message, context }) => ({ id, kind, message, context })) };
}
const marginSats = (qty, price, lev) => Math.ceil((qty / price) * 1e8 / (lev / 10000));
const feeSats = (qty, price, ppm) => Math.ceil((qty / price) * 1e8 * ppm / 1e6);

function applyPosition(owner, side, qty, price) {
  const a = acct(owner); if (!a) return;
  const signed = side === 'long' ? qty : -qty;
  if (a.net_usd === 0 || Math.sign(a.net_usd) === Math.sign(signed)) {
    const tot = Math.abs(a.net_usd) + qty; a.avg = ((a.avg || price) * Math.abs(a.net_usd) + price * qty) / tot;
  } else if (Math.abs(signed) > Math.abs(a.net_usd)) a.avg = price;
  a.net_usd += signed; if (a.net_usd === 0) a.avg = 0;
}

function makeFill({ takerOwner, takerSide, takerTier, takerIntent, makerOrder, price, qty }) {
  const id = 'f' + (++S.tradeSeq).toString().padStart(6, '0') + h32().slice(0, 6);
  const pk = curPacket(), ts = nowUs();
  const mk = takerSide === 'long' ? 'short' : 'long';
  const takerFee = feeSats(qty, price, template.tariff.taker_ppm[TIERS.indexOf(takerTier)]);
  const makerFee = feeSats(qty, price, template.tariff.maker_ppm[TIERS.indexOf(makerOrder.tier)]);
  const batchSeq = ++S.batchSeq;
  const owners = [...new Set([takerOwner, makerOrder.owner].filter((o) => acct(o) && !acct(o).bot))];
  const batch = { seq: batchSeq, digest: h32(), phase: 'sealed', sealed_us: ts, fills: [id], participants: owners,
    approvals: owners.map((o) => ({ owner: o, signed: false })), acks: owners.map((o) => ({ lane: o.slice(0, 8), owner: false, peer: false, monitor: false })),
    fee_ledger: { accrued_sats: takerFee + makerFee, committed_sats: 0, oracle_sats: Math.floor((takerFee + makerFee) * 0.3), router_sats: 0 } };
  batch.fee_ledger.router_sats = batch.fee_ledger.accrued_sats - batch.fee_ledger.oracle_sats;
  S.batches.set(batchSeq, batch);
  const fill = { id, ts_us: ts, price_usd: price, qty_usd: qty, taker: { owner: takerOwner, side: takerSide, tier: takerTier, intent: takerIntent },
    maker: { owner: makerOrder.owner, side: mk, tier: makerOrder.tier, intent: makerOrder.id },
    packet: { seq: pk.seq, slot_us: pk.slot_us, median_usd: pk.median_usd, digest: pk.digest, verified: true },
    binding: { mark_id: sha(id + pk.digest), preimage: { packet_digest: pk.digest, tariff_id: tariffId, execution_policy_id: policyId, price_usd: price, qty_usd: qty } },
    tariff_id: tariffId, execution_policy_id: policyId,
    fees: { taker_sats: takerFee, maker_sats: makerFee, oracle_sats: batch.fee_ledger.oracle_sats, router_sats: batch.fee_ledger.router_sats },
    batch_seq: batchSeq };
  S.fills.set(id, fill);
  const trade = { id, ts_us: ts, price_usd: price, qty_usd: qty, taker_side: takerSide, maker_tier: makerOrder.tier, taker_tier: takerTier, packet_seq: pk.seq, packet_digest: pk.digest, batch_seq: batchSeq };
  S.trades.unshift(trade); S.trades.length = Math.min(S.trades.length, 500);
  addToCandle(Date.now(), price, qty);
  for (const [o, side, role, fee] of [[takerOwner, takerSide, 'taker', takerFee], [makerOrder.owner, mk, 'maker', makerFee]]) {
    const a = acct(o); if (!a || a.bot) continue;
    applyPosition(o, side, qty, price); a.paid_fees += fee; a.committed += marginSats(qty, price, 20000);
    a.fills.unshift({ id, ts_us: ts, side, role, price_usd: price, qty_usd: qty, fee_sats: fee, batch_seq: batchSeq, batch_phase: 'sealed' });
    S.pending.set(o, [...(S.pending.get(o) || []),
      { id: `${batchSeq}:approval:${o.slice(0, 8)}`, kind: 'batch_approval', message: h32(), context: { batch_seq: batchSeq, fill: id } }]);
  }
  journal('fill'); broadcast({ type: 'trade', trade });
  if (!owners.length) advanceBatch(batch, true);
  else broadcast({ type: 'batch', batch: batchSummary(batch) });
  return fill;
}
const batchSummary = (b) => ({ seq: b.seq, digest: b.digest, phase: b.phase, fills: b.fills.length, sealed_us: b.sealed_us });
function advanceBatch(b, auto) {
  if (b.phase === 'sealed') { b.phase = 'prepared'; if (auto) setTimeout(() => advanceBatch(b, true), 600); }
  else if (b.phase === 'prepared') b.phase = 'committed', b.fee_ledger.committed_sats = b.fee_ledger.accrued_sats;
  for (const o of b.participants) for (const f of acct(o).fills) if (f.batch_seq === b.seq) f.batch_phase = b.phase;
  journal('batch'); broadcast({ type: 'batch', batch: batchSummary(b) });
  for (const o of b.participants) broadcast({ type: 'account', owner: o });
}
function completeSignature(owner, id) {
  const items = S.pending.get(owner) || [], it = items.find((x) => x.id === id);
  S.pending.set(owner, items.filter((x) => x.id !== id));
  const bseq = it.context.batch_seq, b = S.batches.get(bseq);
  if (it.kind === 'batch_approval') {
    b.approvals.find((x) => x.owner === owner).signed = true;
    if (b.approvals.every((x) => x.signed)) { b.phase = 'sealed'; advanceBatch(b, false);
      for (const o of b.participants) S.pending.set(o, [...(S.pending.get(o) || []), { id: `${bseq}:ack:${o.slice(0, 8)}`, kind: 'channel_ack', message: h32(), context: { batch_seq: bseq } }]); }
  } else {
    const ack = b.acks.find((x) => x.lane === owner.slice(0, 8)); ack.owner = ack.peer = ack.monitor = true;
    if (b.acks.every((x) => x.owner)) advanceBatch(b, false);
  }
  broadcast({ type: 'account', owner });
}

function handleIntent(it) {
  const a = acct(it.owner); if (!a) return [409, { error: 'UnknownAccount' }];
  const tier = it.tier; const ent = tier === 'standard' ? undefined : S.entitlements.get(it.owner + tier);
  if (tier !== 'standard' && !ent) return [409, { error: 'MissingEntitlement' }];
  return null;
}
async function postIntent(body) {
  const it = body.intent; const err = handleIntent(it); if (err) return err;
  if (it.quantity === 13) return [409, { error: 'a previous fill of this account is still settling' }];
  const ent = it.tier === 'standard' ? undefined : S.entitlements.get(it.owner + it.tier).digest;
  if (it.sequence <= (acct(it.owner).lastSeq || 0)) return [409, { error: 'SequenceNotIncreasing' }];
  let id;
  try { id = hex(await intentId(it, template, ent)); } catch (e) { return [400, { error: 'BadIntent: ' + e.message }]; }
  if (!(await bip340Verify(unhex(id), unhex(it.owner), unhex(it.signature)))) return [409, { error: 'BadSignature' }];
  if (it.expires_us < nowUs()) return [409, { error: 'Expired' }];
  acct(it.owner).lastSeq = it.sequence;
  const tierIdx = TIERS.indexOf(it.tier), delay = [200, 100, 0][tierIdx] * 1000;
  if (it.action === 'cancel') {
    const i = S.resting.findIndex((o) => o.id === it.cancel_target && o.owner === it.owner);
    if (i < 0) return [409, { error: 'UnknownTarget' }];
    S.resting.splice(i, 1); journal('cancel'); broadcast({ type: 'book' }); broadcast({ type: 'account', owner: it.owner });
    return [200, { id, due_us: nowUs() }];
  }
  const need = marginSats(it.quantity, it.limit_usd, it.leverage_bps);
  if (accountView(it.owner).balance.free < need) return [409, { error: 'InsufficientCollateral' }];
  if (it.action === 'post') {
    S.resting.push({ id, owner: it.owner, side: it.side, tier: it.tier, qty: it.quantity, limit: it.limit_usd, lev: it.leverage_bps, ts_us: nowUs() });
    journal('post'); broadcast({ type: 'book' }); broadcast({ type: 'account', owner: it.owner });
    return [200, { id, due_us: nowUs() + delay }];
  }
  // take: fill-or-kill against ONE resting quote no worse than limit
  const book = bookView(30), ladder = it.side === 'long' ? book.asks : book.bids;
  const q = ladder.find(([p, qty]) => (it.side === 'long' ? p <= it.limit_usd : p >= it.limit_usd) && qty >= it.quantity);
  if (!q) return [409, { error: 'FillOrKillUnfilled' }];
  const mine = S.resting.find((o) => o.limit === q[0] && o.side !== it.side && o.qty >= it.quantity);
  const maker = mine || { id: h32(), owner: 'bot', tier: 'standard' };
  if (mine) { mine.qty -= it.quantity; if (mine.qty <= 0) S.resting.splice(S.resting.indexOf(mine), 1); }
  setTimeout(() => { makeFill({ takerOwner: it.owner, takerSide: it.side, takerTier: it.tier, takerIntent: id, makerOrder: maker, price: q[0], qty: it.quantity });
    broadcast({ type: 'book' }); broadcast({ type: 'account', owner: it.owner }); }, Math.min(delay, 200));
  return [200, { id, due_us: nowUs() + delay }];
}

// ---------- tick ----------
setInterval(() => {
  S.mark += (Math.random() - 0.5) * 14; S.mark = Math.max(1000, S.mark);
  if (Date.now() - S.markAt >= 5000) newPacket();
  addToCandle(Date.now(), S.mark, 0);
  if (Math.random() < 0.5) {
    const side = Math.random() < 0.5 ? 'long' : 'short', m = Math.round(S.mark), price = m + (side === 'long' ? 1 : -1) * (1 + Math.floor(Math.random() * 3));
    makeFill({ takerOwner: 'bot', takerSide: side, takerTier: TIERS[Math.floor(Math.random() * 3)], takerIntent: h32(), makerOrder: { id: h32(), owner: 'bot', tier: 'standard' }, price, qty: 500 + Math.floor(Math.random() * 4000) });
  }
  broadcast({ type: 'mark', mark: markView() }); broadcast({ type: 'book' });
}, 1000);
newPacket();
S.accounts.set('bot', { bot: true, fills: [], net_usd: 0, avg: 0, cap: 0, committed: 0, paid_fees: 0 });

// ---------- websocket (server -> client text frames only) ----------
const clients = new Set(); // {socket, kind:'api'|'v1', instrument, interval}
function frame(str) {
  const b = Buffer.from(str), n = b.length;
  const head = n < 126 ? Buffer.from([0x81, n]) : n < 65536 ? Buffer.from([0x81, 126, n >> 8, n & 255]) : (() => { const x = Buffer.alloc(10); x[0] = 0x81; x[1] = 127; x.writeBigUInt64BE(BigInt(n), 2); return x; })();
  return Buffer.concat([head, b]);
}
function broadcast(msg) {
  for (const c of clients) {
    if (c.kind !== 'api') continue;
    let m = msg;
    if (msg.type === 'book') m = { type: 'book', ...bookView(25) };
    else if (msg.type === 'account') { if (c.owner && c.owner !== msg.owner) continue; m = { type: 'account', account: accountView(msg.owner) }; }
    try { c.socket.write(frame(JSON.stringify(m))); } catch { clients.delete(c); }
  }
  if (msg.type === 'trade' || msg.type === 'mark') pushCandles();
}
function pushCandles() {
  for (const c of clients) {
    if (c.kind !== 'v1') continue;
    const row = aggregate(c.interval, 1).pop();
    try { c.socket.write(frame(JSON.stringify({ type: 'candle', instrument: MARKET, interval: c.interval, candle: row }))); } catch { clients.delete(c); }
  }
}
setInterval(() => { for (const c of clients) if (c.kind === 'v1') try { c.socket.write(frame(JSON.stringify({ type: 'heartbeat', instrument: MARKET, interval: c.interval }))); } catch { clients.delete(c); } }, 10000);

// ---------- http ----------
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.md': 'text/plain; charset=utf-8' };
const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'access-control-allow-origin': '*' }).end(JSON.stringify(body)); };
const readBody = (req) => new Promise((ok, bad) => { let d = ''; req.on('data', (c) => { d += c; if (d.length > 1e6) req.destroy(); }); req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { bad(e); } }); });
const lim = (u, d) => Math.min(500, Math.max(1, Number(u.searchParams.get('limit')) || d));

async function api(req, res, u) {
  const p = u.pathname, GET = req.method === 'GET';
  if (GET && p === '/api/template') return json(res, 200, template);
  if (GET && p === '/api/status') return json(res, 200, { market: MARKET, mark: markView(), group_key: sha('group').slice(0, 64),
    router: { clock_us: nowUs(), resting: S.resting.length, batch_sequence: S.batchSeq }, accounts: S.accounts.size - 1, journal: { records: S.journalRecords, digest: S.journalDigest },
    clearing: { book: 0, carry: 0, cash: 4_200_000, claims: 1500, fund: 250_000, fund0: 250_000, identity: 0, legacy: false }, closing_loans: [] });
  if (GET && p === '/api/book') return json(res, 200, bookView(Number(u.searchParams.get('depth')) || 25));
  if (GET && p === '/api/trades') return json(res, 200, S.trades.slice(0, lim(u, 100)));
  if (GET && p.startsWith('/api/account/')) { const v = accountView(p.slice(13)); return v ? json(res, 200, v) : json(res, 404, { error: 'UnknownAccount' }); }
  if (GET && p === '/v1/candles') {
    const rows = aggregate(u.searchParams.get('interval') || '1m', lim(u, 900));
    if (u.searchParams.get('instrument') !== MARKET || !rows) return json(res, 400, { error: 'unsupported' });
    return json(res, 200, { instrument: MARKET, interval: u.searchParams.get('interval'), candles: rows });
  }
  if (GET && p === '/api/explorer/packets') return json(res, 200, S.packets.slice(0, lim(u, 50)));
  if (GET && p === '/api/explorer/batches') return json(res, 200, [...S.batches.values()].sort((a, b) => b.seq - a.seq).slice(0, lim(u, 50)).map((b) => ({ ...batchSummary(b), participants: b.participants.length })));
  if (GET && p.startsWith('/api/explorer/batch/')) { const b = S.batches.get(Number(p.slice(20))); return b ? json(res, 200, { ...b, clearing: clearingView(b) }) : json(res, 404, { error: 'not found' }); }
  if (GET && p.startsWith('/api/explorer/fill/')) { const f = S.fills.get(p.slice(19)); if (!f) return json(res, 404, { error: 'not found' }); const b = S.batches.get(f.batch_seq); return json(res, 200, { ...f, batch: { seq: b.seq, digest: b.digest, phase: b.phase }, approvals: b.approvals, acks: b.acks, fee_ledger: b.fee_ledger }); }
  if (GET && p === '/api/explorer/accounts') return json(res, 200, [...S.accounts.entries()].filter(([, a]) => !a.bot).map(([o, a]) => ({ owner: o, outpoint: a.outpoint, kind: a.kind, cap: a.cap, label: a.label, mempool: a.kind === 'utxo' ? `https://mempool.space/testnet4/tx/${a.outpoint.txid}` : null })));
  if (GET && p === '/api/explorer/journal') return json(res, 200, { records: S.journalRecords, digest: S.journalDigest, config_hash: sha('config') });
  if (GET && p === '/api/explorer/dlc') return json(res, 200, { events: dlcEvents });
  if (req.method === 'POST') {
    const body = await readBody(req);
    if (p === '/api/intent-id') return json(res, 200, { id: hex(await intentId(body.intent, template, body.entitlement_digest)) });
    if (p === '/api/intents') { const [c, b] = await postIntent(body); return json(res, c, b); }
    if (p === '/api/entitlement') {
      const digest = sha('ent' + body.owner + body.tier); S.entitlements.set(body.owner + body.tier, { digest });
      return json(res, 200, { owner: body.owner, tier: body.tier, valid_until_us: nowUs() + 86400e6, digest, entitlement_digest: digest, label: 'TESTNET ENTITLEMENT' });
    }
    if (p === '/api/register/draft') {
      if (!/^[0-9a-f]{64}$/.test(body.owner || '')) return json(res, 400, { error: 'bad owner' });
      const op = body.kind === 'demo' ? { txid: hex(await taggedHash('SHZ/VENUE/DEMO-OUTPOINT/V1', unhex(body.owner))), vout: 0 } : body.outpoint;
      if (!op) return json(res, 400, { error: 'outpoint required' });
      const draft_id = h32().slice(0, 16), allocation_digest = h32(), cap = body.kind === 'demo' ? 200000 : 50000;
      S.drafts.set(draft_id, { owner: body.owner, kind: body.kind, outpoint: op, allocation_digest, cap });
      return json(res, 200, { allocation_digest, draft_id, cap_sats: cap, outpoint: op, label: body.kind === 'demo' ? 'TESTNET DEMO CREDIT' : 'testnet4 utxo (mock-verified)' });
    }
    if (p === '/api/register') {
      const d = S.drafts.get(body.draft_id); if (!d) return json(res, 404, { error: 'unknown draft' });
      if (!(await bip340Verify(unhex(d.allocation_digest), unhex(d.owner), unhex(body.owner_signature)))) return json(res, 409, { error: 'BadSignature' });
      S.accounts.set(d.owner, { owner: d.owner, kind: d.kind, outpoint: d.outpoint, cap: d.cap, label: d.kind === 'demo' ? 'TESTNET DEMO CREDIT' : 'testnet4 utxo', fills: [], net_usd: 0, avg: 0, committed: 0, paid_fees: 0 });
      journal('register'); return json(res, 200, { account: accountView(d.owner) });
    }
    if (p === '/api/signatures') {
      const pend = S.pending.get(body.owner) || []; let ok = 0;
      for (const it of body.items || []) {
        const m = pend.find((x) => x.id === it.id);
        if (m && (await bip340Verify(unhex(m.message), unhex(body.owner), unhex(it.signature)))) { completeSignature(body.owner, it.id); ok++; }
      }
      return json(res, 200, { accepted: ok });
    }
  }
  json(res, 404, { error: 'not found' });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  try {
    if (u.pathname.startsWith('/api/') || u.pathname === '/v1/candles') return await api(req, res, u);
    let f = u.pathname === '/' ? '/index.html' : decodeURIComponent(u.pathname);
    const full = path.join(ROOT, path.normalize(f));
    if (!full.startsWith(ROOT)) return json(res, 403, { error: 'forbidden' });
    const data = await readFile(full);
    res.writeHead(200, { 'content-type': mime[path.extname(full)] || 'application/octet-stream', 'cache-control': 'no-store' }).end(data);
  } catch (e) { json(res, e.code === 'ENOENT' ? 404 : 500, { error: String(e.message || e) }); }
});
server.on('upgrade', (req, socket) => {
  const u = new URL(req.url, 'http://x');
  const kind = u.pathname === '/api/stream' ? 'api' : u.pathname === '/v1/stream' ? 'v1' : null;
  if (!kind) return socket.destroy();
  const key = req.headers['sec-websocket-key'];
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' +
    createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64') + '\r\n\r\n');
  const c = { socket, kind, interval: u.searchParams.get('interval') || '1m', owner: u.searchParams.get('owner') };
  clients.add(c);
  socket.on('data', (d) => { if ((d[0] & 15) === 8) { socket.end(); clients.delete(c); } });
  socket.on('close', () => clients.delete(c)); socket.on('error', () => clients.delete(c));
  if (kind === 'api') socket.write(frame(JSON.stringify({ type: 'mark', mark: markView() })));
});
server.listen(PORT, '127.0.0.1', () => console.log(`mock shz-venue on http://127.0.0.1:${PORT}/  (explorer: /explorer.html)`));
function clearingView(b) {
  const rows = Array.from({ length: Math.max(2, (b.participants || []).length) }, (_, i) => {
    const pnl = i % 2 ? 2400 : -1800, released = 5000, collected = pnl < 0 ? -pnl : 0;
    const shortfall = i % 2 ? 0 : 300, haircut = 0, own = 0, paid = i % 2 ? pnl + released : 0;
    return { pnl, released, collected, own_claim_used: own, shortfall, haircut, claim_before: 0, claim_after: shortfall, paid, net: paid - collected };
  });
  return { rows, shortfall: rows.reduce((s, r) => s + r.shortfall, 0), fund_absorbed: 300, haircut: 0, layer: 'Fund', cash_before: 4_200_000, cash_after: 4_199_700, fund: 249_700, carry: 0, claims: 300 };
}
