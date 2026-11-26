// Liquidation drill: runs the whole liquidation path against a LOCAL venue on a scripted mark.
//
//   node drill.mjs --fund 1000000 --out ../results/liq-drill-fund.jsonl
//   node drill.mjs --fund 0       --out ../results/liq-drill-fund0.jsonl
//
// One process hosts a signed test relay (packets from a scripted BTC/USD path under a test
// group key), starts a debug shz-venue on a fresh state dir against it, registers demo accounts,
// walks the mark down ~8% and on into a gap, then back, and asserts what the venue does.
// The client side is the real ui/venue/liquidate.js (planTakes, describe) driven by a port of
// the page's maybeLiquidate loop (ui/venue/venue.js): Standard tier, 10x leg, takes sized by
// planTakes against the live book, 5 s throttle. No browser page is loaded.
//
// Never talks to anything but 127.0.0.1. The state dir is under --work (default D:/shz/tmp).

import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, writeFileSync, mkdirSync, existsSync, rmSync, openSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, unhex, bip340Sign, bip340Verify, pubkey, signIntent, taggedHash, sha256 } from '../../../ui/venue/crypto.js';
import { planTakes, describe } from '../../../ui/venue/liquidate.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const FUND = Number(arg('fund', '1000000'));
const OUT = path.resolve(arg('out', path.join(HERE, '..', 'results', `liq-drill-fund${FUND}.jsonl`)));
const WORK = arg('work', 'D:/shz/tmp');
const VENUE_BIN = arg('venue-bin', 'D:/shz/target-msvc/debug/shz-venue.exe');
const SEED_BIN = arg('seed-bin', 'D:/shz/target-msvc/debug/liq-drill-seed-fund0.exe');
const VPORT = Number(arg('port', '18095'));
const RPORT = Number(arg('relay-port', '18091'));
const UI_DIR = path.resolve(HERE, '..', '..', '..', 'ui', 'venue');
const SCALE = Number(arg('scale', '1')); // < 1 shortens the holds (the 60 s auction clock does not scale)
const QUICK = arg('quick', '');
// Closing takes are single-flight per account unless --serialize false (see docs: a second closing take in a later
// 100 ms window, submitted before the first batch resolves, wedges the venue's settlement).
const SERIALIZE = arg('serialize', 'true') !== 'false';
const VENUE = `http://127.0.0.1:${VPORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now();

// ---------------------------------------------------------------- logging / asserts
mkdirSync(path.dirname(OUT), { recursive: true });
writeFileSync(OUT, '');
const log = (kind, o = {}) => appendFileSync(OUT, JSON.stringify({ t: +((Date.now() - T0) / 1000).toFixed(2), kind, ...o }) + '\n');
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok });
  log('assert', { name, ok: !!ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail === undefined ? '' : '  ' + JSON.stringify(detail)}`);
}
const note = (m, o = {}) => { log('note', { m, ...o }); console.log('..    ' + m); };

// ---------------------------------------------------------------- scripted relay
const canon = (v) => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
  : JSON.stringify(v);
const GROUP_SK = await sha256(new TextEncoder().encode('shz-liq-drill/test-group-key/v1')); // test key, local only
const GROUP_PK = hex(pubkey(GROUP_SK));
const relay = { seq: 0, price: 100_000, latest: null, clients: new Set(), emitted: [] };
async function emit() {
  relay.seq += 1;
  const us = Date.now() * 1000;
  const body = { schema: 'shz-public-relay/v1', market: 'BTC/USD', data_class: 'public_delayed', seq: relay.seq,
    previous: '0'.repeat(64), interval_ms: 1000, slot_us: us, assembled_us: us, status: 'VALID', median_e8: Math.round(relay.price * 1e8) };
  const digest = await taggedHash('SHZ/PUBLIC-RELAY-PACKET/V1', new TextEncoder().encode(canon(body)));
  const sig = await bip340Sign(digest, GROUP_SK);
  const pkt = { body, digest: hex(digest), signature: hex(sig), frost_signers: ['liq-drill-test-key'] };
  relay.latest = pkt;
  relay.emitted.push({ seq: relay.seq, price: relay.price, t: Date.now() });
  for (const res of relay.clients) res.write(`data: ${JSON.stringify(pkt)}\n\n`);
  return pkt;
}
function startRelay() {
  const srv = http.createServer((req, res) => {
    if (req.url === '/v1/pubkey') { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ pubkey_bip340: GROUP_PK })); }
    if (req.url === '/v1/latest') { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify(relay.latest)); }
    if (req.url === '/v1/stream') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
      relay.clients.add(res); req.on('close', () => relay.clients.delete(res)); return;
    }
    res.statusCode = 404; res.end('{}');
  });
  srv.listen(RPORT, '127.0.0.1');
  setInterval(() => { emit().catch((e) => console.error('emit', e)); }, 1000); // heartbeat keeps the mark fresh (15 s max age)
  return srv;
}
async function setPrice(p) { relay.price = p; await emit(); log('mark_set', { price_usd: p, seq: relay.seq }); }

// ---------------------------------------------------------------- venue process
let venueProc;
async function startVenue() {
  const state = path.join(WORK, `liq-drill-${FUND === 0 ? 'fund0' : 'fund'}-${Date.now()}`);
  mkdirSync(WORK, { recursive: true });
  if (FUND === 0) {
    const seed = hex(await sha256(new TextEncoder().encode('shz-liq-drill/venue-seed/v1')));
    const r = spawnSync(SEED_BIN, [state, seed], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error('seed-fund0 failed: ' + r.stderr);
    note('seeded a journal with clearing fund 0', { state });
  }
  const errFile = path.join(WORK, `liq-drill-venue-${FUND === 0 ? 'fund0' : 'fund'}-${VPORT}.log`);
  const fd = openSync(errFile, 'w');
  venueProc = spawn(VENUE_BIN, ['--listen', `127.0.0.1:${VPORT}`, '--state', state, '--ui', UI_DIR, '--relay', `http://127.0.0.1:${RPORT}`,
    '--group-key', GROUP_PK, '--mempool-api', 'http://127.0.0.1:9/none'], { stdio: ['ignore', fd, fd] });
  venueProc.on('exit', (c) => { if (!shuttingDown) { console.error('venue exited', c); process.exit(3); } });
  for (let i = 0; i < 100; i++) { try { await api('/api/status'); return { state, errFile }; } catch { await sleep(200); } }
  throw new Error('venue did not start');
}
let shuttingDown = false;

// ---------------------------------------------------------------- http helpers
async function raw(p, body) {
  const r = await fetch(VENUE + p, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { /* none */ }
  return { status: r.status, json: j };
}
async function api(p, body) { const r = await raw(p, body); if (r.status >= 300) throw new Error(`${p}: ${r.status} ${r.json && r.json.error}`); return r.json; }

// ---------------------------------------------------------------- accounts
const accts = {}; // name -> account object
let template;
async function mkAcct(name, o) {
  const sk = await sha256(new TextEncoder().encode('shz-liq-drill/account/' + name));
  const owner = hex(pubkey(sk));
  const d = await api('/api/register/draft', { owner, kind: 'demo', outpoint: null });
  const sig = await bip340Sign(unhex(d.allocation_digest), sk);
  const a = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(sig) })).account;
  const w = { name, sk, owner, outpoint: a.outpoint, lev: o.lev, role: o.role, seq: Date.now() * 1000, signed: new Set(), view: a,
    autoliq: !!o.autoliq, liqLast: 0, state: 'flat', hist: [], plan: [] };
  accts[name] = w;
  return w;
}
function intentFor(w, f) {
  w.seq += 1;
  return { owner: w.owner, channel: { txid: w.outpoint.txid, vout: w.outpoint.vout }, sequence: w.seq, expires_us: (Date.now() + 120e3) * 1000,
    action: 'take', side: 'long', tier: 'standard', quantity: 0, limit_usd: 0, leverage_bps: 100000, max_fee_ppm: 0, max_fee_sats: 0,
    max_mark_age_us: template.max_mark_age_us, early_window_opt_in: false, cancel_target: '0'.repeat(64), ...f };
}
async function sendRaw(w, f) { const { id, intent } = await signIntent(intentFor(w, f), template, w.sk, null); const r = await raw('/api/intents', { intent }); return { id, ...r }; }
async function send(w, f) { const r = await sendRaw(w, f); if (r.status >= 300) throw new Error(`intent refused (${r.status}): ${r.json && r.json.error}`); return r.id; }
/** Resolve an intent: filled / rejected(reason) / resting / cancelled / pending (after timeout). */
async function outcome(w, id, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = S.views[w.name] || w.view;
    const f = (v.fills || []).find((x) => x.id === id); if (f) return { status: 'filled', fill: f };
    const r = (v.rejected || []).find((x) => x.id === id); if (r) return { status: 'rejected', reason: r.reason };
    const o = (v.open_orders || []).find((x) => x.id === id); if (o && o.status === 'resting') return { status: 'resting' };
    await sleep(120);
  }
  return { status: 'pending' };
}

// ---------------------------------------------------------------- shared snapshot + monitor
const S = { views: {}, status: null, batchesSeen: new Set(), batchLog: [], lastCash: null, identityBad: 0, solvencyChecks: 0, solvencyBad: 0, running: true,
  liqEvents: [], transitions: {}, book: null, prevClearing: null };
async function signPending(w) {
  const todo = (w.view.pending_signatures || []).filter((x) => !w.signed.has(x.id));
  if (!todo.length) return;
  const items = [];
  for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), w.sk)) });
  await api('/api/signatures', { owner: w.owner, items });
  for (const x of todo) w.signed.add(x.id);
}
function trackRisk(w) {
  const r = w.view.position && w.view.position.risk; if (!r) return;
  const st = r.state || 'flat';
  if (st !== w.state) {
    const rec = { acct: w.name, from: w.state, to: st, mark_usd: r.mark_usd ?? null, margin_bps: r.margin_bps ?? null, equity_sats: r.equity_sats ?? null,
      liquidation_price_usd: r.liquidation_price_usd ?? null, bankruptcy_price_usd: r.bankruptcy_price_usd ?? null, net_usd: w.view.position.net_usd };
    log('risk_transition', rec); w.hist.push({ to: st, mark: rec.mark_usd });
    (S.transitions[w.name] ||= []).push(st);
    w.state = st;
  }
  if (r.reduce_only && r.liquidation) {
    const p = r.liquidation;
    const last = w.plan[w.plan.length - 1];
    if (!last || last.discount !== p.auction_discount_bps || last.tranche !== p.tranche_usd || last.limit !== p.limit_usd) {
      const s = { acct: w.name, mark_usd: r.mark_usd, state: st, net_usd: r.notional_usd, margin_bps: r.margin_bps, tranche_usd: p.tranche_usd, limit_usd: p.limit_usd,
        discount: p.auction_discount_bps, elapsed_ms: p.elapsed_ms, penalty_sats: p.penalty_sats, post_margin_bps: p.post_margin_bps, reduce_side: p.reduce_side };
      log('auction_plan', s); w.plan.push({ ...s, limit: p.limit_usd, tranche: p.tranche_usd });
    }
  }
}
async function maybeLiquidate(w) {
  const r = w.view.position && w.view.position.risk;
  if (!w.autoliq || !r || !r.reduce_only || !r.liquidation) return;
  if (Date.now() - w.liqLast < 5000) return;
  w.liqLast = Date.now();
  const book = S.book || (await api('/api/book?depth=25'));
  const takes = planTakes(r, book);
  const bal = w.view.balance || {};
  const ev = { acct: w.name, risk_state: r.state, mark_usd: r.mark_usd, plan: r.liquidation, banner: describe(r)?.text, takes, free_before: bal.free, committed_before: bal.committed,
    net_before: w.view.position.net_usd, margin_bps_before: r.margin_bps, book_bids: (book.bids || []).slice(0, 6) };
  if (!takes.length) { log('liq_idle', { ...ev, why: 'no bid inside the auction limit yet' }); return; }
  const ids = [];
  for (const k of takes) {
    const need = Math.ceil(k.quantity * 1e8 / k.limit_usd / 10); // 10x leg margin, as the page's take
    try {
      const id = await send(w, { action: 'take', tier: 'standard', side: k.side, quantity: k.quantity, limit_usd: k.limit_usd, leverage_bps: 100000, max_fee_ppm: 0, max_fee_sats: 1 });
      ids.push({ id, k, need });
      if (SERIALIZE) { await outcome(w, id, 6000); await allResolved(); }
    } catch (e) { ids.push({ id: null, k, need, error: e.message }); }
  }
  log('liq_take', { ...ev, submitted: ids.map((x) => ({ qty: x.k.quantity, limit: x.k.limit_usd, leg_margin_sats: x.need, free_before: bal.free, error: x.error })) });
  (async () => {
    const res = [];
    for (const x of ids) { if (!x.id) { res.push({ error: x.error }); continue; } const o = await outcome(w, x.id, 10000); res.push({ qty: x.k.quantity, limit: x.k.limit_usd, leg_margin_sats: x.need, free_before: bal.free, status: o.status, reason: o.reason, price: o.fill?.price_usd, batch: o.fill?.batch_seq }); }
    log('liq_result', { acct: w.name, results: res });
    S.liqEvents.push({ acct: w.name, free_before: bal.free, results: res });
  })();
}
// All accounts are read and signed in parallel, so every batch's approvals and acks are
// answered within ~0.1 s (the browser page signs on the venue's stream events the same way).
async function snapshot() {
  await Promise.all(Object.keys(accts).map(async (n) => {
    const w = accts[n];
    try { w.view = await api('/api/account/' + w.owner); S.views[n] = w.view; await signPending(w); trackRisk(w); } catch (e) { log('monitor_error', { acct: n, e: e.message }); }
  }));
}
async function signLoop() { while (S.running) { await snapshot(); await sleep(60); } }
async function monitor() {
  while (S.running) {
    try {
      S.status = await api('/api/status');
      S.book = await api('/api/book?depth=25');
      for (const n of Object.keys(accts)) await maybeLiquidate(accts[n]);
    } catch (e) { log('monitor_error', { e: e.message }); }
    await sleep(150);
  }
}
async function batchLoop() { while (S.running) { try { await checkBatches(); } catch (e) { log('monitor_error', { batches: e.message }); } await sleep(700); } }
const sum = (xs) => xs.reduce((a, b) => a + b, 0);
async function checkBatches() {
  const seq = S.status?.router?.batch_sequence || 0;
  const list = await api('/api/explorer/batches?limit=60');
  for (const b of list.slice().reverse()) {
    if (b.phase !== 'committed' && b.phase !== 'aborted') continue;
    if (S.batchesSeen.has(b.seq)) continue;
    S.batchesSeen.add(b.seq);
    const c = b.clearing;
    const rows = c ? c.rows.map((r) => ({ owner: (b.accounts.find((a) => a.channel.txid === r.channel.txid) || {}).owner?.slice(0, 8), who: nameOf(b.accounts, r.channel), pnl: r.pnl, released: r.released, collected: r.collected,
      own_claim_used: r.own_claim_used, shortfall: r.shortfall, haircut: r.haircut, claim_before: r.claim_before, claim_after: r.claim_after, paid: r.paid, net: r.net })) : [];
    const conserved = c ? sum(c.rows.map((r) => r.net)) + (c.cash_after - c.cash_before) === 0 : null;
    const cont = c && S.prevClearing ? c.cash_before === S.prevClearing.cash_after && c.carry_after >= 0 : null;
    if (c) S.prevClearing = c;
    const rec = { seq: b.seq, phase: b.phase, legs: b.legs.length, accounts: b.accounts.length,
      clearing: c ? { layer: c.layer, shortfall: c.shortfall, fund_absorbed: c.fund_absorbed, haircut: c.haircut, cash_before: c.cash_before, cash_after: c.cash_after,
        fund_after: c.fund_after, carry_after: c.carry_after, claims_after: c.claims_after, claim_haircuts: c.claim_haircuts.length, rows } : null,
      batch_conserves: conserved, cash_continuous: cont,
      settlements: (b.settlements || []).map((s) => ({ who: nameOf(b.accounts, s.channel), closed_usd: s.closed_usd, net_before: s.net_before_usd, net_after: s.net_after_usd,
        released: s.released_margin_sats, payout: s.payout_sats, realized: s.realized_pnl_sats })) };
    S.batchLog.push(rec);
    log('batch', rec);
    if (c && (c.shortfall > 0)) log('shortfall_batch', { seq: b.seq, layer: c.layer, shortfall: c.shortfall, fund_absorbed: c.fund_absorbed, haircut: c.haircut, carry_after: c.carry_after, fund_after: c.fund_after });
    if (c && conserved === false) S.identityBad += 1;
    await solvencyCheck(b.seq);
  }
}
const nameOf = (accounts, ch) => { const a = accounts.find((x) => x.channel.txid === ch.txid && x.channel.vout === ch.vout); return a ? (Object.values(accts).find((w) => w.owner === a.owner)?.name || a.owner.slice(0, 8)) : '?'; };
/** Identity + conservation: read status, every account, status again; accept only if the journal did not move. */
async function solvencyCheck(seq) {
  for (let k = 0; k < 6; k++) {
    const s1 = await api('/api/status');
    const bal = {};
    for (const n of Object.keys(accts)) bal[n] = (await api('/api/account/' + accts[n].owner)).balance;
    const s2 = await api('/api/status');
    if (s1.journal.digest !== s2.journal.digest) { await sleep(100); continue; }
    const c = s2.clearing; if (!c) return;
    const realized = sum(Object.values(bal).map((b) => b.realized_pnl));
    const e1 = c.identity === 0 || c.identity === '0' || Number(c.identity) === 0;
    const e2 = realized + c.cash === c.fund0;
    S.solvencyChecks += 1; if (!e1 || !e2) S.solvencyBad += 1;
    log('solvency', { after_batch: seq, identity: c.identity, identity_zero: e1, sum_realized_pnl: realized, cash: c.cash, fund0: c.fund0, realized_plus_cash_eq_fund0: e2,
      fund: c.fund, carry: c.carry, claims: c.claims, book: c.book });
    return;
  }
  log('solvency', { after_batch: seq, skipped: 'journal moved on every read' });
}

// ---------------------------------------------------------------- market makers
const MMS = [];
const cancelOrder = (w, o) => send(w, { action: 'cancel', side: o.side, quantity: 0, limit_usd: 0, leverage_bps: 0, max_fee_ppm: 0, max_fee_sats: 0, max_mark_age_us: 0, cancel_target: o.id }).catch(() => {});
let mmLock = Promise.resolve();
const mmRequote = (mark, asksOn = false) => (mmLock = mmLock.then(() => mmRequoteInner(mark, asksOn)).catch((e) => log('mm_error', { e: String(e) })));
async function mmRequoteInner(mark, asksOn = false) {
  await snapshot();
  const plan = [];
  // phase 1: cancel every quote that is not where it should be (the margin comes back after the router processes it)
  for (const m of MMS) {
    const w = accts[m.name];
    const v = S.views[m.name] || w.view;
    const open = (v.open_orders || []).filter((o) => o.status === 'resting' || o.status === 'queued');
    const wantSide = m.side === 'ask' ? 'short' : 'long';
    if (m.side === 'ask' && !asksOn) { for (const o of open) await cancelOrder(w, o); continue; }
    const px = Math.round(mark * (1 + (m.side === 'ask' ? 1 : -1) * m.bps / 1e4));
    const keep = open.find((o) => o.side === wantSide && Math.abs(o.limit_usd - px) / px < 0.001 && o.remaining >= 100 && o.expires_us / 1000 - Date.now() > 30e3);
    for (const o of open) if (o !== keep) await cancelOrder(w, o);
    if (!keep) plan.push({ m, w, px, wantSide });
  }
  await sleep(500); await snapshot();
  // verify: anything resting that is not the wanted quote gets one more cancel
  for (const m of MMS) {
    const w = accts[m.name]; const v = S.views[m.name];
    const want = plan.find((p) => p.m === m);
    const stale = (v.open_orders || []).filter((o) => (o.status === 'resting' || o.status === 'queued') && (want || (m.side === 'ask' && !asksOn)) && o.remaining > 0 && (!(m.side === 'ask' && asksOn)));
    for (const o of stale) { log('mm_cancel_retry', { mm: m.name, id: o.id.slice(0, 8), limit: o.limit_usd }); await cancelOrder(w, o); }
  }
  if (!plan.length) return;
  await sleep(400); await snapshot();
  for (const { m, w, px, wantSide } of plan) {
    const v = S.views[m.name] || w.view;
    const free = (v.balance || {}).free ?? 0; const hold = Math.ceil(m.qty * 1e8 / px / (m.lev / 1e4));
    if (free >= hold && !(v.position?.risk?.reduce_only)) {
      try { await send(w, { action: 'post', side: wantSide, quantity: m.qty, limit_usd: px, leverage_bps: m.lev }); }
      catch (e) { log('mm_refused', { mm: m.name, e: e.message }); }
    } else log('mm_skip', { mm: m.name, free, hold, net_usd: v.position?.net_usd || 0, reduce_only: !!v.position?.risk?.reduce_only });
  }
}
let mmLoopOn = true, mmAsks = false;
async function mmLoop() {
  while (mmLoopOn) { try { if (relay.price) await mmRequote(relay.price, mmAsks); } catch (e) { log('mm_error', { e: e.message }); } await sleep(4000); }
}

// ---------------------------------------------------------------- scenario helpers
async function waitFor(pred, ms, what) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { if (await pred()) return true; } catch { /* retry */ } await sleep(200); }
  log('wait_timeout', { what }); return false;
}
async function markIs(p) { return waitFor(async () => { const st = await api('/api/status'); S.status = st; return st.mark && Math.round(st.mark.price_usd) === p && st.mark.age_s < 5; }, 15000, 'venue mark ' + p); }
async function stepTo(p, holdMs, tag) {
  // Steps inside the 2% collar: the makers requote around the NEW mark first (their quotes at the
  // old mark would otherwise be hit above the new mark); a gap larger than the collar leaves
  // their old quotes unfillable, so they requote after the mark moves.
  const small = Math.abs(p - relay.price) / relay.price <= 0.015;
  if (small) { await mmRequote(p, mmAsks); await sleep(700); }
  await setPrice(p);
  const ok = await markIs(p);
  if (!small) await mmRequote(p, mmAsks);
  note(`mark ${p} (${tag || ''})${ok ? '' : ' venue mark not confirmed'}`, { price_usd: p });
  if (holdMs) await hold(holdMs);
}
async function allResolved(ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { const l = await api('/api/explorer/batches?limit=4'); if (l.every((b) => b.phase === 'committed' || b.phase === 'aborted')) return true; } catch { /* retry */ }
    await sleep(100);
  }
  log('wait_timeout', { what: 'all batches resolved' }); return false;
}
const hold = (ms) => sleep(Math.max(500, ms * SCALE));
async function settled(ms = 20000) {
  return waitFor(async () => {
    const s = S.status; if (!s) return false;
    const pend = Object.values(S.views).some((v) => (v.pending_signatures || []).length);
    const open = (S.batchLog.length ? true : true);
    return !pend && S.batchesSeen.size >= (s.router?.batch_sequence || 0);
  }, ms, 'settled');
}
const net = (n) => (S.views[n]?.position?.net_usd) ?? 0;
const cnet = (n) => (S.views[n]?.position?.committed_net_usd) ?? 0;
const riskOf = (n) => S.views[n]?.position?.risk || {};

// ---------------------------------------------------------------- main
async function main() {
  note('drill start', { fund_sats: FUND, out: OUT, relay_group_key: GROUP_PK });
  startRelay();
  await emit();
  const { state, errFile } = await startVenue();
  note('venue up', { state, log: errFile });
  template = await api('/api/template');
  check('venue pins the drill relay key and verifies its packets', template.group_key === GROUP_PK, { group_key: template.group_key });
  await markIs(100_000);
  const st0 = await api('/api/status');
  check('venue verified the mark (signed by the test key)', st0.mark && st0.mark.verified === true && st0.mark.price_usd === 100_000, { mark: st0.mark && st0.mark.price_usd });
  check('multilateral clearing is on with the requested fund', st0.clearing && st0.clearing.fund0 === FUND && st0.margin_release === true && st0.closing_loans === true, st0.clearing);

  // demo accounts (cap 200,000 sats each)
  await mkAcct('A', { lev: 100000, role: 'long 10x', autoliq: true });
  await mkAcct('B', { lev: 100000, role: 'short 10x' });
  await mkAcct('C', { lev: 80000, role: 'long 8x', autoliq: false }); // client offline until the gap
  await mkAcct('D', { lev: 100000, role: 'short 10x' });
  for (let i = 1; i <= 12; i++) {
    const side = i <= 8 ? 'bid' : 'ask';
    const name = 'MM' + i;
    await mkAcct(name, { lev: 50000, role: 'maker 5x ' + side });
    MMS.push({ name, side, bps: 30 + (side === 'bid' ? (i - 1) * 4 : (i - 9) * 4), qty: 500, lev: 50000 });
  }
  await snapshot();
  signLoop(); monitor(); batchLoop();
  mmLoop();
  for (const [n, w] of Object.entries(accts)) if (!n.startsWith('MM')) log('account', { name: n, role: w.role, cap_sats: w.view.cap_sats });

  // -- open the positions at 100,000
  note('opening: B posts a 2,000 USD ask (10x short), A takes it (10x long); C posts a 1,600 USD bid (8x long), D takes it (10x short)');
  const idB = await send(accts.B, { action: 'post', side: 'short', quantity: 2000, limit_usd: 100_000, leverage_bps: 100000 });
  const idC = await send(accts.C, { action: 'post', side: 'long', quantity: 1600, limit_usd: 100_000, leverage_bps: 80000 });
  check('B and C quotes rest', (await outcome(accts.B, idB)).status === 'resting' && (await outcome(accts.C, idC)).status === 'resting');
  const tA = await send(accts.A, { action: 'take', side: 'long', quantity: 2000, limit_usd: 100_000, leverage_bps: 100000 });
  const tD = await send(accts.D, { action: 'take', side: 'short', quantity: 1600, limit_usd: 100_000, leverage_bps: 100000 });
  check('A and D opening takes fill', (await outcome(accts.A, tA)).status === 'filled' && (await outcome(accts.D, tD)).status === 'filled');
  await waitFor(() => cnet('A') === 2000 && cnet('B') === -2000 && cnet('C') === 1600 && cnet('D') === -1600 && !Object.values(S.views).some((v) => (v.pending_signatures || []).length), 20000, 'positions committed');
  const open = Object.fromEntries(['A', 'B', 'C', 'D'].map((n) => [n, { net: net(n), free: S.views[n].balance.free, committed: S.views[n].balance.committed, margin: S.views[n].position.margin_sats, state: riskOf(n).state, liq: riskOf(n).liquidation_price_usd, bk: riskOf(n).bankruptcy_price_usd }]));
  log('opened', open);
  check('positions committed: A +2000, B -2000, C +1600, D -1600 USD', net('A') === 2000 && net('B') === -2000 && net('C') === 1600 && net('D') === -1600, open);
  check('A and C hold 0 free margin (their whole demo cap is committed)', open.A.free === 0 && open.C.free === 0, { A: open.A.free, C: open.C.free });

  if (QUICK) return quick(QUICK);
  // -- controls at 0 free margin, healthy
  await mmRequote(100_000, false); await sleep(1500);
  const up = await send(accts.A, { action: 'take', side: 'long', quantity: 10, limit_usd: 100_000, leverage_bps: 100000 }).catch((e) => ({ err: e.message }));
  note('A (0 free) tries to INCREASE by 10 USD with no ask resting: needs margin, expect rejection');
  // an ask for the increase to match against, so the rejection is about margin and not liquidity
  const askQ = await send(accts.MM9, { action: 'post', side: 'short', quantity: 100, limit_usd: 100_100, leverage_bps: 50000 }).catch((e) => ({ err: e.message }));
  await sleep(600);
  const inc = await send(accts.A, { action: 'take', side: 'long', quantity: 10, limit_usd: 100_200, leverage_bps: 100000 });
  const incO = await outcome(accts.A, inc, 6000);
  check('control: a healthy account with 0 free margin cannot INCREASE (rejected: Capacity)', incO.status === 'rejected' && /Capacity/.test(incO.reason || ''), incO);
  const red = await send(accts.A, { action: 'take', side: 'short', quantity: 10, limit_usd: 99_000, leverage_bps: 100000 });
  const redO = await outcome(accts.A, red, 8000);
  check('control: the same account CAN reduce by 10 USD with 0 free margin (closing loan)', redO.status === 'filled', redO);
  await settled(); await sleep(500);
  log('control_after', { A_net: net('A'), A_free: S.views.A.balance.free });

  // -- walk down
  note('--- walk down against the longs (A 10x, C 8x) ---');
  for (const p of [99_000, 98_000, 97_000, 96_000]) await stepTo(p, 7000, 'down');
  const aWarn = riskOf('A');
  await stepTo(95_000, 0, 'down: A crosses maintenance');
  const aLiq = await waitFor(() => net('A') <= 0 && riskOf('A').state !== 'maintenance', 150_000 * SCALE + 30000, 'A liquidated');
  await wedgeCheck('after A liquidation');
  await settled(30000);
  note('A after liquidation', { net: net('A'), state: riskOf('A').state, free: S.views.A.balance.free });
  for (const p of [94_000, 93_000, 92_000]) await stepTo(p, 6000, 'down');
  // C is in maintenance with its client offline: let the auction clock run, probe the gate
  await waitFor(() => riskOf('C').state === 'maintenance', 30000, 'C maintenance');
  note('C is below maintenance with its client offline; letting the auction clock run to the cap');
  await hold(66000);
  const cPlanLate = riskOf('C');
  await gateProbe('C', 'maintenance');

  // -- gap
  note('--- gap down to 88,000 (-12%) ---');
  await setPrice(88_000); await markIs(88_000);
  mmAsks = true; await mmRequote(88_000, true); await sleep(3000);
  await waitFor(() => riskOf('C').state === 'bankrupt', 20000, 'C bankrupt');
  await gateProbe('C', 'bankrupt');
  // D takes profit on its whole short (asks from MM9..MM12) right before C's client comes back
  note('D takes profit: closes its 1,600 USD short into MM asks at 88,000; C\'s client comes online straight after');
  const dIds = [];
  const asks = (S.book.asks || []).map((a) => a[0]);
  const askPx = Math.max(...asks);
  for (let i = 0; i < 4; i++) { dIds.push(await send(accts.D, { action: 'take', side: 'long', quantity: 400, limit_usd: askPx, leverage_bps: 100000 }).catch((e) => ({ err: e.message }))); if (SERIALIZE) { await outcome(accts.D, dIds[dIds.length - 1], 6000); await allResolved(); } }
  accts.C.autoliq = true; accts.C.liqLast = 0;
  const dRes = []; for (const id of dIds) dRes.push(typeof id === 'string' ? await outcome(accts.D, id, 10000) : id);
  log('d_take_profit', { results: dRes.map((r) => r.status || r.err) });
  await waitFor(() => net('C') === 0 && riskOf('C').state === 'flat', 120_000, 'C liquidated');
  await wedgeCheck('after C liquidation');
  await settled(30000); await sleep(1500);
  note('C after liquidation', { net: net('C'), state: riskOf('C').state });

  // -- back up
  note('--- walk back up ---');
  for (const p of [90_000, 92_000, 94_000, 96_000, 98_000, 100_000]) await stepTo(p, 5000, 'up');
  mmAsks = false;
  await settled(30000);

  // -- unwind to a flat book
  note('--- unwind to a flat book (pairwise closes) ---');
  await unwind();
  await settled(30000); await sleep(2000);
  const flat = Object.fromEntries(Object.keys(accts).map((n) => [n, net(n)]));
  check('book is flat after the unwind', Object.values(flat).every((x) => x === 0), flat);
  await solvencyCheck('final');

  // ------------------------------------------------------------ verdicts
  const T = S.transitions;
  const inOrder = (seq, want) => { let i = 0; for (const s of seq) if (s === want[i]) i += 1; return i === want.length; };
  check('A walked ok -> warning -> maintenance', inOrder(T.A || [], ['ok', 'warning', 'maintenance']), T.A);
  check('C walked ok -> warning -> maintenance -> bankrupt', inOrder(T.C || [], ['ok', 'warning', 'maintenance', 'bankrupt']), T.C);
  const plans = (n) => accts[n].plan.filter((p) => p.state === 'maintenance' || p.state === 'bankrupt');
  const cp = plans('C');
  const disc = cp.map((p) => p.discount);
  check('auction discount only grows while the breach lasts (C, client offline)', disc.length >= 4 && disc.every((d, i) => i === 0 || d >= disc[i - 1]), disc);
  check('auction discount reaches the 200 bps cap after the 60 s auction', Math.max(...disc, 0) === 200, { max: Math.max(...disc, 0) });
  const limitsLong = cp.filter((p) => p.mark_usd === 92_000).map((p) => p.limit_usd);
  check('the auction limit moves away from the mark as the discount grows (C at 92,000)', limitsLong.length >= 3 && limitsLong.every((l, i) => i === 0 || l <= limitsLong[i - 1]) && limitsLong[limitsLong.length - 1] < limitsLong[0], limitsLong);
  check('plan carries a tranche and the reduce side', cp.every((p) => p.tranche_usd > 0 && p.reduce_side === 'short'), cp.slice(0, 2));
  const aTakes = S.liqEvents.filter((e) => e.acct === 'A');
  const cTakes = S.liqEvents.filter((e) => e.acct === 'C');
  const filled = (evs) => sum(evs.flatMap((e) => e.results).filter((r) => r.status === 'filled').map((r) => r.qty));
  check('client auto-liquidation closed A (planTakes from ui/venue/liquidate.js)', filled(aTakes) > 0 && net('A') === 0, { filled_usd: filled(aTakes), takes: aTakes.length });
  check('client auto-liquidation closed C past bankruptcy', filled(cTakes) > 0 && net('C') === 0, { filled_usd: filled(cTakes), takes: cTakes.length });
  const loanFills = S.liqEvents.flatMap((e) => e.results.filter((r) => r.status === 'filled' && r.leg_margin_sats > (r.free_before ?? 0)));
  check('closing takes with free margin below the leg margin filled (closing loan): A and C had 0 free', loanFills.length > 0, { n: loanFills.length, example: loanFills[0] });
  const sf = S.batchLog.filter((b) => b.clearing && b.clearing.shortfall > 0);
  check('a close past bankruptcy produced a clearing shortfall', sf.length > 0, sf.map((b) => ({ seq: b.seq, layer: b.clearing.layer, shortfall: b.clearing.shortfall, fund: b.clearing.fund_absorbed, haircut: b.clearing.haircut, carry_after: b.clearing.carry_after })));
  if (FUND > 0) check('with a fund, the shortfall layer is Fund', sf.some((b) => b.clearing.layer === 'Fund'), sf.map((b) => b.clearing.layer));
  else check('with fund 0, the shortfall layer is Haircut or Carried', sf.some((b) => ['Haircut', 'Carried'].includes(b.clearing.layer)), sf.map((b) => b.clearing.layer));
  check('every committed batch conserves (sum of nets + pool delta = 0) and the pool never goes negative', S.batchLog.every((b) => b.batch_conserves !== false && (!b.clearing || b.clearing.cash_after >= 0)), { batches: S.batchLog.length });
  check('the pool cash chain is continuous batch to batch', S.batchLog.every((b) => b.cash_continuous !== false), {});
  check('solvency identity is 0 and sum(realized)+cash == fund0 at every checked batch', S.solvencyChecks > 0 && S.solvencyBad === 0, { checks: S.solvencyChecks, bad: S.solvencyBad });
  const aborted = S.batchLog.filter((b) => b.phase === 'aborted').length;
  check('no batch aborted for a missing signature', aborted === 0, { aborted });
  const failed = results.filter((r) => !r.ok).length;
  const finalAccts = {};
  for (const n of Object.keys(accts)) { const b = S.views[n].balance; finalAccts[n] = { cap: b.cap, free: b.free, committed: b.committed, realized_pnl: b.realized_pnl, equity: b.equity, net_usd: net(n), claim: S.views[n].position.deferred_claim_sats }; }
  log('final_accounts', finalAccts);
  log('summary', { passed: results.length - failed, failed, total: results.length, fund_sats: FUND, batches: S.batchLog.length, relay_packets: relay.seq, solvency_checks: S.solvencyChecks });
  console.log(`\n${results.length - failed}/${results.length} assertions passed. log: ${OUT}`);
  await finish(failed ? 1 : 0);
}

async function stuckBatches(ageMs = 5000) {
  const list = await api('/api/explorer/batches?limit=60');
  return list.filter((b) => (b.phase === 'sealed' || b.phase === 'prepared') && Date.now() * 1000 - b.created_us > ageMs * 1000).map((b) => ({ seq: b.seq, phase: b.phase, legs: b.legs.length, accounts: b.accounts.length }));
}
/** Reduce-only gate against committed lots: A in maintenance sells down to 100 USD, then two takes of 90 USD go in back to back. */
async function quickOvershoot() {
  await setPrice(95_000); await markIs(95_000); await mmRequote(95_000, false);
  await waitFor(() => riskOf('A').state === 'maintenance', 15000, 'A maintenance');
  const sell = (q) => send(accts.A, { action: 'take', side: 'short', quantity: q, limit_usd: 90_000, leverage_bps: 100000, max_fee_ppm: 0, max_fee_sats: 1 });
  for (const q of [500, 500, 500, 400]) { const id = await sell(q); await outcome(accts.A, id, 8000); await allResolved(); await sleep(400); }
  await snapshot();
  const before = { notional_usd: riskOf('A').notional_usd, net_usd: net('A'), committed_net_usd: cnet('A'), free: S.views.A.balance.free, state: riskOf('A').state, reduce_only: riskOf('A').reduce_only };
  const a = await sell(90), b = await sell(90);
  const res = [await outcome(accts.A, a, 8000), await outcome(accts.A, b, 8000)];
  await allResolved(); await sleep(800); await snapshot();
  const after = { net_usd: net('A'), committed_net_usd: cnet('A'), free: S.views.A.balance.free, state: riskOf('A').state, side: S.views.A.position.lots.map((l) => l.side + ':' + l.qty_usd) };
  log('overshoot_result', { before, takes: [90, 90], outcomes: res.map((r) => r.status), after });
  check('DEFECT F3: a reduce-only account holding 100 USD cannot sell 180 USD (two takes of 90 each pass the gate against committed lots)', after.net_usd >= 0, { before, after, outcomes: res.map((r) => r.status) });
  await finish(after.net_usd >= 0 ? 0 : 1);
}
/** Closing loan across two batches in flight: A (0 free margin, healthy, 100,000) reduces by 10 USD twice, `gap` ms apart. */
async function quickSplit(variant) {
  const gap = Number(variant.replace('split', '') || 150);
  await mmRequote(100_000, false); await sleep(1500);
  const mk = (q) => send(accts.A, { action: 'take', side: 'short', quantity: q, limit_usd: 99_000, leverage_bps: 100000, max_fee_ppm: 0, max_fee_sats: 1 });
  const before = { free: S.views.A.balance.free, committed: S.views.A.balance.committed };
  const id1 = await mk(10); await sleep(gap); const id2 = await mk(10);
  const res = [await outcome(accts.A, id1, 8000), await outcome(accts.A, id2, 8000)];
  await sleep(8000);
  const stuck = await stuckBatches(5000);
  const list = await api('/api/explorer/batches?limit=4');
  log('quick_result', { variant, gap_ms: gap, A_before: before, fills: res.map((r) => ({ status: r.status, reason: r.reason, batch: r.fill && r.fill.batch_seq })), stuck_batches: stuck, last_batches: list.map((x) => ({ seq: x.seq, phase: x.phase, legs: x.legs.length, accounts: x.accounts.length })) });
  check(`quick ${variant}: two closing takes ${gap} ms apart both settle (no batch stuck past 5 s)`, stuck.length === 0, { stuck, batches: list.map((x) => [x.seq, x.phase]) });
  await finish(stuck.length ? 1 : 0);
}
/** Isolation runs for the stuck-batch finding: open C/D, gap to 88,000, then one of a few close patterns. */
async function quick(variant) {
  accts.A.autoliq = false; accts.C.autoliq = false;
  if (variant.startsWith('split')) return quickSplit(variant);
  if (variant === 'overshoot') return quickOvershoot();
  mmAsks = true;
  await setPrice(88_000); await markIs(88_000); await mmRequote(88_000, true); await sleep(2500);
  await waitFor(() => riskOf('C').state === 'bankrupt', 20000, 'C bankrupt');
  const book = await api('/api/book?depth=25');
  const askPx = Math.max(...book.asks.map((a) => a[0]));
  const cTake = (q) => send(accts.C, { action: 'take', side: 'short', quantity: q, limit_usd: 85_000, leverage_bps: 100000, max_fee_ppm: 0, max_fee_sats: 1 });
  const dTake = (q) => send(accts.D, { action: 'take', side: 'long', quantity: q, limit_usd: askPx, leverage_bps: 100000 });
  const ids = [];
  if (variant === 'c1') ids.push(['C', await cTake(1)]);
  if (variant === 'c400') ids.push(['C', await cTake(400)]);
  if (variant === 'd400') ids.push(['D', await dTake(400)]);
  if (variant === 'c1d400') { ids.push(['C', await cTake(1)]); ids.push(['D', await dTake(400)]); }
  if (variant === 'c400d400') { ids.push(['C', await cTake(400)]); ids.push(['D', await dTake(400)]); }
  const res = []; for (const [n, id] of ids) res.push({ acct: n, ...(await outcome(accts[n], id, 8000)) });
  await sleep(8000);
  const stuck = await stuckBatches(5000);
  const b = (await api('/api/explorer/batches?limit=3'));
  log('quick_result', { variant, fills: res.map((r) => ({ acct: r.acct, status: r.status, reason: r.reason })), stuck_batches: stuck, last_batches: b.map((x) => ({ seq: x.seq, phase: x.phase, legs: x.legs.length, accounts: x.accounts.length, layer: x.clearing && x.clearing.layer })) });
  check(`quick ${variant}: every batch resolves (none stuck past 5 s in sealed/prepared)`, stuck.length === 0, stuck);
  await finish(stuck.length ? 1 : 0);
}

async function wedgeCheck(tag) {
  const stuck = await stuckBatches(8000);
  if (!stuck.length) return;
  log('wedged', { at: tag, stuck });
  check(`venue settlement not wedged (${tag})`, false, stuck);
  log('summary', { passed: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, total: results.length, wedged_at: tag });
  await finish(1);
}

async function gateProbe(name, label) {
  const w = accts[name]; const held = riskOf(name).notional_usd ?? Math.abs(net(name)); const side = net(name) > 0 ? 'long' : 'short'; const other = side === 'long' ? 'short' : 'long';
  const px = relay.price;
  const inc = await sendRaw(w, { action: 'take', side, quantity: 5, limit_usd: side === 'long' ? px + 500 : px - 500, leverage_bps: 100000 });
  const flip = await sendRaw(w, { action: 'take', side: other, quantity: held + 1, limit_usd: other === 'short' ? px - 500 : px + 500, leverage_bps: 100000 });
  const post = await sendRaw(w, { action: 'post', side, quantity: 5, limit_usd: px, leverage_bps: 100000 });
  const text = (r) => r.json && r.json.error;
  log('gate_probe', { acct: name, state: label, held, side, increase: { status: inc.status, error: text(inc) }, flip: { status: flip.status, error: text(flip) }, post: { status: post.status, error: text(post) } });
  const refused = (r) => r.status === 409 && /only orders that reduce the position/.test(text(r) || '');
  check(`reduce-only gate (${name} ${label}): increase, flip and a new increasing quote are all refused`, refused(inc) && refused(flip) && refused(post), { increase: text(inc), flip: text(flip), post: text(post) });
  // a reducing order is accepted at the gate (it queues; it fills only if a bid/ask is inside the collar)
  const red = await sendRaw(w, { action: 'take', side: other, quantity: 1, limit_usd: other === 'short' ? px - 500 : px + 500, leverage_bps: 100000 });
  check(`reduce-only gate (${name} ${label}): a reducing order is accepted`, red.status === 200, { status: red.status, error: text(red) });
  if (SERIALIZE) { await outcome(w, red.id, 6000); await allResolved(); }
}

async function unwind() {
  for (let round = 0; round < 60; round++) {
    await snapshot();
    const pos = Object.keys(accts).map((n) => ({ n, net: net(n), free: S.views[n].balance.free })).filter((x) => x.net !== 0);
    if (!pos.length) return;
    const px = relay.price;
    const unit = (1e8 / px) / 10; // sats of 10x margin per USD
    let best = null;
    for (const L of pos.filter((x) => x.net > 0)) for (const Sh of pos.filter((x) => x.net < 0)) for (const makerIsLong of [true, false]) {
      const mk = makerIsLong ? L : Sh;
      const q = Math.min(L.net, -Sh.net, 400, Math.floor(mk.free / Math.ceil(unit)));
      if (q > 0 && (!best || q > best.q)) best = { L, Sh, mk, tk: makerIsLong ? Sh : L, makerIsLong, q };
    }
    if (!best) { log('unwind_stuck', { pos }); return; }
    const { mk, tk, makerIsLong, q } = best;
    try {
      const quotePx = makerIsLong ? px + 20 : px - 20;
      const idm = await send(accts[mk.n], { action: 'post', side: makerIsLong ? 'short' : 'long', quantity: q, limit_usd: quotePx, leverage_bps: 100000 });
      await outcome(accts[mk.n], idm, 4000);
      const idt = await send(accts[tk.n], { action: 'take', side: makerIsLong ? 'long' : 'short', quantity: q, limit_usd: quotePx, leverage_bps: 100000 });
      const o = await outcome(accts[tk.n], idt, 8000);
      log('unwind_pair', { maker: mk.n, taker: tk.n, qty: q, price: quotePx, status: o.status, reason: o.reason });
      if (o.status !== 'filled') await cancelOrder(accts[mk.n], { id: idm, side: makerIsLong ? 'short' : 'long' });
    } catch (e) { log('unwind_error', { e: e.message }); }
    await allResolved(15000);
  }
}

async function finish(code) {
  shuttingDown = true; S.running = false; mmLoopOn = false;
  await sleep(300);
  try { venueProc && venueProc.kill(); } catch { /* gone */ }
  process.exit(code);
}
process.on('unhandledRejection', (e) => { console.error('unhandled', e); log('fatal', { e: String(e && e.stack || e) }); finish(2); });
main().catch((e) => { console.error(e); log('fatal', { e: String(e && e.stack || e) }); finish(2); });
