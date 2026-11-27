// Spot drill: the BTC/USDT spot path of the venue against a LOCAL venue and a scripted relay.
//
//   node drill.mjs [--out ../results/spot-drill.jsonl] [--port 18395] [--relay-port 18391] [--demo]
//
// One process hosts a signed test relay (oracle mark packets, BTC/USD 90,000, under one local test
// key the venue pins as its group key; no DLC events). It starts a debug shz-venue with
// --options --stable-usdt <demo id> --spot on a fresh state dir, runs the demo market maker
// ops/venue-mm/spot_mm.py against it, and drives a browser-style client through the HTTP API with
// the page's own code (ui/venue/crypto.js signSpotIntent, signTransfer, bip340Sign for the V4
// acks; ui/venue/spot.js for prices, lots and the IOC walk):
//
//   the maker quotes both sides around the mark; the client buys at market and sells at market,
//   each one spot batch staged, then committed by owner/peer/monitor acks (the maker's bot signs
//   its own); BTC and USDT both move per asset, each account's change equals its clearing row in
//   that asset and each asset nets to zero; a resting bid locks USDT and its cancel unlocks it; a
//   take whose client withholds its ack is fence-aborted at the deadline: neither leg moves and the
//   maker's pulled order returns its lock to free; the tape, the BitcoinWisdom candles
//   (/v1/candles SHZ-BTCUSDT-SPOT) and the WS events follow the commits; restart recovery; and a
//   venue without --spot keeps every spot endpoint off.
//
//   --demo: stop after the maker quotes and the client's two trades, keep relay, venue, maker and
//   the client's auto-signer running for a browser session at http://127.0.0.1:<port>/ .
//
// Never talks to anything but 127.0.0.1. State dirs go under --work (default D:/shz/tmp).

import http from 'node:http';
import { spawn } from 'node:child_process';
import { appendFileSync, writeFileSync, mkdirSync, openSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, unhex, bip340Sign, pubkey, taggedHash, sha256, signSpotIntent, signTransfer } from '../../../ui/venue/crypto.js';
import { marketLimit, walk, satsFromBtc, priceToBase, quoteUnits } from '../../../ui/venue/spot.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const OUT = path.resolve(arg('out', path.join(HERE, '..', 'results', 'spot-drill.jsonl')));
const WORK = arg('work', 'D:/shz/tmp');
const VENUE_BIN = arg('venue-bin', 'D:/shz/target-msvc/debug/shz-venue.exe');
const VPORT = Number(arg('port', '18395'));
const RPORT = Number(arg('relay-port', '18391'));
const UI_DIR = path.resolve(HERE, '..', '..', '..', 'ui', 'venue');
const DEMO = process.argv.includes('--demo');
const PYTHON = arg('python', 'C:/Users/patri/AppData/Local/Programs/Python/Python312/python.exe');
const MM_SCRIPT = path.resolve(HERE, '..', '..', 'venue-mm', 'spot_mm.py');
const VENUE = `http://127.0.0.1:${VPORT}`;
const ABORT_AFTER_MS = 10_000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now();
const te = (s) => new TextEncoder().encode(s);

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

// ---------------------------------------------------------------- scripted relay (marks only)
const GROUP_SK = await sha256(te('shz-spot-drill/test-group-key/v1'));
const GROUP_PK = hex(pubkey(GROUP_SK));
const canon = (v) => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
  : JSON.stringify(v);
const relay = { seq: 0, price: 90_000, latest: null, clients: new Set() };
async function emit() {
  relay.seq += 1;
  const us = Date.now() * 1000;
  const body = { schema: 'shz-public-relay/v1', market: 'BTC/USD', data_class: 'public_delayed', seq: relay.seq,
    previous: '0'.repeat(64), interval_ms: 1000, slot_us: us, assembled_us: us, status: 'VALID', median_e8: Math.round(relay.price * 1e8) };
  const digest = await taggedHash('SHZ/PUBLIC-RELAY-PACKET/V1', te(canon(body)));
  const pkt = { body, digest: hex(digest), signature: hex(await bip340Sign(digest, GROUP_SK)), frost_signers: ['spot-drill-test-key'] };
  relay.latest = pkt;
  for (const res of relay.clients) res.write(`data: ${JSON.stringify(pkt)}\n\n`);
}
function startRelay() {
  const json = (res, code, o) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
  const srv = http.createServer((req, res) => {
    if (req.url === '/v1/pubkey') return json(res, 200, { pubkey_bip340: GROUP_PK });
    if (req.url === '/v1/latest') return json(res, 200, relay.latest);
    if (req.url === '/v1/stream') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
      relay.clients.add(res); req.on('close', () => relay.clients.delete(res)); return;
    }
    if (req.url === '/v1/dlc/events') return json(res, 200, { oracle_pubkey_x: GROUP_PK, events: [] });
    json(res, 404, {});
  });
  srv.listen(RPORT, '127.0.0.1');
  setInterval(() => { emit().catch((e) => console.error('emit', e)); }, 1000);
}

// ---------------------------------------------------------------- processes
const USDT_ID = hex(await sha256(te('shz-spot-drill/demo-usdt-rgb-contract/v1')));
const procs = new Set();
let shuttingDown = false;
async function startVenue(state, port, extra, tag) {
  const errFile = path.join(WORK, `spot-drill-venue-${tag}-${port}.log`);
  const fd = openSync(errFile, 'a');
  const p = spawn(VENUE_BIN, ['--listen', `127.0.0.1:${port}`, '--state', state, '--ui', UI_DIR, '--relay', `http://127.0.0.1:${RPORT}`,
    '--group-key', GROUP_PK, '--mempool-api', 'http://127.0.0.1:9/none', ...extra], { stdio: ['ignore', fd, fd] });
  procs.add(p);
  p.on('exit', (c) => { procs.delete(p); if (!shuttingDown && !p.expectedExit) { console.error(`${tag} exited`, c); finish(3); } });
  for (let i = 0; i < 100; i++) { try { await fetchJson(`http://127.0.0.1:${port}/api/status`); return p; } catch { await sleep(200); } }
  throw new Error('venue did not start');
}
async function stopProc(p) { p.expectedExit = true; p.kill(); await new Promise((r) => (p.exitCode !== null ? r() : p.on('exit', r))); }
function startMM(state) {
  const fd = openSync(path.join(WORK, `spot-drill-mm-${VPORT}.jsonl`), 'a');
  const p = spawn(PYTHON, ['-I', MM_SCRIPT, 'run', '--server', VENUE, '--state-dir', state, '--poll-s', '0.3', '--fund-sats', '150000', '--deposit-usdt', '2000'], { stdio: ['ignore', fd, fd] });
  procs.add(p);
  p.on('exit', (c) => { procs.delete(p); if (!shuttingDown && !p.expectedExit) { console.error('spot_mm exited', c); finish(3); } });
  return p;
}

// ---------------------------------------------------------------- http helpers
async function fetchJson(url, body) {
  const r = await fetch(url, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { /* none */ }
  return { status: r.status, json: j };
}
async function api(p, body) { const r = await fetchJson(VENUE + p, body); if (r.status >= 300) throw new Error(`${p}: ${r.status} ${r.json && r.json.error}`); return r.json; }

// ---------------------------------------------------------------- the browser-style client
let template, pair;
const client = { name: 'client', sk: null, owner: null, outpoint: null, seq: Date.now() * 1000, offline: false, signed: new Set(), view: null };
let xferNonce = 0;
async function transfer(op, amount, asset = null) {
  xferNonce += 1;
  const body = await signTransfer(op, { owner: client.owner, asset, amount, expires_us: (Date.now() + 60_000) * 1000 + xferNonce }, client.sk);
  return api('/api/options/' + op, body);
}
async function spotIntent(f) {
  client.seq += 1;
  const { id, intent } = await signSpotIntent({ owner: client.owner, channel: { txid: client.outpoint.txid, vout: client.outpoint.vout }, pair: pair.pair,
    sequence: client.seq, expires_us: (Date.now() + 120e3) * 1000, ...f }, template, client.sk);
  const r = await fetchJson(VENUE + '/api/spot/intents', { intent });
  return { id, status: r.status, ...r.json };
}
async function view(owner) { return api('/api/account/' + owner); }
/** The page's autoSign: every pending signature of the account, signed with its key. */
async function signLoop() {
  for (;;) {
    try {
      client.view = await view(client.owner);
      const todo = client.offline ? [] : (client.view.pending_signatures || []).filter((x) => !client.signed.has(x.id));
      if (todo.length) {
        const items = [];
        for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), client.sk)) });
        await api('/api/signatures', { owner: client.owner, items });
        for (const x of todo) { client.signed.add(x.id); log('signed', { id: x.id, kind: x.kind, batch_kind: x.context?.batch_kind }); }
      }
    } catch (e) { log('sign_error', { e: e.message }); }
    await sleep(80);
  }
}
/** Per account and asset: total = free + spot-locked + option-locked. */
async function wallets(owners) {
  const out = {};
  for (const [name, o] of Object.entries(owners)) {
    const v = await view(o);
    out[name] = Object.fromEntries((v.spot?.balances || []).map((b) => [b.asset, { free: b.free, spot_locked: b.spot_locked, total: b.free + b.spot_locked + b.option_locked }]));
  }
  return out;
}

// ---------------------------------------------------------------- WS capture
const wsEvents = [];
function openWs() {
  const ws = new WebSocket(`ws://127.0.0.1:${VPORT}/api/stream`);
  ws.onmessage = (ev) => { try { const m = JSON.parse(ev.data); if (String(m.type).startsWith('spot') || (m.type === 'option_batch' && m.batch?.kind === 'spot')) { wsEvents.push(m); log('ws', { type: m.type, phase: m.phase, n: m.n ?? m.batch?.n }); } } catch { /* ignore */ } };
  return ws;
}
async function waitFor(pred, ms, what) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { const v = await pred(); if (v) return v; } catch { /* retry */ } await sleep(150); }
  log('wait_timeout', { what }); return null;
}
async function batchN(n) { return (await api('/api/options/batches?limit=100')).find((b) => b.n === n); }
async function resolved(n, ms = 20000) { return waitFor(async () => { const b = await batchN(n); return b && b.phase !== 'staged' ? b : null; }, ms, 'batch ' + n); }

/** Each account's change in each asset equals its clearing row's net; every asset nets to zero; no one else moved. */
function rowsMatch(b, before, after, ownerName) {
  const bad = [];
  const touched = new Set();
  for (const c of b.clearing) {
    let sum = 0;
    for (const r of c.rows) {
      const n = ownerName(r.owner); touched.add(n + '/' + c.asset); sum += r.net;
      const d = after[n][c.asset].total - before[n][c.asset].total;
      if (d !== r.net) bad.push({ acct: n, asset: c.asset, net: r.net, delta: d });
    }
    if (sum !== 0 || c.pool_net !== 0) bad.push({ asset: c.asset, sum, pool_net: c.pool_net });
  }
  for (const n of Object.keys(after)) for (const a of Object.keys(after[n])) {
    if (!touched.has(n + '/' + a) && after[n][a].total !== before[n][a].total) bad.push({ acct: n, asset: a, untouched_moved: after[n][a].total - before[n][a].total });
  }
  return bad;
}

async function main() {
  startRelay();
  await emit();
  const state = path.join(WORK, `spot-drill-${process.pid}-${Date.now()}`);
  let venue = await startVenue(state, VPORT, ['--options', '--stable-usdt', USDT_ID, '--spot'], 'spot');
  const status = await api('/api/status');
  check('venue runs spot on the options desk', status.spot?.enabled && status.options?.enabled && status.options?.acks, { spot: status.spot?.market, lot: status.spot?.lot_sats, tick: status.spot?.tick });
  template = await api('/api/template');
  await waitFor(async () => (await api('/api/spot/book')).mark_usd, 15000, 'oracle mark');
  pair = (await api('/api/spot/book')).pair;
  openWs();

  // ---- maker
  const mmState = path.join(state, 'mm');
  let mm = startMM(mmState);
  const quoted = await waitFor(async () => { const b = await api('/api/spot/book'); return b.bids.length >= 3 && b.asks.length >= 3 ? b : null; }, 30000, 'maker quotes');
  check('maker quotes three levels each side around the mark', !!quoted, quoted && { best_bid: quoted.bids[0]?.[0], best_ask: quoted.asks[0]?.[0], mark: quoted.mark_usd });
  if (!quoted) return finish(1);
  const mark = quoted.mark_usd * 10 ** pair.quote.decimals;
  check('maker bid below and ask above the oracle mark, on the tick', quoted.bids[0][0] < mark && quoted.asks[0][0] > mark && [...quoted.bids, ...quoted.asks].every((l) => l[0] % pair.tick === 0), { bid: quoted.bids[0][0], ask: quoted.asks[0][0], mark });
  const mmOwner = await waitFor(async () => {
    const accts = await api('/api/explorer/accounts');
    const list = Array.isArray(accts) ? accts : accts.accounts || [];
    for (const a of list) { const v = await view(a.owner); if ((v.spot?.open_orders || []).length) return a.owner; }
    return null;
  }, 10000, 'maker account');
  check('maker account found', !!mmOwner);

  // ---- client: register, fund the shared asset wallet
  client.sk = await sha256(te('shz-spot-drill/account/client'));
  client.owner = hex(pubkey(client.sk));
  const d = await api('/api/register/draft', { owner: client.owner, kind: 'demo', outpoint: null });
  client.outpoint = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(await bip340Sign(unhex(d.allocation_digest), client.sk)) })).account.outpoint;
  await transfer('fund', 100_000);
  await transfer('deposit', 1_000_000_000, { kind: 'stable', protocol: pair.quote.protocol, id: pair.quote.id, decimals: pair.quote.decimals });
  signLoop();
  const owners = { client: client.owner, mm: mmOwner };
  const ownerName = (o) => Object.entries(owners).find(([, v]) => v === o)?.[0] || o?.slice(0, 8);
  const w0 = await wallets(owners);
  check('client wallet funded: 100,000 sats and 1,000 USDT', w0.client.BTC.free === 100_000 && w0.client.USDT.free === 1_000_000_000, w0.client);

  // ---- buy at market (IOC against the maker's asks)
  let n = 0;
  async function trade(label, buy, btcAmt) {
    const book = await api('/api/spot/book?depth=40');
    const sats = satsFromBtc(btcAmt, pair);
    const side = buy ? book.asks : book.bids;
    const limit = marketLimit(side, buy, pair);
    const est = walk(side, sats, buy, limit);
    const before = await wallets(owners);
    const r = await spotIntent({ action: 'take', buy, qty_sats: sats, price: limit });
    check(`${label}: take staged as a spot batch`, r.status === 200 && r.outcome === 'staged', { status: r.status, outcome: r.outcome, error: r.error, batch: r.batch });
    if (r.outcome !== 'staged') return null;
    n = r.batch;
    const b = await resolved(n);
    const after = await wallets(owners);
    check(`${label}: committed on every lane's acknowledgement`, b?.phase === 'committed' && b.acks.every((a) => a.owner_signed), { phase: b?.phase, lanes: b?.acks.length });
    const f = b?.spot || [];
    const got = f.reduce((x, y) => x + y.sats, 0), paid = f.reduce((x, y) => x + y.quote_units, 0);
    check(`${label}: fills match the book walk (${got} sats for ${paid / 1e6} USDT)`, got === est.sats && paid === est.quote && f.every((x) => x.quote_units === quoteUnits(x.sats, x.price)), { est, got, paid });
    const sgn = buy ? 1 : -1;
    check(`${label}: BTC and USDT both moved, buyer to seller and seller to buyer`,
      after.client.BTC.total - before.client.BTC.total === sgn * got && after.client.USDT.total - before.client.USDT.total === -sgn * paid &&
      after.mm.BTC.total - before.mm.BTC.total === -sgn * got && after.mm.USDT.total - before.mm.USDT.total === sgn * paid,
    { client: [after.client.BTC.total - before.client.BTC.total, after.client.USDT.total - before.client.USDT.total], mm: [after.mm.BTC.total - before.mm.BTC.total, after.mm.USDT.total - before.mm.USDT.total] });
    const bad = rowsMatch(b, before, after, ownerName);
    check(`${label}: one clearing row per account per asset equals its change; each asset nets to zero`, !bad.length && b.clearing.map((c) => c.asset).join() === 'BTC,USDT' && b.clearing.every((c) => c.rows.length === 2), bad.length ? bad : b.clearing.map((c) => ({ asset: c.asset, rows: c.rows.map((x) => [ownerName(x.owner), x.net]) })));
    return { b, got, paid };
  }
  const t1 = await trade('buy 0.0005 BTC at market', true, '0.0005');
  await sleep(1500);
  const t2 = await trade('sell 0.0003 BTC at market', false, '0.0003');
  const tape = await api('/api/spot/trades?limit=10');
  check('trades tape lists both commits newest first', tape.length >= 2 && tape[0].taker_side === 'sell' && tape.some((t) => t.taker_side === 'buy'), tape.slice(0, 3).map((t) => [t.batch, t.taker_side, t.sats, t.price]));
  const candles = await api('/v1/candles?instrument=SHZ-BTCUSDT-SPOT&interval=1m&limit=10');
  const lastC = candles.candles.at(-1);
  check('chart candles (SHZ-BTCUSDT-SPOT) follow the spot fills', candles.instrument === 'SHZ-BTCUSDT-SPOT' && lastC && lastC.close === tape[0].price / 1e6 && lastC.volume > 0, lastC);
  const ev = (type, phase) => wsEvents.filter((e) => e.type === type && (!phase || e.phase === phase)).length;
  check('WS: spot_batch staged and committed, spot_trade per fill, spot_book', ev('spot_batch', 'staged') >= 2 && ev('spot_batch', 'committed') >= 2 && ev('spot_trade') >= 2 && ev('spot_book') >= 2,
    { staged: ev('spot_batch', 'staged'), committed: ev('spot_batch', 'committed'), trades: ev('spot_trade'), book: ev('spot_book') });

  if (DEMO) {
    note(`demo: venue ${VENUE}/ (Spot tab), maker quoting, client auto-signing; Ctrl+C to stop`);
    return;
  }

  // ---- resting bid locks USDT, cancel unlocks it
  const bk = await api('/api/spot/book');
  const bidPx = bk.bids[0][0] - 50 * pair.tick;
  const wb = await wallets(owners);
  const post = await spotIntent({ action: 'post', buy: true, qty_sats: 10_000, price: bidPx });
  const wl = await wallets(owners);
  const lock = quoteUnits(10_000, bidPx);
  check('a resting bid locks exactly its USDT', post.outcome === 'posted' && wl.client.USDT.spot_locked === lock && wl.client.USDT.free === wb.client.USDT.free - lock, { lock, w: wl.client.USDT });
  const crossing = await spotIntent({ action: 'post', buy: true, qty_sats: 1_000, price: bk.asks[0][0] });
  check('a post-only bid that would cross is refused', crossing.status === 409, { status: crossing.status, error: crossing.error });
  // (An IOC take only pays for what crosses its limit; the router suite covers a taker that cannot pay its fills.)
  const tooBig = await spotIntent({ action: 'post', buy: false, qty_sats: 50_000_000, price: bk.asks[0][0] + 100 * pair.tick });
  check('a sell the wallet cannot fund is refused', tooBig.status === 409 && /Capacity/.test(tooBig.error || ''), { status: tooBig.status, error: tooBig.error });
  const cx = await spotIntent({ action: 'cancel', cancel_target: post.id });
  const wc = await wallets(owners);
  check('cancel unlocks it', cx.outcome === 'cancelled' && wc.client.USDT.spot_locked === 0 && wc.client.USDT.free === wb.client.USDT.free, wc.client.USDT);

  // ---- an unsigned batch aborts at the deadline: neither leg moves, both sides unlock
  await waitFor(async () => (await api('/api/spot/book')).asks.length >= 3, 10000, 'maker requote');
  client.offline = true;
  const ab = await api('/api/spot/book?depth=40');
  const mmBefore = await view(mmOwner);
  const before = await wallets(owners);
  const lim = marketLimit(ab.asks, true, pair);
  const r = await spotIntent({ action: 'take', buy: true, qty_sats: 20_000, price: lim });
  check('withheld ack: take staged', r.outcome === 'staged', r);
  const pulled = (await batchN(r.batch))?.spot.map((f) => f.maker) || [];
  const b = await resolved(r.batch, ABORT_AFTER_MS + 8000);
  const after = await wallets(owners);
  check('withheld ack: fence-aborted at the deadline', b?.phase === 'aborted' && b.acks.some((a) => !a.owner_signed), { phase: b?.phase });
  check('withheld ack: neither leg moved (BTC and USDT totals unchanged for both)', ['client', 'mm'].every((x) => ['BTC', 'USDT'].every((a) => after[x][a].total === before[x][a].total)), { before, after });
  check('withheld ack: client wallet untouched', JSON.stringify(after.client) === JSON.stringify(before.client), after.client);
  const mmIntents = (await view(mmOwner)).spot.intents;
  const pulledRecs = mmIntents.filter((i) => pulled.includes(i.id));
  check('withheld ack: the maker order in the batch is pulled and its BTC lock returned to free', pulledRecs.length === pulled.length && pulledRecs.every((i) => i.status === 'cancelled') &&
    after.mm.BTC.total === before.mm.BTC.total, { pulled: pulledRecs.map((i) => [i.status, i.reason]), mm_btc: [before.mm.BTC, after.mm.BTC], mm_orders_before: mmBefore.spot.open_orders.length });
  const ci = (await view(client.owner)).spot.intents.find((i) => i.id === r.id);
  check('withheld ack: the taker intent reads aborted', ci?.status === 'aborted', ci);
  client.offline = false;
  const requote = await waitFor(async () => { const x = await api('/api/spot/book'); return x.asks.length >= 3 && x.bids.length >= 3 ? x : null; }, 15000, 'maker requote after abort');
  check('maker requotes after its order was pulled', !!requote);

  // ---- restart recovery
  await stopProc(mm);
  const keep = { w: await wallets(owners), tape: await api('/api/spot/trades?limit=20'), batches: (await api('/api/options/batches?limit=100')).map((x) => [x.n, x.kind, x.phase, x.digest]) };
  await stopProc(venue);
  venue = await startVenue(state, VPORT, ['--options', '--stable-usdt', USDT_ID, '--spot'], 'spot-restart');
  const back = { w: await wallets(owners), tape: await api('/api/spot/trades?limit=20'), batches: (await api('/api/options/batches?limit=100')).map((x) => [x.n, x.kind, x.phase, x.digest]) };
  check('restart: wallets, the tape and every spot batch (committed and aborted) come back', JSON.stringify(back) === JSON.stringify(keep), { batches: back.batches.length, tape: back.tape.length });
  const ci2 = (await view(client.owner)).spot.intents.find((i) => i.id === r.id);
  check('restart: intent history restored', ci2?.status === 'aborted');

  // ---- a venue without --spot keeps spot off
  const offPort = VPORT + 1;
  const off = await startVenue(path.join(WORK, `spot-drill-off-${process.pid}-${Date.now()}`), offPort, ['--options', '--stable-usdt', USDT_ID], 'nospot');
  const offBook = await fetchJson(`http://127.0.0.1:${offPort}/api/spot/book`);
  const offPost = await fetchJson(`http://127.0.0.1:${offPort}/api/spot/intents`, { intent: {} });
  const offCandles = await fetchJson(`http://127.0.0.1:${offPort}/v1/candles?instrument=SHZ-BTCUSDT-SPOT&interval=1m`);
  const offStatus = (await fetchJson(`http://127.0.0.1:${offPort}/api/status`)).json;
  check('without --spot: every spot endpoint is off', offBook.status === 404 && offPost.status === 404 && offCandles.status === 404 && offStatus.spot.enabled === false,
    { book: offBook.status, post: offPost.status, candles: offCandles.status });
  await stopProc(off);
  log('summary', { t1: t1 && { sats: t1.got, usdt: t1.paid }, t2: t2 && { sats: t2.got, usdt: t2.paid } });
  finish(results.every((x) => x.ok) ? 0 : 1);
}

async function finish(code) {
  shuttingDown = true;
  for (const p of procs) { try { p.kill(); } catch { /* gone */ } }
  const pass = results.filter((x) => x.ok).length;
  console.log(`\n${pass}/${results.length} checks passed -> ${OUT}`);
  log('done', { pass, total: results.length, code });
  process.exit(code);
}
process.on('SIGINT', () => finish(130));
main().catch((e) => { console.error(e); log('error', { e: String(e.stack || e) }); finish(2); });
