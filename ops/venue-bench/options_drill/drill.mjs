// Options drill: the whole option path of the venue against a LOCAL venue and a scripted relay.
//
//   node drill.mjs [--out ../results/options-drill.jsonl] [--port 18295] [--relay-port 18291]
//
// One process hosts a signed test relay: oracle mark packets (BTC/USD 100,000) and DLC events
// in the dlc_coord.py format (announcement threshold-signed with its announcement nonce, digit
// attestations with the pre-committed nonces), all under one local test key that the venue pins
// as its group key. It starts a debug shz-venue with --options --stable-usdt <demo id> on a fresh
// state dir and drives it through the HTTP API with ui/venue/crypto.js (signIntentV7,
// signTransfer, bip340Sign for the V4 acks):
//
//   listing (an event under 60 s to maturity stays unlisted), BTC call bought, USDT cash-secured
//   put sold, collar combo (long USDT put + short BTC call, BTC limit in other_limits), each
//   staged then committed by owner/peer/monitor acks; one take whose taker withholds its ack is
//   fence-aborted at the deadline; the event expires at the attested price with a holder offline
//   (ownerless expiry); a third event the oracle declares unattestable is voided; every committed
//   batch's per-asset clearing rows equal each account's balance change in that asset; restart
//   recovery (balances, committed and aborted batches); and a second venue without --options
//   keeps every option endpoint off.
//
//   --mm [--python <exe>]: instead of the scripted makers, run ops/venue-mm/options_mm.py against the
//   venue, take its call ask and hit its USDT put bid (both committed with the bot's own acks),
//   then move the mark and check that it requotes.
//
// Never talks to anything but 127.0.0.1. State dirs go under --work (default D:/shz/tmp).

import http from 'node:http';
import { spawn } from 'node:child_process';
import { appendFileSync, writeFileSync, mkdirSync, openSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, unhex, bip340Sign, pubkey, taggedHash, sha256, mul, liftX, bytesToInt, intToBytes, signIntentV7, signTransfer } from '../../../ui/venue/crypto.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const OUT = path.resolve(arg('out', path.join(HERE, '..', 'results', 'options-drill.jsonl')));
const WORK = arg('work', 'D:/shz/tmp');
const VENUE_BIN = arg('venue-bin', 'D:/shz/target-msvc/debug/shz-venue.exe');
const VPORT = Number(arg('port', '18295'));
const RPORT = Number(arg('relay-port', '18291'));
const UI_DIR = path.resolve(HERE, '..', '..', '..', 'ui', 'venue');
// --demo: stop after the makers quote and keep relay, venue and makers (auto-signing their acks)
// running for a browser session at http://127.0.0.1:<port>/ .
const DEMO = process.argv.includes('--demo');
const MM = process.argv.includes('--mm');
const PYTHON = arg('python', 'C:/Users/patri/AppData/Local/Programs/Python/Python312/python.exe');
const MM_SCRIPT = path.resolve(HERE, '..', '..', 'venue-mm', 'options_mm.py');
const VENUE = `http://127.0.0.1:${VPORT}`;
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

// ---------------------------------------------------------------- test oracle (fixed-nonce BIP340, local test key only)
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = liftX(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n);
const GROUP_SK = await sha256(te('shz-options-drill/test-group-key/v1'));
const GROUP_PK = hex(pubkey(GROUP_SK));
const oracleD = (() => { let d = bytesToInt(GROUP_SK); const P = mul(G, d); if (P[1] % 2n) d = N - d; return d; })();
async function nonce(label) {
  let k = bytesToInt(await sha256(te('shz-options-drill/nonce/' + label))) % N;
  const R = mul(G, k); if (R[1] % 2n) k = N - k;
  return { k, rx: intToBytes(mul(G, k)[0]) };
}
async function signWithNonce(msg, n) {
  const e = bytesToInt(await taggedHash('BIP0340/challenge', n.rx, unhex(GROUP_PK), msg)) % N;
  return new Uint8Array([...n.rx, ...intToBytes((n.k + e * oracleD) % N)]);
}
const canon = (v) => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
  : JSON.stringify(v);
const NUM_BITS = 20;
const eventId = (m) => 'SHZ-BTCUSD-' + new Date(m * 1000).toISOString().replace(/[-:]/g, '').slice(0, 13) + 'Z';
const events = new Map();
async function announce(maturity) {
  const id = eventId(maturity);
  const digits = []; for (let j = 0; j < NUM_BITS; j++) digits.push(await nonce(`${id}/digit/${j}`));
  const annN = await nonce(`${id}/announcement`), unN = await nonce(`${id}/unattestable`);
  const core = { event_id: id, maturity_unix: maturity, num_bits: NUM_BITS, oracle_pubkey_x: GROUP_PK, digit_nonces_x: digits.map((d) => hex(d.rx)),
    announcement_nonce_x: hex(annN.rx), unattestable_nonce_x: hex(unN.rx), unattestable_rule: 'drill: unused', outcome: 'drill: scripted price at maturity',
    digit_message: "shz_dlc::oracle_digit_message(event_id, digit_idx, bit), MSB first (shz_margin::decompose_price_bits)", threshold: '1-of-1 (drill test key)' };
  const digest = await taggedHash('SHZ/DLC/ANNOUNCEMENT/V1', te(canon(core)));
  const ev = { core, announcement_digest: hex(digest), announcement_signature: hex(await signWithNonce(digest, annN)), status: 'announced', qualified: [1],
    shz_dlc_announcement: { event_id: id, maturity_unix: maturity, oracle_pubkey_x: [...unhex(GROUP_PK)], digit_nonces_x: digits.map((d) => [...d.rx]) }, _digits: digits, _un: unN };
  events.set(id, ev);
  return ev;
}
/** The oracle's unattestable notice (dlc_coord.py declare_unattestable): BIP340 over
 *  tagged_hash("SHZ/DLC/UNATTESTABLE/V1", event_id) with the event's unattestable nonce. */
async function declareUnattestable(id) {
  const ev = events.get(id);
  const msg = await taggedHash('SHZ/DLC/UNATTESTABLE/V1', te(id));
  ev.status = 'unattestable';
  ev.unattestable_digest = hex(msg);
  ev.unattestable_signature = hex(await signWithNonce(msg, ev._un));
}
async function attest(id, price) {
  const ev = events.get(id);
  const bits = []; for (let s = NUM_BITS - 1; s >= 0; s--) bits.push((price >> s) & 1);
  const sigs = [];
  for (let j = 0; j < NUM_BITS; j++) {
    const idb = te(id), len = new Uint8Array(4); new DataView(len.buffer).setUint32(0, idb.length, true);
    const msg = await taggedHash('SatsHedgeZero/DLC/DigitOutcome/v0', len, idb, Uint8Array.of(j, bits[j]));
    sigs.push(await signWithNonce(msg, ev._digits[j]));
  }
  ev.status = 'attested';
  ev.attestation = { price_usd: price, digit_bits: bits, digit_signatures: sigs.map(hex), signers: [1] };
  ev.shz_dlc_attestation = { event_id: id, attested_timestamp_unix: Math.floor(Date.now() / 1000), price_usd: price, digit_bits: bits,
    digit_signatures: sigs.map((s) => ({ r_x: [...s.slice(0, 32)], s: [...s.slice(32)] })) };
}

// ---------------------------------------------------------------- scripted relay
const relay = { seq: 0, price: 100_000, latest: null, clients: new Set() };
async function emit() {
  relay.seq += 1;
  const us = Date.now() * 1000;
  const body = { schema: 'shz-public-relay/v1', market: 'BTC/USD', data_class: 'public_delayed', seq: relay.seq,
    previous: '0'.repeat(64), interval_ms: 1000, slot_us: us, assembled_us: us, status: 'VALID', median_e8: Math.round(relay.price * 1e8) };
  const digest = await taggedHash('SHZ/PUBLIC-RELAY-PACKET/V1', te(canon(body)));
  const pkt = { body, digest: hex(digest), signature: hex(await bip340Sign(digest, GROUP_SK)), frost_signers: ['options-drill-test-key'] };
  relay.latest = pkt;
  for (const res of relay.clients) res.write(`data: ${JSON.stringify(pkt)}\n\n`);
}
async function setPrice(p) { relay.price = p; await emit(); log('mark_set', { price_usd: p, seq: relay.seq }); }
function startRelay() {
  const json = (res, code, o) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
  const srv = http.createServer((req, res) => {
    if (req.url === '/v1/pubkey') return json(res, 200, { pubkey_bip340: GROUP_PK });
    if (req.url === '/v1/latest') return json(res, 200, relay.latest);
    if (req.url === '/v1/stream') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
      relay.clients.add(res); req.on('close', () => relay.clients.delete(res)); return;
    }
    if (req.url === '/v1/dlc/events') return json(res, 200, { oracle_pubkey_x: GROUP_PK, events: [...events.values()].map((e) => ({ event_id: e.core.event_id, maturity_unix: e.core.maturity_unix, status: e.status, price_usd: e.attestation?.price_usd ?? null })) });
    if (req.url.startsWith('/v1/dlc/event/')) {
      const e = events.get(req.url.slice('/v1/dlc/event/'.length));
      if (!e) return json(res, 404, { error: 'unknown event' });
      const { _digits, _un, ...pub } = e; return json(res, 200, pub);
    }
    json(res, 404, {});
  });
  srv.listen(RPORT, '127.0.0.1');
  setInterval(() => { emit().catch((e) => console.error('emit', e)); }, 1000);
}

// ---------------------------------------------------------------- venue process
const USDT_ID = hex(await sha256(te('shz-options-drill/demo-usdt-rgb-contract/v1')));
const procs = new Set();
async function startVenue(state, port, extra, tag) {
  const errFile = path.join(WORK, `options-drill-venue-${tag}-${port}.log`);
  const fd = openSync(errFile, 'a');
  const p = spawn(VENUE_BIN, ['--listen', `127.0.0.1:${port}`, '--state', state, '--ui', UI_DIR, '--relay', `http://127.0.0.1:${RPORT}`,
    '--group-key', GROUP_PK, '--mempool-api', 'http://127.0.0.1:9/none', ...extra], { stdio: ['ignore', fd, fd] });
  procs.add(p);
  p.on('exit', (c) => { procs.delete(p); if (!shuttingDown && !p.expectedExit) { console.error(`venue ${tag} exited`, c); finish(3); } });
  for (let i = 0; i < 100; i++) { try { await fetchJson(`http://127.0.0.1:${port}/api/status`); return { p, errFile }; } catch { await sleep(200); } }
  throw new Error('venue did not start');
}
async function stopVenue(p) { p.expectedExit = true; p.kill(); await new Promise((r) => (p.exitCode !== null ? r() : p.on('exit', r))); }
let shuttingDown = false;

// ---------------------------------------------------------------- http helpers
async function fetchJson(url, body) {
  const r = await fetch(url, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { /* none */ }
  return { status: r.status, json: j };
}
async function api(p, body) { const r = await fetchJson(VENUE + p, body); if (r.status >= 300) throw new Error(`${p}: ${r.status} ${r.json && r.json.error}`); return r.json; }

// ---------------------------------------------------------------- accounts, signing
const accts = {};
let template;
let xferNonce = 0;
async function mkAcct(name) {
  const sk = await sha256(te('shz-options-drill/account/' + name));
  const owner = hex(pubkey(sk));
  const d = await api('/api/register/draft', { owner, kind: 'demo', outpoint: null });
  const a = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(await bip340Sign(unhex(d.allocation_digest), sk)) })).account;
  return (accts[name] = { name, sk, owner, outpoint: a.outpoint, seq: Date.now() * 1000, offline: false, signed: new Set(), view: a });
}
async function transfer(w, op, amount, asset = null) {
  xferNonce += 1;
  const body = await signTransfer(op, { owner: w.owner, asset, amount, expires_us: (Date.now() + 60_000) * 1000 + xferNonce }, w.sk);
  return api('/api/options/' + op, body);
}
async function intent(w, f) {
  w.seq += 1;
  const { id, intent: signed } = await signIntentV7({ owner: w.owner, channel: { txid: w.outpoint.txid, vout: w.outpoint.vout }, sequence: w.seq,
    expires_us: (Date.now() + 120e3) * 1000, ...f }, template, w.sk);
  const r = await fetchJson(VENUE + '/api/options/intents', { intent: signed });
  return { id, status: r.status, ...r.json };
}
async function view(w) { w.view = await api('/api/account/' + w.owner); return w.view; }
async function signPending(w) {
  if (w.offline) return;
  const todo = (w.view.pending_signatures || []).filter((x) => !w.signed.has(x.id));
  if (!todo.length) return;
  const items = [];
  for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), w.sk)) });
  await api('/api/signatures', { owner: w.owner, items });
  for (const x of todo) { w.signed.add(x.id); log('signed', { acct: w.name, id: x.id, kind: x.kind }); }
}
let signing = true;
async function signLoop() {
  while (signing) {
    await Promise.all(Object.values(accts).map(async (w) => { try { await view(w); await signPending(w); } catch (e) { log('sign_error', { acct: w.name, e: e.message }); } }));
    await sleep(80);
  }
}
const bal = (w, asset) => (w.view.options?.balances || []).find((b) => b.asset === asset) || { free: 0, locked: 0, realized: 0 };
async function snapshot() {
  const s = {};
  for (const w of Object.values(accts)) { await view(w); s[w.name] = Object.fromEntries((w.view.options?.balances || []).map((b) => [b.asset, { free: b.free, locked: b.locked, realized: b.realized }])); }
  return s;
}
const nameOf = (owner) => Object.values(accts).find((w) => w.owner === owner)?.name || owner?.slice(0, 8);

// ---------------------------------------------------------------- WS event capture
const wsEvents = [];
function openWs() {
  const ws = new WebSocket(`ws://127.0.0.1:${VPORT}/api/stream`);
  ws.onmessage = (ev) => { try { const m = JSON.parse(ev.data); if (String(m.type).startsWith('option')) { wsEvents.push(m); log('ws', { type: m.type, phase: m.phase, n: m.batch?.n ?? m.batch }); } } catch { /* ignore */ } };
  return ws;
}

// ---------------------------------------------------------------- scenario helpers
async function waitFor(pred, ms, what) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { const v = await pred(); if (v) return v; } catch { /* retry */ } await sleep(150); }
  log('wait_timeout', { what }); return null;
}
async function batchN(n) { return (await api('/api/options/batches?limit=100')).find((b) => b.n === n); }
async function resolved(n, ms = 20000) { return waitFor(async () => { const b = await batchN(n); return b && b.phase !== 'staged' ? b : null; }, ms, 'option batch ' + n); }
const phasesOf = (n) => wsEvents.filter((e) => e.type === 'option_batch' && e.batch?.n === n).map((e) => e.phase);
/** Per-asset clearing rows of a committed batch equal each account's balance change in that asset. */
function clearingMatches(b, before, after) {
  const bad = [];
  for (const c of b.clearing) {
    let sumNet = 0;
    for (const r of c.rows) {
      const n = nameOf(r.owner); sumNet += r.net;
      const x = before[n][c.asset] || { free: 0, locked: 0, realized: 0 }, y = after[n][c.asset];
      const dTotal = (y.free + y.locked) - (x.free + x.locked), dReal = y.realized - x.realized;
      if (dTotal !== r.net || dReal !== r.net) bad.push({ acct: n, asset: c.asset, net: r.net, dTotal, dReal });
    }
    if (sumNet + c.pool_net !== 0) bad.push({ asset: c.asset, sumNet, pool_net: c.pool_net });
  }
  // accounts without a row in an asset did not move in it
  for (const n of Object.keys(after)) for (const a of Object.keys(after[n])) {
    const inRows = b.clearing.some((c) => c.asset === a && c.rows.some((r) => nameOf(r.owner) === n));
    const x = before[n][a] || { free: 0, locked: 0, realized: 0 }, y = after[n][a];
    if (!inRows && (x.free + x.locked !== y.free + y.locked || x.realized !== y.realized)) bad.push({ acct: n, asset: a, moved_without_row: true });
  }
  return bad;
}
/** Submit a take and follow it to resolution, checking the clearing against the balances. */
async function tradeAndSettle(label, w, f, expectPhase = 'committed') {
  const before = await snapshot();
  const r = await intent(w, f);
  log('take', { label, acct: w.name, status: r.status, outcome: r.outcome, batch: r.batch, error: r.error });
  if (r.status !== 200 || r.outcome !== 'staged') { check(`${label}: take is staged`, false, r); return null; }
  const staged = await batchN(r.batch);
  const b = await resolved(r.batch, expectPhase === 'aborted' ? 25000 : 15000);
  const after = await snapshot();
  const ph = phasesOf(r.batch);
  log('batch', { label, n: r.batch, phase: b?.phase, fills: b?.fills, clearing: b?.clearing, acks: b?.acks, ws_phases: ph });
  check(`${label}: staged, then ${expectPhase} (WS option_batch ${ph.join(' -> ')})`, staged && b && b.phase === expectPhase && ph[0] === 'staged' && ph.includes(expectPhase), { n: r.batch, phase: b?.phase, ws: ph });
  if (b && expectPhase === 'committed') {
    const bad = clearingMatches(b, before, after);
    check(`${label}: every account's balance change equals its clearing row in each asset (${b.clearing.map((c) => c.asset).join(', ')})`, bad.length === 0, bad.length ? bad : b.clearing.map((c) => ({ asset: c.asset, rows: c.rows.map((x) => [nameOf(x.owner), x.net]) })));
    check(`${label}: every lane carried owner, peer and monitor signatures`, b.acks.length > 0 && b.acks.every((a) => a.owner_signed && /[1-9a-f]/.test(a.peer_signature) && /[1-9a-f]/.test(a.monitor_signature)), b.acks.length);
  }
  return { r, b, before, after };
}

// ---------------------------------------------------------------- main
async function main() {
  note('drill start', { relay_group_key: GROUP_PK, usdt: USDT_ID });
  startRelay(); await emit();
  const nowS = Math.floor(Date.now() / 1000);
  const maturity = Math.ceil((nowS + 95) / 60) * 60;
  const soon = await announce(nowS + 30); // under the 60 s listing lead: must stay unlisted
  const e1 = await announce(maturity);
  const e2 = await announce(maturity + 900);
  const e3 = await announce(maturity + 60); // declared unattestable after maturity: voided
  note('relay announced 4 events', { soon: soon.core.event_id, e1: e1.core.event_id, e2: e2.core.event_id, e3: e3.core.event_id, e1_maturity_in_s: maturity - nowS });

  // off by default: a venue without --options
  const offState = path.join(WORK, `options-drill-off-${Date.now()}`);
  const off = await startVenue(offState, VPORT + 1, [], 'off');
  const offSeries = await fetchJson(`http://127.0.0.1:${VPORT + 1}/api/options/series`);
  const offIntent = await fetchJson(`http://127.0.0.1:${VPORT + 1}/api/options/intents`, { intent: {} });
  const offFund = await fetchJson(`http://127.0.0.1:${VPORT + 1}/api/options/fund`, {});
  const offStatus = await fetchJson(`http://127.0.0.1:${VPORT + 1}/api/status`);
  check('without --options: series says enabled=false, intents and fund answer 404, status.options.enabled=false',
    offSeries.json.enabled === false && offIntent.status === 404 && offFund.status === 404 && offStatus.json.options.enabled === false,
    { series: offSeries.json, intents: offIntent.status, fund: offFund.status, status: offStatus.json.options });
  await stopVenue(off.p);

  const state = path.join(WORK, `options-drill-${Date.now()}`);
  let v = await startVenue(state, VPORT, ['--options', '--stable-usdt', USDT_ID], 'on');
  note('venue up', { state, log: v.errFile });
  template = await api('/api/template');
  const st0 = await api('/api/status');
  check('venue pins the drill key; options on with combos, acks, ownerless expiry and the USDT asset', template.group_key === GROUP_PK && st0.options.enabled && st0.options.combos && st0.options.acks && st0.options.ownerless_expiry && st0.options.usdt?.id === USDT_ID, st0.options);
  openWs();

  // listing
  const listed = await waitFor(async () => { const s = await api('/api/options/series'); return s.series.length >= 45 ? s : null; }, 30000, 'series listed');
  const S = listed || await api('/api/options/series');
  const ev1 = S.series.filter((s) => s.event_id === e1.core.event_id), ev2 = S.series.filter((s) => s.event_id === e2.core.event_id), ev3 = S.series.filter((s) => s.event_id === e3.core.event_id);
  const strikes = [...new Set(ev1.map((s) => s.strike_usd))];
  check('the three events ahead of the 60 s lead list 15 series each (5 strikes x BTC call, BTC put, USDT put)', ev1.length === 15 && ev2.length === 15 && ev3.length === 15, { e1: ev1.length, e2: ev2.length, e3: ev3.length, strikes });
  check('the strike grid centres on the 100,000 mark (98,000 .. 102,000)', JSON.stringify(strikes) === JSON.stringify([98000, 99000, 100000, 101000, 102000]), strikes);
  check('an event under 60 s to maturity is not listed', !S.series.some((s) => s.event_id === soon.core.event_id), {});
  check('calls are BTC only; puts list in BTC and USDT', ev1.filter((s) => s.kind === 'call').every((s) => s.asset_code === 'BTC') && ev1.filter((s) => s.kind === 'put' && s.asset_code === 'USDT').length === 5);
  const ser = (kind, asset, k) => ev1.find((s) => s.kind === kind && s.asset_code === asset && s.strike_usd === k);
  const C100 = ser('call', 'BTC', 100000), C101 = ser('call', 'BTC', 101000), C102 = ser('call', 'BTC', 102000), P98 = ser('put', 'USDT', 98000), P102 = ser('put', 'USDT', 102000);
  const usdt = S.assets.find((a) => a.code === 'USDT');
  check('series view carries the worst case per side: short 100k BTC call ~90,463 sats per 100 USD, short USDT 98k put 979.99 USDT per 0.01 BTC',
    C100.worst_case_per_contract.short >= 90460 && C100.worst_case_per_contract.short <= 90470 && P98.worst_case_per_contract.short === 979_990_000 && C100.worst_case_per_contract.long === 0,
    { c100: C100.worst_case_per_contract, p98: P98.worst_case_per_contract });

  // accounts and collateral
  const M1 = await mkAcct('M1'), M2 = await mkAcct('M2'), T1 = await mkAcct('T1'), T2 = await mkAcct('T2'), T3 = await mkAcct('T3');
  await transfer(M1, 'fund', 150_000); await transfer(T1, 'fund', 40_000); await transfer(T3, 'fund', 120_000);
  await transfer(M2, 'deposit', 3_000_000_000, usdt); await transfer(T2, 'deposit', 2_000_000_000, usdt); await transfer(T3, 'deposit', 200_000_000, usdt);
  const replay = await fetchJson(VENUE + '/api/options/fund', await signTransfer('fund', { owner: T1.owner, amount: 1, expires_us: (Date.now() + 1000) * 1000 }, T1.sk));
  const forged = await fetchJson(VENUE + '/api/options/withdraw', { ...(await signTransfer('withdraw', { owner: T2.owner, asset: usdt, amount: 5, expires_us: (Date.now() + 90_000) * 1000 }, T1.sk)) });
  check('a transfer with a stale nonce and a withdrawal signed by another key are refused', replay.status === 409 && forged.status === 409, { replay: replay.json?.error, forged: forged.json?.error });
  const snap0 = await snapshot();
  check('collateral landed: M1/T1/T3 BTC free 150,000/40,000/120,000; M2/T2/T3 USDT 3,000/2,000/200',
    snap0.M1.BTC.free === 150000 && snap0.T1.BTC.free === 40000 && snap0.T3.BTC.free === 120000 && snap0.M2.USDT.free === 3e9 && snap0.T2.USDT.free === 2e9 && snap0.T3.USDT.free === 2e8, snap0);
  const perp = (await view(M1)).balance;
  check('fund moved sats out of the perpetual allocation (cap and free drop by 150,000)', perp.cap === 50_000 && perp.free === 50_000, perp);
  signLoop();
  if (MM) return mmScenario({ T1, T2, C100, P100: ser('put', 'USDT', 100000), usdt });

  // makers quote
  const posts = [
    [M1, { action: 'post', legs: [{ series: C100.id, long: false, qty: 100 }], premium_milli: 3000 }], // ask: sell 100k call, 300 sats per 100 USD
    [M1, { action: 'post', legs: [{ series: C102.id, long: true, qty: 100 }], premium_milli: 500 }], // bid: buy 102k call, 50 sats
    [M2, { action: 'post', legs: [{ series: P102.id, long: true, qty: 1_000_000 }], premium_milli: 25_000 }], // bid: buy 102k USDT put, 25 USDT per 0.01 BTC
    [M2, { action: 'post', legs: [{ series: P98.id, long: false, qty: 1_000_000 }], premium_milli: 15_000 }], // ask: sell 98k USDT put, 15 USDT
  ];
  const postRes = []; for (const [w, f] of posts) postRes.push(await intent(w, f));
  check('four maker quotes rest (posts settle nothing)', postRes.every((r) => r.status === 200 && r.outcome === 'posted'), postRes.map((r) => r.outcome || r.error));
  if (DEMO) {
    const p100 = ser('put', 'BTC', 100000), p99 = ser('put', 'BTC', 99000), U99 = ser('put', 'USDT', 99000), U100 = ser('put', 'USDT', 100000), C99 = ser('call', 'BTC', 99000);
    for (const [w, f] of [[M1, { legs: [{ series: C101.id, long: false, qty: 200 }], premium_milli: 1500 }], [M1, { legs: [{ series: C101.id, long: true, qty: 200 }], premium_milli: 1100 }],
      [M1, { legs: [{ series: C99.id, long: true, qty: 100 }], premium_milli: 6000 }], [M1, { legs: [{ series: C100.id, long: true, qty: 100 }], premium_milli: 2500 }],
      [M1, { legs: [{ series: p100.id, long: true, qty: 100 }], premium_milli: 2000 }], [M1, { legs: [{ series: p99.id, long: true, qty: 100 }], premium_milli: 800 }],
      [M2, { legs: [{ series: U99.id, long: false, qty: 2_000_000 }], premium_milli: 9_000 }], [M2, { legs: [{ series: U100.id, long: true, qty: 1_000_000 }], premium_milli: 20_000 }],
      [M2, { legs: [{ series: U100.id, long: false, qty: 1_000_000 }], premium_milli: 24_000 }]]) {
      const r = await intent(w, { action: 'post', ...f }); if (r.status !== 200) note('demo quote refused: ' + r.error);
    }
    note(`DEMO ready: open ${VENUE}/ (makers M1/M2 sign their acks; e1 matures at ${new Date(maturity * 1000).toISOString()})`);
    return;
  }
  const bk = await api('/api/options/book/' + C100.id);
  check('book of the 100k call shows the 300-sat ask', bk.asks.length === 1 && bk.asks[0][0] === 3000 && bk.asks[0][1] === 100, bk.asks);

  // 1. buy a BTC call
  const t1 = await tradeAndSettle('buy BTC call (T1 takes M1 100k call ask)', T1, { action: 'take', legs: [{ series: C100.id, long: true, qty: 100 }], premium_milli: 300_000 });
  check('T1 holds +100 of the 100k call and paid 300 sats; M1 locked the short call worst case', bal(T1, 'BTC').free === 39_700 && (T1.view.options.legs.find((l) => l.series === C100.id) || {}).net === 100 && bal(M1, 'BTC').locked >= 90460,
    { T1: bal(T1, 'BTC'), M1: bal(M1, 'BTC'), legs: T1.view.options.legs });

  // 2. sell a USDT cash-secured put
  await tradeAndSettle('sell USDT cash-secured put (T2 hits M2 102k put bid)', T2, { action: 'take', legs: [{ series: P102.id, long: false, qty: 1_000_000 }], premium_milli: -25_000_000_000 }); // receive at least 25 USDT
  check('T2 received 25 USDT and locked strike x size (1,019.99 USDT) in USDT', bal(T2, 'USDT').realized === 25_000_000 && bal(T2, 'USDT').locked === 1_019_990_000, bal(T2, 'USDT'));

  // 3. collar combo: long USDT put + short BTC call, one batch, two assets
  const collar = (btcLimit) => ({ action: 'take', legs: [{ series: P98.id, long: true, qty: 1_000_000 }, { series: C102.id, long: false, qty: 100 }], premium_milli: 15_000_000_000, other_limits: [{ asset: { kind: 'btc' }, premium_milli: btcLimit }] });
  const tight = await intent(T3, collar(-60_000)); // wants >= 60 sats for the call; the bid pays 50
  const bkTight = await api('/api/options/book/' + C102.id);
  check('a combo whose BTC limit cannot be met is refused whole, nothing staged, both quotes still rest', tight.status === 409 && /FeeLimit/.test(tight.error || '') && bkTight.bids.length === 1, { error: tight.error, bids: bkTight.bids });
  const t3 = await tradeAndSettle('collar combo (T3: long 98k USDT put + short 102k BTC call)', T3, collar(-50_000));
  check('collar is one batch with fills and clearing in both assets', t3?.b && t3.b.fills.length === 2 && t3.b.clearing.map((c) => c.asset).sort().join() === 'BTC,USDT', t3?.b?.clearing?.map((c) => c.asset));

  // 4. one batch left unsigned: fenced abort at the deadline
  const p101 = await intent(M1, { action: 'post', legs: [{ series: C101.id, long: false, qty: 50 }], premium_milli: 2000 });
  T1.offline = true;
  const beforeAbort = await snapshot();
  const t4 = await tradeAndSettle('unsigned take (T1 offline) is fence-aborted after the deadline', T1, { action: 'take', legs: [{ series: C101.id, long: true, qty: 50 }], premium_milli: 100_000 }, 'aborted');
  T1.offline = false;
  const afterAbort = await snapshot();
  const moved = Object.keys(afterAbort).filter((n) => JSON.stringify(afterAbort[n]) !== JSON.stringify(beforeAbort[n]));
  const bk101 = await api('/api/options/book/' + C101.id);
  const held = (T1.view.options.legs.find((l) => l.series === C101.id) || {}).net || 0;
  check('the abort moved no balance, gave T1 no leg and pulled M1\'s quote behind the fill', p101.outcome === 'posted' && moved.length === 0 && held === 0 && bk101.asks.length === 0, { moved, held, asks: bk101.asks });
  check('the aborted batch took ~10 s (ABORT_AFTER_US) and its acks carried peer/monitor only', t4?.b && t4.b.resolved_us - t4.b.staged_us >= 10_000_000 && t4.b.acks.some((a) => !a.owner_signed), t4?.b && { took_ms: (t4.b.resolved_us - t4.b.staged_us) / 1000 });

  // 5a. a position on e3, which the oracle will declare unattestable
  const E3C = ev3.find((s) => s.kind === 'call' && s.asset_code === 'BTC' && s.strike_usd === 100000);
  await intent(M1, { action: 'post', legs: [{ series: E3C.id, long: false, qty: 100 }], premium_milli: 3000 });
  await tradeAndSettle('buy an e3 BTC call (T1 takes M1)', T1, { action: 'take', legs: [{ series: E3C.id, long: true, qty: 100 }], premium_milli: 300_000 });

  // 5. expiry at the attested price, with T1's client offline (ownerless expiry)
  const px = 101_000;
  const waitS = maturity - Math.floor(Date.now() / 1000);
  note(`waiting ${Math.max(0, waitS)} s for maturity, then the relay attests ${px}`);
  await sleep(Math.max(0, waitS) * 1000 + 500);
  const beforeExp = await snapshot();
  T1.offline = true;
  await attest(e1.core.event_id, px);
  const expBatch = await waitFor(async () => (await api('/api/options/batches?limit=100')).find((b) => b.kind === 'expiry' && b.phase === 'committed'), 30000, 'expiry committed');
  T1.offline = false;
  const afterExp = await snapshot();
  log('expiry', { batch: expBatch, ws: wsEvents.filter((e) => e.type === 'option_expiry') });
  check('the event expired automatically at the attested 101,000 with T1 offline: staged, then committed on peer and monitor signatures (ownerless expiry)',
    expBatch && expBatch.detail.price_usd === px && phasesOf(expBatch.n)[0] === 'staged' && expBatch.resolved_us - expBatch.staged_us < 5_000_000 && expBatch.acks.every((a) => !a.owner_signed),
    expBatch && { n: expBatch.n, ws: phasesOf(expBatch.n), took_ms: (expBatch.resolved_us - expBatch.staged_us) / 1000 });
  if (expBatch) {
    const bad = clearingMatches(expBatch, beforeExp, afterExp);
    check('expiry: every account\'s balance change equals its clearing row in each asset', bad.length === 0, bad.length ? bad : expBatch.clearing.map((c) => ({ asset: c.asset, rows: c.rows.map((x) => [nameOf(x.owner), x.net]), pool_net: c.pool_net })));
    const btc = expBatch.clearing.find((c) => c.asset === 'BTC'), us = expBatch.clearing.find((c) => c.asset === 'USDT');
    const row = (c, n) => c?.rows.find((r) => nameOf(r.owner) === n)?.net;
    check('expiry payouts: T1 +990 sats (100 USD of the 100k call at 101k), M1 -991 (rounded up), BTC dust 1 to the fund; T2 -10 USDT, M2 +10 USDT',
      row(btc, 'T1') === 990 && row(btc, 'M1') === -991 && btc.pool_net === 1 && row(us, 'T2') === -10_000_000 && row(us, 'M2') === 10_000_000 && us.pool_net === 0,
      { btc: btc?.rows.map((r) => [nameOf(r.owner), r.net]), btc_pool_net: btc?.pool_net, usdt: us?.rows.map((r) => [nameOf(r.owner), r.net]) });
    const wsExp = wsEvents.find((e) => e.type === 'option_expiry' && e.batch === expBatch.n);
    check('WS option_expiry carries the price and per-asset clearing', wsExp && wsExp.price_usd === px && wsExp.clearing.length === 2, wsExp && { price: wsExp.price_usd, assets: wsExp.clearing.map((c) => c.asset) });
  }
  const s1 = await api('/api/options/series');
  check('every e1 series is settled at 101,000; e2 stays open', s1.series.filter((s) => s.event_id === e1.core.event_id).every((s) => s.settled_price_usd === px) && s1.series.filter((s) => s.event_id === e2.core.event_id).every((s) => s.settled_price_usd === null));
  // 5b. e3 matures and the oracle declares it unattestable: void, legs gone, premiums stay paid
  const e3Wait = e3.core.maturity_unix - Math.floor(Date.now() / 1000);
  note(`waiting ${Math.max(0, e3Wait)} s for e3 maturity, then the relay publishes its unattestable notice`);
  await sleep(Math.max(0, e3Wait) * 1000 + 500);
  const beforeVoid = await snapshot();
  await declareUnattestable(e3.core.event_id);
  const voidBatch = await waitFor(async () => (await api('/api/options/batches?limit=100')).find((b) => b.kind === 'void' && b.phase === 'committed'), 30000, 'void committed');
  const afterVoid = await snapshot();
  log('void', { batch: voidBatch });
  check('the unattestable notice voided e3 in one batch: every clearing row nets 0, balances only unlock', voidBatch && voidBatch.clearing.every((c) => c.rows.every((r) => r.net === 0)) && clearingMatches(voidBatch, beforeVoid, afterVoid).length === 0,
    voidBatch && voidBatch.clearing.map((c) => ({ asset: c.asset, rows: c.rows.map((r) => [nameOf(r.owner), r.net]) })));
  check('after the void T1 holds no e3 leg and its 300-sat premium stays paid; M1 is unlocked; e3 reads void', afterVoid.T1.BTC.realized === beforeVoid.T1.BTC.realized && afterVoid.M1.BTC.locked === 0 &&
    !(T1.view.options.legs || []).some((l) => l.event_id === e3.core.event_id) && (await api('/api/options/series')).events.find((e) => e.event_id === e3.core.event_id)?.status === 'void',
    { T1: afterVoid.T1.BTC, M1: afterVoid.M1.BTC });
  const flat = ['M1', 'M2', 'T1', 'T2', 'T3'].every((n) => (accts[n].view.options.legs || []).length === 0);
  const unlocked = ['M1', 'M2', 'T1', 'T2', 'T3'].every((n) => (accts[n].view.options.balances || []).every((b) => b.locked === 0));
  check('after expiry no leg remains and no collateral stays locked; every account is fully funded', flat && unlocked && Object.values(accts).every((w) => w.view.options.fully_funded), {});
  check('WS carried option_fill events for every committed fill', wsEvents.filter((e) => e.type === 'option_fill').length >= 5, wsEvents.filter((e) => e.type === 'option_fill').length);
  const totals = {};
  for (const n of Object.keys(afterExp)) for (const [a, b] of Object.entries(afterExp[n])) { totals[a] ||= { realized: 0 }; totals[a].realized += b.realized; }
  const pools = (await api('/api/options/series')).assets.find((a) => a.code === 'USDT').pool;
  check('per asset, the sum of realized option PnL plus the pool\'s dust is zero (USDT pool cash = fund = dust)', totals.USDT.realized + pools.cash === 0 && pools.cash === pools.fund, { totals, usdt_pool: pools });

  // 6. restart recovery
  signing = false; await sleep(300);
  const pre = await snapshot();
  const batchSig = async () => (await api('/api/options/batches?limit=100')).map((b) => `${b.n}:${b.phase}:${b.kind}:${b.digest}`).join(' ');
  const intentSig = async () => (await view(T1)).options.intents.map((i) => `${i.id}:${i.status}`).join(' ');
  const preBatches = await batchSig(), preIntents = await intentSig();
  await stopVenue(v.p);
  v = await startVenue(state, VPORT, ['--options', '--stable-usdt', USDT_ID], 'on-restart');
  const post = await snapshot();
  const postBatches = await batchSig(), postIntents = await intentSig();
  check('after a restart: every balance, every option batch (committed and aborted, same numbers) and the intent history come back',
    JSON.stringify(pre) === JSON.stringify(post) && preBatches === postBatches && preIntents === postIntents && /aborted/.test(postBatches),
    { batches: postBatches.split(' ').map((x) => x.split(':').slice(0, 3).join(':')), intents_match: preIntents === postIntents });

  const failed = results.filter((r) => !r.ok).length;
  log('summary', { passed: results.length - failed, failed, total: results.length, ws_events: wsEvents.length, state });
  console.log(`\n${results.length - failed}/${results.length} assertions passed. log: ${OUT}`);
  await finish(failed ? 1 : 0);
}

// ---------------------------------------------------------------- --mm: the demo options market maker
async function mmScenario({ T1, T2, C100, P100, usdt }) {
  const mmState = path.join(WORK, `options-mm-${Date.now()}`);
  const mmLog = path.join(WORK, `options-mm-${VPORT}.jsonl`);
  const fd = openSync(mmLog, 'w');
  const mm = spawn(PYTHON, [MM_SCRIPT, 'run', '--server', VENUE, '--state-dir', mmState, '--poll-s', '0.5'], { stdio: ['ignore', fd, fd] });
  procs.add(mm); mm.expectedExit = true;
  note('options_mm.py started', { log: mmLog });
  const book = (id) => api('/api/options/book/' + id);
  const quoted = await waitFor(async () => {
    const s = await api('/api/options/series');
    const e1 = s.series.filter((x) => x.event_id === C100.event_id);
    const calls = e1.filter((x) => x.kind === 'call' && x.ask), puts = e1.filter((x) => x.kind === 'put' && x.asset_code === 'USDT' && x.ask);
    return calls.length === 5 && puts.length === 5 ? { calls, puts } : null;
  }, 60000, 'mm quotes');
  check('the bot quotes all 5 BTC calls and all 5 USDT puts of the nearest expiry, with bids below asks', quoted && [...quoted.calls, ...quoted.puts].every((x) => !x.bid || x.bid.premium_milli < x.ask.premium_milli),
    quoted && quoted.calls.map((x) => [x.strike_usd, x.bid?.premium_milli, x.ask.premium_milli]));
  const c0 = (await book(C100.id)).asks[0], p0 = (await book(P100.id)).bids[0];
  log('mm_ladder', { c100_ask: c0, p100_bid: p0 });
  // Independent Black-76 at the time left (60% vol, r = 0; erf by Abramowitz-Stegun 7.1.26), in premium_milli per unit.
  const erf = (x) => { const t = 1 / (1 + 0.3275911 * Math.abs(x)); const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x); return x >= 0 ? y : -y; };
  const N = (x) => 0.5 * (1 + erf(x / Math.SQRT2));
  const b76 = (kind, F, K, T) => { const sd = 0.6 * Math.sqrt(T), d1 = (Math.log(F / K) + sd * sd / 2) / sd, d2 = d1 - sd; return kind === 'call' ? F * N(d1) - K * N(d2) : K * N(-d2) - F * N(-d1); };
  const T = (C100.maturity_unix - Date.now() / 1000) / (365 * 86400);
  const fairCall = b76('call', 100_000, 100_000, T) / (100_000 * 100_000) * 1e11, fairPut = b76('put', 100_000, 100_000, T) * 10;
  check('the ATM call ask and ATM USDT put bid bracket an independent Black-76 at the time left (8% spread each side)',
    c0 && p0 && c0[0] > fairCall && c0[0] < fairCall * 1.12 && p0[0] < fairPut && p0[0] > fairPut * 0.88, { c0: c0?.[0], fairCall: Math.round(fairCall), p0: p0?.[0], fairPut: Math.round(fairPut), minutes_left: +(T * 365 * 1440).toFixed(2) });
  // the bot's account joins the balance snapshots (observed only: the drill never signs for it)
  const { readFileSync } = await import('node:fs');
  const botOwner = hex(pubkey(unhex(readFileSync(path.join(mmState, 'options_mm.key'), 'utf8').trim(), 32)));
  accts.BOT = { name: 'BOT', owner: botOwner, offline: true, signed: new Set(), view: await api('/api/account/' + botOwner) };
  const tc = await tradeAndSettle('T1 buys the bot\'s 100k call ask (bot signs its V4 ack)', T1, { action: 'take', legs: [{ series: C100.id, long: true, qty: 100 }], premium_milli: Math.ceil(c0[0] * 100 / 1000) * 1000 * 2 });
  const tp = await tradeAndSettle('T2 sells into the bot\'s 100k USDT put bid (bot signs its V4 ack)', T2, { action: 'take', legs: [{ series: P100.id, long: false, qty: 1_000_000 }], premium_milli: -1000 });
  check('both fills are against the bot', tc?.b && tp?.b && [tc.b, tp.b].every((b) => b.fills.every((f) => f.long.owner !== f.short.owner)), {});
  const before = (await book(C100.id)).asks[0] || c0;
  await setPrice(101_000);
  const moved = await waitFor(async () => { const a = (await book(C100.id)).asks[0]; return a && a[0] > before[0] * 2 ? a : null; }, 20000, 'mm requote');
  const mmLines = readFileSync(mmLog, 'utf8').trim().split('\n').map((l) => { try { return JSON.parse(l); } catch { return {}; } });
  log('mm_requote', { before, after: moved, requotes: mmLines.filter((l) => l.ev === 'requoted').map((l) => ({ reason: l.reason, posted: l.posted, cancelled: l.cancelled })) });
  check('after the mark moves to 101,000 the bot cancels and requotes: the 100k call ask rises (now 1,000 USD in the money)', moved, { before, after: moved });
  check('the bot signed its own acks (signed events in its log) and logged no error', mmLines.some((l) => l.ev === 'signed' && l.kinds?.includes('option_ack')) && !mmLines.some((l) => l.ev === 'error'), mmLines.filter((l) => l.ev === 'error').slice(0, 3));
  const failed = results.filter((r) => !r.ok).length;
  log('summary', { mode: 'mm', passed: results.length - failed, failed, total: results.length });
  console.log(`\n${results.length - failed}/${results.length} assertions passed. log: ${OUT}`);
  await finish(failed ? 1 : 0);
}

async function finish(code) {
  shuttingDown = true; signing = false;
  await sleep(300);
  for (const p of procs) { try { p.kill(); } catch { /* gone */ } }
  process.exit(code);
}
process.on('unhandledRejection', (e) => { console.error('unhandled', e); log('fatal', { e: String(e && e.stack || e) }); finish(2); });
main().catch((e) => { console.error(e); log('fatal', { e: String(e && e.stack || e) }); finish(2); });
