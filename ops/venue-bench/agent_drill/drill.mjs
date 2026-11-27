// Agent drill: delegated agent keys and the agent API v1 against a LOCAL venue and a scripted relay.
//
//   node drill.mjs [--out ../results/agent-drill.jsonl] [--port 18495] [--relay-port 18491] [--mcp-port 18497]
//
// One process hosts a signed test relay (BTC/USD marks at 100,000 and one DLC event, under a local
// test key the venue pins as its group key), starts a debug shz-venue with --options --stable-usdt
// <demo id> --spot --agents on a fresh state dir, and drives it:
//
//   owner O registers, funds, and signs one grant for agent key A (perps, options, spot; capped);
//   O's own signer stays OFFLINE: A trades a perpetual, a BTC call and BTC/USDT spot through the
//   TypeScript SDK, and every batch commits on A's acknowledgement of its own legs (makers sign
//   theirs); a trade O makes by hand is not offered to A and A's signature for it is refused; A is
//   refused past each limit (per-order notional, collar, open orders, 24 h notional, rate, instrument,
//   withdrawal); idempotency keys, rate-limit headers, structured errors, sequenced WS
//   subscriptions with resync; the IronClaw MCP server (integrations/ironclaw/server.ts) driven as an
//   MCP client would (initialize, tools/list, tools/call, bearer token, refusals as tool errors); the
//   Python SDK and both example strategies; O revokes A mid-session (resting orders pulled at once,
//   A refused, the MCP session halts); a short grant expires; restart keeps grants, revocation and
//   usage; a venue without --agents keeps every agent write off and journals nothing for it.
//
//   --demo: stop once the makers quote and keep relay, venue and makers up at http://127.0.0.1:<port>/
//   (Settings -> Agents delegates a key from the browser).
//
// Never talks to anything but 127.0.0.1. State dirs go under --work (default D:/shz/tmp).

import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { appendFileSync, writeFileSync, mkdirSync, openSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { hex, unhex, bip340Sign, pubkey, taggedHash, sha256, mul, liftX, bytesToInt, intToBytes, signIntent, signIntentV7, signSpotIntent, signTransfer } from '../../../ui/venue/crypto.js';
import { Agent, Client, LightningerError, Stream, createGrant, revokeGrant } from '../../../sdk/ts/src/index.ts';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..', '..');
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const OUT = path.resolve(arg('out', path.join(HERE, '..', 'results', 'agent-drill.jsonl')));
const WORK = arg('work', 'D:/shz/tmp');
const VENUE_BIN = arg('venue-bin', 'D:/shz/target-msvc/debug/shz-venue.exe');
const NODE = process.execPath;
const PYTHON = arg('python', 'C:/Users/patri/AppData/Local/Programs/Python/Python312/python.exe');
const VPORT = Number(arg('port', '18495'));
const RPORT = Number(arg('relay-port', '18491'));
const MPORT = Number(arg('mcp-port', '18497'));
const PPORT = Number(arg('proxy-port', '18499'));
// A stand-in for Caddy in front of the venue: forwards HTTP and WebSocket upgrades and APPENDS the
// client address to X-Forwarded-For (any client-sent value stays to its left, as Caddy does). The
// drill models distinct client addresses with an `x-test-client` header or `__client` query
// parameter, which the proxy strips and uses as the address it "accepted the connection from".
function startProxy() {
  const clientOf = (req) => {
    const u = new URL(req.url, 'http://x');
    const c = req.headers['x-test-client'] || u.searchParams.get('__client') || req.socket.remoteAddress;
    u.searchParams.delete('__client');
    const headers = { ...req.headers };
    delete headers['x-test-client'];
    headers['x-forwarded-for'] = headers['x-forwarded-for'] ? `${headers['x-forwarded-for']}, ${c}` : c;
    return { path: u.pathname + u.search, headers };
  };
  const srv = http.createServer((req, res) => {
    const { path: p, headers } = clientOf(req);
    const up = http.request({ host: '127.0.0.1', port: VPORT, method: req.method, path: p, headers }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    up.on('error', () => { res.writeHead(502); res.end(); });
    req.pipe(up);
  });
  srv.on('upgrade', (req, sock, head) => {
    const { path: p, headers } = clientOf(req);
    const up = net.connect(VPORT, '127.0.0.1', () => {
      up.write(`${req.method} ${p} HTTP/1.1\r\n` + Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n');
      if (head?.length) up.write(head);
      up.pipe(sock); sock.pipe(up);
    });
    up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
  });
  srv.listen(PPORT, '127.0.0.1');
}
// --demo: stop after the makers quote; keep relay, venue and makers running for a browser session.
const DEMO = process.argv.includes('--demo');
const UI_DIR = path.join(ROOT, 'ui', 'venue');
const VENUE = `http://127.0.0.1:${VPORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const T0 = Date.now();
const te = (s) => new TextEncoder().encode(s);

mkdirSync(path.dirname(OUT), { recursive: true });
writeFileSync(OUT, '');
const log = (kind, o = {}) => appendFileSync(OUT, JSON.stringify({ t: +((Date.now() - T0) / 1000).toFixed(2), kind, ...o }) + '\n');
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok });
  log('assert', { name, ok: !!ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail === undefined ? '' : '  ' + JSON.stringify(detail).slice(0, 400)}`);
}
const note = (m, o = {}) => { log('note', { m, ...o }); console.log('..    ' + m); };

// ---------------------------------------------------------------- test oracle + relay (local test key only)
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = liftX(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n);
const GROUP_SK = await sha256(te('shz-agent-drill/test-group-key/v1'));
const GROUP_PK = hex(pubkey(GROUP_SK));
const oracleD = (() => { let d = bytesToInt(GROUP_SK); const P = mul(G, d); if (P[1] % 2n) d = N - d; return d; })();
async function nonce(label) {
  let k = bytesToInt(await sha256(te('shz-agent-drill/nonce/' + label))) % N;
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
const events = new Map();
async function announce(maturity) {
  const id = 'SHZ-BTCUSD-' + new Date(maturity * 1000).toISOString().replace(/[-:]/g, '').slice(0, 13) + 'Z';
  const digits = []; for (let j = 0; j < NUM_BITS; j++) digits.push(await nonce(`${id}/digit/${j}`));
  const annN = await nonce(`${id}/announcement`), unN = await nonce(`${id}/unattestable`);
  const core = { event_id: id, maturity_unix: maturity, num_bits: NUM_BITS, oracle_pubkey_x: GROUP_PK, digit_nonces_x: digits.map((d) => hex(d.rx)),
    announcement_nonce_x: hex(annN.rx), unattestable_nonce_x: hex(unN.rx), unattestable_rule: 'drill: unused', outcome: 'drill: scripted',
    digit_message: 'shz_dlc::oracle_digit_message(event_id, digit_idx, bit), MSB first (shz_margin::decompose_price_bits)', threshold: '1-of-1 (drill test key)' };
  const digest = await taggedHash('SHZ/DLC/ANNOUNCEMENT/V1', te(canon(core)));
  events.set(id, { core, announcement_digest: hex(digest), announcement_signature: hex(await signWithNonce(digest, annN)), status: 'announced', qualified: [1],
    shz_dlc_announcement: { event_id: id, maturity_unix: maturity, oracle_pubkey_x: [...unhex(GROUP_PK)], digit_nonces_x: digits.map((d) => [...d.rx]) } });
  return id;
}
const relay = { seq: 0, price: 100_000, latest: null, clients: new Set() };
async function emit() {
  relay.seq += 1;
  const us = Date.now() * 1000;
  const body = { schema: 'shz-public-relay/v1', market: 'BTC/USD', data_class: 'public_delayed', seq: relay.seq, previous: '0'.repeat(64), interval_ms: 1000,
    slot_us: us, assembled_us: us, status: 'VALID', median_e8: Math.round(relay.price * 1e8) };
  const digest = await taggedHash('SHZ/PUBLIC-RELAY-PACKET/V1', te(canon(body)));
  relay.latest = { body, digest: hex(digest), signature: hex(await bip340Sign(digest, GROUP_SK)), frost_signers: ['agent-drill-test-key'] };
  for (const res of relay.clients) res.write(`data: ${JSON.stringify(relay.latest)}\n\n`);
}
function startRelay() {
  const json = (res, code, o) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
  http.createServer((req, res) => {
    if (req.url === '/v1/pubkey') return json(res, 200, { pubkey_bip340: GROUP_PK });
    if (req.url === '/v1/latest') return json(res, 200, relay.latest);
    if (req.url === '/v1/stream') { res.writeHead(200, { 'content-type': 'text/event-stream' }); relay.clients.add(res); req.on('close', () => relay.clients.delete(res)); return; }
    if (req.url === '/v1/dlc/events') return json(res, 200, { oracle_pubkey_x: GROUP_PK, events: [...events.values()].map((e) => ({ event_id: e.core.event_id, maturity_unix: e.core.maturity_unix, status: e.status, price_usd: null })) });
    if (req.url.startsWith('/v1/dlc/event/')) { const e = events.get(req.url.slice(14)); return e ? json(res, 200, e) : json(res, 404, { error: 'unknown event' }); }
    json(res, 404, {});
  }).listen(RPORT, '127.0.0.1');
  setInterval(() => { emit().catch((e) => console.error('emit', e)); }, 1000);
}

// ---------------------------------------------------------------- processes
const USDT_ID = hex(await sha256(te('shz-agent-drill/demo-usdt-rgb-contract/v1')));
const USDT = { kind: 'stable', protocol: 'rgb', id: USDT_ID, decimals: 6 };
const procs = new Set();
let shuttingDown = false;
function spawnLogged(cmd, args, tag) {
  const fd = openSync(path.join(WORK, `agent-drill-${tag}.log`), 'a');
  const p = spawn(cmd, args, { stdio: ['ignore', fd, fd], cwd: ROOT });
  procs.add(p); p.on('exit', () => procs.delete(p));
  return p;
}
async function startVenue(state, port, extra, tag) {
  const p = spawnLogged(VENUE_BIN, ['--listen', `127.0.0.1:${port}`, '--state', state, '--ui', UI_DIR, '--relay', `http://127.0.0.1:${RPORT}`,
    '--group-key', GROUP_PK, '--mempool-api', 'http://127.0.0.1:9/none', ...extra], `venue-${tag}-${port}`);
  p.on('exit', (c) => { if (!shuttingDown && !p.expectedExit) { console.error(`venue ${tag} exited`, c); finish(3); } });
  for (let i = 0; i < 150; i++) { try { await fetchJson(`http://127.0.0.1:${port}/api/status`); return p; } catch { await sleep(200); } }
  throw new Error('venue did not start');
}
async function stopProc(p) { p.expectedExit = true; p.kill(); await new Promise((r) => (p.exitCode !== null ? r() : p.on('exit', r))); }
async function fetchJson(url, body, headers = {}) {
  const r = await fetch(url, body === undefined ? { cache: 'no-store', headers } : { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { /* none */ }
  return { status: r.status, json: j, headers: r.headers };
}
async function api(p, body) { const r = await fetchJson(VENUE + p, body); if (r.status >= 300) throw new Error(`${p}: ${r.status} ${JSON.stringify(r.json?.error)}`); return r.json; }
async function waitFor(pred, ms, what) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { const v = await pred(); if (v) return v; } catch { /* retry */ } await sleep(150); }
  log('wait_timeout', { what }); return null;
}
const code = async (p) => { try { await p; return 'accepted'; } catch (e) { return e instanceof LightningerError ? e.code : 'error:' + e.message; } };

// ---------------------------------------------------------------- owner-side accounts (owner keys)
let template;
const accts = {};
async function mkAcct(name) {
  const sk = await sha256(te('shz-agent-drill/account/' + name));
  const owner = hex(pubkey(sk));
  const d = await api('/api/register/draft', { owner, kind: 'demo', outpoint: null });
  const a = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(await bip340Sign(unhex(d.allocation_digest), sk)) })).account;
  return (accts[name] = { name, sk, owner, outpoint: a.outpoint, seqP: 0, seqO: 0, seqS: 0, signed: new Set(), online: true });
}
let xn = 0;
async function transfer(w, op, amount, asset = null) {
  xn += 1;
  return api('/api/options/' + op, await signTransfer(op, { owner: w.owner, asset, amount, expires_us: (Date.now() + 60_000) * 1000 + xn }, w.sk));
}
const chan = (w) => ({ txid: w.outpoint.txid, vout: w.outpoint.vout });
// Owner sequences exactly as the browser makes them (ui/venue/venue.js, options.js, spot.js): one
// counter per instrument, microsecond clock. These are the counters an agent must stay above.
const usNow = () => Date.now() * 1000;
const nextPerp = (w) => (w.seqP = Math.max(w.seqP + 1, usNow()));
const nextOpt = (w) => (w.seqO = Math.max(w.seqO + 1, usNow()));
const nextSpot = (w) => (w.seqS = Math.max(w.seqS + 1, usNow()));
async function perpOwner(w, f) {
  const { id, intent } = await signIntent({ owner: w.owner, channel: chan(w), sequence: nextPerp(w), expires_us: (Date.now() + 120e3) * 1000, tier: 'standard',
    max_fee_ppm: 0, max_fee_sats: 100_000, max_mark_age_us: 15_000_000, early_window_opt_in: false, cancel_target: '0'.repeat(64), ...f }, template, w.sk);
  const r = await fetchJson(VENUE + '/api/intents', { intent });
  return { id, status: r.status, ...r.json };
}
async function optionOwner(w, f) {
  const { id, intent } = await signIntentV7({ owner: w.owner, channel: chan(w), sequence: nextOpt(w), expires_us: (Date.now() + 600e3) * 1000, ...f }, template, w.sk);
  const r = await fetchJson(VENUE + '/api/options/intents', { intent });
  return { id, status: r.status, ...r.json };
}
async function spotOwner(w, f) {
  const { id, intent } = await signSpotIntent({ owner: w.owner, channel: chan(w), sequence: nextSpot(w), expires_us: (Date.now() + 600e3) * 1000, pair: spotPair, ...f }, template, w.sk);
  const r = await fetchJson(VENUE + '/api/spot/intents', { intent });
  return { id, status: r.status, ...r.json };
}
async function signPending(w) {
  const v = await api('/api/account/' + w.owner);
  const todo = (v.pending_signatures || []).filter((x) => !w.signed.has(x.id));
  if (!todo.length) return 0;
  const items = [];
  for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), w.sk)) });
  await api('/api/signatures', { owner: w.owner, items });
  for (const x of todo) w.signed.add(x.id);
  return todo.length;
}
let signing = true;
async function makerSignLoop() {
  while (signing) {
    for (const w of Object.values(accts)) if (w.online) { try { await signPending(w); } catch (e) { log('sign_error', { acct: w.name, e: e.message }); } }
    await sleep(100);
  }
}
let spotPair;
const usdtBase = (p) => Math.round(p * 10) * 100_000;

// ---------------------------------------------------------------- MCP client (what IronClaw sends)
async function mcp(ep, method, params, tokenHeader) {
  const headers = { accept: 'application/json, text/event-stream', ...(tokenHeader ? { authorization: tokenHeader } : {}) };
  const r = await fetchJson(`http://127.0.0.1:${MPORT}/mcp/${ep}`, { jsonrpc: '2.0', id: Math.floor(Math.random() * 1e9), method, params }, headers);
  return r;
}
const tool = async (ep, name, args, tok) => (await mcp(ep, 'tools/call', { name, arguments: args }, tok)).json?.result;

// ---------------------------------------------------------------- main
async function main() {
  startRelay(); await emit();
  const nowS = Math.floor(Date.now() / 1000);
  const ev = await announce(Math.ceil((nowS + 1800) / 60) * 60);
  note('relay up', { group_key: GROUP_PK, event: ev });

  // ---- off by default
  const offState = path.join(WORK, `agent-drill-off-${Date.now()}`);
  const off = await startVenue(offState, VPORT + 1, [], 'off');
  const OFF = `http://127.0.0.1:${VPORT + 1}`;
  const j0 = (await fetchJson(OFF + '/api/status')).json.journal.records;
  const offInfo = await fetchJson(OFF + '/agent/v1/info');
  const offDraft = await fetchJson(OFF + '/agent/v1/grants/draft', { owner: '11'.repeat(32), agent: '22'.repeat(32), instruments: ['perps'], limits: {} });
  const offGrant = await fetchJson(OFF + '/agent/v1/grants', { grant: {} });
  await stopProc(off);
  const offWal = readFileSync(path.join(offState, 'router.wal')).toString('latin1');
  check('without --agents: reads serve (info agents.enabled=false), draft and create answer 404 agents.off, and the router journal holds no agent record',
    offInfo.status === 200 && offInfo.json.agents.enabled === false && offDraft.status === 404 && offDraft.json.error.code === 'agents.off' && offGrant.json.error.code === 'agents.off' && !/Agent/.test(offWal),
    { info: offInfo.json?.agents, draft: offDraft.json?.error?.code, wal_bytes: offWal.length, journal_records_at_start: j0 });

  // ---- venue with agents
  const state = path.join(WORK, `agent-drill-${Date.now()}`);
  let v = await startVenue(state, VPORT, ['--options', '--stable-usdt', USDT_ID, '--spot', '--agents'], 'on');
  template = await api('/api/template');
  const c = new Client(VENUE);
  const info = await c.info();
  check('agent API v1 is up: testnet4, not production, agents/options/spot on, 20 methods, error codes listed', info.api_version === 'agent/v1' && info.network === 'testnet4' && info.production_ready === false
    && info.agents.enabled && info.options && info.spot && info.methods.length === 20 && info.error_codes.length >= 20, { agents: info.agents, methods: info.methods.length });
  const spec = await fetchJson(VENUE + '/agent/v1/openapi.json');
  check('the OpenAPI document is served and lists every REST route', spec.status === 200 && spec.json.openapi === '3.1.0' && info.methods.every((m) => spec.json.paths[m.rest.split(' ')[1]]), Object.keys(spec.json.paths).length);
  const mk = await c.markets();
  spotPair = mk.spot.pair;
  const series = await waitFor(async () => { const s = await c.optionChain(); return s.series?.length >= 15 ? s : null; }, 40_000, 'series listed');
  const C100 = series?.series.find((s) => s.kind === 'call' && s.asset_code === 'BTC' && s.strike_usd === 100000);
  check('market data: perp template, spot pair, the option chain lists the 100k BTC call', !!mk.perp.scope && !!spotPair && !!C100, { series: series?.series?.length });

  // accounts: O delegates (its signer is offline), MP makes perps and spot, MO writes calls
  const O = await mkAcct('O'), MP = await mkAcct('MP'), MO = await mkAcct('MO');
  O.online = false;
  await transfer(O, 'fund', 50_000); await transfer(O, 'deposit', 500_000_000, USDT);
  await transfer(MP, 'fund', 100_000); await transfer(MP, 'deposit', 2_000_000_000, USDT);
  await transfer(MO, 'fund', 150_000);
  makerSignLoop();
  const quotes = [
    await perpOwner(MP, { action: 'post', side: 'short', quantity: 300, limit_usd: 100_000, leverage_bps: 100_000 }),
    await perpOwner(MP, { action: 'post', side: 'long', quantity: 300, limit_usd: 99_900, leverage_bps: 100_000 }),
    await optionOwner(MO, { action: 'post', legs: [{ series: C100.id, long: false, qty: 100 }], premium_milli: 3000 }),
    await spotOwner(MP, { action: 'post', buy: false, qty_sats: 50_000, price: usdtBase(100_050) }),
    await spotOwner(MP, { action: 'post', buy: true, qty_sats: 50_000, price: usdtBase(99_950) }),
  ];
  check('makers quote perp, call and spot (owner-signed, existing endpoints)', quotes.every((q) => q.status === 200), quotes.map((q) => q.outcome || q.status));
  await sleep(500);
  if (DEMO) { note(`DEMO ready: ${VENUE}/ (makers quote and sign their acks)`); return; }

  // ---- grant: O signs for agent key A (owner key used here only)
  const aSk = randomBytes(32), aPk = hex(pubkey(aSk));
  const limits = { max_order_notional_usd: 300, max_daily_notional_usd: 1_200, max_open_orders: 3, max_orders_per_minute: 60, collar_bps: 300 };
  let consentShown = '';
  const gv = await createGrant(c, O.sk, aPk, ['perps', 'options', 'spot'], limits, { expiresInS: 3600, label: 'drill agent A', confirm: (t) => { consentShown = t; return true; } });
  check('O drafts, checks and signs a grant; the consent text was shown before signing and says no withdrawals', gv.status === 'active' && gv.grant.may_withdraw === false && /cannot withdraw/.test(consentShown) && gv.grant.agent === aPk,
    { id: gv.id, consent: consentShown.slice(0, 120) });
  const G1 = gv.id;
  const tamper = await fetchJson(VENUE + '/agent/v1/grants', { grant: { ...gv.grant, limits: { ...limits, max_order_notional_usd: 100_000 } } });
  check('a grant whose fields differ from what the owner signed is refused (grant.signature)', tamper.status === 401 && tamper.json.error.code === 'grant.signature', tamper.json?.error);

  // The owner trades every instrument from the browser first (browser sequence scheme), on the
  // same account the agent will trade: the agent must start above each of those counters.
  const oSpot = await spotOwner(O, { action: 'post', buy: true, qty_sats: 1_000, price: usdtBase(90_000) });
  const oSpotX = await spotOwner(O, { action: 'cancel', buy: false, qty_sats: 0, price: 0, cancel_target: oSpot.id });
  const oOpt = await optionOwner(O, { action: 'post', legs: [{ series: C100.id, long: true, qty: 100 }], premium_milli: 100 });
  const oOptX = await optionOwner(O, { action: 'cancel', legs: [], premium_milli: 0, cancel_target: oOpt.id });
  const oPerp = await perpOwner(O, { action: 'post', side: 'long', quantity: 10, limit_usd: 95_000, leverage_bps: 50_000 });
  const oPerpX = await perpOwner(O, { action: 'cancel', side: 'long', quantity: 0, limit_usd: 0, leverage_bps: 0, max_fee_ppm: 0, max_fee_sats: 0, max_mark_age_us: 0, cancel_target: oPerp.id });
  check('the owner posts and cancels spot, an option and a perpetual from the browser path first (microsecond sequences)',
    [oSpot, oSpotX, oOpt, oOptX, oPerp, oPerpX].every((x) => x.status === 200), [oSpot, oSpotX, oOpt, oOptX, oPerp, oPerpX].map((x) => x.outcome || x.status || x.error));
  const A = await Agent.open(c, aSk, G1);
  const overCap = await code(A.spotPost(true, 400_000, usdtBase(99_900)));
  check('on that account an over-cap agent order is refused by the grant (limit.order_notional), not by the router', overCap === 'limit.order_notional', overCap);
  const stopA = A.startAutosigner(150);
  const stream = await Stream.open(VENUE);
  const seen = { trades: [], batches: [], grants: [] };
  await stream.subscribe(['trades', 'batches', 'grants'], (ch, kind, data) => { seen[ch].push({ kind, data }); });

  // ---- A trades perps: its own acks commit the batch while O is offline
  const pBefore = (await c.account(O.owner)).position.committed_net_usd;
  const pt = await A.perpTake('long', 100, 100_100, 50_000);
  const pCommitted = await waitFor(async () => { const a = await c.account(O.owner); return a.position.committed_net_usd === pBefore + 100 ? a : null; }, 20_000, 'perp batch committed');
  const lastBatch = pCommitted && (await api('/api/explorer/batches?limit=5'))[0];
  check('A takes 100 USD of the perpetual for O; the batch commits on A\'s approval and lane ack (O offline)', !!pCommitted && lastBatch?.phase === 'committed', { take: pt.id?.slice(0, 16), net: pCommitted?.position?.committed_net_usd, phase: lastBatch?.phase });

  // ---- A buys a BTC call
  const oBefore = (await c.account(O.owner)).options.legs.length;
  const ot = await A.optionTake([{ series: C100.id, long: true, qty: 100 }], 350_000); // take: net premium limit in millisats (ask 3,000 x 100)
  const oDone = await waitFor(async () => { const a = await c.account(O.owner); return a.options.legs.some((l) => l.series === C100.id && l.net === 100) ? a : null; }, 20_000, 'option committed');
  check('A buys the 100k call (staged option batch) and it commits on A\'s V4 ack', ot.outcome === 'staged' && !!oDone, { outcome: ot.outcome, legs_before: oBefore, legs: oDone?.options?.legs });

  // ---- A buys spot
  const sBefore = (await c.account(O.owner)).options.balances.find((b) => b.asset === 'BTC').free;
  // The owner's browser clock runs 60 s ahead: its desk sequence jumps past the agent's counter after
  // the agent started; the agent's next spot order is refused once (Replay), re-reads the venue's
  // sequences and goes through.
  O.seqS = usNow() + 60_000_000;
  const ahead = await spotOwner(O, { action: 'post', buy: true, qty_sats: 1_000, price: usdtBase(90_000) });
  await spotOwner(O, { action: 'cancel', buy: false, qty_sats: 0, price: 0, cancel_target: ahead.id });
  const deskBefore = A.seq.desk;
  const st = await A.spotTake(true, 20_000, usdtBase(100_100));
  check('owner clock ahead: the agent re-seeds from the venue and its spot order is accepted', ahead.status === 200 && st.outcome === 'staged' && A.seq.desk > O.seqS && deskBefore < O.seqS,
    { owner_seq: O.seqS, agent_before: deskBefore, agent_after: A.seq.desk });
  const sDone = await waitFor(async () => { const a = await c.account(O.owner); const b = a.options.balances.find((x) => x.asset === 'BTC').free; return b === sBefore + 20_000 ? a : null; }, 20_000, 'spot committed');
  check('A buys 20,000 sats spot with demo USDT; the spot batch commits on A\'s ack', st.outcome === 'staged' && !!sDone, { outcome: st.outcome, btc_free: [sBefore, sDone && sBefore + 20_000] });

  // ---- a trade O makes by hand is not A's to acknowledge
  O.online = false;
  const hand = await perpOwner(O, { action: 'take', side: 'long', quantity: 50, limit_usd: 100_100, leverage_bps: 50_000 });
  const pend = await waitFor(async () => { const a = await c.account(O.owner); return (a.pending_signatures || []).length ? a.pending_signatures : null; }, 10_000, 'owner batch pending');
  const offered = await c.pendingAcks(G1);
  const forced = pend ? await c.submitAcks(G1, [{ id: pend[0].id, signature: hex(await bip340Sign(unhex(pend[0].message, 32), aSk)) }]) : null;
  check('O\'s own trade: A is not offered its ack, and A\'s signature for it is refused (ack.outside_grant)', hand.status === 200 && pend && !offered.some((x) => x.id === pend[0].id) && forced?.refused?.[0]?.code === 'ack.outside_grant',
    { pending: pend?.length, offered: offered.length, forced });
  await signPending(O); await sleep(400); await signPending(O);
  const handDone = await waitFor(async () => (await c.account(O.owner)).position.committed_net_usd === pBefore + 150, 20_000, 'owner trade committed');
  check('O signs its own trade and it commits', !!handDone);

  // ---- refusals, one per limit
  const r = {};
  r.order_notional = await code(A.perpPost('long', 301, 99_000, 50_000));
  r.collar = await code(A.perpPost('long', 50, 96_000, 50_000));
  const rest = [];
  for (const px of [99_000, 98_900, 98_800]) rest.push(await A.perpPost('long', 100, px, 50_000));
  r.open_orders = await code(A.perpPost('long', 10, 98_700, 50_000));
  for (const x of rest.slice(1)) await A.perpCancel(x.id);
  await sleep(300);
  // 24 h: 100 + 100 + 20 + 300 so far; 300 + 300 more reach 1,120; the next 100 passes 1,200.
  const d1 = await A.perpPost('short', 300, 101_000, 50_000); await A.perpCancel(d1.id);
  const d2 = await A.perpPost('short', 300, 101_100, 50_000); await A.perpCancel(d2.id);
  r.daily_notional = await code(A.perpPost('short', 100, 101_200, 50_000));
  const usage = (await A.status()).usage;
  await A.perpCancel(rest[0].id);
  r.instrument_grant = await (async () => { // a second key with a perps-only grant tries spot
    const bSk = randomBytes(32);
    const g = await createGrant(c, O.sk, hex(pubkey(bSk)), ['perps'], { ...limits, max_orders_per_minute: 2 }, { expiresInS: 600, label: 'perps-only, 2/min' });
    const B = await Agent.open(c, bSk, g.id);
    B.template.spot_pair = spotPair;
    const inst = await code(B.spotPost(true, 1_000, usdtBase(99_000)));
    const c1 = await code(B.perpCancel('ab'.repeat(32))), c2 = await code(B.perpCancel('cd'.repeat(32))), c3 = await code(B.perpCancel('ef'.repeat(32)));
    return { inst, rate: [c1, c2, c3] };
  })();
  // withdrawal: an agent-signed defund of O's options balance (owner field O)
  xn += 1;
  const wd = await fetchJson(VENUE + '/api/options/defund', await signTransfer('defund', { owner: O.owner, amount: 1_000, expires_us: (Date.now() + 60_000) * 1000 + xn }, aSk));
  const wdAgent = await fetchJson(VENUE + '/agent/v1/withdraw', { grant: G1, amount: 1 });
  check('per-order notional: 301 USD > 300 is refused (limit.order_notional, 422)', r.order_notional === 'limit.order_notional');
  check('collar: a bid 4 % under the mark is refused (limit.collar)', r.collar === 'limit.collar');
  check('open orders: a 4th resting order is refused (limit.open_orders)', r.open_orders === 'limit.open_orders');
  check('24 h notional: the order that would pass 1,200 USD is refused (limit.daily_notional)', r.daily_notional === 'limit.daily_notional', usage);
  check('instrument: a perps-only grant cannot place spot (grant.instrument)', r.instrument_grant.inst === 'grant.instrument', r.instrument_grant);
  check('rate: the 3rd call in a minute on a 2/min grant is refused (limit.rate, 429)', r.instrument_grant.rate[2] === 'limit.rate', r.instrument_grant.rate);
  check('withdrawal: an agent-signed defund is refused and the agent API has no withdraw route', wd.status === 409 && /signature/.test(wd.json?.error) && wdAgent.status === 404, { defund: wd.json?.error, route: wdAgent.status });

  // ---- idempotency, rate headers, structured errors
  const signed = A.signed('perp', { action: 'post', side: 'long', tier: 'standard', quantity: 10, limit_usd: 99_500, leverage_bps: 50_000, max_fee_ppm: 0, max_fee_sats: 100_000, max_mark_age_us: 15_000_000, early_window_opt_in: false, cancel_target: '0'.repeat(64) }, 120);
  const ik = 'drill-' + Date.now();
  const i1 = await fetchJson(VENUE + '/agent/v1/orders', { grant: G1, instrument: 'perp', intent: signed.intent }, { 'idempotency-key': ik });
  const i2 = await fetchJson(VENUE + '/agent/v1/orders', { grant: G1, instrument: 'perp', intent: signed.intent }, { 'idempotency-key': ik });
  const i3 = await fetchJson(VENUE + '/agent/v1/orders', { grant: G1, instrument: 'perp', intent: { ...signed.intent, quantity: 11 } }, { 'idempotency-key': ik });
  check('idempotency: a retried order with the same key returns the first response; a different body is refused (409 idempotency.mismatch)',
    i1.status === 200 && i2.status === 200 && i2.json.idempotent_replay === true && i2.json.id === i1.json.id && i3.status === 409 && i3.json.error.code === 'idempotency.mismatch',
    { first: i1.json?.id?.slice(0, 16), replay: i2.json?.idempotent_replay, mismatch: i3.json?.error?.code });
  check('a direct local client is not rate limited (X-RateLimit-Scope: local); errors are {code, message, details, retryable}', i1.headers.get('x-ratelimit-scope') === 'local'
    && i3.json.error.retryable === false && typeof i3.json.error.message === 'string', { scope: i1.headers.get('x-ratelimit-scope') });
  await A.perpCancel(i1.json.id);

  // ---- WebSocket: sequenced notifications, RPC methods, resync
  await sleep(500);
  const seqs = seen.trades.filter((x) => x.kind === 'event').map((x) => x.data.type);
  const bseq = seen.batches.length;
  const rs = await stream.resync('batches');
  const viaWs = await stream.call('grant.get', { id: G1 });
  check('WS: trades and batches arrive as numbered subscription events; resync replays or snapshots; every REST method is a JSON-RPC method',
    seqs.length >= 3 && bseq >= 3 && rs.seq >= bseq && ('replay' in rs || 'snapshot' in rs) && viaWs.id === G1 && seen.grants.length >= 1,
    { trade_events: seqs, batch_events: bseq, resync: { seq: rs.seq, kind: 'replay' in rs ? 'replay' : 'snapshot' }, grants: seen.grants.length });
  const badCh = await stream.call('subscribe', { channels: ['nope'] }).catch((e) => e);
  check('WS: an unknown channel is a structured JSON-RPC error', badCh.code === 'channel.unknown' && badCh.rpcCode < -32000, { code: badCh.code, rpc: badCh.rpcCode });

  // ---- IronClaw MCP server
  const tokenFile = path.join(WORK, `agent-drill-mcp-${Date.now()}.token`);
  const tok = randomBytes(32).toString('hex');
  writeFileSync(tokenFile, tok, { mode: 0o600 });
  const keyFile = path.join(WORK, `agent-drill-a-${Date.now()}.key`);
  writeFileSync(keyFile, hex(aSk), { mode: 0o600 });
  const mcpProc = spawnLogged(NODE, [path.join(ROOT, 'integrations', 'ironclaw', 'server.ts'), '--venue', VENUE, '--listen', `127.0.0.1:${MPORT}`,
    '--agent-key', keyFile, '--grant', G1, '--token-file', tokenFile, '--max-trades-per-minute', '20'], 'mcp');
  await waitFor(async () => (await fetchJson(`http://127.0.0.1:${MPORT}/mcp/market`, { jsonrpc: '2.0', id: 1, method: 'ping' })).status === 200, 15_000, 'mcp up');
  const bearer = 'Bearer ' + tok;
  const initM = await mcp('market', 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'drill-ironclaw-client', version: '1' } });
  const initT = await mcp('trade', 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'drill-ironclaw-client', version: '1' } }, bearer);
  const noTok = await mcp('trade', 'tools/list', {});
  const listM = (await mcp('market', 'tools/list', {})).json.result.tools;
  const listT = (await mcp('trade', 'tools/list', {}, bearer)).json.result.tools;
  const note202 = await fetchJson(`http://127.0.0.1:${MPORT}/mcp/market`, { jsonrpc: '2.0', method: 'notifications/initialized' });
  check('MCP: initialize on both endpoints (protocol 2025-06-18, session id), notifications get 202, the trade endpoint needs the bearer token',
    initM.json.result.protocolVersion === '2025-06-18' && !!initM.headers.get('mcp-session-id') && initT.json.result.instructions.includes('cannot withdraw') && noTok.status === 401 && note202.status === 202,
    { market: initM.json?.result?.serverInfo, trade_401: noTok.status });
  check('MCP: /mcp/market lists 6 read-only tools; /mcp/trade adds 7 grant-bound tools, trading ones marked destructive and carrying the grant text',
    listM.length === 6 && listM.every((t) => t.annotations.readOnlyHint) && listT.length === 13
    && listT.filter((t) => !t.annotations.readOnlyHint).every((t) => t.annotations.destructiveHint && (t.name === 'halt_trading' || t.description.includes('Delegated grant'))),
    { market: listM.map((t) => t.name), trade: listT.map((t) => t.name) });
  const mo = await tool('market', 'market_overview', {});
  const gs = await tool('trade', 'grant_status', {}, bearer);
  const mOk = await tool('trade', 'place_perp_order', { type: 'post', side: 'long', quantity_usd: 20, limit_usd: 99_400, leverage: 5 }, bearer);
  const mBig = await tool('trade', 'place_perp_order', { type: 'post', side: 'long', quantity_usd: 5_000, limit_usd: 99_400, leverage: 5 }, bearer);
  check('MCP tools: market data read freely; grant_status shows the consent and usage; an order inside the grant is accepted; one past it is a tool error with the API code',
    !mo.isError && mo.structuredContent.mark_usd === 100000 && /cannot withdraw/.test(gs.structuredContent.consent) && !mOk.isError && mBig.isError && mBig.structuredContent.error === 'limit.order_notional',
    { mark: mo.structuredContent?.mark_usd, ok: mOk.structuredContent?.id?.slice(0, 16), big: mBig.structuredContent?.error });
  const mcpOrder = mOk.structuredContent.id;

  // ---- Python SDK and both examples (separate grant, agent key B2)
  const b2Sk = randomBytes(32);
  const g2 = await createGrant(c, O.sk, hex(pubkey(b2Sk)), ['perps', 'spot'], { ...limits, max_open_orders: 4, max_daily_notional_usd: 5_000 }, { expiresInS: 900, label: 'examples' });
  const b2File = path.join(WORK, `agent-drill-b2-${Date.now()}.key`);
  writeFileSync(b2File, hex(b2Sk), { mode: 0o600 });
  const runOut = (cmd, args, ms) => new Promise((res) => {
    const p = spawn(cmd, args, { cwd: ROOT }); let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    const t = setTimeout(() => p.kill(), ms);
    p.on('exit', (code) => { clearTimeout(t); res({ code, out, err }); });
  });
  const pyScript = `
import json, sys
sys.path.insert(0, "sdk/python")
from lightninger import Agent, Client, LightningerError, Stream
a = Agent(Client("${VENUE}"), bytes.fromhex(open(r"${b2File}").read().strip()), "${g2.id}")
s = Stream("${VENUE}"); got = []
s.subscribe(["mark"], lambda ch, kind, d: got.append(kind))
p = a.perp_post("short", 15, 100_900, 50_000)
c = a.perp_cancel(p["id"])
try:
    a.perp_post("short", 1000, 100_900, 50_000); big = "accepted"
except LightningerError as e:
    big = e.code
import time; time.sleep(2.5)
print(json.dumps({"post": p["id"], "cancel": c["id"], "big": big, "marks": len(got), "rate": a.c.rate}))
`;
  const py = await runOut(PYTHON, ['-c', pyScript], 30_000);
  let pj = null; try { pj = JSON.parse(py.out.trim().split('\n').pop()); } catch { /* below */ }
  check('Python SDK: posts and cancels under its grant, gets limit.order_notional past it, receives WS marks',
    py.code === 0 && pj && pj.big === 'limit.order_notional' && pj.marks >= 1, pj || py.err.slice(-400));
  const pyEx = await runOut(PYTHON, ['sdk/python/examples/quote_agent.py', '--venue', VENUE, '--agent-key', b2File, '--grant', g2.id, '--seconds', '5'], 40_000);
  const tsEx = await runOut(NODE, ['sdk/ts/examples/quote_agent.ts', '--venue', VENUE, '--agent-key', b2File, '--grant', g2.id, '--seconds', '5'], 40_000);
  check('example strategies run: Python quotes the perpetual, TypeScript quotes spot, both inside the grant, both exit cleanly',
    pyEx.code === 0 && /"quoted"/.test(pyEx.out) && /"done"/.test(pyEx.out) && tsEx.code === 0 && /"quoted"/.test(tsEx.out) && /"instrument":"spot"/.test(tsEx.out),
    { py: pyEx.out.split('\n').filter(Boolean).slice(-1)[0]?.slice(0, 160), ts: tsEx.out.split('\n').filter(Boolean).slice(-1)[0]?.slice(0, 160), py_err: pyEx.err.slice(-200), ts_err: tsEx.err.slice(-200) });

  // ---- revocation mid-session
  // A's open orders other than the MCP one (cancels are queued, so wait until the venue shows them done).
  const openOf = async () => (await c.orders(G1)).filter((o) => ['resting', 'queued', 'partially filled'].includes(o.status) && o.id !== mcpOrder && o.intent?.action !== 'cancel');
  const leftover = await openOf();
  log('open_before_revocation', { ids: leftover.map((o) => [o.id.slice(0, 16), o.instrument, o.status]) });
  for (const o of leftover) await (o.instrument === 'spot' ? A.spotCancel(o.id) : A.perpCancel(o.id));
  await waitFor(async () => (await openOf()).length === 0, 5_000, 'leftover orders cancelled');
  const restP = await A.perpPost('short', 40, 100_800, 50_000); // 24 h: 1,120 + 10 + 20 (MCP) + 40 + 5 (spot) = 1,195
  const restS = await A.spotPost(false, 5_000, usdtBase(100_900));
  const pre = await c.account(O.owner);
  const hadP = pre.open_orders.some((o) => o.id === restP.id), hadS = pre.spot?.open_orders?.some?.((o) => o.id === restS.id) ?? true;
  const rv = await revokeGrant(c, O.sk, G1);
  const post = await c.account(O.owner);
  const after = await code(A.perpPost('long', 10, 99_500, 50_000));
  const orders = await c.orders(G1);
  const mAfter = await tool('trade', 'place_perp_order', { type: 'post', side: 'long', quantity_usd: 10, limit_usd: 99_400, leverage: 5 }, bearer);
  const mHalted = await tool('trade', 'place_perp_order', { type: 'post', side: 'long', quantity_usd: 10, limit_usd: 99_400, leverage: 5 }, bearer);
  check('revoked mid-session: the revoke pulls A\'s resting perp and spot orders (and the MCP order) in the same journal record',
    hadP && hadS && rv.orders_pulled.includes(restP.id) && rv.orders_pulled.includes(restS.id) && rv.orders_pulled.includes(mcpOrder) && !post.open_orders.some((o) => o.id === restP.id)
    && orders.filter((o) => [restP.id, restS.id].includes(o.id)).every((o) => o.status === 'cancelled'),
    { pulled: rv.orders_pulled.length, open_after: post.open_orders.length });
  check('after revocation A is refused (grant.revoked, 403) and the MCP session reports it and halts', after === 'grant.revoked' && mAfter.isError && mAfter.structuredContent.error === 'grant.revoked'
    && mHalted.structuredContent.error === 'trading.halted', { sdk: after, mcp: mAfter.structuredContent?.error, next: mHalted.structuredContent?.error });

  // ---- expiry
  const eSk = randomBytes(32);
  const g3 = await createGrant(c, O.sk, hex(pubkey(eSk)), ['perps'], limits, { expiresInS: 2, label: 'expires' });
  const E = await Agent.open(c, eSk, g3.id);
  const e1 = await code(E.perpPost('long', 10, 99_500, 50_000));
  await sleep(2_600);
  const e2 = await code(E.perpPost('long', 10, 99_500, 50_000));
  check('a 2-second grant: accepted while live, then grant.expired', e1 === 'accepted' && e2 === 'grant.expired' && (await c.grant(g3.id)).status === 'expired', { e1, e2 });

  // ---- through a Caddy-like reverse proxy: per-client buckets on /api, /v1, /agent/v1 and WS upgrades
  const PX = `http://127.0.0.1:${PPORT}`;
  startProxy();
  const via = (p, client, extra = {}) => fetchJson(PX + p, undefined, { 'x-test-client': client, ...extra });
  const ui = await via('/', '198.51.100.10'), st1 = await via('/api/status', '198.51.100.10');
  const wsHello = async (p, client) => new Promise((res) => {
    const ws = new WebSocket(PX.replace('http', 'ws') + p + (p.includes('?') ? '&' : '?') + '__client=' + client);
    const t = setTimeout(() => { ws.close(); res('timeout'); }, 5_000);
    ws.onmessage = (ev) => { clearTimeout(t); ws.close(); res(JSON.parse(ev.data).type ?? JSON.parse(ev.data).method); };
    ws.onerror = () => { clearTimeout(t); res('refused'); };
  });
  const uiStream = await wsHello('/api/stream', '198.51.100.10'), agentStream = await wsHello('/agent/v1/ws', '198.51.100.10');
  check('through the proxy the UI, /api, the UI stream and the agent stream work, charged to the forwarded client (X-RateLimit-Scope: address)',
    ui.status === 200 && st1.status === 200 && st1.headers.get('x-ratelimit-scope') === 'address' && st1.headers.get('x-ratelimit-limit') === '60' && uiStream === 'status' && agentStream === 'hello',
    { ui: ui.status, api: st1.status, scope: st1.headers.get('x-ratelimit-scope'), ui_stream: uiStream, agent_stream: agentStream });
  const burst = await Promise.all(Array.from({ length: 120 }, (_, i) => via(['/agent/v1/time', '/api/status', '/v1/candles?instrument=SHZ-BTCUSD-INV&interval=1m'][i % 3], '203.0.113.50')));
  const limited = burst.filter((x) => x.status === 429);
  // The bucket refills at 20/s, so the follow-ups go out as concurrent batches right after the burst:
  // an honoured spoof would land in a fresh bucket of 60 and pass in full.
  const [spoofs, wsBatch, other, wsOther] = await Promise.all([
    Promise.all(Array.from({ length: 40 }, () => via('/api/status', '203.0.113.50', { 'x-forwarded-for': '192.0.2.200' }))),
    Promise.all(Array.from({ length: 6 }, () => wsHello('/api/stream', '203.0.113.50'))),
    via('/api/status', '203.0.113.51'), wsHello('/api/stream', '203.0.113.51')]);
  const spoofRefused = spoofs.filter((x) => x.status === 429).length, wsRefused = wsBatch.filter((x) => x === 'refused').length;
  const agentLimited = limited.find((x) => x.json?.error?.code === 'rate_limited');
  check('a client bursting past 60 gets 429 with Retry-After on /api, /v1 and /agent/v1 (structured rate_limited there) and its WS upgrade is refused; another client is untouched',
    limited.length >= 20 && !!agentLimited && !!limited[0].headers.get('retry-after') && wsRefused >= 4 && other.status === 200 && wsOther === 'status',
    { limited: limited.length, other: other.status, ws_refused: `${wsRefused}/6`, ws_other: wsOther });
  check('a client-sent X-Forwarded-For does not move it to another bucket (the proxy-appended right-most hop decides)', spoofRefused >= 10, { refused: `${spoofRefused}/40` }); // honoured, it would be 0/40 (fresh bucket of 60)
  await sleep(3_500);

  // ---- restart: grants, revocation and usage come back
  const usageBefore = (await c.grant(G1)).usage.day_notional_usd;
  stopA(); stream.close(); await stopProc(mcpProc);
  await stopProc(v);
  v = await startVenue(state, VPORT, ['--options', '--stable-usdt', USDT_ID, '--spot', '--agents'], 'restart');
  const g1r = await c.grant(G1), g2r = await c.grant(g2.id);
  check('restart: G1 still revoked with its 24 h usage, the examples grant still active', g1r.status === 'revoked' && g1r.usage.day_notional_usd === usageBefore && g2r.status === 'active',
    { g1: [g1r.status, g1r.usage.day_notional_usd, usageBefore], g2: g2r.status });
  await stopProc(v);
  // Agent records in the router journal, read while no venue holds its lock.
  const wal = () => readFileSync(path.join(state, 'router.wal')).toString('latin1').split('Agent').length - 1;
  const j2 = wal();
  v = await startVenue(state, VPORT, ['--options', '--stable-usdt', USDT_ID, '--spot'], 'noagents');
  const offDraft2 = await fetchJson(VENUE + '/agent/v1/grants/draft', { owner: O.owner, agent: aPk, instruments: ['perps'], limits });
  const offOrder = await fetchJson(VENUE + '/agent/v1/orders', { grant: g2.id, instrument: 'perp', intent: signed.intent });
  const acctOk = (await api('/api/account/' + O.owner)).owner === O.owner;
  await stopProc(v);
  const j3 = wal();
  check('the same journal reopened without --agents: agent writes answer agents.off and journal nothing; existing reads work',
    offDraft2.json?.error?.code === 'agents.off' && offOrder.json?.error?.code === 'agents.off' && j2 === j3 && j2 > 0 && acctOk,
    { draft: offDraft2.json?.error?.code, order: offOrder.json?.error?.code, agent_records: [j2, j3] });
  finish(results.every((x) => x.ok) ? 0 : 1);
}

function finish(code) {
  shuttingDown = true; signing = false;
  for (const p of procs) { try { p.kill(); } catch { /* gone */ } }
  const pass = results.filter((r) => r.ok).length;
  console.log(`\n${pass}/${results.length} checks passed`);
  log('summary', { pass, total: results.length });
  process.exit(code);
}
main().catch((e) => { console.error(e); log('fatal', { e: String(e.stack || e) }); finish(2); });
