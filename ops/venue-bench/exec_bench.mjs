// Front-end execution latency against a running shz-venue (testnet).
//
// Acts like the browser client: BIP340 keys from ui/venue/crypto.js, demo
// accounts, signs pending batch approvals / channel acks as soon as the venue
// announces an account change on the WebSocket.
//
//   node exec_bench.mjs --server https://shz-venue.170-75-168-145.sslip.io --mode mm --n 20
//   node exec_bench.mjs --server http://127.0.0.1:8096 --mode self --n 20
//
// --mode mm    one taker key; market FOK takes against the resting market makers
//              (their approvals and acks arrive on their own poll loop).
// --mode self  two keys of our own: A posts 1 bps inside the makers' best quote,
//              B takes it; both sign immediately, so commit time is the venue's.
//
// Output: one JSON line per trade (client-side ms from send, server-side ms
// from the batch record), then a summary line with median / p90 / max.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { hex, unhex, bip340Sign, pubkey, signIntent } from '../../ui/venue/crypto.js';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const SERVER = arg('server', 'http://127.0.0.1:8096').replace(/\/$/, '');
const MODE = arg('mode', 'mm');
const N = +arg('n', 20);
const SIZE = +arg('size', 5);
const STATE = arg('state', `bench-keys-${MODE}.json`);
const GAP_MS = +arg('gap-ms', 1500);
const TIMEOUT_MS = +arg('timeout-ms', 20000);
const now = () => performance.now();

async function api(path, body) {
  const r = await fetch(SERVER + path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { /* non-json */ }
  if (!r.ok) throw new Error(`${path}: ${r.status} ${j && j.error}`);
  return j;
}

// ---------- accounts ----------
const keys = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {};
const names = MODE === 'self' ? ['maker', 'taker'] : ['taker'];
for (const n of names) if (!keys[n]) keys[n] = hex(crypto.getRandomValues(new Uint8Array(32)));
writeFileSync(STATE, JSON.stringify(keys));
const who = {};
for (const n of names) {
  const sk = unhex(keys[n], 32); const owner = hex(pubkey(sk));
  let acct;
  try { acct = await api('/api/account/' + owner); } catch {
    const d = await api('/api/register/draft', { owner, kind: 'demo', outpoint: null });
    const sig = await bip340Sign(unhex(d.allocation_digest), sk);
    acct = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(sig) })).account;
  }
  who[n] = { sk, owner, outpoint: acct.outpoint, signed: new Set(), signing: false, again: false };
}
const template = await api('/api/template');
let lastSeq = 0;

// ---------- signing loop (browser autoSign equivalent) ----------
async function autoSign(w) {
  if (w.signing) { w.again = true; return; }
  w.signing = true;
  try {
    do {
      w.again = false;
      const a = await api('/api/account/' + w.owner);
      const todo = (a.pending_signatures || []).filter((x) => !w.signed.has(x.id));
      if (!todo.length) continue;
      const items = [];
      for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), w.sk)) });
      await api('/api/signatures', { owner: w.owner, items });
      for (const x of todo) w.signed.add(x.id);
    } while (w.again);
  } catch (e) { console.error('sign:', e.message); } finally { w.signing = false; }
}

// ---------- event stream ----------
const waits = new Map(); // key -> resolve
const seen = new Map();  // key -> t
const mark = (k) => { if (!seen.has(k)) seen.set(k, now()); const r = waits.get(k); if (r) { waits.delete(k); r(); } };
const until = (k) => seen.has(k) ? Promise.resolve() : new Promise((res, rej) => { waits.set(k, res); setTimeout(() => rej(new Error('timeout ' + k)), TIMEOUT_MS); });
const wsUrl = SERVER.replace(/^http/, 'ws') + '/api/stream';
const ws = new WebSocket(wsUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('ws connect failed')); });
const batchOf = new Map(); // trade id -> batch seq
ws.onmessage = async (m) => {
  const t = now();
  let e; try { e = JSON.parse(m.data); } catch { return; }
  if (e.type === 'trade') { if (!seen.has('fill:' + e.trade.id)) seen.set('fill:' + e.trade.id, t); mark('fill:' + e.trade.id); }
  else if (e.type === 'batch') {
    if (!seen.has(`batch:${e.seq}:${e.phase}`)) seen.set(`batch:${e.seq}:${e.phase}`, t);
    mark(`batch:${e.seq}:${e.phase}`);
    for (const w of Object.values(who)) autoSign(w); // sealed -> approvals due, prepared -> acks due
  } else if (e.type === 'account') { for (const w of Object.values(who)) autoSign(w); }
};

function intent(w, fields) {
  lastSeq = Math.max(lastSeq + 1, Date.now());
  return { owner: w.owner, channel: { txid: w.outpoint.txid, vout: w.outpoint.vout }, sequence: lastSeq,
    expires_us: (Date.now() + 120e3) * 1000, action: 'take', side: 'long', tier: 'standard', quantity: SIZE, limit_usd: 0,
    leverage_bps: 20000, max_fee_ppm: 200, max_fee_sats: 1000, max_mark_age_us: template.max_mark_age_us,
    early_window_opt_in: false, cancel_target: '0'.repeat(64), ...fields };
}
async function send(w, it) { const { intent: s } = await signIntent(it, template, w.sk, null); return api('/api/intents', { intent: s }); }

// ---------- one trade ----------
async function trade(i) {
  const side = i % 2 ? 'short' : 'long';
  const book = await api('/api/book?depth=5');
  const best = side === 'long' ? book.asks?.[0] : book.bids?.[0];
  if (!best) throw new Error('empty book side');
  let px = best.price_usd ?? best.price ?? best[0];
  let postMs = null;
  if (MODE === 'self') {
    px = side === 'long' ? px - 1 : px + 1; // inside the makers' quote, so the taker hits ours
    const t = now();
    await send(who.maker, intent(who.maker, { action: 'post', side: side === 'long' ? 'short' : 'long', limit_usd: px }));
    postMs = now() - t;
    await new Promise((r) => setTimeout(r, 60)); // let the post rest before the take is due
  }
  const it = intent(who.taker, { action: 'take', side, limit_usd: px });
  const t0 = now();
  const r = await send(who.taker, it);
  const tAck = now();
  const id = r.id;
  await until('fill:' + id);
  const tFill = seen.get('fill:' + id);
  const f = await api('/api/explorer/fill/' + id);
  let seq = f.batch?.seq ?? f.trade?.batch_seq;
  for (let k = 0; seq == null && k < 100; k++) { await new Promise((x) => setTimeout(x, 20)); const g = await api('/api/explorer/fill/' + id); seq = g.batch?.seq ?? g.trade?.batch_seq; }
  for (const p of ['sealed', 'prepared', 'committed']) await until(`batch:${seq}:${p}`);
  const b = (await api('/api/explorer/batch/' + seq)).batch;
  const tr = (await api('/api/explorer/fill/' + id)).trade;
  const ms = (x) => Math.round(x * 10) / 10;
  return {
    i, side, price: px, maker: tr.maker_owner.slice(0, 8), batch: seq, fills_in_batch: (b.legs || []).length,
    client_ms: { post_ack: postMs == null ? null : ms(postMs), take_ack: ms(tAck - t0), fill: ms(tFill - t0),
      sealed: ms(seen.get(`batch:${seq}:sealed`) - t0), prepared: ms(seen.get(`batch:${seq}:prepared`) - t0), committed: ms(seen.get(`batch:${seq}:committed`) - t0) },
    server_ms: { match_to_window_end: ms((b.window_us[1] - tr.ts_us) / 1000), window_end_to_sealed: ms((b.created_us - b.window_us[1]) / 1000),
      sealed_to_prepared: b.prepared_us ? ms((b.prepared_us - b.created_us) / 1000) : null,
      prepared_to_committed: b.committed_us && b.prepared_us ? ms((b.committed_us - b.prepared_us) / 1000) : null,
      match_to_committed: b.committed_us ? ms((b.committed_us - tr.ts_us) / 1000) : null },
  };
}

// Sign anything a previous run left pending: batches resolve in order, so an
// unsigned approval or ack from us would hold every later batch.
for (const w of Object.values(who)) await autoSign(w);

const rows = [];
for (let i = 0; i < N; i++) {
  try { const row = await trade(i); rows.push(row); console.log(JSON.stringify(row)); }
  catch (e) { console.log(JSON.stringify({ i, error: e.message })); }
  await new Promise((r) => setTimeout(r, GAP_MS));
}
const pct = (xs, q) => { const s = xs.filter((x) => x != null).sort((a, b) => a - b); return s.length ? s[Math.min(s.length - 1, Math.floor(q * s.length))] : null; };
const summarize = (group) => Object.fromEntries(Object.keys(rows[0]?.[group] || {}).map((k) => {
  const xs = rows.map((r) => r[group][k]); return [k, { median: pct(xs, 0.5), p90: pct(xs, 0.9), max: pct(xs, 1) }];
}));
// Drain: do not exit with our own approvals or acks still pending.
for (let k = 0; k < 100; k++) {
  let left = 0;
  for (const w of Object.values(who)) { await autoSign(w); left += ((await api('/api/account/' + w.owner)).pending_signatures || []).length; }
  if (!left) break;
  await new Promise((r) => setTimeout(r, 100));
}
console.log(JSON.stringify({ summary: true, server: SERVER, mode: MODE, n_ok: rows.length, n: N, client_ms: summarize('client_ms'), server_ms: summarize('server_ms') }));
ws.close();
