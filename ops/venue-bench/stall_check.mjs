// Liveness check: a taker that fills and never signs must not hold later batches.
//
// Keys: M (maker, signs), S (silent taker, never signs), B (taker, signs). M posts
// 1 USD inside the best quote, S takes it and stays silent; M posts again, B takes.
// Expect S's batch to be fenced and aborted about ABORT_AFTER_US (10 s) after its
// window, B's batch to commit right after, and S's position to stay flat.
//
//   node stall_check.mjs --server http://127.0.0.1:8097 [--deadline-s 10]

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { hex, unhex, bip340Sign, pubkey, signIntent } from '../../ui/venue/crypto.js';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const SERVER = arg('server', 'http://127.0.0.1:8097').replace(/\/$/, '');
const DEADLINE_S = +arg('deadline-s', 10);
const STATE = arg('state', 'stall-keys.json');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, body) {
  const r = await fetch(SERVER + path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { /* non-json */ }
  if (!r.ok) throw new Error(`${path}: ${r.status} ${j && j.error}`);
  return j;
}
const keys = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {};
for (const n of ['M', 'S', 'B']) if (!keys[n]) keys[n] = hex(crypto.getRandomValues(new Uint8Array(32)));
writeFileSync(STATE, JSON.stringify(keys));
const who = {};
for (const n of ['M', 'S', 'B']) {
  const sk = unhex(keys[n], 32); const owner = hex(pubkey(sk));
  let acct;
  try { acct = await api('/api/account/' + owner); } catch {
    const d = await api('/api/register/draft', { owner, kind: 'demo', outpoint: null });
    acct = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(await bip340Sign(unhex(d.allocation_digest), sk)) })).account;
  }
  who[n] = { sk, owner, outpoint: acct.outpoint };
}
const template = await api('/api/template');
let lastSeq = 0;
const intent = (w, f) => {
  lastSeq = Math.max(lastSeq + 1, Date.now());
  return { owner: w.owner, channel: { txid: w.outpoint.txid, vout: w.outpoint.vout }, sequence: lastSeq, expires_us: (Date.now() + 120e3) * 1000,
    action: 'take', side: 'long', tier: 'standard', quantity: 5, limit_usd: 0, leverage_bps: 20000, max_fee_ppm: 200, max_fee_sats: 1000,
    max_mark_age_us: template.max_mark_age_us, early_window_opt_in: false, cancel_target: '0'.repeat(64), ...f };
};
const send = async (w, it) => api('/api/intents', { intent: (await signIntent(it, template, w.sk, null)).intent });
async function signPending(w) {
  const a = await api('/api/account/' + w.owner);
  const items = [];
  for (const x of a.pending_signatures || []) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), w.sk)) });
  if (items.length) await api('/api/signatures', { owner: w.owner, items });
}
let signing = true;
(async () => { while (signing) { for (const n of ['M', 'B']) { try { await signPending(who[n]); } catch { /* retry */ } } await sleep(100); } })();

async function fillVia(taker) {
  const book = await api('/api/book?depth=3');
  let px = book.asks?.[0]?.[0] ?? Math.round(book.mark.price_usd * 1.002);
  px -= 1;
  await send(who.M, intent(who.M, { action: 'post', side: 'short', limit_usd: px }));
  await sleep(80);
  const r = await send(taker, intent(taker, { action: 'take', side: 'long', limit_usd: px }));
  for (let k = 0; k < 100; k++) {
    const f = await api('/api/explorer/fill/' + r.id).catch(() => null);
    if (f?.batch?.seq != null) return { id: r.id, seq: f.batch.seq, maker: f.trade.maker_owner };
    await sleep(50);
  }
  throw new Error('fill not sealed into a batch');
}

const t0 = Date.now();
const s = await fillVia(who.S);
const b = await fillVia(who.B);
const out = { silent: s, signed: b, deadline_s: DEADLINE_S };
let phases;
for (;;) {
  const bs = await api('/api/explorer/batches?limit=20');
  phases = Object.fromEntries(bs.map((x) => [x.seq, x.phase]));
  if (phases[b.seq] === 'committed' || Date.now() - t0 > (DEADLINE_S + 20) * 1000) break;
  await sleep(200);
}
signing = false;
const sb = (await api('/api/explorer/batch/' + s.seq)).batch;
const bb = (await api('/api/explorer/batch/' + b.seq)).batch;
const sAcct = await api('/api/account/' + who.S.owner);
out.silent_phase = sb.phase;
out.signed_phase = bb.phase;
out.silent_resolved_after_window_s = sb.committed_us ? (sb.committed_us - sb.window_us[1]) / 1e6 : null;
out.signed_committed_after_silent_abort_ms = bb.committed_us && sb.committed_us ? (bb.committed_us - sb.committed_us) / 1e3 : null;
out.silent_position_usd = sAcct.position.net_usd;
out.silent_balance = sAcct.balance;
out.silent_pending = (sAcct.pending_signatures || []).length;
out.pass = sb.phase === 'aborted' && bb.phase === 'committed' && sAcct.position.net_usd === 0 && sAcct.balance.pending === 0 && sAcct.balance.committed === 0;
console.log(JSON.stringify(out));
process.exit(out.pass ? 0 : 1);
