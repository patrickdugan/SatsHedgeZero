// DLC batcher demo, venue half: eight demo accounts open four $QTY inverse-perp pairs on the live
// venue, wait for the mark to move, then close in a ring (each account flattens against a different
// counterparty than it opened with), so every account realizes PnL through the multilateral V3
// clearing. Every account signs its batch approvals and channel acks. Writes the venue clearing
// summary taken before the first fill and every committed batch from the first to the last as
// `{name, status_before, status_after, accounts, fills, batches}` -- the input of `trace::from_venue`.
//
//   node fills.mjs --keys D:/shz/tmp/dlc-batch/keys.json --out <dir>/venue_batches.json
//
// --keys holds the eight account secret keys (created on first run, kept outside the repo). The same
// keys sign the accounts' settlement inputs on Bitcoin, so venue owners are the account leaf keys.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { hex, unhex, bip340Sign, pubkey, signIntent, randomKey } from '../../../ui/venue/crypto.js';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const VENUE = arg('venue', 'https://shz-venue.170-75-168-145.sslip.io');
const KEYS = arg('keys', 'D:/shz/tmp/dlc-batch/keys.json');
const OUT = arg('out', 'venue_batches.json');
const QTY = Number(arg('qty', '100'));
const LEV = Number(arg('lev-bps', '100000'));
const MIN_WAIT_S = Number(arg('min-wait-s', '120'));
const MAX_WAIT_S = Number(arg('max-wait-s', '900'));
const MIN_MOVE_USD = Number(arg('min-move-usd', '15'));
const N = 8;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(p, body) {
  const r = await fetch(VENUE + p, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => null);
  if (r.status >= 300) throw new Error(`${p}: ${r.status} ${JSON.stringify(j)}`);
  return j;
}

if (!existsSync(KEYS)) {
  mkdirSync(dirname(KEYS), { recursive: true });
  writeFileSync(KEYS, JSON.stringify({ accounts: Array.from({ length: N }, () => hex(randomKey())) }, null, 1));
}
const ks = JSON.parse(readFileSync(KEYS, 'utf8'));
const template = await api('/api/template');

async function account(i, skHex) {
  const sk = unhex(skHex, 32);
  const owner = hex(pubkey(sk));
  let view;
  try { view = await api(`/api/account/${owner}`); } catch { view = null; }
  if (!view || !view.outpoint) {
    const d = await api('/api/register/draft', { owner, kind: 'demo', outpoint: null });
    const sig = await bip340Sign(unhex(d.allocation_digest), sk);
    view = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(sig) })).account;
  }
  const seq = Math.max(Date.now() * 1000, (view.sequences && view.sequences.perp) || 0);
  return { i, sk, owner, outpoint: view.outpoint, seq, signed: new Set() };
}
const accts = [];
for (let i = 0; i < N; i++) accts.push(await account(i, ks.accounts[i]));
for (const a of accts) {
  const v = await api(`/api/account/${a.owner}`);
  if (v.position && v.position.net_usd) throw new Error(`account ${a.i} is not flat (net ${v.position.net_usd})`);
}

function intent(w, f) {
  w.seq = Math.max(w.seq + 1, Date.now() * 1000);
  return { owner: w.owner, channel: { txid: w.outpoint.txid, vout: w.outpoint.vout }, sequence: w.seq, expires_us: (Date.now() + 60e3) * 1000,
    tier: 'standard', quantity: QTY, leverage_bps: LEV, max_fee_ppm: 0, max_fee_sats: 0, max_mark_age_us: template.max_mark_age_us,
    early_window_opt_in: false, cancel_target: '0'.repeat(64), ...f };
}
async function send(w, f) {
  const { id, intent: it } = await signIntent(intent(w, f), template, w.sk, null);
  await api('/api/intents', { intent: it });
  return { id, intent: it };
}
async function signPending(w) {
  const v = await api(`/api/account/${w.owner}`);
  const todo = (v.pending_signatures || []).filter((x) => !w.signed.has(x.id));
  if (todo.length) {
    const items = [];
    for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), w.sk)) });
    await api('/api/signatures', { owner: w.owner, items });
    for (const x of todo) w.signed.add(x.id);
  }
  return v;
}

// One round: for each (maker, makerSide, taker) the maker posts at the rounded mark and the taker takes
// the other side at the same limit. Pairs go one at a time so each take meets its own maker's post
// (the market makers' quotes sit tens of dollars outside the mark). Then every account signs until all
// the round's fills are in committed batches.
// The venue aborts a batch whose approvals and acks are not all in 10 s after its window, so each pair
// is signed to commitment (both owners in parallel, no pause) before the next pair is sent. An aborted
// batch would break the consecutive-batch chain the clearing fold needs, so the run stops on one.
async function round(name, pairs) {
  const fills = [];
  const seqs = [];
  for (const [m, side, t] of pairs) {
    const st = await api('/api/status');
    const limit = Math.round(st.mark.price_usd);
    const post = await send(accts[m], { action: 'post', side, limit_usd: limit });
    const take = await send(accts[t], { action: 'take', side: side === 'long' ? 'short' : 'long', limit_usd: limit });
    const f = { maker: m, taker: t, maker_side: side, limit_usd: limit, post: post.id, take: take.id };
    fills.push(f);
    const t0 = Date.now();
    for (;;) {
      if (Date.now() - t0 > 60e3) throw new Error(`${name}: pair ${m}/${t} did not commit in 60 s`);
      const [, tv] = await Promise.all([signPending(accts[m]), signPending(accts[t])]);
      if (!f.fill) f.fill = (tv.fills || []).find((x) => x.id === f.take || x.taker_intent === f.take || x.intent === f.take);
      const b = f.fill && (f.fill.batch_seq ?? f.fill.batch);
      if (b == null) continue;
      f.batch_seq = b;
      const ph = (await api(`/api/explorer/batch/${b}`)).batch.phase;
      if (ph === 'committed') break;
      if (ph === 'aborted') throw new Error(`${name}: batch ${b} of pair ${m}/${t} aborted`);
    }
    seqs.push(f.batch_seq);
    console.log(`${name}: account ${m} posted ${side} @ ${limit}, account ${t} took; batch ${f.batch_seq} committed in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
  }
  return { fills, seqs };
}

const statusBefore = await api('/api/status');
const firstSeq = statusBefore.router.batch_sequence + 1;
// Open: 0L/1S, 2L/3S, 4S/5L, 6S/7L (maker, maker side, taker).
const open = await round('open', [[0, 'long', 1], [2, 'long', 3], [4, 'short', 5], [6, 'short', 7]]);
const openMark = (await api('/api/status')).mark.price_usd;
const t0 = Date.now();
for (;;) {
  await sleep(5000);
  const m = (await api('/api/status')).mark.price_usd;
  const el = (Date.now() - t0) / 1000;
  if ((el >= MIN_WAIT_S && Math.abs(m - openMark) >= MIN_MOVE_USD) || el >= MAX_WAIT_S) { console.log(`mark ${openMark} -> ${m} after ${el.toFixed(0)} s`); break; }
}
// Close in a ring: longs 0,2,5,7 sell; shorts 1,3,4,6 buy, each against a new counterparty.
const close = await round('close', [[0, 'short', 3], [2, 'short', 1], [5, 'short', 6], [7, 'short', 4]]);
const statusAfter = await api('/api/status');
const lastSeq = Math.max(...open.seqs, ...close.seqs);
const batches = [];
for (let s = firstSeq; s <= lastSeq; s++) batches.push(await api(`/api/explorer/batch/${s}`));
const views = [];
for (const a of accts) views.push(await api(`/api/account/${a.owner}`));
writeFileSync(OUT, JSON.stringify({
  name: `testnet4_batches_${firstSeq}_${lastSeq}`, venue: VENUE, template, qty_usd: QTY, leverage_bps: LEV,
  accounts: accts.map((a, i) => ({ index: i, owner: a.owner, outpoint: a.outpoint, realized_pnl_sats: views[i].balance.realized_pnl, net_usd_after: views[i].position ? views[i].position.net_usd : 0 })),
  rounds: { open: open.fills, close: close.fills }, open_mark_usd: openMark,
  status_before: statusBefore, status_after: statusAfter, batches,
}, null, 1));
console.log(`batches ${firstSeq}..${lastSeq} committed; wrote ${OUT}`);
