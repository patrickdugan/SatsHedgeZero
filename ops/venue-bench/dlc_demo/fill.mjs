// Testnet4 DLC demo, venue half: two demo accounts (Alice, Bob) trade one $1 inverse perp fill on the
// live venue, sign their batch approvals and channel acks, and the batch commits. Writes the fill, its
// batch and the venue clearing summary before and after to --out.
//
//   node fill.mjs --keys D:/shz/tmp/testnet4-demo/keys.json --out <dir>/venue_fill.json
//
// --keys holds the Alice/Bob/guard secret keys (created on first run, kept outside the repo). The same
// Alice and Bob keys sign the DLC CETs, so the venue owners are the DLC leaf keys.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { hex, unhex, bip340Sign, pubkey, signIntent, randomKey } from '../../../ui/venue/crypto.js';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const VENUE = arg('venue', 'https://shz-venue.170-75-168-145.sslip.io');
const KEYS = arg('keys', 'D:/shz/tmp/testnet4-demo/keys.json');
const OUT = arg('out', 'venue_fill.json');
const QTY = Number(arg('qty', '1'));
const LEV = Number(arg('lev-bps', '10000'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(p, body) {
  const r = await fetch(VENUE + p, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => null);
  if (r.status >= 300) throw new Error(`${p}: ${r.status} ${JSON.stringify(j)}`);
  return j;
}

if (!existsSync(KEYS)) {
  writeFileSync(KEYS, JSON.stringify({ alice_sk: hex(randomKey()), bob_sk: hex(randomKey()), guard_sk: hex(randomKey()) }, null, 1));
}
const ks = JSON.parse(readFileSync(KEYS, 'utf8'));
const template = await api('/api/template');

async function account(name, skHex) {
  const sk = unhex(skHex, 32);
  const owner = hex(pubkey(sk));
  let view;
  try { view = await api(`/api/account/${owner}`); } catch { view = null; }
  if (!view || !view.outpoint) {
    const d = await api('/api/register/draft', { owner, kind: 'demo', outpoint: null });
    const sig = await bip340Sign(unhex(d.allocation_digest), sk);
    view = (await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(sig) })).account;
  }
  return { name, sk, owner, outpoint: view.outpoint, seq: Date.now() * 1000, signed: new Set() };
}
const alice = await account('alice', ks.alice_sk);
const bob = await account('bob', ks.bob_sk);

function intent(w, f) {
  w.seq = Math.max(w.seq + 1, Date.now() * 1000);
  return { owner: w.owner, channel: { txid: w.outpoint.txid, vout: w.outpoint.vout }, sequence: w.seq, expires_us: (Date.now() + 60e3) * 1000,
    tier: 'standard', quantity: QTY, leverage_bps: LEV, max_fee_ppm: 0, max_fee_sats: 0, max_mark_age_us: template.max_mark_age_us,
    early_window_opt_in: false, cancel_target: '0'.repeat(64), ...f };
}
async function send(w, f) {
  const { id, intent: it } = await signIntent(intent(w, f), template, w.sk, null);
  const r = await api('/api/intents', { intent: it });
  return { id, intent: it, accepted: r };
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

const before = await api('/api/status');
const limit = Math.round(before.mark.price_usd);
const post = await send(alice, { action: 'post', side: 'long', limit_usd: limit });
const take = await send(bob, { action: 'take', side: 'short', limit_usd: limit });
console.log(`posted ${post.id.slice(0, 12)} long @ ${limit}, took ${take.id.slice(0, 12)} short`);

let fill = null, batch = null, views = {};
for (let i = 0; i < 240 && !(batch && batch.batch && batch.batch.phase === 'committed'); i++) {
  await sleep(500);
  views.alice = await signPending(alice);
  views.bob = await signPending(bob);
  if (!fill) {
    const f = (views.bob.fills || []).find((x) => x.id === take.id || x.taker_intent === take.id || x.intent === take.id) || (views.bob.fills || [])[0];
    if (f) fill = f;
  }
  const bseq = fill && (fill.batch_seq ?? fill.batch);
  if (bseq != null) batch = await api(`/api/explorer/batch/${bseq}`);
}
if (!batch || batch.batch.phase !== 'committed') throw new Error('batch did not commit: ' + JSON.stringify({ fill, phase: batch && batch.batch.phase }));
const after = await api('/api/status');
const fillExplorer = fill.id ? await api(`/api/explorer/fill/${fill.id}`).catch((e) => ({ error: String(e) })) : null;
const prev = await api(`/api/explorer/batch/${batch.batch.seq - 1}`).catch(() => null);
writeFileSync(OUT, JSON.stringify({
  venue: VENUE, template, accounts: { alice: { owner: alice.owner, outpoint: alice.outpoint }, bob: { owner: bob.owner, outpoint: bob.outpoint } },
  post: { id: post.id, intent: post.intent }, take: { id: take.id, intent: take.intent },
  status_before: before, status_after: after, fill, fill_explorer: fillExplorer, batch, previous_batch: prev,
  account_views_after: { alice: await api(`/api/account/${alice.owner}`), bob: await api(`/api/account/${bob.owner}`) },
}, null, 1));
console.log(`fill ${fill.id} batch ${batch.batch.seq} committed; wrote ${OUT}`);
