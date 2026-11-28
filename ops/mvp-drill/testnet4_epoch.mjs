// One real testnet4 epoch on the Lightninger venue (--collateral-chain testnet4): two traders,
// funded by one transaction, activate at the venue's min-conf, trade one small round trip under
// the oracle collar, co-sign the next maturity's settlement entry with ui/venue/settle.js, and wait
// for the daemon's settlement to confirm. Funding is broadcast by the operator between the phases.
//
//   node ops/mvp-drill/testnet4_epoch.mjs prepare --venue URL --dir D:/shz/tmp/mvp-testnet4
//   (fund both addresses in dir/addresses.json)
//   node ops/mvp-drill/testnet4_epoch.mjs run --venue URL --dir D:/shz/tmp/mvp-testnet4 --deposit-txid TXID --out receipt.json
//
// dir/trader-keys.json holds the two secret keys (outside the repo).
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { hex, unhex, bip340Sign, pubkey, signIntent, randomKey } from '../../ui/venue/crypto.js';
import { signEntry } from '../../ui/venue/settle.js';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const VENUE = arg('venue', 'https://lightninger-testnet4.170-75-168-145.sslip.io');
const DIR = arg('dir', 'D:/shz/tmp/mvp-testnet4');
const QTY = Number(arg('qty', '100'));
const LEV = Number(arg('lev-bps', '100000'));
const SPREAD = Number(arg('spread', '50'));
const MEMPOOL = 'https://mempool.space/testnet4/api';

async function api(p, body) {
  const r = await fetch(VENUE + p, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => null);
  if (r.status >= 300) throw new Error(`${p}: ${r.status} ${JSON.stringify(j)}`);
  return j;
}
const until = async (what, fn, ms, every = 5000) => {
  const t0 = Date.now();
  for (;;) {
    const v = await fn().catch(() => null);
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out: ' + what);
    await sleep(every);
  }
};

mkdirSync(DIR, { recursive: true });
const KEYS = DIR + '/trader-keys.json';
if (!existsSync(KEYS)) writeFileSync(KEYS, JSON.stringify({ traders: [hex(randomKey()), hex(randomKey())] }));
const T = JSON.parse(readFileSync(KEYS, 'utf8')).traders.map((k, i) => { const sk = unhex(k, 32); return { i, sk, owner: hex(pubkey(sk)), signed: new Set(), seq: 0 }; });

if (process.argv[2] === 'prepare') {
  const out = [];
  for (const t of T) {
    const v = await api('/api/collateral/address', { owner: t.owner });
    out.push({ trader: t.i, owner: t.owner, address: v.deposit.address, refund_height: v.deposit.refund_height, credit_by_height: v.deposit.credit_by_height });
  }
  writeFileSync(DIR + '/addresses.json', JSON.stringify(out, null, 1));
  console.log(JSON.stringify(out, null, 1));
  process.exit(0);
}

const OUT = arg('out', DIR + '/receipt.json');
const receipt = { venue: VENUE, network: 'testnet4', started: new Date().toISOString(), deposit_txid: arg('deposit-txid'), traders: T.map((t) => ({ index: t.i, owner: t.owner })), steps: [] };
const step = (name, data) => { receipt.steps.push({ name, at: new Date().toISOString(), ...data }); log(name, JSON.stringify(data)); writeFileSync(OUT, JSON.stringify(receipt, null, 1)); };
const status = await api('/api/status');
if (status.collateral?.network !== 'testnet4') throw new Error('venue is not --collateral-chain testnet4');
const template = await api('/api/template');

// 1. Credit and activation.
for (const t of T) {
  const v = await api('/api/collateral/' + t.owner);
  if (!v.account) {
    const seen = await until(`trader ${t.i} deposit at min-conf`, async () => { const x = await api('/api/collateral/' + t.owner); return x.seen?.ready && x.seen; }, 3 * 3600e3, 15000);
    const d = await api('/api/register/draft', { owner: t.owner, kind: 'collateral' });
    await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(await bip340Sign(unhex(d.allocation_digest), t.sk)) });
    step('activated', { trader: t.i, outpoint: `${seen.txid}:${seen.vout}`, value: seen.value, height: seen.height, confirmations: seen.confirmations });
  }
  const a = await api('/api/account/' + t.owner);
  t.channel = a.outpoint; t.deposit = a.cap_sats; t.seq = Math.max(Date.now() * 1000, a.sequences?.perp || 0);
}

// 2. Settlement signer for both traders until the end.
let stop = false;
const signer = (async () => {
  while (!stop) {
    for (const t of T) {
      let p;
      try { p = await api('/api/settlement/package?owner=' + t.owner); } catch { continue; }
      const id = `${p.epoch}#${p.segment}`;
      if (p.account.signed || t.signed.has(id)) continue;
      t.signed.add(id);
      try {
        const acct = (await api('/api/collateral/' + t.owner)).account;
        const { review, body } = await signEntry(p, t.owner, t.sk, { account: acct, batcherKey: status.collateral.batcher_key });
        await api('/api/settlement/signature', body);
        step('signed', { trader: t.i, epoch: p.epoch, segment: p.segment, batches: review.batches, value_in: Number(review.valueIn), net: Number(review.net),
          roll: review.rollover && { value: Number(review.rollover.value), refund_height: review.rollover.refundHeight }, sighash: hex(review.sighash) });
      } catch (e) { step('refused', { trader: t.i, epoch: p.epoch, error: e.message }); }
    }
    await sleep(3000);
  }
})();

// 3. One round trip: trader 0 posts short at the mark, trader 1 takes; trader 1 posts the close SPREAD higher, trader 0 takes.
function intent(t, f) {
  t.seq = Math.max(t.seq + 1, Date.now() * 1000);
  return { owner: t.owner, channel: t.channel, sequence: t.seq, expires_us: (Date.now() + 60e3) * 1000, tier: 'standard', quantity: QTY, leverage_bps: LEV,
    max_fee_ppm: 0, max_fee_sats: 0, max_mark_age_us: template.max_mark_age_us, early_window_opt_in: false, cancel_target: '0'.repeat(64), ...f };
}
async function send(t, f) { const { id, intent: it } = await signIntent(intent(t, f), template, t.sk, null); await api('/api/intents', { intent: it }); return id; }
async function signPending(t) {
  const v = await api('/api/account/' + t.owner);
  const todo = (v.pending_signatures || []).filter((x) => !t.signed.has(x.id));
  if (todo.length) {
    const items = [];
    for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), t.sk)) });
    await api('/api/signatures', { owner: t.owner, items });
    for (const x of todo) t.signed.add(x.id);
  }
  return v;
}
async function pair(name, maker, side, taker, limit) {
  await send(maker, { action: 'post', side, limit_usd: limit });
  const take = await send(taker, { action: 'take', side: side === 'long' ? 'short' : 'long', limit_usd: limit });
  const t0 = Date.now();
  for (;;) {
    if (Date.now() - t0 > 60e3) throw new Error(`${name}: did not commit in 60 s`);
    const [, tv] = await Promise.all([signPending(maker), signPending(taker)]);
    const f = (tv.fills || []).find((x) => x.id === take);
    if (f?.batch_seq == null) continue;
    const ph = (await api(`/api/explorer/batch/${f.batch_seq}`)).batch.phase;
    if (ph === 'committed') { step('fill', { name, maker: maker.i, taker: taker.i, side, limit_usd: limit, qty_usd: QTY, leverage_bps: LEV, batch: f.batch_seq, fill: take }); return f.batch_seq; }
    if (ph === 'aborted') throw new Error(`${name}: batch ${f.batch_seq} aborted`);
  }
}
const p0 = Math.round((await api('/api/status')).mark.price_usd);
await pair('open', T[0], 'short', T[1], p0);
const close = await pair('close', T[1], 'short', T[0], p0 + SPREAD);
const pnl = {};
for (const t of T) pnl[t.i] = (await api('/api/account/' + t.owner)).balance.realized_pnl;
step('traded', { open_price: p0, close_price: p0 + SPREAD, close_batch: close, realized: pnl });

// 4. The next maturity's settlement: both rolled at min-conf, checked against deposit + PnL and mempool.space.
for (const t of T) {
  const a = await until(`trader ${t.i} settled through ${close}`, async () => { const x = (await api('/api/collateral/' + t.owner)).account; return x.settled_through >= close && x; }, 3 * 3600e3, 15000);
  const want = t.deposit + pnl[t.i];
  const ms = await (await fetch(`${MEMPOOL}/tx/${a.outpoint.txid}`)).json().catch(() => null);
  const out = ms?.vout?.[a.outpoint.vout];
  step('settled', { trader: t.i, outpoint: `${a.outpoint.txid}:${a.outpoint.vout}`, value: a.value, want_deposit_plus_pnl: want, ok: a.value === want, refund_height: a.refund_height,
    mempool_space: ms && { confirmed: ms.status?.confirmed, block_height: ms.status?.block_height, output_value: out?.value, output_spk: out?.scriptpubkey, url: `https://mempool.space/testnet4/tx/${a.outpoint.txid}` } });
}
stop = true; await signer;
receipt.settlements = await api('/api/explorer/settlements');
receipt.finished = new Date().toISOString();
writeFileSync(OUT, JSON.stringify(receipt, null, 1));
log('epoch complete; receipt', OUT);
