// Lightninger MVP drill, trader side: two browser-less clients deposit real (regtest or testnet4)
// coins to their collateral addresses, activate after confirmations, trade a round trip against each
// other on the venue, review and sign every settlement package with ui/venue/settle.js (the same code
// the browser runs), wait for the venue to roll their accounts on chain, then trader 0 withdraws in
// full. Writes a receipt with every txid, value and height.
//
//   node ops/mvp-drill/client.mjs --venue http://127.0.0.1:8098 --cli <bitcoin-cli> --cli-args "<args>"
//        --keys <keys.json> --out <receipt.json> [--deposit-btc 0.002] [--qty 200] [--spread 300]
//   node ops/mvp-drill/client.mjs opaddr <operator x-only>   (address of the <O> CHECKSIG liquidity leaf)
//
// --keys holds the two trader secret keys (created on first run, kept outside the repo).
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { hex, unhex, bip340Sign, pubkey, signIntent, randomKey, concat, bech32mEncode } from '../../ui/venue/crypto.js';
import { reviewEntry, signEntry, signWithdrawal, scriptOutput } from '../../ui/venue/settle.js';

const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

if (process.argv[2] === 'opaddr') {
  const spk = await scriptOutput(concat(Uint8Array.of(0x20), unhex(process.argv[3], 32), Uint8Array.of(0xac)));
  console.log(bech32mEncode(process.argv[4] || 'bcrt', 1, spk.slice(2)));
  process.exit(0);
}

const VENUE = arg('venue', 'http://127.0.0.1:8098');
const CLI = arg('cli');
const CLI_ARGS = (arg('cli-args', '') || '').split(' ').filter(Boolean);
const KEYS = arg('keys');
const OUT = arg('out', 'receipt.json');
const DEPOSIT = arg('deposit-btc', '0.002');
const QTY = Number(arg('qty', '200'));
const LEV = Number(arg('lev-bps', '100000'));
const SPREAD = Number(arg('spread', '300'));
const MINE = arg('mine', '1') === '1'; // regtest: mine our own confirmations
const cli = (...a) => execFileSync(CLI, [...CLI_ARGS, ...a], { encoding: 'utf8' }).trim();

async function api(p, body) {
  const r = await fetch(VENUE + p, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => null);
  if (r.status >= 300) { const e = new Error(`${p}: ${r.status} ${JSON.stringify(j)}`); e.status = r.status; throw e; }
  return j;
}
const until = async (what, fn, ms = 600e3, every = 1000) => {
  const t0 = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out: ' + what);
    await sleep(every);
  }
};

if (!existsSync(KEYS)) mkdirSync(dirname(KEYS), { recursive: true });
const keyList = existsSync(KEYS) ? JSON.parse(readFileSync(KEYS, 'utf8')).traders : [];
while (keyList.length < 3) keyList.push(hex(randomKey()));
writeFileSync(KEYS, JSON.stringify({ traders: keyList }));
const T = keyList.map((k, i) => { const sk = unhex(k, 32); return { i, sk, owner: hex(pubkey(sk)), signed: new Set(), seq: 0, reviews: [] }; });
const receipt = { venue: VENUE, started: new Date().toISOString(), traders: T.map((t) => ({ index: t.i, owner: t.owner })), steps: [] };
// Trader 2 trades with trader 1 after trader 0's withdrawal request, so the venue keeps producing
// batches (the daemon settles inside segments of new batches) while trader 0's account pays out.
const step = (name, data) => { receipt.steps.push({ name, at: new Date().toISOString(), ...data }); log(name, JSON.stringify(data)); writeFileSync(OUT, JSON.stringify(receipt, null, 1)); };

const status = await api('/api/status');
if (!status.collateral) throw new Error('venue runs without --collateral-chain');
const net = status.collateral.network;
const template = await api('/api/template');
const sink = MINE ? cli('getnewaddress', '', 'bech32m') : null;
const mine = (n = 1) => { if (MINE) cli('generatetoaddress', String(n), sink); };

// 1. Deposit addresses and deposits.
for (const t of T) {
  const v = await api('/api/collateral/address', { owner: t.owner });
  t.address = v.deposit.address;
  if (v.account) { t.registered = true; continue; }
  if (!v.seen) t.fund = cli('sendtoaddress', t.address, DEPOSIT);
  step('deposit', { trader: t.i, address: t.address, refund_height: v.deposit.refund_height, txid: t.fund || v.seen?.txid });
}
mine(1);

// 2. Activate after the venue's watcher sees the confirmations.
for (const t of T) {
  if (!t.registered) {
    const seen = await until(`trader ${t.i} deposit confirmed`, async () => { const v = await api('/api/collateral/' + t.owner); return v.seen?.ready && v.seen; });
    const d = await api('/api/register/draft', { owner: t.owner, kind: 'collateral' });
    const sig = await bip340Sign(unhex(d.allocation_digest), t.sk);
    await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(sig) });
    step('activated', { trader: t.i, outpoint: `${seen.txid}:${seen.vout}`, value: seen.value, height: seen.height, confirmations: seen.confirmations });
  }
  const a = await api('/api/account/' + t.owner);
  t.channel = a.outpoint; t.seq = Math.max(Date.now() * 1000, a.sequences?.perp || 0);
  if (a.label === 'TESTNET DEMO CREDIT') throw new Error('demo credit on a collateral venue');
}

// 3. Settlement signer: runs for the rest of the drill.
let stopSigner = false;
const signer = (async () => {
  while (!stopSigner) {
    for (const t of T) {
      let p;
      try { p = await api('/api/settlement/package?owner=' + t.owner); } catch { continue; }
      const id = `${p.epoch}#${p.segment}`;
      if (p.account.signed || t.signed.has(id)) continue;
      t.signed.add(id);
      const acct = (await api('/api/collateral/' + t.owner)).account;
      try {
        const { review, body } = await signEntry(p, t.owner, t.sk, { account: acct, batcherKey: status.collateral.batcher_key, withdrawAddress: t.withdrawAddress });
        await api('/api/settlement/signature', body);
        const r = { epoch: p.epoch, segment: p.segment, batches: review.batches, value_in: Number(review.valueIn), net: Number(review.net),
          roll: review.rollover && { value: Number(review.rollover.value), refund_height: review.rollover.refundHeight },
          withdraw: review.withdraw && { value: Number(review.withdraw.value), address: review.withdraw.address }, sighash: hex(review.sighash) };
        t.reviews.push(r);
        step('signed', { trader: t.i, ...r });
      } catch (e) { step('refused', { trader: t.i, epoch: p.epoch, error: e.message }); }
    }
    await sleep(700);
  }
})();

// 4. Trade a round trip: trader 0 posts, trader 1 takes; then trader 1 posts the close `SPREAD` higher.
function intent(t, f) {
  t.seq = Math.max(t.seq + 1, Date.now() * 1000);
  return { owner: t.owner, channel: t.channel, sequence: t.seq, expires_us: (Date.now() + 60e3) * 1000, tier: 'standard', quantity: QTY, leverage_bps: LEV,
    max_fee_ppm: 0, max_fee_sats: 0, max_mark_age_us: template.max_mark_age_us, early_window_opt_in: false, cancel_target: '0'.repeat(64), ...f };
}
async function send(t, f) {
  const { id, intent: it } = await signIntent(intent(t, f), template, t.sk, null);
  await api('/api/intents', { intent: it });
  return id;
}
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
    if (ph === 'committed') { step('fill', { name, maker: maker.i, taker: taker.i, side, limit_usd: limit, qty_usd: QTY, batch: f.batch_seq }); return f.batch_seq; }
    if (ph === 'aborted') throw new Error(`${name}: batch ${f.batch_seq} aborted`);
  }
}
const mark = await until('oracle mark', async () => (await api('/api/status')).mark?.price_usd, 120e3);
const p0 = Math.round(mark);
const open = await pair('open', T[0], 'short', T[1], p0);
const close = await pair('close', T[1], 'short', T[0], p0 + SPREAD);
const nets = [];
for (const t of T) { const a = await api('/api/account/' + t.owner); nets.push({ trader: t.i, realized_pnl: a.balance.realized_pnl, net_usd: a.position.net_usd }); }
step('traded', { open_batch: open, close_batch: close, open_price: p0, close_price: p0 + SPREAD, accounts: nets });

// 5. Wait until the venue applied a settlement covering the close batch for both accounts (rolled on chain).
for (const t of T.slice(0, 2)) {
  const a = await until(`trader ${t.i} settled through ${close}`, async () => { const v = await api('/api/collateral/' + t.owner); return v.account.settled_through >= close && v.account; }, 900e3, 2000);
  step('rolled', { trader: t.i, outpoint: `${a.outpoint.txid}:${a.outpoint.vout}`, value: a.value, refund_height: a.refund_height, settled_through: a.settled_through });
  if (MINE) { const o = JSON.parse(cli('gettxout', a.outpoint.txid, String(a.outpoint.vout), 'false')); step('chain', { trader: t.i, outpoint_value_btc: o.value, confirmations: o.confirmations, spk: o.scriptPubKey.hex }); }
}

// 6. Trader 0 withdraws everything to a fresh wallet address.
const w = T[0];
w.withdrawAddress = MINE ? cli('getnewaddress', '', 'bech32m') : arg('withdraw-address');
const body = await signWithdrawal({ owner: w.owner, address: w.withdrawAddress, network: net }, w.sk);
const wr = await api('/api/settlement/withdraw', body);
step('withdraw-requested', { trader: w.i, address: w.withdrawAddress, router_debit_sats: wr.router_debit_sats });
try { await send(w, { action: 'post', side: 'long', limit_usd: p0 }); step('gate', { trader: w.i, error: 'order accepted after withdrawal request' }); }
catch (e) { step('gate', { trader: w.i, refused: e.message.slice(0, 160) }); }
const p1 = Math.round((await api('/api/status')).mark.price_usd);
await pair('open-2', T[2], 'long', T[1], p1);
await pair('close-2', T[1], 'long', T[2], p1 - SPREAD);
const closed = await until('withdrawal paid', async () => { const v = await api('/api/collateral/' + w.owner); return v.account.closed && v.account; }, 900e3, 2000);
step('withdrawn', { trader: w.i, txid: closed.withdrawal.txid, closed: closed.closed });
if (MINE) {
  const scan = JSON.parse(cli('scantxoutset', 'start', JSON.stringify([`addr(${w.withdrawAddress})`])));
  step('chain-withdrawal', { address: w.withdrawAddress, unspents: scan.unspents.map((u) => ({ txid: u.txid, vout: u.vout, btc: u.amount, height: u.height })) });
}
stopSigner = true; await signer;
receipt.settlements = await api('/api/explorer/settlements');
receipt.finished = new Date().toISOString();
writeFileSync(OUT, JSON.stringify(receipt, null, 1));
log('drill complete; receipt', OUT);
