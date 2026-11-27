// Lightninger MVP drill, trader side: three browser-less clients deposit real (regtest or testnet4)
// coins to their collateral addresses, activate after confirmations, and trade over three epochs,
// reviewing and signing every settlement entry with ui/venue/settle.js (the browser's code):
//   A  trader 0 vs 1, both sign;  B  trader 1 vs 2, trader 2 leaves its package unsigned (its net
//   carries);  C  trader 0 vs 2, then trader 0 withdraws everything; trader 2's carried and new net
//   settle together.
// Checks each account's on-chain value against its realized PnL and writes a receipt with every
// txid, value and height (and, with --await-proofs 1, each segment's statement SHA-256).
//
//   node ops/mvp-drill/client.mjs --venue http://127.0.0.1:8098 --cli <bitcoin-cli> --cli-args "<args>"
//        --keys <keys.json> --out <receipt.json> [--deposit-btc 0.002] [--qty 200] [--spread 300]
//        [--refuse 2:1] [--epoch-secs 60] [--await-proofs 1 --proof-wait-s 3600]
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

// 3. Settlement signer: runs for the rest of the drill. `--refuse i:n` leaves trader i's n-th package
// unsigned (the daemon drops it; its net carries to the next settlement).
const refuse = new Map((arg('refuse', '2:1') || '').split(',').filter(Boolean).map((x) => x.split(':').map(Number)));
let stopSigner = false;
const signer = (async () => {
  while (!stopSigner) {
    for (const t of T) {
      let p;
      try { p = await api('/api/settlement/package?owner=' + t.owner); } catch { continue; }
      const id = `${p.epoch}#${p.segment}`;
      if (p.account.signed || t.signed.has(id)) continue;
      t.signed.add(id);
      t.packages = (t.packages || 0) + 1;
      if (refuse.get(t.i) === t.packages) { step('left-unsigned', { trader: t.i, epoch: p.epoch, segment: p.segment, net: (p.account.carry_in || 0) + (p.account.net || 0) }); continue; }
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
const pnl = async (t) => (await api('/api/account/' + t.owner)).balance.realized_pnl;
const coll = async (t) => (await api('/api/collateral/' + t.owner)).account;
// One epoch's trading: `a` opens `side` against `b` at the mark and closes `SPREAD` against itself.
// Trades start early in an epoch so a round and the withdrawal after it land before one maturity.
const EPOCH = Number(arg('epoch-secs', '60'));
async function roundTrip(name, a, b, side) {
  await until('early in an epoch', async () => { const s = (Date.now() / 1000) % EPOCH; return s > 5 && s < EPOCH / 2; }, EPOCH * 2000, 500);
  await until('oracle mark', async () => (await api('/api/status')).mark?.price_usd, 120e3);
  const p = Math.round((await api('/api/status')).mark.price_usd);
  await pair(name + '-open', a, side, b, p);
  const close = await pair(name + '-close', b, side, a, side === 'short' ? p + SPREAD : p - SPREAD);
  step('traded', { round: name, close_batch: close, realized: { [a.i]: await pnl(a), [b.i]: await pnl(b) } });
  return close;
}
async function settledThrough(t, seq, what) {
  const a = await until(`${what}: trader ${t.i} settled through ${seq}`, async () => { const x = await coll(t); return x.settled_through >= seq && x; }, 900e3, 2000);
  const o = MINE && !a.closed ? JSON.parse(cli('gettxout', a.outpoint.txid, String(a.outpoint.vout), 'false')) : null;
  step('settled', { round: what, trader: t.i, outpoint: `${a.outpoint.txid}:${a.outpoint.vout}`, value: a.value, refund_height: a.refund_height, settled_through: a.settled_through,
    chain: o && { btc: o.value, confirmations: o.confirmations }, closed: a.closed });
  return a;
}

// 4. Epoch A: trader 0 vs trader 1; both sign.
const closeA = await roundTrip('A', T[0], T[1], 'short');
for (const t of [T[0], T[1]]) await settledThrough(t, closeA, 'A');

// 5. Epoch B: trader 1 vs trader 2; trader 2 leaves its package unsigned, its net carries.
const closeB = await roundTrip('B', T[2], T[1], 'long');
await settledThrough(T[1], closeB, 'B');
await until('epoch B result', async () => (await api('/api/explorer/settlements')).some((r) => (r.rolled || []).includes(T[2].owner)), 300e3, 2000);
const t2 = await coll(T[2]);
const carried = (await api('/api/settlement/epoch')).accounts.find((x) => x.owner === T[2].owner);
step('carried', { trader: 2, settled_through: t2.settled_through, value: t2.value, venue_net_unsettled: carried.net, realized: await pnl(T[2]) });

// 6. Epoch C: trader 2 vs trader 0; trader 0 then asks to withdraw everything before the maturity.
const closeC = await roundTrip('C', T[0], T[2], 'long');
const w = T[0];
w.withdrawAddress = MINE ? cli('getnewaddress', '', 'bech32m') : arg('withdraw-address');
const wr = await api('/api/settlement/withdraw', await signWithdrawal({ owner: w.owner, address: w.withdrawAddress, network: net }, w.sk));
step('withdraw-requested', { trader: w.i, address: w.withdrawAddress, router_debit_sats: wr.router_debit_sats });
try { await send(w, { action: 'post', side: 'long', limit_usd: Math.round((await api('/api/status')).mark.price_usd) }); step('gate', { trader: w.i, error: 'order accepted after withdrawal request' }); }
catch (e) { step('gate', { trader: w.i, refused: e.message.slice(0, 160) }); }
const a2 = await settledThrough(T[2], closeC, 'C');
const want2 = 200000 + await pnl(T[2]);
step('check', { what: 'trader 2 collateral = deposit + realized over epochs B (carried) and C', value: a2.value, want: want2, ok: a2.value === want2 });
const closed = await until('withdrawal paid', async () => { const v = await coll(w); return v.closed && v; }, 900e3, 2000);
step('withdrawn', { trader: w.i, txid: closed.withdrawal.txid, closed: closed.closed });
if (MINE) {
  const scan = JSON.parse(cli('scantxoutset', 'start', JSON.stringify([`addr(${w.withdrawAddress})`])));
  const got = Math.round((scan.unspents[0]?.amount || 0) * 1e8), want0 = 200000 + await pnl(w);
  step('chain-withdrawal', { address: w.withdrawAddress, unspents: scan.unspents.map((u) => ({ txid: u.txid, vout: u.vout, btc: u.amount, height: u.height })), sats: got, want: want0, ok: got === want0 });
}
stopSigner = true; await signer;

// 7. Proofs: the daemon posts each segment's statement SHA-256 as a second result.
if (arg('await-proofs', '0') === '1') {
  await until('statements of every settled segment', async () => {
    const r = await api('/api/explorer/settlements');
    return r.filter((x) => x.status === 'broadcast').every((x) => x.statement_sha256);
  }, Number(arg('proof-wait-s', '3600')) * 1000, 15000).catch((e) => step('proofs', { error: e.message }));
}
receipt.settlements = await api('/api/explorer/settlements');
step('statements', { segments: receipt.settlements.map((x) => ({ epoch: x.epoch, segment: x.segment, txid: x.txid, status: x.status, statement_sha256: x.statement_sha256 || null, rolled: x.rolled })) });
receipt.finished = new Date().toISOString();
writeFileSync(OUT, JSON.stringify(receipt, null, 1));
log('drill complete; receipt', OUT);
