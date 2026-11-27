// On-chain collateral in the trading page (venues run with --collateral-chain): deposit address,
// activation after confirmations, settlement review and signing, withdrawal and the refund path.
// The review shows what the trader's own input and output pay, checked by settle.js against the
// trader's key and account; the sighash signed is the locally computed one.
import { hex, unhex, bip340Sign } from './crypto.js';
import { reviewEntry, signEntry, signWithdrawal } from './settle.js';
import { qrSvg } from './qr.js';

let C = null; // { api, esc, fmt, short, st, rerender, store }
const view = { coll: null, pkg: null, review: null, reviewErr: null, busy: false, msg: '', err: false };
const WKEY = (o) => 'shz.venue.withdraw.' + o;

export function init(ctx) { C = ctx; }
export const on = () => !!C?.st.collateral;
export const state = () => view;

/** Refresh the owner's collateral view and, when a package awaits its signature, review it. */
export async function refresh() {
  const { st, api } = C;
  if (!on() || !st.owner) { view.coll = null; return; }
  try { view.coll = await api('/api/collateral/' + st.owner); } catch { return; }
  const open = (view.coll.packages || []).find((p) => !p.signed);
  if (open) {
    if (!view.pkg || view.pkg.epoch !== open.epoch || view.pkg.segment !== open.segment) {
      try {
        view.pkg = await api('/api/settlement/package?owner=' + st.owner);
        view.review = await reviewEntry(view.pkg, st.owner, expectation());
        view.reviewErr = null;
      } catch (e) { view.review = null; view.reviewErr = e.message; }
    }
  } else { view.pkg = null; view.review = null; view.reviewErr = null; }
}

function expectation() {
  const a = view.coll?.account, w = a?.withdrawal;
  const local = C.store.get(WKEY(C.st.owner));
  return { account: a, batcherKey: C.st.collateral.batcher_key, network: view.coll?.network, withdrawAddress: w ? (local || w.address) : undefined };
}

const sats = (n) => C.fmt(n) + ' sats';
const signed = (n) => (Number(n) > 0 ? '+' : '') + C.fmt(n);

/** Wallet-panel block: replaces demo credit registration under --collateral-chain. */
export function walletHtml() {
  const { esc, short, st } = C, c = view.coll, a = st.account;
  if (!c) return '<div class="muted">Loading collateral…</div>';
  const net = esc(c.network);
  let h = '';
  if (!a) {
    const d = c.deposit, seen = c.seen;
    if (!d) {
      h += `<div class="muted">This venue trades against real ${net} collateral. Your deposit address is a Taproot output that your key and the batcher spend together at each settlement, with a refund path to your key alone after a block height.</div>
        <button class="btn" id="cdepaddr">Get my ${net} deposit address</button>`;
    } else {
      h += `<label class="f">Deposit address (${net})<div class="addr" id="cdep">${esc(d.address)}</div></label>
        <div class="qr">${qrSvg(d.address, { px: 3 })}</div>
        <div class="est"><div><span>Refund to your key alone after</span><span>block ${C.fmt(d.refund_height)}</span></div>
        <div><span>Deposit before</span><span>block ${C.fmt(d.credit_by_height)}</span></div>
        <div><span>Chain tip</span><span>${C.fmt(c.tip_height)}</span></div><div><span>Confirmations needed</span><span>${c.min_conf}</span></div></div>`;
      if (!seen) h += '<div class="muted">Watching the chain for a deposit to this address…</div>';
      else {
        h += `<div class="est"><div><span>Deposit seen</span><span>${esc(short(seen.txid))}:${seen.vout}</span></div><div><span>Amount</span><span>${sats(seen.value)}</span></div>
          <div><span>Confirmations</span><span class="${seen.ready ? 'long' : 'amber'}">${seen.confirmations} / ${seen.required}</span></div></div>`;
        h += seen.ready ? `<button class="btn" id="cactivate">Activate account with ${sats(seen.value)}</button>` : '<div class="muted">Activation unlocks at the required confirmations.</div>';
      }
    }
  } else {
    const acct = c.account;
    if (acct) {
      h += `<div class="est"><div><span>Collateral (${net})</span><span>${sats(acct.value)}</span></div>
        <div><span>Outpoint</span><span>${acct.explorer_url ? `<a href="${esc(acct.explorer_url)}" target="_blank" rel="noopener">${esc(short(acct.outpoint.txid))}:${acct.outpoint.vout}</a>` : `${esc(short(acct.outpoint.txid))}:${acct.outpoint.vout}`}</span></div>
        <div><span>Free to trade</span><span>${sats(a.balance?.free)}</span></div>
        <div><span>Refund path</span><span title="refund leaf ${esc(acct.script?.refund_script)}">your key alone after block ${C.fmt(acct.refund_height)} (${acct.blocks_to_refund > 0 ? C.fmt(acct.blocks_to_refund) + ' blocks' : 'open now'})</span></div></div>`;
      if (acct.closed) h += `<div class="warn-box">Closed: ${esc(acct.closed)}</div>`;
    }
    h += reviewHtml();
    for (const p of c.confirming || []) h += `<div class="muted">Settlement ${esc(short(p.txid))} broadcast (${esc(p.kind)}, ${sats(p.value)}); applied at ${c.min_conf} confirmation${c.min_conf > 1 ? 's' : ''}.</div>`;
    if (acct && !acct.closed) {
      const w = acct.withdrawal;
      h += w ? `<div class="muted">Withdrawal requested: the whole account pays out to ${esc(w.address)} at the next settlement. New orders are refused until then.</div>`
        : `<label class="f">Withdraw everything to your ${net} address (flat account, no resting orders)<input type="text" id="cwaddr" placeholder="${c.network === 'regtest' ? 'bcrt1…' : 'tb1…'}" autocomplete="off" spellcheck="false"></label>
        <button class="btn" id="cwithdraw">Request withdrawal</button>`;
    }
  }
  h += `<div class="msg ${view.err ? 'err' : 'ok'}" id="cmsg">${esc(view.msg)}</div>`;
  return h;
}

function reviewHtml() {
  const { esc } = C, open = view.coll?.packages || [];
  if (!open.length) return '';
  const un = open.find((p) => !p.signed);
  if (!un) return `<div class="muted">Settlement ${esc(open[0].epoch)}: your input is signed; waiting for the batcher.</div>`;
  if (view.reviewErr) return `<div class="warn-box">Settlement ${esc(un.epoch)} refused by your browser: ${esc(view.reviewErr)}. Nothing was signed; the batcher leaves your account out and your net carries to the next settlement.</div>`;
  const r = view.review;
  if (!r) return '<div class="muted">Loading settlement…</div>';
  const left = r.deadlineUs ? Math.max(0, Math.round((r.deadlineUs / 1000 - Date.now()) / 1000)) : null;
  return `<div class="review"><b>Settlement to sign</b> <span class="muted">${esc(r.epoch)}${r.segment ? ' / segment ' + r.segment : ''}</span>
    <div class="est"><div><span>Venue batches</span><span>#${r.firstSeq} &rarr; #${r.lastSeq}${r.batches?.length ? ` (yours: ${r.batches.map((b) => '#' + b).join(', ')})` : ''}</span></div>
    <div><span>Collateral in</span><span>${sats(r.valueIn)}</span></div>
    <div><span>Your net</span><span class="${r.net >= 0n ? 'long' : 'short'}">${signed(r.net)} sats</span></div>
    ${r.rollover ? `<div><span>Back to your collateral account</span><span>${sats(r.rollover.value)}, refund after block ${C.fmt(r.rollover.refundHeight)}</span></div>` : ''}
    ${r.withdraw ? `<div><span>Paid out to ${esc(r.withdraw.address)}</span><span>${sats(r.withdraw.value)}</span></div>` : ''}
    <div><span>Your signature covers</span><span>your input and your output only (SINGLE|ANYONECANPAY)</span></div>
    ${left !== null ? `<div><span>Signing closes in</span><span>${C.fmt(left)} s</span></div>` : ''}</div>
    <div class="muted">Checked in this browser: your input is your collateral account, your output pays your account script or your withdrawal address, and it equals collateral plus net. The message signed is computed here, not taken from the venue.</div>
    <button class="btn" id="csign">Sign my input</button></div>`;
}

export function bind() {
  const $ = (id) => document.getElementById(id);
  const click = (id, fn) => { const e = $(id); if (e) e.onclick = fn; };
  click('cdepaddr', () => act(async () => { await C.api('/api/collateral/address', { owner: C.st.owner }); return 'Deposit address issued.'; }));
  click('cactivate', () => act(async () => {
    const d = await C.api('/api/register/draft', { owner: C.st.owner, kind: 'collateral' });
    const sig = await bip340Sign(unhex(d.allocation_digest), C.st.key);
    const r = await C.api('/api/register', { draft_id: d.draft_id, owner_signature: hex(sig) });
    C.st.account = r.account; return `Activated: ${C.fmt(d.cap_sats)} sats of ${view.coll.network} collateral.`;
  }));
  click('csign', () => act(async () => {
    const { body } = await signEntry(view.pkg, C.st.owner, C.st.key, expectation());
    await C.api('/api/settlement/signature', body);
    view.pkg = null; return 'Signed. The batcher broadcasts at the deadline with every account that signed.';
  }));
  click('cwithdraw', () => act(async () => {
    const addr = $('cwaddr').value.trim();
    const body = await signWithdrawal({ owner: C.st.owner, address: addr, network: view.coll.network }, C.st.key);
    await C.api('/api/settlement/withdraw', body);
    C.store.set(WKEY(C.st.owner), addr);
    return 'Withdrawal requested; the next settlement pays the whole account to ' + addr + '.';
  }));
}

async function act(fn) {
  if (view.busy) return;
  view.busy = true; view.msg = 'Working…'; view.err = false; C.rerender();
  try { view.msg = await fn(); view.err = false; } catch (e) { view.msg = e.message; view.err = true; }
  view.busy = false;
  await C.refreshAccount(); C.rerender();
}

/** Bottom "Collateral" tab: chain record of the account. */
export function bottomHtml(bottomTable) {
  const { esc, short } = C, c = view.coll;
  if (!c) return '<div class="empty">Collateral view unavailable</div>';
  const a = c.account;
  const rows = [];
  if (a) {
    rows.push(`<tr><td>Venue channel (first deposit)</td><td class="mono">${esc(a.channel.txid)}:${a.channel.vout}</td></tr>`);
    rows.push(`<tr><td>Current collateral output</td><td class="mono">${esc(a.outpoint.txid)}:${a.outpoint.vout}</td></tr>`);
    rows.push(`<tr><td>Value</td><td>${sats(a.value)}</td></tr>`);
    rows.push(`<tr><td>Settled through venue batch</td><td>#${a.settled_through}</td></tr>`);
    rows.push(`<tr><td>Refund height (CLTV)</td><td>${C.fmt(a.refund_height)} (tip ${C.fmt(c.tip_height)})</td></tr>`);
    rows.push(`<tr><td>Refund leaf</td><td class="mono">${esc(a.script?.refund_script)}</td></tr>`);
    rows.push(`<tr><td>Refund control block</td><td class="mono">${esc(a.script?.refund_control)}</td></tr>`);
    rows.push(`<tr><td>Settle leaf (you + batcher)</td><td class="mono">${esc(a.script?.settle_script)}</td></tr>`);
  }
  return `<div style="padding:6px 10px" class="muted">${esc(c.network)} collateral, batcher key ${esc(short(c.batcher_key))}. If the batcher stops settling, your key alone spends the collateral output through the refund leaf at the refund height.</div>`
    + bottomTable(['Field', 'Value'], rows)
    + bottomTable(['Withdrawal to', 'Status', 'Txid'], a?.withdrawal ? [`<tr><td class="mono">${esc(a.withdrawal.address)}</td><td>${esc(a.withdrawal.status)}</td><td class="mono">${esc(a.withdrawal.txid || '')}</td></tr>`] : []);
}
