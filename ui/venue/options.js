// Options tab of the venue page: chain (expiry x strike, calls left, puts right per asset),
// ticket for single legs and combos (spread, collar, covered call), collateral moves and the
// options part of the bottom panel. Shown only when GET /api/options/series says enabled.
// Orders are IntentV7 signed in this browser (crypto.js: id in JS, BIP340 signing in sign.wasm);
// the venue's V4 option acknowledgements arrive as pending signatures and are signed by the
// page's autoSign like perpetual acks. TESTNET ONLY; USDT moves through a simulated adapter.
import { signIntentV7, signTransfer } from './crypto.js';

// ---------------------------------------------------------------- pure helpers (node-tested)
export const PRESETS = {
  single: { label: 'Single leg' },
  spread: { label: 'Call spread', note: 'Buy the selected call, sell the next strike up (one expiry, BTC).' },
  collar: { label: 'Collar', note: 'Buy a put one strike below the mark (USDT if listed), sell a call one strike above (BTC).' },
  covered: { label: 'Covered call', note: 'Sell a call one strike above the mark, covered by BTC collateral in the options account.' },
};
const ten = (n) => 10 ** n;
const decimalsOf = (s) => (s.asset.kind === 'btc' ? 0 : s.asset.decimals);
export const unitName = (s) => (s.asset.kind === 'btc' ? 'sats' : s.asset_code);
/** Base units of the settlement asset for one contract at `milli` per unit. */
export const perContractBase = (s, milli) => Math.floor((milli * s.contract_qty) / 1000);
/** Human amount (sats, or whole stablecoin units) of `base` units of the series' asset. */
export const human = (s, base) => base / ten(decimalsOf(s));
/** premium_milli per unit from a human premium per contract (sats or USDT). */
export function milliFromHuman(s, perContract) {
  const m = Math.round((perContract * ten(decimalsOf(s)) * 1000) / s.contract_qty);
  if (!Number.isFinite(m) || m <= 0) throw new Error('premium must be positive');
  return m;
}
export const contractLabel = (s) => (s.asset.kind === 'btc' ? `${s.contract_qty} USD` : `${s.contract_qty / 1e8} BTC`);

/** Group the series view into expiries, each a strike ladder of {call, puts: {BTC, USDT, ...}}. */
export function buildChain(view) {
  const events = new Map();
  for (const e of view.events || []) events.set(e.event_id, { ...e, strikes: new Map() });
  for (const s of view.series || []) {
    if (!events.has(s.event_id)) events.set(s.event_id, { event_id: s.event_id, maturity_unix: s.maturity_unix, status: 'listed', strikes: new Map() });
    const ev = events.get(s.event_id);
    if (ev.maturity_unix == null) ev.maturity_unix = s.maturity_unix;
    if (!ev.strikes.has(s.strike_usd)) ev.strikes.set(s.strike_usd, { strike: s.strike_usd, call: null, puts: {} });
    const row = ev.strikes.get(s.strike_usd);
    if (s.kind === 'call') row.call = s; else row.puts[s.asset_code] = s;
  }
  const putAssets = [...new Set((view.series || []).filter((s) => s.kind === 'put').map((s) => s.asset_code))].sort((a, b) => (a === 'BTC' ? -1 : b === 'BTC' ? 1 : a.localeCompare(b)));
  const list = [...events.values()].filter((e) => e.strikes.size).map((e) => ({ ...e, rows: [...e.strikes.values()].sort((a, b) => a.strike - b.strike) }))
    .sort((a, b) => (a.maturity_unix || 0) - (b.maturity_unix || 0));
  for (const e of list) delete e.strikes;
  return { events: list, putAssets };
}
const atmIndex = (rows, mark) => rows.reduce((bi, r, i) => (Math.abs(r.strike - mark) < Math.abs(rows[bi].strike - mark) ? i : bi), 0);

/** Legs of a preset on one expiry: [{series, long, qty}] with qty in units (contracts x contract size). */
export function presetLegs(name, ev, mark, contracts, pick = null) {
  if (!ev || !ev.rows.length) throw new Error('no listed expiry');
  const rows = ev.rows, a = atmIndex(rows, mark);
  const units = (s) => contracts * s.contract_qty;
  const leg = (s, long) => { if (!s) throw new Error('strike not listed'); return { series: s.id, long, qty: units(s) }; };
  if (name === 'spread') {
    const i = pick ? rows.findIndex((r) => r.call && r.call.id === pick.id) : a;
    if (i < 0 || i + 1 >= rows.length) throw new Error('a call spread needs a listed strike above the selected call');
    return [leg(rows[i].call, true), leg(rows[i + 1].call, false)];
  }
  if (name === 'collar') {
    if (a < 1 || a + 1 >= rows.length) throw new Error('a collar needs strikes on both sides of the mark');
    const putRow = rows[a - 1].puts;
    const put = putRow.USDT || putRow.BTC || Object.values(putRow)[0];
    return [leg(put, true), leg(rows[a + 1].call, false)];
  }
  if (name === 'covered') {
    if (a + 1 >= rows.length) throw new Error('no strike above the mark');
    return [leg(rows[a + 1].call, false)];
  }
  throw new Error('unknown preset');
}

/**
 * Per-asset net premium of a take at the best quotes, as the IntentV7 limits: the first leg's
 * asset in premium_milli, every other asset once in other_limits. Limits allow `slipBps` of the
 * net (at least one base unit) for fills that walk past the best quote.
 */
export function takeLimits(legs, byId, slipBps = 500) {
  const nets = new Map(); const missing = [];
  for (const l of legs) {
    const s = byId.get(l.series); const q = l.long ? s.ask : s.bid;
    if (!q) { missing.push(l.series); continue; }
    const base = Math.floor((l.qty * q.premium_milli) / 1000);
    const k = s.asset_code;
    if (!nets.has(k)) nets.set(k, { asset: s.asset, net: 0, short: q.qty < l.qty });
    const e = nets.get(k); e.net += (l.long ? 1 : -1) * base * 1000; e.short ||= q.qty < l.qty;
  }
  const lim = (n) => n + Math.max(1000, Math.ceil((Math.abs(n) * slipBps) / 10_000));
  const first = legs.length ? byId.get(legs[0].series).asset_code : null;
  const premium_milli = first && nets.has(first) ? lim(nets.get(first).net) : 0;
  const other_limits = [...nets.entries()].filter(([k]) => k !== first).map(([, e]) => ({ asset: assetDescriptor(e.asset), premium_milli: lim(e.net) }));
  return { premium_milli, other_limits, nets: Object.fromEntries([...nets.entries()].map(([k, e]) => [k, e.net / 1000])), missing, thin: [...nets.values()].some((e) => e.short) };
}
export const assetDescriptor = (a) => (a.kind === 'btc' ? { kind: 'btc' } : { kind: 'stable', protocol: a.protocol, id: a.id, decimals: a.decimals });

/** Worst-case collateral of the legs if nothing offsets (sum of the short legs' worst case), per asset. */
export function worstCaseUpper(legs, byId) {
  const out = {};
  for (const l of legs) {
    const s = byId.get(l.series); if (l.long) continue;
    out[s.asset_code] = (out[s.asset_code] || 0) + (s.worst_case_per_contract.short * l.qty) / s.contract_qty;
  }
  return out;
}

// ---------------------------------------------------------------- DOM
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = (n, d = 0) => (n === null || n === undefined || Number.isNaN(n) ? '—' : Number(n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d }));
const short = (h) => (h ? h.slice(0, 8) + '…' : '');
const fmtAmt = (s, base) => { const d = decimalsOf(s); return fmtN(human(s, base), d ? 2 : 0) + ' ' + unitName(s); };
const hhmm = (u) => (u ? new Date(u * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) : '?');

const o = { xmsg: '', xmsgCls: '', xamt: '', xasset: 'BTC', ctx: null, view: null, chain: null, byId: new Map(), ev: null, preset: 'single', sel: null, long: true, contracts: 1, take: true, price: '', msg: '', msgCls: '', timer: null, seq: 0, xfer: 0 };

export async function init(ctx) {
  o.ctx = ctx;
  let v;
  try { v = await ctx.api('/api/options/series'); } catch { return false; }
  if (!v.enabled) return false;
  for (const el of document.querySelectorAll('[data-options]')) el.hidden = false;
  $('viewseg').onclick = (e) => { const m = e.target.dataset?.v; if (m) setView(m); };
  // A saved Spot view is restored by spot.js once it knows spot is on.
  setView(savedView() === 'options' ? 'options' : 'perps');
  apply(v);
  setInterval(refresh, 5000);
  return true;
}
export function savedView() { try { return localStorage.getItem('shz.venue.view'); } catch { return null; } }
const viewHooks = {};
/** Product view: perps, options or spot (spot.js registers its show hook). */
export function setView(m, hooks = null) {
  if (hooks) Object.assign(viewHooks, hooks);
  document.querySelector('.shell').classList.toggle('opts', m === 'options');
  document.querySelector('.shell').classList.toggle('spot', m === 'spot');
  for (const b of $('viewseg').children) b.classList.toggle('on', b.dataset.v === m);
  try { localStorage.setItem('shz.venue.view', m); } catch { /* storage blocked */ }
  viewHooks[m]?.();
}
async function refresh() { try { apply(await o.ctx.api('/api/options/series')); } catch { /* keep the last view */ } }
function apply(v) {
  o.view = v; o.chain = buildChain(v); o.byId = new Map((v.series || []).map((s) => [s.id, s]));
  const open = o.chain.events.filter((e) => e.rows.some((r) => (r.call || Object.values(r.puts)[0])?.settled_price_usd == null));
  if (!o.ev || !o.chain.events.some((e) => e.event_id === o.ev)) o.ev = (open[0] || o.chain.events[0] || {}).event_id || null;
  if (o.sel) o.sel = o.byId.get(o.sel.id) || null;
  renderChain();
  // Typing in the ticket is not interrupted by a refresh; it re-renders on the next change.
  const f = document.activeElement;
  if (!f || !/^(INPUT|SELECT)$/.test(f.tagName) || !$('optticket')?.contains(f)) renderTicket();
}
/** WS events from venue.js (types starting with "option"). */
export function onEvent(m) {
  clearTimeout(o.timer); o.timer = setTimeout(refresh, 250);
  if (m.type === 'option_batch' && m.batch && m.batch.kind !== 'spot') {
    const mine = o.ctx?.st.owner && JSON.stringify(m.batch).includes(o.ctx.st.owner);
    if (mine) { setMsg(`Option batch #${m.batch.n} ${m.phase}${m.phase === 'staged' ? ': signing the acknowledgement…' : ''}`, m.phase === 'aborted' ? 'err' : 'ok'); o.ctx.refreshAccount().then(o.ctx.renderBottom); }
  }
  if (m.type === 'option_expiry') setMsg(`Expiry ${m.event_id} settled at ${fmtN(m.price_usd)} USD`, 'ok');
}
function setMsg(t, cls = '') { o.msg = t; o.msgCls = cls; const e = $('omsg2'); if (e) { e.textContent = t; e.className = 'msg ' + cls; } }

function quoteCell(s, side) {
  if (!s) return '<td class="muted">·</td>';
  const q = side === 'bid' ? s.bid : s.ask;
  const sel = o.sel && o.sel.id === s.id && (side === 'ask') === o.long ? ' sel' : '';
  return `<td class="q ${side === 'bid' ? 'long' : 'short'}${sel}" data-s="${s.id}" data-side="${side}" title="${q ? `${fmtN(q.qty / s.contract_qty, 2)} contracts` : 'no quote'}">${q ? fmtN(human(s, perContractBase(s, q.premium_milli)), decimalsOf(s) ? 2 : 0) : '—'}</td>`;
}
// A void series (unattestable event) has settled_price_usd 0: shown as "void", never as a price.
const settledMark = (s) => (!s || s.settled_price_usd == null ? '' : s.void || s.settled_price_usd === 0 ? ' <span class="muted">void</span>' : ' ✓');
const worstCell = (s) => (s ? `<td class="muted" title="worst-case loss of one contract written">${fmtN(human(s, s.worst_case_per_contract.short), decimalsOf(s) ? 2 : 0)}</td>` : '<td></td>');
function renderChain() {
  const el = $('optchain'); if (!el) return;
  const c = o.chain, v = o.view;
  if (!c.events.length) { el.innerHTML = `<h3>Options chain</h3><div class="empty">No series listed yet. Series list from the relay's announced DLC events once an oracle mark is in.</div>`; return; }
  const ev = c.events.find((e) => e.event_id === o.ev) || c.events[0];
  const tabs = c.events.map((e) => `<button data-ev="${esc(e.event_id)}" class="${e.event_id === ev.event_id ? 'on' : ''}">${hhmm(e.maturity_unix)}Z <span class="muted">${esc(e.status === 'settled' ? 'settled ' + fmtN(e.price_usd) : e.status || '')}</span></button>`).join('');
  const pa = c.putAssets;
  const head = `<tr><th colspan="3" class="cgrp">Calls <span class="abadge">BTC</span></th><th></th>${pa.map((a) => `<th colspan="3" class="cgrp">Puts <span class="abadge${a === 'BTC' ? '' : ' st'}">${esc(a)}</span></th>`).join('')}</tr>
    <tr><th>Bid</th><th>Ask</th><th>Worst</th><th class="k">Strike</th>${pa.map(() => '<th>Bid</th><th>Ask</th><th>Worst</th>').join('')}</tr>`;
  const mark = v.mark_usd;
  const a = mark ? atmIndex(ev.rows, mark) : -1;
  const rows = ev.rows.map((r, i) => `<tr class="${i === a ? 'atm' : ''}">${quoteCell(r.call, 'bid')}${quoteCell(r.call, 'ask')}${worstCell(r.call)}<td class="k">${fmtN(r.strike)}${settledMark(r.call || Object.values(r.puts)[0])}</td>${pa.map((x) => quoteCell(r.puts[x], 'bid') + quoteCell(r.puts[x], 'ask') + worstCell(r.puts[x])).join('')}</tr>`).join('');
  const any = ev.rows.find((r) => r.call) || {};
  const pAny = ev.rows.map((r) => r.puts.USDT).find(Boolean);
  el.innerHTML = `<h3>Options chain <span class="mono muted">mark ${fmtN(mark)} &middot; ${esc(ev.event_id)} &middot; DLC oracle ${esc(short(v.oracle))}</span></h3>
    <div class="tabs evtabs" id="evtabs">${tabs}</div>
    <div class="scroll"><table class="chain"><thead>${head}</thead><tbody>${rows}</tbody></table>
    <div class="muted cnote">Premiums per contract: BTC series ${any.call ? esc(contractLabel(any.call)) : '100 USD'} notional in sats${pAny ? `, USDT series ${esc(contractLabel(pAny))} in USDT (cash-secured: the writer locks strike &times; size)` : ''}. Worst = worst-case loss of writing one contract, the collateral it locks; the buyer risks only the premium. Click an ask to buy, a bid to sell.</div></div>`;
  $('evtabs').onclick = (e) => { const b = e.target.closest('[data-ev]'); if (b) { o.ev = b.dataset.ev; renderChain(); renderTicket(); } };
  el.querySelector('.chain').onclick = (e) => {
    const td = e.target.closest('td.q'); if (!td) return;
    o.sel = o.byId.get(td.dataset.s); o.long = td.dataset.side === 'ask'; o.preset = o.preset === 'covered' || o.preset === 'collar' ? 'single' : o.preset;
    const q = o.long ? o.sel.ask : o.sel.bid; o.price = q ? String(human(o.sel, perContractBase(o.sel, q.premium_milli))) : '';
    renderChain(); renderTicket();
  };
}

function describe(s) { return `${s.kind === 'call' ? 'Call' : 'Put'} ${fmtN(s.strike_usd)} ${s.asset_code} ${hhmm(s.maturity_unix)}Z`; }
function ticketLegs() {
  const ev = o.chain.events.find((e) => e.event_id === o.ev);
  if (o.preset === 'single') { if (!o.sel) return []; return [{ series: o.sel.id, long: o.long, qty: o.contracts * o.sel.contract_qty }]; }
  return presetLegs(o.preset, ev, o.view.mark_usd || 0, o.contracts, o.sel && o.sel.kind === 'call' ? o.sel : null);
}
function renderTicket() {
  const el = $('optticket'); if (!el) return;
  const st = o.ctx.st, acct = st.account;
  let legs = [], err = '';
  try { legs = ticketLegs(); } catch (e) { err = e.message; }
  const single = o.preset === 'single';
  const lim = legs.length ? takeLimits(legs, o.byId) : null;
  const worst = legs.length ? worstCaseUpper(legs, o.byId) : {};
  const legRows = legs.map((l) => {
    const s = o.byId.get(l.series), q = l.long ? s.ask : s.bid;
    return `<div><span class="${l.long ? 'long' : 'short'}">${l.long ? 'Buy' : 'Sell'} ${fmtN(l.qty / s.contract_qty, 2)} &times; ${esc(describe(s))}</span><span>${q ? fmtAmt(s, perContractBase(s, q.premium_milli)) : 'no quote'}</span></div>`;
  }).join('');
  const nets = lim ? Object.entries(lim.nets).map(([k, n]) => { const s = legs.map((l) => o.byId.get(l.series)).find((x) => x.asset_code === k); return `<div><span>Net premium ${esc(k)}</span><span class="${n > 0 ? 'short' : 'long'}">${n > 0 ? 'pay ' : 'receive '}${fmtAmt(s, Math.abs(n))}</span></div>`; }).join('') : '';
  const worstRows = Object.entries(worst).map(([k, w]) => { const s = legs.map((l) => o.byId.get(l.series)).find((x) => x.asset_code === k); return `<div><span>Worst case written ${esc(k)}</span><span>${fmtAmt(s, w)}</span></div>`; }).join('');
  const bals = (acct?.options?.balances || []).map((b) => `<div><span>${esc(b.asset)} free / locked</span><span>${fmtN(b.free)} / ${fmtN(b.locked)}</span></div>`).join('');
  el.innerHTML = `<div class="tabs" id="optpresets">${Object.entries(PRESETS).map(([k, p]) => `<button data-p="${k}" class="${o.preset === k ? 'on' : ''}">${p.label}</button>`).join('')}</div>
    <div class="form">
      ${single ? `<div class="sides" id="osides"><button class="long ${o.long ? 'on' : ''}" data-l="1">Buy</button><button class="short ${o.long ? '' : 'on'}" data-l="0">Sell</button></div>
        <div class="est"><div><span>Series</span><span>${o.sel ? esc(describe(o.sel)) : 'pick a bid or ask in the chain'}</span></div>${o.sel ? `<div><span>Contract</span><span>${esc(contractLabel(o.sel))}</span></div>` : ''}</div>
        <div class="seg" id="otake"><button data-t="1" class="${o.take ? 'on' : ''}">Take (fill now)</button><button data-t="0" class="${o.take ? '' : 'on'}">Post (rest)</button></div>
        ${!o.take ? `<label class="f">Premium per contract (${o.sel ? esc(unitName(o.sel)) : ''})<input type="number" id="oprice" min="0" step="any" value="${esc(o.price)}"></label>` : ''}`
      : `<div class="mnote">${esc(PRESETS[o.preset].note)} One signed IntentV7, all legs or none, in one option batch.</div>`}
      <label class="f">Contracts<input type="number" id="oqty" min="0.01" step="0.01" value="${o.contracts}"></label>
      <div class="est">${legRows || `<div class="muted">${esc(err || 'no legs')}</div>`}${nets}${worstRows}${lim && lim.missing.length ? '<div class="short"><span>A leg has no quote to take</span></div>' : ''}${lim && lim.thin ? '<div class="amber"><span>Best quote is smaller than the size; the limit allows 5% more</span></div>' : ''}</div>
      <button class="go ${single && !o.long ? 'short' : 'long'}" id="ogo" ${!acct || !legs.length || (o.take || !single ? lim?.missing.length : !o.price) ? 'disabled' : ''}>${single ? (o.take ? (o.long ? 'Buy' : 'Sell') + ' now' : 'Post ' + (o.long ? 'bid' : 'ask')) : 'Trade ' + esc(PRESETS[o.preset].label.toLowerCase())}</button>
      <div class="msg ${o.msgCls}" id="omsg2">${esc(o.msg)}</div>
    </div>
    <div class="wallet"><div class="mnote">Options collateral (separate from perpetual margin). BTC moves from your perpetual allocation; USDT through the simulated RGB adapter, nothing on chain.</div>
      <div class="est">${bals || '<div class="muted">register an account first</div>'}</div>
      <div class="xfer"><input type="number" id="xamt" min="0" step="any" placeholder="amount" value="${esc(o.xamt)}"><select id="xasset">${(o.view.assets || []).map((a) => `<option value="${esc(a.code)}"${a.code === o.xasset ? ' selected' : ''}>${esc(a.code)}${a.kind === 'btc' ? ' (sats)' : ''}</option>`).join('')}</select>
      <button class="btn sm" data-x="in">Add</button><button class="btn sm" data-x="out">Remove</button></div><div class="msg ${o.xmsgCls}" id="xmsg">${esc(o.xmsg)}</div></div>`;
  $('optpresets').onclick = (e) => { const p = e.target.closest('[data-p]')?.dataset.p; if (p) { o.preset = p; renderTicket(); } };
  if ($('osides')) $('osides').onclick = (e) => { const b = e.target.closest('[data-l]'); if (b) { o.long = b.dataset.l === '1'; renderTicket(); renderChain(); } };
  if ($('otake')) $('otake').onclick = (e) => { const b = e.target.closest('[data-t]'); if (b) { o.take = b.dataset.t === '1'; renderTicket(); } };
  if ($('oprice')) $('oprice').oninput = (e) => { o.price = e.target.value; $('ogo').disabled = !e.target.value || !acct || !legs.length; };
  $('oqty').onchange = (e) => { o.contracts = Math.max(0.01, Number(e.target.value) || 1); renderTicket(); };
  $('ogo').onclick = () => submitTicket(legs, lim);
  $('xamt').oninput = (e) => { o.xamt = e.target.value; };
  $('xasset').onchange = (e) => { o.xasset = e.target.value; };
  el.querySelector('.xfer').onclick = (e) => { const b = e.target.closest('[data-x]'); if (b) moveCollateral(b.dataset.x === 'in'); };
}
function nextSeq() { o.seq = Math.max(o.seq + 1, Date.now() * 1000, (o.ctx?.st.account?.sequences?.option ?? 0) + 1); return o.seq; }
async function sendIntent(fields) {
  const st = o.ctx.st, a = st.account;
  const { intent } = await signIntentV7({ owner: st.owner, channel: { txid: a.outpoint.txid, vout: a.outpoint.vout }, sequence: nextSeq(), expires_us: (Date.now() + 120e3) * 1000, ...fields }, st.template, st.key);
  return o.ctx.api('/api/options/intents', { intent });
}
async function submitTicket(legs, lim) {
  try {
    setMsg('Signing…');
    let r;
    if (o.preset === 'single' && !o.take) {
      r = await sendIntent({ action: 'post', legs, premium_milli: milliFromHuman(o.sel, Number(o.price)) });
    } else {
      r = await sendIntent({ action: 'take', legs, premium_milli: lim.premium_milli, other_limits: lim.other_limits });
    }
    setMsg(r.outcome === 'staged' ? `Staged as option batch #${r.batch}: acknowledging…` : r.outcome === 'posted' ? 'Posted ' + short(r.id) : r.outcome, 'ok');
    await o.ctx.refreshAccount(); o.ctx.renderBottom(); refresh();
  } catch (e) { setMsg(/still settling/.test(e.message) ? 'Another option batch is settling. Try again in a moment.' : e.message, /still settling/.test(e.message) ? 'note' : 'err'); }
}
async function moveCollateral(into) {
  const st = o.ctx.st;
  const say = (t, cls) => { o.xmsg = t; o.xmsgCls = cls; const m = $('xmsg'); if (m) { m.textContent = t; m.className = 'msg ' + cls; } };
  try {
    const code = $('xasset').value, asset = (o.view.assets || []).find((a) => a.code === code);
    const amt = Math.round(Number($('xamt').value) * (asset.kind === 'btc' ? 1 : ten(asset.decimals)));
    if (!(amt > 0)) throw new Error('enter an amount');
    const op = asset.kind === 'btc' ? (into ? 'fund' : 'defund') : (into ? 'deposit' : 'withdraw');
    o.xfer = Math.max(o.xfer + 1, (Date.now() + 60_000) * 1000);
    const body = await signTransfer(op, { owner: st.owner, asset: assetDescriptor(asset), amount: amt, expires_us: o.xfer }, st.key);
    await o.ctx.api('/api/options/' + op, body);
    const done = `${op} ${fmtN(Number($('xamt').value), asset.kind === 'btc' ? 0 : 2)} ${code} done`;
    o.xamt = '';
    await o.ctx.refreshAccount(); o.ctx.renderBottom(); renderTicket();
    say(done, 'ok');
  } catch (e) { say(e.message, 'err'); }
}
export async function cancelOption(id) {
  try { await sendIntent({ action: 'cancel', legs: [], premium_milli: 0, cancel_target: id }); await o.ctx.refreshAccount(); o.ctx.renderBottom(); refresh(); }
  catch (e) { setMsg('Cancel: ' + e.message, 'err'); }
}

/** Options part of the bottom panel: balances per asset, positions, open quotes, fills, acks. */
export function renderBottom(el, table) {
  const op = o.ctx?.st.account?.options;
  if (!op) { el.innerHTML = '<div class="empty">Options are on; register an account to trade them.</div>'; return; }
  const sOf = (id) => o.byId.get(id);
  const label = (id) => { const s = sOf(id); return s ? describe(s) : short(id); };
  const amt = (id, base) => { const s = sOf(id); return s ? fmtAmt(s, base) : fmtN(base); };
  el.innerHTML = `<div class="optbal">${op.balances.map((b) => `<span><b>${esc(b.asset)}</b> free ${fmtN(b.free)} &middot; locked ${fmtN(b.locked)} &middot; realized <span class="${b.realized >= 0 ? 'long' : 'short'}">${fmtN(b.realized)}</span></span>`).join('')}<span class="${op.fully_funded ? 'long' : 'short'}">${op.fully_funded ? 'fully funded: no liquidation' : 'under-collateralized'}</span></div>`
    + table(['Option position', 'Net contracts', 'Asset', 'Expiry', 'Settled'], op.legs.map((l) => { const s = sOf(l.series); return `<tr><td>${esc(label(l.series))}</td><td class="${l.net > 0 ? 'long' : 'short'}">${s ? fmtN(l.net / s.contract_qty, 2) : l.net}</td><td><span class="abadge${l.asset === 'BTC' ? '' : ' st'}">${esc(l.asset)}</span></td><td>${esc(l.event_id)}</td><td>${l.void ? 'void' : l.settled_price_usd != null ? fmtN(l.settled_price_usd) : ''}</td></tr>`; }))
    + table(['Open option quote', 'Side', 'Premium / contract', 'Remaining', ''], op.open_orders.map((q) => { const s = sOf(q.series); return `<tr><td>${esc(label(q.series))}</td><td class="${q.long ? 'long' : 'short'}">${q.long ? 'bid' : 'ask'}</td><td>${s ? amt(q.series, perContractBase(s, q.premium_milli)) : q.premium_milli}</td><td>${s ? fmtN(q.remaining / s.contract_qty, 2) : q.remaining}</td><td><button class="btn sm" data-ocancel="${esc(q.id)}">Cancel</button></td></tr>`; }))
    + table(['Option fill', 'Batch', 'Phase', 'Side', 'Contracts', 'Premium'], op.fills.slice(0, 40).map((f) => { const s = sOf(f.series); return `<tr><td>${esc(label(f.series))}</td><td>#${f.batch}</td><td><span class="phase ${esc(f.phase)}">${esc(f.phase)}</span></td><td class="${f.side === 'long' ? 'long' : 'short'}">${f.side}</td><td>${s ? fmtN(f.qty / s.contract_qty, 2) : f.qty}</td><td>${amt(f.series, f.premium)}</td></tr>`; }))
    + table(['Option acknowledgement', 'Batch', 'Lane rows', 'Status'], op.pending_signatures.map((p) => `<tr><td>${esc(p.id)}</td><td>#${p.context.option_batch} ${esc(p.context.batch_kind)}</td><td>${esc((p.context.rows || []).map((r) => `${r.asset} ${r.net >= 0 ? '+' : ''}${fmtN(r.net)}`).join(', '))}</td><td class="amber">${o.ctx.st.signed.has(p.id) ? 'signed, awaiting the other lanes' : 'auto-signing…'}</td></tr>`));
}
