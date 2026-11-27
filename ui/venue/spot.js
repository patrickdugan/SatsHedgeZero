// Spot tab of the venue page: BTC/USDT book, trades tape, buy/sell ticket, chart and the spot
// part of the bottom panel. Shown only when GET /api/spot/book answers (venue started with --spot).
// Orders are SpotIntent (version 8) signed in this browser (crypto.js: id in JS, BIP340 in sign.wasm).
// A take is a spot batch the venue stages; its V4 acknowledgements arrive as pending signatures and
// the page's autoSign signs them like option acks. Balances are the options asset wallet (BTC moved
// from the perpetual allocation, USDT through the simulated adapter). TESTNET ONLY: nothing moves on chain.
import { signSpotIntent } from './crypto.js';
import { chartSrc } from './settings.js';

export const SPOT_MARKET = 'SHZ-BTCUSDT-SPOT';
const SATS = 1e8;

// ---------------------------------------------------------------- pure helpers (node-tested)
/** Price in quote base units per BTC from a human price (USDT per BTC), rounded to the tick. */
export function priceToBase(usdt, pair) {
  const d = pair.quote.decimals, b = Math.round((Number(usdt) * 10 ** d) / pair.tick) * pair.tick;
  if (!Number.isFinite(b) || b <= 0) throw new Error('price must be positive');
  return b;
}
export const baseToPrice = (b, pair) => b / 10 ** pair.quote.decimals;
/** Sats from a human BTC amount, rounded down to the lot. */
export function satsFromBtc(btc, pair) {
  const s = Math.floor(Math.round(Number(btc) * SATS) / pair.lot_sats) * pair.lot_sats;
  if (!Number.isFinite(s) || s <= 0) throw new Error(`size must be at least ${pair.lot_sats / SATS} BTC`);
  return s;
}
/** Quote base units of `sats` at `price` (exact for on-lot sizes and on-tick prices). */
export const quoteUnits = (sats, price) => Number((BigInt(sats) * BigInt(price)) / 100_000_000n);
/**
 * Fill estimate of an IOC take of `sats` against one side of the book ([[price, sats, n]] in
 * priority order) with limit `limit` (null: no limit). Returns {sats, quote, avg, levels}.
 */
export function walk(levels, sats, buy, limit = null) {
  let left = sats, quote = 0, got = 0, used = 0;
  for (const [p, q] of levels) {
    if (left <= 0) break;
    if (limit != null && (buy ? p > limit : p < limit)) break;
    const n = Math.min(left, q); quote += quoteUnits(n, p); got += n; left -= n; used += 1;
  }
  return { sats: got, quote, avg: got ? (quote * SATS) / got : null, levels: used };
}
/** Limit for a market take: `slipBps` past the best opposite level, on the tick. */
export function marketLimit(levels, buy, pair, slipBps = 50) {
  const best = levels[0]?.[0]; if (!best) return null;
  const raw = buy ? best * (1 + slipBps / 1e4) : best * (1 - slipBps / 1e4);
  return Math.max(pair.tick, (buy ? Math.ceil(raw / pair.tick) : Math.floor(raw / pair.tick)) * pair.tick);
}
/** Cumulative depth rows [price, sats, n, cum] for display. */
export function depthRows(levels, n = 14) {
  let c = 0; return levels.slice(0, n).map(([p, q, k]) => [p, q, k, (c += q)]);
}

// ---------------------------------------------------------------- DOM
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = (n, d = 0) => (n === null || n === undefined || Number.isNaN(n) ? '—' : Number(n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d }));
const short = (h) => (h ? h.slice(0, 8) + '…' : '');
const btc = (sats) => fmtN(sats / SATS, 5);

const s = { ctx: null, pair: null, book: { bids: [], asks: [] }, trades: [], buy: true, take: false, price: '', amount: '0.001', msg: '', msgCls: '', seq: 0, timer: null, chart: false };
const usdt = (base) => fmtN(base / 10 ** (s.pair?.quote.decimals ?? 6), 2);
const px = (base) => fmtN(baseToPrice(base, s.pair), 1);

export async function init(ctx) {
  s.ctx = ctx;
  let b;
  try { b = await ctx.api('/api/spot/book?depth=40'); } catch { return false; }
  s.pair = b.pair; s.book = b;
  for (const el of document.querySelectorAll('[data-spot]')) el.hidden = false;
  try { s.trades = await ctx.api('/api/spot/trades?limit=60'); } catch { /* empty tape */ }
  render();
  setInterval(refresh, 5000);
  return true;
}
/** The view switch (options.js setView) calls this when Spot is shown. */
export function shown() {
  if (!s.chart && s.pair) { s.chart = true; $('spotframe').src = chartSrc(SPOT_MARKET, location.origin); }
  render();
}
export function reloadChart() { if (s.chart) $('spotframe').src = chartSrc(SPOT_MARKET, location.origin); }
async function refresh() {
  try { s.book = await s.ctx.api('/api/spot/book?depth=40'); s.trades = await s.ctx.api('/api/spot/trades?limit=60'); render(); } catch { /* keep the last view */ }
}
/** WS events from venue.js (types starting with "spot"). */
export function onEvent(m) {
  if (m.type === 'spot_trade' && m.trade) { s.trades.unshift(m.trade); s.trades.length = Math.min(s.trades.length, 60); renderTape(); }
  if (m.type === 'spot_batch' && s.ctx) {
    s.ctx.refreshAccount().then(() => {
      const mine = (s.ctx.st.account?.spot?.intents || []).some((i) => i.batch === m.n);
      if (mine && m.phase !== 'staged') setMsg(`Spot batch #${m.n} ${m.phase}${m.phase === 'aborted' ? ': neither leg moved' : ': both legs settled'}`, m.phase === 'aborted' ? 'err' : 'ok');
      s.ctx.renderBottom(); renderTicket();
    });
  }
  clearTimeout(s.timer); s.timer = setTimeout(refresh, 200);
}
function setMsg(t, cls = '') { s.msg = t; s.msgCls = cls; const e = $('smsg'); if (e) { e.textContent = t; e.className = 'msg ' + cls; } }

function render() { renderBook(); renderTape(); const f = document.activeElement; if (!f || !/^(INPUT|SELECT)$/.test(f.tagName) || !$('spotticket')?.contains(f)) renderTicket(); }
function renderBook() {
  const el = $('spotbook'); if (!el || !s.pair) return;
  const asks = depthRows(s.book.asks || []), bids = depthRows(s.book.bids || []);
  const mx = Math.max(1, asks.at(-1)?.[3] || 0, bids.at(-1)?.[3] || 0);
  const row = (cls, r) => `<div class="row ${cls}" data-sp="${r[0]}"><span class="${cls === 'ask' ? 'short' : 'long'}">${px(r[0])}</span><span>${btc(r[1])}</span><span>${btc(r[3])}</span><i class="bar" style="width:${(r[3] / mx * 100).toFixed(1)}%"></i></div>`;
  const a = asks[0]?.[0], b = bids[0]?.[0];
  const last = s.trades[0];
  el.querySelector('#sasks').innerHTML = asks.map((r) => row('ask', r)).reverse().join('');
  el.querySelector('#sbids').innerHTML = bids.map((r) => row('bid', r)).join('');
  el.querySelector('#sspread').innerHTML = a && b ? `<span>Spread ${px(a - b)} (${((a - b) / a * 1e4).toFixed(1)} bps)</span><span class="muted">${last ? 'last ' + px(last.price) : 'oracle ' + fmtN(s.book.mark_usd)}</span>` : `<span class="muted">${a || b ? 'one-sided book' : 'no book'}</span><span class="muted">oracle ${fmtN(s.book.mark_usd)}</span>`;
}
function renderTape() {
  const el = $('stape'); if (!el) return;
  el.innerHTML = s.trades.length ? s.trades.slice(0, 40).map((t) => `<div class="row"><span class="${t.taker_side === 'buy' ? 'long' : 'short'}" title="batch #${t.batch}">${px(t.price)}</span><span>${btc(t.sats)}</span><span class="muted">${new Date(t.ts_us / 1000).toLocaleTimeString('en-GB')}</span></div>`).join('') : '<div class="empty">No spot trades yet</div>';
}
const wallet = () => {
  const bals = s.ctx?.st.account?.spot?.balances || [];
  const g = (code) => bals.find((b) => b.asset === code) || { free: 0, spot_locked: 0, option_locked: 0 };
  return { btc: g('BTC'), usdt: g(s.pair?.quote.code || 'USDT') };
};
function ticketEstimate() {
  if (!s.pair) return null;
  let sats, price = null;
  try { sats = satsFromBtc(s.amount, s.pair); } catch (e) { return { err: e.message }; }
  const side = s.buy ? s.book.asks || [] : s.book.bids || [];
  if (s.take) {
    const lim = s.price ? priceToBase(s.price, s.pair) : marketLimit(side, s.buy, s.pair);
    if (!lim) return { err: 'no ' + (s.buy ? 'asks' : 'bids') + ' to take' };
    const w = walk(side, sats, s.buy, lim);
    return { sats, price: lim, fill: w, cost: s.buy ? w.quote : w.sats };
  }
  try { price = priceToBase(s.price, s.pair); } catch (e) { return { sats, err: 'enter a price' }; }
  return { sats, price, cost: s.buy ? quoteUnits(sats, price) : sats };
}
function renderTicket() {
  const el = $('spotticket'); if (!el || !s.pair) return;
  const acct = s.ctx.st.account, w = wallet(), e = ticketEstimate() || {};
  const need = e.cost ?? 0, have = s.buy ? w.usdt.free : w.btc.free;
  const est = e.err ? `<div class="muted">${esc(e.err)}</div>` : s.take
    ? `<div><span>Limit (IOC)</span><span>${px(e.price)} USDT</span></div><div><span>Fills now</span><span>${btc(e.fill.sats)} BTC over ${e.fill.levels} level${e.fill.levels === 1 ? '' : 's'}</span></div><div><span>Avg price</span><span>${e.fill.avg ? px(e.fill.avg) : '—'}</span></div><div><span>${s.buy ? 'Pay' : 'Receive'}</span><span>${usdt(e.fill.quote)} USDT</span></div>${e.fill.sats < e.sats ? '<div class="amber"><span>Book is thinner than the size: the rest is dropped (IOC)</span></div>' : ''}`
    : `<div><span>${s.buy ? 'Locks' : 'Locks'}</span><span>${s.buy ? usdt(need) + ' USDT' : btc(need) + ' BTC'}</span></div><div><span>Total</span><span>${usdt(quoteUnits(e.sats, e.price))} USDT</span></div>`;
  el.innerHTML = `<div class="tabs" id="stabs"><button data-t="0" class="${s.take ? '' : 'on'}">Limit (post)</button><button data-t="1" class="${s.take ? 'on' : ''}">Take (IOC)</button></div>
    <div class="form">
      <div class="sides" id="ssides"><button class="long ${s.buy ? 'on' : ''}" data-b="1">Buy BTC</button><button class="short ${s.buy ? '' : 'on'}" data-b="0">Sell BTC</button></div>
      <label class="f">${s.take ? 'Limit price (USDT, blank = best + 0.5%)' : 'Price (USDT per BTC)'}<input type="number" id="sprice" min="0" step="0.1" value="${esc(s.price)}"></label>
      <label class="f">Amount (BTC, lot ${s.pair.lot_sats / SATS})<input type="number" id="samt" min="0" step="${s.pair.lot_sats / SATS}" value="${esc(s.amount)}"></label>
      <div class="est">${est}<div><span>Available</span><span class="${have < need ? 'short' : ''}">${s.buy ? usdt(have) + ' USDT' : btc(have) + ' BTC'}</span></div></div>
      <button class="go ${s.buy ? 'long' : 'short'}" id="sgo" ${!acct || e.err || (s.take && !e.fill?.sats) ? 'disabled' : ''}>${s.take ? (s.buy ? 'Buy now' : 'Sell now') : (s.buy ? 'Post bid' : 'Post ask')}</button>
      <div class="msg ${s.msgCls}" id="smsg">${esc(s.msg || (acct ? '' : 'Connect a wallet (top right) or register an account on the Perpetual view to trade.'))}</div>
    </div>
    <div class="wallet"><div class="mnote">Spot is fully funded: a buy locks USDT, a sell locks BTC, no leverage and no liquidation. Balances are the options wallet (add BTC or USDT on the Options ticket). Each take is one batch: both legs commit on every lane's acknowledgement, or neither moves. USDT here is a simulated adapter credit; nothing settles on chain.</div>
      <div class="est"><div><span>BTC free / in orders</span><span>${btc(w.btc.free)} / ${btc(w.btc.spot_locked)}</span></div><div><span>${esc(s.pair.quote.code)} free / in orders</span><span>${usdt(w.usdt.free)} / ${usdt(w.usdt.spot_locked)}</span></div>${w.btc.option_locked || w.usdt.option_locked ? `<div><span>Option collateral</span><span>${btc(w.btc.option_locked)} BTC &middot; ${usdt(w.usdt.option_locked)} USDT</span></div>` : ''}</div></div>`;
  $('stabs').onclick = (ev) => { const b = ev.target.closest('[data-t]'); if (b) { s.take = b.dataset.t === '1'; if (s.take) s.price = ''; renderTicket(); } };
  $('ssides').onclick = (ev) => { const b = ev.target.closest('[data-b]'); if (b) { s.buy = b.dataset.b === '1'; renderTicket(); } };
  $('sprice').oninput = (ev) => { s.price = ev.target.value; };
  $('sprice').onchange = () => renderTicket();
  $('samt').oninput = (ev) => { s.amount = ev.target.value; };
  $('samt').onchange = () => renderTicket();
  $('sgo').onclick = submit;
}
function nextSeq() { s.seq = Math.max(s.seq + 1, Date.now() * 1000); return s.seq; }
async function send(fields) {
  const st = s.ctx.st, a = st.account;
  const { intent } = await signSpotIntent({ owner: st.owner, channel: { txid: a.outpoint.txid, vout: a.outpoint.vout }, pair: s.pair.pair, sequence: nextSeq(), expires_us: (Date.now() + 120e3) * 1000, ...fields }, st.template, st.key);
  return s.ctx.api('/api/spot/intents', { intent });
}
async function submit() {
  const e = ticketEstimate();
  if (!e || e.err) return setMsg(e?.err || 'nothing to send', 'err');
  try {
    setMsg('Signing…');
    const r = await send({ action: s.take ? 'take' : 'post', buy: s.buy, qty_sats: e.sats, price: e.price });
    setMsg(r.outcome === 'staged' ? `Staged as batch #${r.batch}: acknowledging…` : r.outcome === 'posted' ? 'Posted ' + short(r.id) : r.outcome, 'ok');
    await s.ctx.refreshAccount(); s.ctx.renderBottom(); refresh();
  } catch (err) { setMsg(/still settling/.test(err.message) ? 'Another batch is settling. Try again in a moment.' : err.message, /still settling/.test(err.message) ? 'note' : 'err'); }
}
export async function cancel(id) {
  try { await send({ action: 'cancel', buy: false, qty_sats: 0, price: 0, cancel_target: id }); await s.ctx.refreshAccount(); s.ctx.renderBottom(); refresh(); }
  catch (e) { setMsg('Cancel: ' + e.message, 'err'); }
}
/** Book row click: put its price in the ticket. */
export function pickPrice(base) { s.price = String(baseToPrice(Number(base), s.pair)); s.take = false; renderTicket(); }

/** Spot part of the bottom panel: wallet, open orders, fills, intents, acknowledgements. */
export function renderBottom(el, table) {
  const sp = s.ctx?.st.account?.spot;
  if (!sp || !s.pair) { el.innerHTML = '<div class="empty">Spot is on; register an account to trade it.</div>'; return; }
  el.innerHTML = `<div class="optbal">${sp.balances.map((b) => `<span><b>${esc(b.asset)}</b> free ${b.asset === 'BTC' ? btc(b.free) : usdt(b.free)} &middot; in orders ${b.asset === 'BTC' ? btc(b.spot_locked) : usdt(b.spot_locked)}</span>`).join('')}<span class="long">fully funded: no leverage, no liquidation</span></div>`
    + table(['Open spot order', 'Side', 'Price', 'Remaining BTC', ''], sp.open_orders.map((o) => `<tr><td>${esc(short(o.id))}</td><td class="${o.side === 'buy' ? 'long' : 'short'}">${o.side}</td><td>${px(o.price)}</td><td>${btc(o.remaining_sats)}</td><td><button class="btn sm" data-scancel="${esc(o.id)}">Cancel</button></td></tr>`))
    + table(['Spot fill', 'Phase', 'Side', 'Role', 'Price', 'BTC', 'USDT'], sp.fills.slice(0, 40).map((f) => `<tr><td>#${f.batch}</td><td><span class="phase ${esc(f.phase)}">${esc(f.phase)}</span></td><td class="${f.side === 'buy' ? 'long' : 'short'}">${f.side}</td><td>${f.role}</td><td>${px(f.price)}</td><td>${btc(f.sats)}</td><td>${usdt(f.quote_units)}</td></tr>`))
    + table(['Spot order', 'Action', 'Side', 'Price', 'BTC', 'Filled', 'Status'], sp.intents.slice(0, 20).map((i) => `<tr><td>${esc(short(i.id))}</td><td>${i.action}</td><td class="${i.side === 'buy' ? 'long' : 'short'}">${i.action === 'cancel' ? '' : i.side}</td><td>${i.price ? px(i.price) : ''}</td><td>${i.qty_sats ? btc(i.qty_sats) : ''}</td><td>${i.filled_sats ? btc(i.filled_sats) : ''}</td><td title="${esc(i.reason || '')}">${esc(i.status)}${i.batch ? ' #' + i.batch : ''}</td></tr>`))
    + table(['Spot acknowledgement', 'Batch', 'Lane rows', 'Status'], sp.pending_signatures.map((p) => `<tr><td>${esc(p.id)}</td><td>#${p.context.option_batch}</td><td>${esc((p.context.rows || []).map((r) => `${r.asset} ${r.net >= 0 ? '+' : ''}${fmtN(r.net)}`).join(', '))}</td><td class="amber">${s.ctx.st.signed.has(p.id) ? 'signed, awaiting the other lanes' : 'auto-signing…'}</td></tr>`));
}
