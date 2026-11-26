// SHZ venue trading page. No frameworks. TESTNET ONLY: keys live in localStorage.
import { hex, unhex, pubkey, p2trAddress, bip340Sign, signIntent, randomKey } from './crypto.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (n, d = 0) => (n === null || n === undefined || Number.isNaN(n) ? '—' : Number(n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d }));
const short = (h) => (h ? h.slice(0, 8) + '…' + h.slice(-4) : '');
const KEY_STORE = 'shz.venue.key';
const TIERS = ['standard', 'intermediate', 'premium'];
const MARKET = 'SHZ-BTCUSD-INV';

const st = { template: null, mark: null, markAt: 0, book: { bids: [], asks: [] }, trades: [], account: null, batches: new Map(),
  key: null, owner: null, address: null, tier: 'standard', otype: 'limit', side: 'long', btab: 'positions', lastSeq: 0,
  ws: null, wsOk: false, ents: new Map(), signing: new Set(), signed: new Set() };

const store = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } },
  del: (k) => { try { localStorage.removeItem(k); } catch { /* storage blocked */ } },
};
async function api(path, body) {
  const r = await fetch(path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch { /* non-json */ }
  if (!r.ok) { const e = new Error((j && j.error) || 'HTTP ' + r.status); e.status = r.status; throw e; }
  return j;
}

// ---------- wallet ----------
async function setKey(bytes) {
  st.key = bytes; st.owner = hex(pubkey(bytes)); st.address = await p2trAddress(unhex(st.owner), 'tb');
  store.set(KEY_STORE, hex(bytes)); st.account = null; st.signed.clear(); await refreshAccount(); reconnectWs(); renderAll();
}
function renderWallet() {
  const w = $('wallet'), a = st.account;
  let h = '<div class="warn-box">TESTNET ONLY. The key is stored unencrypted in this browser\'s localStorage. Never import a key that holds real coins.</div>';
  if (!st.owner) {
    h += '<button class="btn" id="wgen">Generate testnet key</button><label class="f">Or import 32-byte hex key<input type="text" id="wimp" placeholder="64 hex chars" autocomplete="off" spellcheck="false"></label><button class="btn" id="wimpb">Import</button>';
  } else {
    h += `<label class="f">Owner pubkey (x-only)<div class="addr" id="wpk">${esc(st.owner)}</div></label>
      <label class="f">Funding address (testnet4 P2TR, key-path, no script tree)<div class="addr" id="waddr">${esc(st.address)}</div></label>`;
    if (a) h += `<div class="est"><div><span>Account</span><span>${esc(a.label || 'registered')}</span></div><div><span>Outpoint</span><span>${esc(short(a.outpoint?.txid))}:${esc(a.outpoint?.vout)}</span></div><div><span>Collateral cap</span><span>${fmt(a.balance?.cap)} sats</span></div><div><span>Free</span><span>${fmt(a.balance?.free)} sats</span></div></div>`;
    else h += `<div class="muted">Not registered. Demo credit is synthetic (no coins). For a utxo account, fund the address above on testnet4, then enter the output.</div>
      <button class="btn" id="wdemo">Register demo account (TESTNET DEMO CREDIT)</button>
      <label class="f">utxo outpoint txid:vout<input type="text" id="wutxo" placeholder="txid:vout" autocomplete="off" spellcheck="false"></label><button class="btn" id="wutxob">Register utxo account</button>`;
    h += '<button class="btn sm" id="wforget">Forget key</button>';
  }
  h += '<div class="msg" id="wmsg"></div>';
  w.innerHTML = h;
  const on = (id, fn) => { const e = $(id); if (e) e.onclick = fn; };
  on('wgen', () => setKey(randomKey()));
  on('wimpb', async () => { try { await setKey(unhex($('wimp').value.trim(), 32)); } catch (e) { wmsg(e.message, true); } });
  on('wdemo', () => register('demo', null));
  on('wutxob', () => { const m = /^([0-9a-fA-F]{64}):(\d+)$/.exec($('wutxo').value.trim()); if (!m) return wmsg('Expected txid:vout', true); register('utxo', { txid: m[1].toLowerCase(), vout: Number(m[2]) }); });
  on('wforget', () => { if (confirm('Delete the key from this browser? Back it up first.')) { store.del(KEY_STORE); st.key = st.owner = st.address = st.account = null; reconnectWs(); renderAll(); } });
}
const wmsg = (t, err) => { const m = $('wmsg'); if (m) { m.textContent = t; m.className = 'msg ' + (err ? 'err' : 'ok'); } };
async function register(kind, outpoint) {
  try {
    wmsg('Requesting allocation draft…');
    const d = await api('/api/register/draft', { owner: st.owner, kind, outpoint });
    const sig = await bip340Sign(unhex(d.allocation_digest), st.key);
    const r = await api('/api/register', { draft_id: d.draft_id, owner_signature: hex(sig) });
    st.account = r.account; renderAll(); wmsg('Registered.');
  } catch (e) { wmsg(e.message, true); }
}

// ---------- data ----------
async function refreshAccount() {
  if (!st.owner) return;
  try { st.account = await api('/api/account/' + st.owner); } catch (e) { if (e.status === 404) st.account = null; else return; }
  autoSign();
}
async function refreshBatches() {
  try { for (const b of await api('/api/explorer/batches?limit=30')) st.batches.set(b.seq, b); } catch { /* explorer optional */ }
}
async function pollAll() {
  try {
    const [status, book, trades] = await Promise.all([api('/api/status'), api('/api/book?depth=25'), api('/api/trades?limit=60')]);
    setMark(status.mark); st.book = book; st.trades = trades; st.router = status.router;
    await refreshAccount(); renderAll(); setConn(st.wsOk ? 'live (ws)' : 'polling', st.wsOk ? 'ok' : 'warn');
  } catch (e) { setConn('offline', 'bad'); }
}
function setMark(m) { if (!m) return; st.mark = m; st.markAt = Date.now() - (m.age_s || 0) * 1000; }
function setConn(t, cls) { const c = $('conn'); c.textContent = t; c.className = 'badge ' + cls; }

function reconnectWs() {
  try { st.ws?.close(); } catch { /* closed */ }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  let ws; try { ws = new WebSocket(`${proto}//${location.host}/api/stream${st.owner ? '?owner=' + st.owner : ''}`); } catch { return; }
  st.ws = ws;
  ws.onopen = () => { st.wsOk = true; setConn('live (ws)', 'ok'); };
  ws.onclose = () => { if (st.ws === ws) { st.wsOk = false; setConn('polling', 'warn'); setTimeout(() => st.ws === ws && reconnectWs(), 5000); } };
  ws.onerror = () => { st.wsOk = false; };
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === 'mark') { setMark(m.mark || m); renderTop(); }
    else if (m.type === 'book') { st.book = { bids: m.bids || [], asks: m.asks || [] }; if (m.mark) setMark(m.mark); renderBook(); }
    else if (m.type === 'trade') { st.trades.unshift(m.trade || m); st.trades.length = Math.min(st.trades.length, 60); renderTrades(); }
    else if (m.type === 'batch') { const b = m.batch || m; if (b.seq !== undefined) st.batches.set(b.seq, { ...st.batches.get(b.seq), ...b }); refreshAccount().then(renderBottom); }
    else if (m.type === 'account') { if (m.account && m.account.owner === st.owner) { st.account = m.account; autoSign(); renderBottom(); renderWallet(); renderEst(); } else if (!m.account) refreshAccount().then(renderBottom); }
  };
}

// ---------- render ----------
function renderTop() {
  const m = st.mark; $('mark').textContent = m ? fmt(m.price_usd) : '—';
  const f = $('frost'); f.href = m ? `explorer.html#/packet/${m.seq}` : 'explorer.html#/packet';
  f.className = 'badge ' + (m && m.verified ? 'ok' : 'warn'); f.textContent = m && m.verified ? 'FROST 3-of-5 signed ✓' : 'FROST 3-of-5 unverified';
  f.title = m ? 'packet #' + m.seq + ' ' + short(m.packet_digest) : '';
  const r = st.router; $('routerinfo').textContent = r ? `${r.resting} / #${r.batch_sequence}` : '—';
  for (const b of document.querySelectorAll('#toptier button, #ftier button')) b.classList.toggle('on', b.dataset.tier === st.tier);
  tickAge();
}
function tickAge() { const el = $('markage'); if (!st.mark) return; const s = (Date.now() - st.markAt) / 1000; el.textContent = s.toFixed(1) + 's'; el.className = 'mono ' + (s > 10 ? 'short' : s > 6 ? 'amber' : 'long'); }
setInterval(tickAge, 250);

function renderBook() {
  const lv = 12, asks = st.book.asks.slice(0, lv), bids = st.book.bids.slice(0, lv);
  const cum = (rows) => { let c = 0; return rows.map((r) => (c += r[1])); };
  const ca = cum(asks), cb = cum(bids), mx = Math.max(1, ca.at(-1) || 0, cb.at(-1) || 0);
  const row = (cls, r, c) => `<div class="row ${cls}" data-p="${r[0]}"><span class="${cls === 'ask' ? 'short' : 'long'}">${fmt(r[0])}</span><span>${fmt(r[1])}</span><span>${fmt(c)}</span><i class="bar" style="width:${(c / mx * 100).toFixed(1)}%"></i></div>`;
  $('asks').innerHTML = asks.map((r, i) => row('ask', r, ca[i])).reverse().join('');
  $('bids').innerHTML = bids.map((r, i) => row('bid', r, cb[i])).join('');
  const a = asks[0]?.[0], b = bids[0]?.[0];
  $('spread').innerHTML = a && b ? `<span>Spread ${fmt(a - b)} (${((a - b) / a * 1e4).toFixed(1)} bps)</span><span class="muted">mark ${fmt(st.mark?.price_usd)}</span>` : '<span class="muted">no book</span>';
  renderEst();
}
function renderTrades() {
  $('trades').innerHTML = st.trades.length ? st.trades.slice(0, 40).map((t) => `<div class="row"><span class="${t.taker_side === 'long' ? 'long' : 'short'}"><a href="explorer.html#/fill/${esc(t.id)}">${fmt(t.price_usd)}</a></span><span>${fmt(t.qty_usd)}</span><span class="muted">${new Date(t.ts_us / 1000).toLocaleTimeString('en-GB')}</span></div>`).join('') : '<div class="empty">No trades yet</div>';
}
const bps = (tier) => st.template?.tariff;
function estimate() {
  const t = st.template; if (!t) return null;
  const size = Number(($('size') || {}).value) || 0, lev = Number($('lev').value);
  const book = st.book, bestAsk = book.asks[0]?.[0], bestBid = book.bids[0]?.[0];
  let price = Number($('price').value);
  if (st.otype === 'market') price = (st.side === 'long' ? book.asks : book.bids).find((r) => r[1] >= size)?.[0] ?? null;
  if (!price) return { size, lev, price: null };
  const ti = TIERS.indexOf(st.tier), ppm = (st.otype === 'market' ? t.tariff.taker_ppm : t.tariff.maker_ppm)[ti];
  const notionalSats = size / price * 1e8, fee = Math.ceil(notionalSats * ppm / 1e6), margin = Math.ceil(notionalSats / lev);
  return { size, lev, price, ppm, fee, margin, notionalSats, bestAsk, bestBid };
}
function renderEst() {
  if (!$('est')) return; const e = estimate(); const free = st.account?.balance?.free;
  $('est').innerHTML = !e || !e.price ? `<div class="muted">${st.otype === 'market' ? 'No single resting quote is large enough for this size (fill-or-kill)' : 'Enter a price'}</div>` :
    `<div><span>${st.otype === 'market' ? 'Fills at' : 'Limit'}</span><span>${fmt(e.price)} USD</span></div><div><span>Notional</span><span>${fmt(e.notionalSats)} sats</span></div><div><span>Margin (${e.lev}x)</span><span>${fmt(e.margin)} sats</span></div><div><span>Fee (${st.otype === 'market' ? 'taker' : 'maker'} ${e.ppm} ppm, ${st.tier})</span><span>${fmt(e.fee)} sats</span></div>${free !== undefined ? `<div><span>Free collateral</span><span class="${free < e.margin + e.fee ? 'short' : ''}">${fmt(free)} sats</span></div>` : ''}`;
  $('go').className = 'go ' + st.side; $('go').textContent = (st.side === 'long' ? 'Buy / Long' : 'Sell / Short') + (st.otype === 'market' ? ' (market, FOK)' : ' (limit)');
  $('go').disabled = !st.account || !e || !e.price || !e.size;
  $('pricewrap').style.display = st.otype === 'market' ? 'none' : '';
  $('levv').textContent = e ? e.lev + 'x' : '';
}

function bottomTable(cols, rows) {
  return rows.length ? `<table><thead><tr>${cols.map((c) => `<th>${c}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>` : '<div class="empty">Nothing here yet</div>';
}
function renderBottom() {
  for (const b of document.querySelectorAll('#btabs button')) b.classList.toggle('on', b.dataset.t === st.btab);
  const a = st.account, p = $('bpane');
  if (!a) { p.innerHTML = '<div class="empty">Generate or import a key and register an account to trade (wallet panel, right).</div>'; return; }
  const mark = st.mark?.price_usd;
  if (st.btab === 'positions') {
    const pos = a.position || {}, un = pos.net_usd && pos.avg_entry_usd && mark ? Math.round(pos.net_usd * (1 / pos.avg_entry_usd - 1 / mark) * 1e8) : (pos.unrealized_sats || 0);
    const b = a.balance || {};
    const rz = b.realized_pnl || 0, unset = pos.unsettled_usd || 0;
    p.innerHTML = bottomTable(['Market', 'Net USD', 'Avg entry', 'Mark', 'Unrealized (sats)', 'Realized (sats)', 'Cap', 'Free', 'Resting', 'Committed', 'Fees paid'],
      [`<tr><td>${MARKET}</td><td class="${pos.net_usd > 0 ? 'long' : pos.net_usd < 0 ? 'short' : ''}">${fmt(pos.net_usd)}${unset ? ` <span class="muted" title="fills whose batch has not committed">(${unset > 0 ? '+' : ''}${fmt(unset)} unsettled)</span>` : ''}</td><td>${fmt(pos.avg_entry_usd, 2)}</td><td>${fmt(mark)}</td><td class="${un >= 0 ? 'long' : 'short'}">${fmt(un)}</td><td class="${rz >= 0 ? 'long' : 'short'}">${fmt(rz)}</td><td>${fmt(b.cap)}</td><td>${fmt(b.free)}</td><td>${fmt(b.resting)}</td><td>${fmt(b.committed)}</td><td>${fmt(b.paid_fees)}</td></tr>`]);
  } else if (st.btab === 'orders') {
    p.innerHTML = bottomTable(['Order', 'Side', 'Tier', 'Size USD', 'Limit', 'Lev', ''], (a.open_orders || []).map((o) =>
      `<tr><td title="${esc(o.id)}">${esc(short(o.id))}</td><td class="${o.side === 'long' ? 'long' : 'short'}">${esc(o.side)}</td><td>${esc(o.tier)}</td><td>${fmt(o.quantity)}</td><td>${fmt(o.limit_usd)}</td><td>${(o.leverage_bps || 0) / 1e4}x</td><td><button class="btn sm" data-cancel="${esc(o.id)}">Cancel</button></td></tr>`));
  } else if (st.btab === 'fills') {
    p.innerHTML = bottomTable(['Fill (explorer)', 'Time', 'Side', 'Role', 'Price', 'Size USD', 'Fee sats', 'Batch'], (a.fills || []).map((f) =>
      `<tr><td><a href="explorer.html#/fill/${esc(f.id)}">${esc(short(f.id))}</a></td><td>${new Date((f.ts_us || 0) / 1000).toLocaleTimeString('en-GB')}</td><td class="${f.side === 'long' ? 'long' : 'short'}">${esc(f.side)}</td><td>${esc(f.role)}</td><td>${fmt(f.price_usd)}</td><td>${fmt(f.qty_usd ?? f.quantity)}</td><td>${fmt(f.fee_sats)}</td><td>${f.batch_seq != null ? `<a href="explorer.html#/batch/${f.batch_seq}">#${f.batch_seq}</a>` : ''}</td></tr>`));
  } else {
    const pend = a.pending_signatures || [];
    const mine = [...new Set((a.fills || []).map((f) => f.batch_seq).filter((x) => x != null))].slice(0, 20);
    p.innerHTML = `<div style="padding:6px 10px" class="muted">Fills seal into 100 ms batches: sealed &rarr; prepared &rarr; committed. Signatures below are produced automatically by your browser key.</div>` +
      bottomTable(['Batch', 'Phase', 'Fills'], mine.map((s) => { const b = st.batches.get(s) || {}; const ph = b.phase || (a.fills.find((f) => f.batch_seq === s) || {}).batch_phase || 'sealed'; return `<tr><td><a href="explorer.html#/batch/${s}">#${s}</a></td><td><span class="phase ${esc(ph)}">${esc(ph)}</span></td><td>${b.fills ?? ''}</td></tr>`; })) +
      bottomTable(['Pending signature', 'Kind', 'Message', 'Status'], pend.map((x) => `<tr><td>${esc(x.id)}</td><td>${esc(x.kind)}</td><td>${esc(short(x.message))}</td><td class="amber">${st.signed.has(x.id) ? 'signed, awaiting venue' : 'auto-signing…'}</td></tr>`));
  }
}
function renderAll() { renderTop(); renderBook(); renderTrades(); renderBottom(); renderWallet(); renderEst(); }

// ---------- signing / orders ----------
async function autoSign() {
  const a = st.account; if (!a || !st.key) return;
  const todo = (a.pending_signatures || []).filter((x) => !st.signing.has(x.id) && !st.signed.has(x.id));
  if (!todo.length) return;
  for (const x of todo) st.signing.add(x.id);
  try {
    const items = [];
    for (const x of todo) items.push({ id: x.id, signature: hex(await bip340Sign(unhex(x.message, 32), st.key)) });
    await api('/api/signatures', { owner: st.owner, items });
    for (const x of todo) st.signed.add(x.id);
    refreshAccount().then(renderBottom);
  } catch (e) { console.warn('auto-sign failed', e); }
  finally { for (const x of todo) st.signing.delete(x.id); }
}
async function entitlementDigest(tier) {
  if (tier === 'standard') return null;
  const k = st.owner + tier, c = st.ents.get(k);
  if (c && c.until > Date.now()) return c.digest;
  const r = await api('/api/entitlement', { owner: st.owner, tier });
  const digest = r.entitlement_digest || r.digest || r.entitlement?.digest;
  if (!digest) throw new Error('entitlement response carried no digest');
  st.ents.set(k, { digest, until: Date.now() + 3600e3 }); return digest;
}
function baseIntent(fields) {
  const t = st.template, a = st.account; st.lastSeq = Math.max(st.lastSeq + 1, Date.now());
  return { owner: st.owner, channel: { txid: a.outpoint.txid, vout: a.outpoint.vout }, sequence: st.lastSeq,
    expires_us: (Date.now() + 120e3) * 1000, action: 'post', side: 'long', tier: st.tier, quantity: 0, limit_usd: 0, leverage_bps: 10000,
    max_fee_ppm: 0, max_fee_sats: 0, max_mark_age_us: t.max_mark_age_us, early_window_opt_in: false, cancel_target: '0'.repeat(64), ...fields };
}
async function submit(intent) {
  const digest = await entitlementDigest(intent.tier);
  const { intent: signed } = await signIntent(intent, st.template, st.key, digest);
  return api('/api/intents', { intent: signed });
}
async function placeOrder() {
  const msg = $('omsg'); msg.className = 'msg'; msg.textContent = 'Signing…';
  try {
    const e = estimate(); if (!e || !e.price) throw new Error('No executable price');
    const intent = baseIntent({ action: st.otype === 'market' ? 'take' : 'post', side: st.side, quantity: e.size, limit_usd: e.price,
      leverage_bps: e.lev * 10000, max_fee_ppm: e.ppm, max_fee_sats: Math.ceil(e.fee * 1.2) + 1 });
    const r = await submit(intent);
    msg.className = 'msg ok'; msg.textContent = (st.otype === 'market' ? 'Taken' : 'Posted') + ' ' + short(r.id);
    refreshAccount().then(renderBottom);
  } catch (err) { msg.className = 'msg err'; msg.textContent = err.message; }
}
async function cancelOrder(id) {
  const o = (st.account.open_orders || []).find((x) => x.id === id); if (!o) return;
  try { await submit(baseIntent({ action: 'cancel', side: o.side, tier: o.tier, quantity: o.quantity, limit_usd: o.limit_usd, leverage_bps: o.leverage_bps, cancel_target: id })); await refreshAccount(); renderBottom(); }
  catch (err) { $('omsg').className = 'msg err'; $('omsg').textContent = 'Cancel: ' + err.message; }
}

// ---------- wiring ----------
function setTier(t) { st.tier = t; store.set('shz.venue.tier', t); renderTop(); renderEst(); }
for (const b of document.querySelectorAll('#toptier button, #ftier button')) b.onclick = () => setTier(b.dataset.tier);
$('otabs').onclick = (e) => { const t = e.target.dataset?.t; if (!t) return; st.otype = t; for (const b of $('otabs').children) b.classList.toggle('on', b.dataset.t === t); renderEst(); };
$('sides').onclick = (e) => { const s = e.target.dataset?.s; if (!s) return; st.side = s; for (const b of $('sides').children) b.classList.toggle('on', b.dataset.s === s); renderEst(); };
$('btabs').onclick = (e) => { const t = e.target.dataset?.t; if (!t) return; st.btab = t; renderBottom(); };
$('bpane').onclick = (e) => { const id = e.target.dataset?.cancel; if (id) cancelOrder(id); };
for (const id of ['size', 'price', 'lev']) $(id).oninput = renderEst;
$('go').onclick = placeOrder;
$('asks').onclick = $('bids').onclick = (e) => { const r = e.target.closest('.row'); if (r) { $('price').value = r.dataset.p; st.otype = 'limit'; for (const b of $('otabs').children) b.classList.toggle('on', b.dataset.t === 'limit'); renderEst(); } };
$('market').onchange = () => {};

async function init() {
  const saved = store.get('shz.venue.tier'); if (TIERS.includes(saved)) st.tier = saved;
  const origin = location.origin;
  $('chart').src = `vendor/bitcornwisdom/embed.html?instrument=${MARKET}&interval=1m&preferred=relay:1&relay=${encodeURIComponent(origin)}`;
  try { st.template = await api('/api/template'); } catch (e) { setConn('no server', 'bad'); }
  const k = store.get(KEY_STORE);
  if (k && /^[0-9a-f]{64}$/.test(k)) { try { await setKey(unhex(k)); } catch { store.del(KEY_STORE); } }
  await pollAll(); refreshBatches(); reconnectWs(); renderAll();
  if (st.template && !$('price').value && st.book.bids[0]) $('price').value = st.book.bids[0][0];
  setInterval(() => { if (!st.wsOk) pollAll(); else api('/api/status').then((s) => { setMark(s.mark); st.router = s.router; renderTop(); }).catch(() => {}); }, 1500);
  setInterval(refreshBatches, 5000);
}
init();
window.__shz = st; // debugging handle
