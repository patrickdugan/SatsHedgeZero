// SHZ venue trading page. No frameworks. TESTNET ONLY: keys live in localStorage.
import { hex, unhex, pubkey, p2trAddress, bip340Sign, signIntent, randomKey } from './crypto.js';
import { planTakes, describe as riskText } from './liquidate.js';
import { connectNostr, lnurlStart, lnurlFinish, nostrAvailable, weblnInfo } from './wallet.js';
import { qrSvg } from './qr.js';
import { applyUiMode, chartSrc, renderSettings } from './settings.js';
import * as Opt from './options.js';
import * as Spot from './spot.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (n, d = 0) => (n === null || n === undefined || Number.isNaN(n) ? '—' : Number(n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d }));
const short = (h) => (h ? h.slice(0, 8) + '…' + h.slice(-4) : '');
const settling = (e) => e && e.status === 409 && /still settling/i.test(e.message || '');
const SETTLING_NOTE = 'Your previous fill is still settling. Try again in a moment.';
const KEY_STORE = 'shz.venue.key';
const WALLET_STORE = 'shz.venue.wallet'; // {kind, wallet, expires_us}: which wallet authorized the stored trading key
const TRADE_KEY_PREFIX = 'shz.venue.trade.'; // per-wallet trading key, kept across disconnects
const TIERS = ['standard', 'intermediate', 'premium'];
const MARKET = 'SHZ-BTCUSD-INV';

const st = { template: null, mark: null, markAt: 0, book: { bids: [], asks: [] }, trades: [], account: null, batches: new Map(),
  key: null, wallet: null, owner: null, address: null, tier: 'standard', otype: 'limit', side: 'long', btab: 'positions', lastSeq: 0,
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
async function setKey(bytes, wallet = null) {
  st.key = bytes; st.owner = hex(pubkey(bytes)); st.address = await p2trAddress(unhex(st.owner), 'tb');
  st.wallet = wallet; if (wallet) store.set(WALLET_STORE, JSON.stringify(wallet)); else store.del(WALLET_STORE);
  store.set(KEY_STORE, hex(bytes)); st.account = null; st.signed.clear(); await refreshAccount(); reconnectWs(); renderAll();
}
function renderWallet() {
  const w = $('wallet'), a = st.account;
  let h = st.wallet
    ? `<div class="warn-box">TESTNET ONLY. ${esc(WALLET_NAMES[st.wallet.kind])} wallet ${esc(short(st.wallet.wallet))} authorized this browser's trading key${walletExpired() ? ' &mdash; <b>authorization expired</b>' : ' until ' + esc(new Date(st.wallet.expires_us / 1000).toLocaleString('en-GB'))}. The trading key itself is stored unencrypted in localStorage.</div>${walletExpired() ? '<button class="btn" id="wreconnect">Reconnect wallet</button>' : ''}`
    : '<div class="warn-box">TESTNET ONLY. The key is stored unencrypted in this browser\'s localStorage. Never import a key that holds real coins.</div>';
  if (!st.owner) {
    h += '<button class="btn" id="wopen">Connect wallet</button><button class="btn" id="wgen">Generate local testnet key</button><label class="f">Or import 32-byte hex key<input type="text" id="wimp" placeholder="64 hex chars" autocomplete="off" spellcheck="false"></label><button class="btn" id="wimpb">Import</button>';
  } else {
    h += `<label class="f">${st.wallet ? 'Trading key (account owner, x-only)' : 'Owner pubkey (x-only)'}<div class="addr" id="wpk">${esc(st.owner)}</div></label>
      <label class="f">Funding address (testnet4 P2TR, key-path, no script tree)<div class="addr" id="waddr">${esc(st.address)}</div></label>`;
    if (a) h += `<div class="est"><div><span>Account</span><span>${esc(a.label || 'registered')}</span></div><div><span>Outpoint</span><span>${esc(short(a.outpoint?.txid))}:${esc(a.outpoint?.vout)}</span></div><div><span>Collateral cap</span><span>${fmt(a.balance?.cap)} sats</span></div><div><span>Free</span><span>${fmt(a.balance?.free)} sats</span></div></div>`;
    else h += `<div class="muted">Not registered. Demo credit is synthetic (no coins). For a utxo account, fund the address above on testnet4, then enter the output.</div>
      <button class="btn" id="wdemo">Register demo account (TESTNET DEMO CREDIT)</button>
      <label class="f">utxo outpoint txid:vout<input type="text" id="wutxo" placeholder="txid:vout" autocomplete="off" spellcheck="false"></label><button class="btn" id="wutxob">Register utxo account</button>`;
    h += st.wallet ? '<button class="btn sm" id="wdisc">Disconnect wallet</button>' : '<button class="btn sm" id="wforget">Forget key</button>';
  }
  h += '<div class="msg" id="wmsg"></div>';
  w.innerHTML = h;
  const on = (id, fn) => { const e = $(id); if (e) e.onclick = fn; };
  on('wgen', () => setKey(randomKey()));
  on('wopen', () => openModal()); on('wreconnect', () => openModal()); on('wdisc', disconnectWallet);
  on('wimpb', async () => { try { await setKey(unhex($('wimp').value.trim(), 32)); } catch (e) { wmsg(e.message, true); } });
  on('wdemo', () => register('demo', null));
  on('wutxob', () => { const m = /^([0-9a-fA-F]{64}):(\d+)$/.exec($('wutxo').value.trim()); if (!m) return wmsg('Expected txid:vout', true); register('utxo', { txid: m[1].toLowerCase(), vout: Number(m[2]) }); });
  on('wforget', () => { if (confirm('Delete the key from this browser? Back it up first.')) { store.del(KEY_STORE); store.del(WALLET_STORE); st.key = st.owner = st.address = st.account = st.wallet = null; reconnectWs(); renderAll(); } });
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
    else if (m.type === 'risk') { if (m.owner === st.owner) refreshAccount().then(() => { renderBottom(); maybeLiquidate(); }); }
    else if (String(m.type).startsWith('option')) Opt.onEvent(m);
    else if (String(m.type).startsWith('spot')) Spot.onEvent(m);
    else if (m.type === 'account') { if (m.account && m.account.owner === st.owner) { st.account = m.account; autoSign(); maybeLiquidate(); renderBottom(); renderWallet(); renderEst(); } else if (!m.account) refreshAccount().then(renderBottom); }
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
    const r = pos.risk || {}, rt = riskText(r), auto = store.get(AUTO_LIQ) !== 'off';
    const banner = rt ? `<div class="risk-box ${rt.level}">${esc(rt.text)}${r.reduce_only ? `<label class="autoliq"><input type="checkbox" id="autoliq" ${auto ? 'checked' : ''}> Auto-liquidate with this browser's key</label>` : ''}${st.liqLog ? `<div class="mono">${esc(st.liqLog)}</div>` : ''}</div>` : '';
    const ratio = r.margin_bps != null ? (r.margin_bps / 100).toFixed(2) + '%' : '-';
    p.innerHTML = banner + bottomTable(['Market', 'Net USD', 'Avg entry', 'Mark', 'Margin', 'Liq. price', 'Risk', 'Unrealized (sats)', 'Realized (sats)', 'Cap', 'Free', 'Resting', 'Committed', 'Fees paid'],
      [`<tr><td>${MARKET}</td><td class="${pos.net_usd > 0 ? 'long' : pos.net_usd < 0 ? 'short' : ''}">${fmt(pos.net_usd)}${unset ? ` <span class="muted" title="fills whose batch has not committed">(${unset > 0 ? '+' : ''}${fmt(unset)} unsettled)</span>` : ''}</td><td>${fmt(pos.avg_entry_usd, 2)}</td><td>${fmt(mark)}</td><td>${ratio}</td><td title="bankruptcy ${fmt(r.bankruptcy_price_usd)}">${fmt(r.liquidation_price_usd)}</td><td><span class="risk ${esc(r.state || 'flat')}">${esc(r.state || 'flat')}</span></td><td class="${un >= 0 ? 'long' : 'short'}">${fmt(un)}</td><td class="${rz >= 0 ? 'long' : 'short'}">${fmt(rz)}</td><td>${fmt(b.cap)}</td><td>${fmt(b.free)}</td><td>${fmt(b.resting)}</td><td>${fmt(b.committed)}</td><td>${fmt(b.paid_fees)}</td></tr>`])
      + (pos.deferred_claim_sats > 0 ? `<div class="warn-box" style="margin:6px 10px">Deferred claim: ${fmt(pos.deferred_claim_sats)} sats. The clearing pool could not pay this account's last settlement in full; the amount stays owed and is paid as the pool refills (batch pages show the waterfall).</div>` : '');
  } else if (st.btab === 'orders') {
    p.innerHTML = bottomTable(['Order', 'Side', 'Tier', 'Size USD', 'Limit', 'Lev', ''], (a.open_orders || []).map((o) =>
      `<tr><td title="${esc(o.id)}">${esc(short(o.id))}</td><td class="${o.side === 'long' ? 'long' : 'short'}">${esc(o.side)}</td><td>${esc(o.tier)}</td><td>${fmt(o.quantity)}</td><td>${fmt(o.limit_usd)}</td><td>${(o.leverage_bps || 0) / 1e4}x</td><td><button class="btn sm" data-cancel="${esc(o.id)}">Cancel</button></td></tr>`));
  } else if (st.btab === 'options') {
    Opt.renderBottom(p, bottomTable);
  } else if (st.btab === 'spot') {
    Spot.renderBottom(p, bottomTable);
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
function renderAll() { renderTop(); renderBook(); renderTrades(); renderBottom(); renderWallet(); renderEst(); renderWalletBtn(); }

// ---------- wallet connect ----------
const WALLET_NAMES = { nostr: 'Nostr', lnurl: 'Lightning (LNURL-auth)' };
const walletExpired = () => !!st.wallet && st.wallet.expires_us / 1000 <= Date.now();
function renderWalletBtn() {
  const b = $('wbtn'); if (!b) return;
  b.textContent = st.wallet ? `${st.wallet.kind === 'nostr' ? 'Nostr' : 'LN'} ${short(st.wallet.wallet)}${walletExpired() ? ' (expired)' : ''}` : st.owner ? 'Local key ' + short(st.owner) : 'Connect wallet';
  b.title = st.wallet ? 'Connected wallet ' + st.wallet.wallet : '';
}
let lnurlAbort = null, modalView = 'list';
function openModal(view = st.wallet && !walletExpired() ? 'connected' : 'list') { $('wmodal').hidden = false; renderModal(view); }
function closeModal() { if (lnurlAbort) lnurlAbort.abort(); lnurlAbort = null; $('wmodal').hidden = true; }
function tradeKeyFor(slot) {
  const k = store.get(TRADE_KEY_PREFIX + slot);
  if (k && /^[0-9a-f]{64}$/.test(k)) return unhex(k);
  const nk = randomKey(); store.set(TRADE_KEY_PREFIX + slot, hex(nk)); return nk;
}
async function finishConnect(r, tradeSecret) {
  await setKey(tradeSecret, { kind: r.kind, wallet: r.wallet, expires_us: r.expires_us });
  closeModal();
}
function renderModal(view) {
  if (lnurlAbort) { lnurlAbort.abort(); lnurlAbort = null; }
  modalView = view;
  const body = $('wmbody'), set = (h) => { body.innerHTML = h; };
  const err = (m) => `<div class="msg err">${esc(m)}</div>`;
  const back = '<button class="btn" id="mback">Back</button>';
  const wire = (id, fn) => { const e = $(id); if (e) e.onclick = fn; };
  if (view === 'list') {
    const hasNostr = nostrAvailable(window), hasWebln = !!window.webln;
    set(`<div class="mnote">Connecting proves you control a wallet key and authorizes a trading key in this browser. The wallet never sees your orders; the trading key signs them. Testnet only.</div>
      <button class="wopt" id="mnostr"><b>Browser extension (Nostr / Alby)</b><span>${hasNostr ? 'NIP-07 signer detected. The extension signs one authorization event.' : 'No NIP-07 extension detected. Install Alby or nos2x, then reload.'}</span></button>
      <button class="wopt" id="mln"><b>Lightning wallet (scan LNURL-auth QR)</b><span>Phoenix, Zeus, Breez, BlueWallet, Blixt, Alby mobile. Scan the QR code with the wallet.</span></button>
      <button class="wopt" id="mlocal"><b>Local testnet key</b><span>${st.owner && !st.wallet ? 'Keep using the key already in this browser.' : 'Generate a throwaway key stored in this browser. Testnet only.'}</span></button>
      ${hasWebln ? '<button class="wopt" id="mwebln"><b>WebLN wallet detected</b><span>Show its name. Identity display only.</span></button>' : ''}<div id="mweblninfo"></div>`);
    wire('mnostr', () => renderModal('nostr')); wire('mln', () => renderModal('lnurl'));
    wire('mlocal', async () => { if (!st.owner || st.wallet) await setKey(randomKey()); closeModal(); });
    wire('mwebln', async () => {
      $('mweblninfo').innerHTML = '<div class="mnote">Asking the wallet…</div>';
      const i = await weblnInfo(window);
      $('mweblninfo').innerHTML = !i ? err('WebLN wallet disappeared') : `<div class="est"><div><span>WebLN wallet</span><span>${esc(i.alias || 'unnamed')}</span></div>${i.pubkey ? `<div><span>Node key</span><span>${esc(short(i.pubkey))}</span></div>` : ''}</div>${i.error ? err(i.error) : ''}<div class="mnote">Identity display only. This venue has no Lightning backend (its channel adapter is simulated), so no invoices or payments are requested, and a WebLN node key proves nothing here. Use the Nostr or QR option to sign in.</div>`;
    });
  } else if (view === 'nostr') {
    set(`<div class="mnote">Your extension will ask you to sign one authorization event for this venue (a Nostr event, never a payment). Approve it to continue.</div><div id="mstate" class="msg">Waiting for the extension…</div>${back}`);
    wire('mback', () => renderModal('list'));
    (async () => {
      try {
        if (!nostrAvailable(window)) throw new Error('No NIP-07 extension found. Install Alby or nos2x and reload.');
        const pk = String(await window.nostr.getPublicKey()).toLowerCase();
        const tradeSecret = tradeKeyFor('nostr.' + pk);
        const r = await connectNostr({ api, nostr: window.nostr, tradeSecret });
        await finishConnect(r, tradeSecret);
      } catch (e) { if (modalView === 'nostr' && $('mstate')) $('mstate').outerHTML = err(e.message || String(e)); }
    })();
  } else if (view === 'lnurl') {
    set('<div id="mstate" class="msg">Requesting a login code…</div>' + back);
    const ctl = new AbortController(); lnurlAbort = ctl;
    wire('mback', () => renderModal('list'));
    (async () => {
      try {
        const tradeSecret = tradeKeyFor('lnurl');
        const s = await lnurlStart({ api, tradeSecret, origin: location.origin });
        if (ctl.signal.aborted) return;
        $('mstate').outerHTML = `<div class="qrbox">${qrSvg(s.lnurl, { ecc: 'L', px: 5 })}</div><div class="mnote">Scan with a Lightning wallet that supports LNURL-auth. On this phone? <a href="lightning:${esc(s.lnurl)}">Open in wallet</a>. The code expires in 5 minutes.</div><textarea readonly rows="3" aria-label="LNURL" onclick="this.select()">${esc(s.lnurl)}</textarea><div id="mstate" class="msg">Waiting for the wallet…</div>`;
        const r = await lnurlFinish({ api, tradeSecret, k1: s.k1, expiresUs: s.expires_us, signal: ctl.signal, onState: (x) => { const m = $('mstate'); if (m && x === 'authed') m.textContent = 'Wallet authenticated, finishing…'; } });
        await finishConnect(r, tradeSecret);
      } catch (e) {
        if (ctl.signal.aborted) return;
        let m = e.message || String(e);
        if (/bound to another wallet/.test(m)) { store.del(TRADE_KEY_PREFIX + 'lnurl'); m += ' A new trading key will be used; try again.'; }
        const el = $('mstate'); if (el) el.outerHTML = err(m);
      }
    })();
  } else {
    const w = st.wallet;
    set(`<div class="est"><div><span>Wallet</span><span>${esc(WALLET_NAMES[w.kind])}</span></div><div><span>Wallet key</span><span title="${esc(w.wallet)}">${esc(short(w.wallet))}</span></div><div><span>Trading key</span><span title="${esc(st.owner)}">${esc(short(st.owner))}</span></div><div><span>Authorized until</span><span>${esc(new Date(w.expires_us / 1000).toLocaleString('en-GB'))}</span></div></div>
      <button class="btn" id="mrenew">Renew authorization</button><button class="btn" id="mdisc">Disconnect</button>`);
    wire('mrenew', () => renderModal(w.kind === 'nostr' ? 'nostr' : 'lnurl')); wire('mdisc', () => { disconnectWallet(); closeModal(); });
  }
}
function disconnectWallet() {
  // The trading key stays in per-wallet storage so reconnecting restores the same account.
  store.del(KEY_STORE); store.del(WALLET_STORE); st.key = st.owner = st.address = st.account = st.wallet = null; st.signed.clear();
  reconnectWs(); renderAll();
}
$('wbtn').onclick = () => openModal();
$('wmclose').onclick = closeModal;
$('wmodal').onclick = (e) => { if (e.target === $('wmodal')) closeModal(); };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('wmodal').hidden) closeModal(); });
setInterval(() => { if (walletExpired()) { renderWallet(); renderWalletBtn(); } }, 30000);


// ---------- signing / orders ----------
async function autoSign() {
  const a = st.account; if (!a || !st.key || walletExpired()) return;
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
// Below maintenance the venue accepts only reducing orders and publishes a Dutch-auction plan;
// this browser executes it with its own key (the venue never signs for an account).
const AUTO_LIQ = 'shz.venue.autoliq';
let liqBusy = false, liqLast = 0;
async function maybeLiquidate() {
  const r = st.account?.position?.risk;
  if (!r?.reduce_only || !r.liquidation || !st.key || walletExpired() || liqBusy || store.get(AUTO_LIQ) === 'off') return;
  if (Date.now() - liqLast < 5000) return;
  liqBusy = true; liqLast = Date.now();
  try {
    // One take per round: the venue accepts one position-reducing take per account until it commits.
    const takes = planTakes(r, st.book, 1);
    if (!takes.length) { st.liqLog = `${new Date().toLocaleTimeString('en-GB')}: no bid or ask inside the auction limit ${r.liquidation.limit_usd} yet`; return; }
    // Standard tier: its taker fee is 0, and a closing take borrows its margin from the lots it
    // closes (router closing loan), so an account with no free margin can still liquidate.
    const ppm = st.template.tariff.taker_ppm[TIERS.indexOf('standard')];
    for (const k of takes) {
      const sats = Math.ceil(k.quantity * 1e8 / k.limit_usd);
      await submit(baseIntent({ action: 'take', tier: 'standard', side: k.side, quantity: k.quantity, limit_usd: k.limit_usd, leverage_bps: 100000,
        max_fee_ppm: ppm, max_fee_sats: Math.ceil(sats * ppm / 1e6 * 1.2) + 1 }));
    }
    st.liqLog = `${new Date().toLocaleTimeString('en-GB')}: submitted ${takes.length} reduce-only take(s), ${takes.reduce((s, x) => s + x.quantity, 0)} USD`;
  } catch (e) { st.liqLog = settling(e) ? 'previous fill still settling; the next liquidation take follows once it commits' : 'liquidation take refused: ' + e.message; }
  finally { liqBusy = false; renderBottom(); }
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
  } catch (err) { if (settling(err)) { msg.className = 'msg note'; msg.textContent = SETTLING_NOTE; } else { msg.className = 'msg err'; msg.textContent = err.message; } }
}
async function cancelOrder(id) {
  const o = (st.account.open_orders || []).find((x) => x.id === id); if (!o) return;
  try { await submit(baseIntent({ action: 'cancel', side: o.side, tier: o.tier, quantity: o.quantity, limit_usd: o.limit_usd, leverage_bps: o.leverage_bps, cancel_target: id })); await refreshAccount(); renderBottom(); }
  catch (err) { const calm = settling(err); $('omsg').className = calm ? 'msg note' : 'msg err'; $('omsg').textContent = calm ? SETTLING_NOTE : 'Cancel: ' + err.message; }
}

// ---------- wiring ----------
function setTier(t) { st.tier = t; store.set('shz.venue.tier', t); renderTop(); renderEst(); }
for (const b of document.querySelectorAll('#toptier button, #ftier button')) b.onclick = () => setTier(b.dataset.tier);
$('otabs').onclick = (e) => { const t = e.target.dataset?.t; if (!t) return; st.otype = t; for (const b of $('otabs').children) b.classList.toggle('on', b.dataset.t === t); renderEst(); };
$('sides').onclick = (e) => { const s = e.target.dataset?.s; if (!s) return; st.side = s; for (const b of $('sides').children) b.classList.toggle('on', b.dataset.s === s); renderEst(); };
$('btabs').onclick = (e) => { const t = e.target.dataset?.t; if (!t) return; st.btab = t; renderBottom(); };
$('bpane').onclick = (e) => { const id = e.target.dataset?.cancel; if (id) cancelOrder(id); const oid = e.target.dataset?.ocancel; if (oid) Opt.cancelOption(oid); const sid = e.target.dataset?.scancel; if (sid) Spot.cancel(sid); };
$('bpane').onchange = (e) => { if (e.target.id === 'autoliq') { store.set(AUTO_LIQ, e.target.checked ? 'on' : 'off'); if (e.target.checked) maybeLiquidate(); } };
for (const id of ['size', 'price', 'lev']) $(id).oninput = renderEst;
$('go').onclick = placeOrder;
$('asks').onclick = $('bids').onclick = (e) => { const r = e.target.closest('.row'); if (r) { $('price').value = r.dataset.p; st.otype = 'limit'; for (const b of $('otabs').children) b.classList.toggle('on', b.dataset.t === 'limit'); renderEst(); } };
$('market').onchange = () => {};

async function init() {
  const saved = store.get('shz.venue.tier'); if (TIERS.includes(saved)) st.tier = saved;
  const origin = location.origin;
  $('chart').src = chartSrc(MARKET, origin);
  try { st.template = await api('/api/template'); } catch (e) { setConn('no server', 'bad'); }
  const k = store.get(KEY_STORE);
  if (k && /^[0-9a-f]{64}$/.test(k)) {
    let w = null; try { w = JSON.parse(store.get(WALLET_STORE) || 'null'); } catch { /* corrupt */ }
    if (w && !(w.kind in WALLET_NAMES && /^[0-9a-f]{64,66}$/.test(w.wallet) && Number.isFinite(w.expires_us))) w = null;
    try { await setKey(unhex(k), w); } catch { store.del(KEY_STORE); }
  }
  await pollAll(); refreshBatches(); reconnectWs(); renderAll();
  const optOn = await Opt.init({ api, st, refreshAccount, renderBottom });
  // Spot rides on the options desk: its view joins the product switch when the venue runs --spot.
  if (optOn && await Spot.init({ api, st, refreshAccount, renderBottom })) {
    Opt.setView(Opt.savedView() === 'spot' ? 'spot' : Opt.savedView() === 'options' ? 'options' : 'perps', { spot: Spot.shown });
    $('spotbook').onclick = (e) => { const r = e.target.closest('.row[data-sp]'); if (r) Spot.pickPrice(r.dataset.sp); };
  }
  if (st.template && !$('price').value && st.book.bids[0]) $('price').value = st.book.bids[0][0];
  setInterval(() => { if (!st.wsOk) pollAll(); else api('/api/status').then((s) => { setMark(s.mark); st.router = s.router; renderTop(); }).catch(() => {}); }, 1500);
  setInterval(refreshBatches, 5000);
}
applyUiMode();
const openSettings = () => { $('smodal').hidden = false; renderSettings($('sbody'), () => { $('chart').src = chartSrc(MARKET, location.origin); Spot.reloadChart(); }); };
$('sbtn').onclick = openSettings;
$('smclose').onclick = () => { $('smodal').hidden = true; };
$('smodal').onclick = (e) => { if (e.target === $('smodal')) $('smodal').hidden = true; };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('smodal').hidden = true; });
init();
window.__shz = st; // debugging handle
