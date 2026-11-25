// SHZ plumbing explorer: hash-routed. #/packets #/packet/<seq> #/fill/<id> #/batches #/batch/<seq> #/accounts #/journal #/dlc
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (n) => (n === null || n === undefined ? '—' : Number(n).toLocaleString('en-US'));
const short = (h) => (h && h.length > 16 ? h.slice(0, 10) + '…' + h.slice(-6) : h || '');
const time = (us) => (us ? new Date(us / 1000).toISOString().replace('T', ' ').slice(0, 23) + 'Z' : '—');
async function get(p) { const r = await fetch(p, { cache: 'no-store' }); const j = await r.json().catch(() => null); if (!r.ok) throw new Error((j && j.error) || 'HTTP ' + r.status); return j; }
const list = (x, keys) => (Array.isArray(x) ? x : keys.map((k) => x?.[k]).find(Array.isArray) || []);
const verified = (v) => `<span class="badge ${v ? 'ok' : 'bad'}">${v ? 'verified' : 'UNVERIFIED'}</span>`;
const hl = (cls, href, txt) => `<a class="mono" href="${href}" title="${esc(txt)}">${esc(short(txt))}</a>`;
const kv = (rows) => `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v ?? '—'}</dd>`).join('')}</dl>`;
const card = (title, body) => `<section class="card"><h3>${esc(title)}</h3>${body}</section>`;
const raw = (o) => `<details><summary>raw JSON</summary><pre>${esc(JSON.stringify(o, null, 2))}</pre></details>`;
const table = (cols, rows) => rows.length ? `<table><thead><tr>${cols.map((c) => `<th>${c}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>` : '<div class="empty">Nothing here</div>';
const phase = (p) => `<span class="phase ${esc(p)}">${esc(p)}</span>`;
const acctLink = (o) => `<a class="mono" href="#/accounts" title="${esc(o)}">${esc(short(o))}</a>`;

const NAV = [['packets', 'Oracle packets'], ['batches', 'Batches'], ['accounts', 'Accounts'], ['journal', 'Journal'], ['dlc', 'DLC events']];

const routes = {
  async packets() {
    const rows = list(await get('/api/explorer/packets?limit=100'), ['packets']);
    return card('Oracle packets ingested by the venue', table(['Seq', 'Slot', 'Status', 'Median USD', 'Digest', 'Signers', 'Verified'],
      rows.map((p) => `<tr><td><a href="#/packet/${p.seq}">#${p.seq}</a></td><td>${time(p.slot_us)}</td><td>${esc(p.status)}</td><td>${fmt(p.median_usd ?? p.price_usd)}</td><td>${esc(short(p.digest))}</td><td>${esc(Array.isArray(p.signers) ? p.signers.length + ' of 5' : p.signers)}</td><td>${verified(p.verified)}</td></tr>`)));
  },
  async packet(seq) {
    const rows = list(await get('/api/explorer/packets?limit=500'), ['packets']);
    const p = rows.find((x) => String(x.seq) === String(seq)); if (!p) throw new Error('packet #' + seq + ' not in the last 500');
    const fills = list(await get('/api/trades?limit=500').catch(() => []), []).filter((t) => t.packet_seq === p.seq);
    return card('Packet #' + p.seq + ' ' + '', kv([['verified', verified(p.verified)], ['status', esc(p.status)], ['slot', time(p.slot_us)], ['median USD', fmt(p.median_usd ?? p.price_usd)],
      ['digest', esc(p.digest)], ['signers', esc(JSON.stringify(p.signers))], ['threshold', esc(p.threshold || '3-of-5 FROST group signature')]])) +
      card('Fills bound to this packet (' + fills.length + ' of the latest 500 trades)', table(['Fill', 'Price', 'Size', 'Batch'], fills.map((t) => `<tr><td><a href="#/fill/${esc(t.id)}">${esc(short(t.id))}</a></td><td>${fmt(t.price_usd)}</td><td>${fmt(t.qty_usd)}</td><td>${t.batch_seq != null ? `<a href="#/batch/${t.batch_seq}">#${t.batch_seq}</a>` : ''}</td></tr>`))) + card('Raw', raw(p));
  },
  async fill(id) {
    const f = await get('/api/explorer/fill/' + encodeURIComponent(id));
    const pk = f.packet || {}, b = f.batch || {}, bind = f.binding || {}, fees = f.fees || {}, t = f.trade || {}, m = f.margins || {};
    const accts = b.accounts || [], acks = b.acks || [];
    const signedAcks = acks.filter((a) => a.owner_signed && a.peer_signature && a.monitor_signature).length;
    const allAp = accts.length && accts.every((a) => a.approved), allAck = acks.length && signedAcks === acks.length;
    const node = (cls, title, body) => `<div class="node ${cls}"><b>${title}</b>${body}</div>`;
    const chain = `<div class="chain">
      ${node(pk.verified ? 'ok' : 'wait', '1 Oracle packet', pk.seq != null ? `<a href="#/packet/${pk.seq}">#${esc(pk.seq)}</a><br>median ${fmt(pk.price_usd)}<br>${esc(short(pk.digest))}<br>${verified(pk.verified)}` : 'not retained<br>(venue restarted)')}
      <span class="arrow">&rarr;</span>
      ${node(bind.matches ? 'ok' : 'wait', '2 Fill binding', `mark_id<br>${esc(short(bind.mark_id))}<br>${bind.matches ? '<span class="badge ok">recomputed ✓</span>' : bind.matches === false ? '<span class="badge bad">MISMATCH</span>' : ''}<br>@ ${fmt(t.price_usd)} x ${fmt(t.qty_usd)} USD`)}
      <span class="arrow">&rarr;</span>
      ${node(b.phase === 'committed' ? 'ok' : 'wait', '3 Batch', b.seq != null ? `<a href="#/batch/${b.seq}">#${esc(b.seq)}</a><br>${esc(short(b.digest))}<br>${phase(b.phase)}` : 'not sealed yet')}
      <span class="arrow">&rarr;</span>
      ${node(allAp && allAck ? 'ok' : 'wait', '4 Approvals / acks', `approvals ${accts.filter((a) => a.approved).length}/${accts.length}<br>acks ${signedAcks}/${acks.length}`)}
      <span class="arrow">&rarr;</span>
      ${node(f.ledger_state === 'Committed' ? 'ok' : 'wait', '5 Fee ledger', `${esc(f.ledger_state || 'not observed')}<br>oracle ${fmt(fees.oracle_due_sats)} / router ${fmt(fees.router_due_sats)} sats`)}</div>`;
    const party = (i, owner, side, tier) => `${acctLink(owner)} ${esc(side)} / ${esc(tier)}${i ? ` · ${esc(i.action)} ${fmt(i.quantity)} USD @ ${fmt(i.limit_usd)} · ${(i.leverage_bps / 10000).toFixed(1)}x` : ''}`;
    const makerSide = t.taker_side === 'long' ? 'short' : 'long';
    return card('Fill ' + id, chain) +
      card('Intents and parties', kv([['taker', party(f.taker_intent, t.taker_owner, t.taker_side, t.taker_tier)], ['taker intent', esc(f.taker_intent?.id || t.id)], ['maker', party(f.maker_intent, t.maker_owner, makerSide, t.maker_tier)], ['maker intent', esc(f.maker_intent?.id || t.maker_id)], ['time', time(t.ts_us)], ['margin locked', `long ${fmt(m.long_margin_sats)} / short ${fmt(m.short_margin_sats)} sats`]])) +
      card('Binding preimage fields', kv([['Fill.mark_id', esc(bind.mark_id)], ['recomputed', esc(bind.recomputed)], ...Object.entries(bind.preimage || {}).map(([k, v]) => [k, esc(v)])])) +
      card('Fees', kv([['taker', fmt(fees.taker_fee_sats) + ' sats'], ['maker', fmt(fees.maker_fee_sats) + ' sats'], ['oracle share', fmt(fees.oracle_due_sats) + ' sats'], ['router share', fmt(fees.router_due_sats) + ' sats']])) +
      card('Approvals and acknowledgements', table(['Owner', 'Margin sats', 'Batch approval', 'Channel ack (owner / peer / monitor)'], accts.map((a) => { const k = acks.find((x) => x.channel?.txid === a.channel?.txid && x.channel?.vout === a.channel?.vout) || {}; return `<tr><td>${acctLink(a.owner)}</td><td>${fmt(a.margin_sats)}</td><td>${a.approved ? '✓ signed' : 'pending'}</td><td>${k.owner_signed ? '✓' : '–'} / ${k.peer_signature ? '✓' : '–'} / ${k.monitor_signature ? '✓' : '–'}</td></tr>`; }))) +
      (f.settlement_note ? card('Settlement adapter', `<p class="muted">${esc(f.settlement_note)}</p>`) : '') + card('Raw', raw(f));
  },
  async batches() {
    const rows = list(await get('/api/explorer/batches?limit=100'), ['batches']);
    return card('Batches (100 ms)', table(['Seq', 'Phase', 'Fills', 'Participants', 'Digest', 'Window start', 'Fee ledger'], rows.map((b) => `<tr><td><a href="#/batch/${b.seq}">#${b.seq}</a></td><td>${phase(b.phase)}</td><td>${fmt((b.legs || []).length)}</td><td>${fmt((b.accounts || []).length)}</td><td>${esc(short(b.digest))}</td><td>${time((b.window_us || [])[0])}</td><td>${esc(b.ledger_state || '')}</td></tr>`)));
  },
  async batch(seq) {
    const r = await get('/api/explorer/batch/' + encodeURIComponent(seq)); const b = r.batch || r; const fills = Array.isArray(r.fills) ? r.fills : [];
    return card('Batch #' + b.seq, kv([['phase', phase(b.phase)], ['digest', esc(b.digest)], ['window', `${time((b.window_us || [])[0])} → ${time((b.window_us || [])[1])}`], ['fee ledger', `${esc(b.ledger_state || 'not observed')} · oracle ${fmt(b.oracle_due_sats)} / router ${fmt(b.router_due_sats)} sats`]])) +
      card('Fills', table(['Fill', 'Taker', 'Price', 'Size USD', 'Packet'], fills.map((f) => `<tr><td><a href="#/fill/${esc(f.id)}">${esc(short(f.id))}</a></td><td>${esc(f.taker_side)}</td><td>${fmt(f.price_usd)}</td><td>${fmt(f.qty_usd)}</td><td>${f.packet_seq != null ? `<a href="#/packet/${f.packet_seq}">#${f.packet_seq}</a>` : '—'}</td></tr>`))) +
      card('Approvals', table(['Owner', 'Channel', 'Margin sats', 'Signed'], (b.accounts || []).map((a) => `<tr><td>${acctLink(a.owner)}</td><td class="mono">${esc(short(a.channel?.txid))}:${esc(a.channel?.vout)}</td><td>${fmt(a.margin_sats)}</td><td>${a.approved ? '✓' : 'pending'}</td></tr>`))) +
      card('Channel acknowledgements', table(['Channel', 'Commitment', 'Owner', 'Peer (simulated)', 'Monitor (simulated)'], (b.acks || []).map((a) => `<tr><td class="mono">${esc(short(a.channel?.txid))}:${esc(a.channel?.vout)}</td><td>${fmt(a.previous_commitment)} → ${fmt(a.next_commitment)}</td><td>${a.owner_signed ? '✓' : '–'}</td><td>${a.peer_signature ? '✓' : '–'}</td><td>${a.monitor_signature ? '✓' : '–'}</td></tr>`))) + card('Raw', raw(r));
  },
  async accounts() {
    const rows = list(await get('/api/explorer/accounts'), ['accounts']);
    return card('Accounts (router allocations)', table(['Owner', 'Kind', 'Outpoint', 'Cap sats', 'Free sats', 'Committed sats', 'Net USD', 'Label'], rows.map((a) => {
      const op = a.outpoint ? `${esc(short(a.outpoint.txid))}:${esc(a.outpoint.vout)}` : '';
      const link = a.explorer_url || (a.kind === 'utxo' && a.outpoint ? `https://mempool.space/testnet4/tx/${a.outpoint.txid}` : null);
      return `<tr><td title="${esc(a.owner)}">${esc(short(a.owner))}</td><td>${esc(a.kind)}</td><td>${link ? `<a href="${esc(link)}" target="_blank" rel="noopener">${op} ↗</a>` : op + ' <span class="muted">(synthetic)</span>'}</td><td>${fmt(a.cap_sats)}</td><td>${fmt(a.balance?.free)}</td><td>${fmt(a.balance?.committed)}</td><td>${fmt(a.position?.net_usd)}</td><td>${a.kind === 'demo' ? '<span class="tag testnet" style="margin:0">' + esc(a.label) + '</span>' : esc(a.label)}</td></tr>`;
    })));
  },
  async journal() {
    const j = await get('/api/explorer/journal');
    return card('Journal tip', kv(Object.entries(j).map(([k, v]) => [k, esc(typeof v === 'object' ? JSON.stringify(v) : v)]))) + card('Raw', raw(j));
  },
  async dlc() {
    const j = await get('/api/explorer/dlc'); const ev = list(j, ['events', 'items']);
    const cls = { announced: 'sealed', attested: 'committed', unattestable: 'bad', setup_abandoned: 'bad' };
    const st = (e) => e.status || e.state;
    return card('DLC events (FROST relay /v1/dlc/events)', (j.oracle_pubkey_x ? kv([['oracle key (FROST group)', esc(j.oracle_pubkey_x)], ['stats', esc(JSON.stringify(j.stats || {}))]]) : '') + table(['Event', 'State', 'Maturity', 'Outcome / reason'], ev.map((e) => `<tr><td>${esc(e.event_id || e.id)}</td><td><span class="phase ${cls[st(e)] || ''}">${esc(st(e))}</span></td><td>${e.maturity_unix ? time(e.maturity_unix * 1e6) : esc(e.maturity || '')}</td><td>${esc(e.price_usd != null ? fmt(e.price_usd) + ' USD' : e.outcome ?? e.reason ?? '')}</td></tr>`))) + card('Raw', raw(j));
  },
};

async function render() {
  const [, name = 'packets', arg] = location.hash.replace(/^#\/?/, '#/').split('/').map(decodeURIComponent);
  const key = (name === 'packet' || name === 'fill' || name === 'batch') && !arg ? name + 's' : name;
  $('nav').innerHTML = NAV.map(([k, l]) => `<a href="#/${k}" class="${key === k || key + 's' === k ? 'on' : ''}">${l}</a>`).join(' ');
  const view = $('view');
  if (!routes[key]) { view.innerHTML = '<div class="err">Unknown page</div>'; return; }
  try { view.innerHTML = await routes[key](arg); } catch (e) { view.innerHTML = `<div class="card err">${esc(e.message)}</div>`; }
}
window.addEventListener('hashchange', render);
render();
setInterval(() => { if (/^#\/(packets|batches|journal|dlc)?$/.test(location.hash) || !location.hash) render(); }, 5000);
