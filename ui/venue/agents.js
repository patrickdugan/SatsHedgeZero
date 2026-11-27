// Agents panel (Settings): the account owner delegates a capped agent key, reviews the exact grant
// and its consent text before signing it with this browser's trading key, watches usage, and
// revokes it at once. The agent never gets this key. docs/SHZ_AGENT_API.md.
//
// grantId / revocationId mirror crates/shz-dex/src/routing/agents.rs byte for byte;
// ui/venue/test/agents.test.mjs checks them against sdk/vectors/agent_vectors.json.
import { hex, unhex, concat, taggedHash, bip340Sign } from './crypto.js';

const BITS = { perps: 1, options: 2, spot: 4 };
function uN(n, bytes) {
  let v = BigInt(n);
  if (v < 0n || v >= 1n << BigInt(8 * bytes)) throw new RangeError('integer out of range');
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
const u8 = (n) => Uint8Array.of(n), u32 = (n) => uN(n, 4), u64 = (n) => uN(n, 8);
const scope = (s) => concat(unhex(s.network, 32), u64(s.epoch), unhex(s.policy, 32));
export async function grantId(g) {
  const l = g.limits;
  let bits = 0;
  for (const n of g.instruments) { if (!(n in BITS)) throw new Error('bad instrument'); bits |= BITS[n]; }
  return taggedHash('SHZ/HFT06/AGENT-GRANT/V1', u32(g.version), scope(g.scope), u32(g.router), unhex(g.channel.txid, 32), u32(g.channel.vout),
    unhex(g.owner, 32), unhex(g.agent, 32), u64(g.nonce), u64(g.issued_us), u64(g.expires_us), u8(bits), u8(g.may_withdraw ? 1 : 0),
    u64(l.max_order_notional_usd), u64(l.max_daily_notional_usd), u32(l.max_open_orders), u32(l.max_orders_per_minute), u32(l.collar_bps));
}
export async function revocationId(r, s) {
  return taggedHash('SHZ/HFT06/AGENT-REVOKE/V1', u32(r.version ?? 1), scope(s), u32(r.router ?? 1), unhex(r.grant, 32), unhex(r.owner, 32), u64(r.issued_us));
}
/** Refuse a drafted grant unless it is what the form asked for, allows no withdrawal, and its id hashes its fields. */
export async function checkDraft(d, want) {
  const g = d.grant, bad = [];
  if (g.owner !== want.owner) bad.push('owner');
  if (g.agent !== want.agent) bad.push('agent key');
  if ([...g.instruments].sort().join() !== [...want.instruments].sort().join()) bad.push('instruments');
  for (const k of Object.keys(want.limits)) if (g.limits[k] !== want.limits[k]) bad.push(k);
  if (g.may_withdraw) bad.push('withdrawals');
  if (hex(await grantId(g)) !== d.id) bad.push('grant id');
  if (bad.length) throw new Error('the drafted grant differs from the request (' + bad.join(', ') + '): not signing');
  return unhex(d.id, 32);
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
async function call(path, body) {
  const r = await fetch(path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(j?.error?.message || j?.error || 'HTTP ' + r.status);
  return j;
}
const when = (us) => new Date(us / 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

/** ctx: { owner (hex) | null, key (Uint8Array) | null } */
export async function renderAgents(el, ctx) {
  el.innerHTML = '<div class="mnote">Agents</div><div class="msg">Loading…</div>';
  let info;
  try { info = await call('/agent/v1/info'); } catch { el.innerHTML = '<div class="mnote">Agents</div><div class="msg">Agent API unavailable.</div>'; return; }
  if (!info.agents?.enabled) { el.innerHTML = '<div class="mnote">Agents</div><div class="msg">Delegated agents are off on this venue.</div>'; return; }
  if (!ctx.owner || !ctx.key) { el.innerHTML = '<div class="mnote">Agents</div><div class="msg">Connect a trading key to delegate an agent.</div>'; return; }
  const grants = await call('/agent/v1/grants?owner=' + ctx.owner).catch(() => []);
  const inst = ['perps', ...(info.options ? ['options'] : []), ...(info.spot ? ['spot'] : [])];
  const c = info.grant_ceiling;
  el.innerHTML = `<div class="mnote">Agents <span class="dim">(testnet; an agent trades with its own key inside the limits you sign, and can never withdraw)</span></div>
    <div class="agl">${grants.length ? grants.map((g) => `<div class="agrow" data-g="${esc(g.id)}"><b>${esc(g.label || 'agent')}</b> <code>${esc(g.grant.agent.slice(0, 12))}…</code>
      <span class="ag-${esc(g.status)}">${esc(g.status)}</span> ${esc(g.grant.instruments.join(', '))} · $${g.usage.day_notional_usd}/$${g.grant.limits.max_daily_notional_usd} today · ${g.usage.open_orders} open · until ${esc(when(g.grant.expires_us))}
      ${g.status === 'active' ? '<button type="button" class="btn sm agrev">Revoke now</button>' : ''}</div>`).join('') : '<div class="msg">No agents yet.</div>'}</div>
    <form class="agform">
      <label>Agent public key <input name="agent" required pattern="[0-9a-f]{64}" placeholder="64 hex characters" autocomplete="off"></label>
      <label>Label <input name="label" maxlength="64" placeholder="my bot"></label>
      <div>${inst.map((n) => `<label class="chk"><input type="checkbox" name="i_${n}" ${n === 'perps' ? 'checked' : ''}> ${n}</label>`).join(' ')}</div>
      <label>Max per order (USD) <input name="max_order" type="number" min="1" max="${c.max_order_notional_usd}" value="100" required></label>
      <label>Max per 24 h (USD) <input name="max_daily" type="number" min="1" max="${c.max_daily_notional_usd}" value="1000" required></label>
      <label>Max open orders <input name="max_open" type="number" min="1" max="${c.max_open_orders}" value="10" required></label>
      <label>Orders per minute <input name="rate" type="number" min="1" max="${c.max_orders_per_minute}" value="30" required></label>
      <label>Price collar (% of mark) <input name="collar" type="number" min="0.01" max="${c.collar_bps / 100}" step="0.01" value="2" required></label>
      <label>Expires in (hours) <input name="hours" type="number" min="0.1" max="720" step="0.1" value="24" required></label>
      <button type="submit" class="btn">Review grant</button>
    </form><div class="agreview"></div>`;
  for (const b of el.querySelectorAll('.agrev')) b.onclick = async () => {
    const id = b.closest('.agrow').dataset.g, g = grants.find((x) => x.id === id);
    const r = { version: 1, router: g.grant.router, grant: id, owner: ctx.owner, issued_us: Date.now() * 1000 };
    r.signature = hex(await bip340Sign(await revocationId(r, g.grant.scope), ctx.key));
    b.disabled = true;
    try { const out = await call('/agent/v1/grants/revoke', { revocation: r }); b.replaceWith(Object.assign(document.createElement('span'), { textContent: `revoked, ${out.orders_pulled.length} orders pulled` })); }
    catch (e) { b.disabled = false; alert(e.message); }
  };
  el.querySelector('.agform').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target), rv = el.querySelector('.agreview');
    const want = { owner: ctx.owner, agent: String(f.get('agent')).trim().toLowerCase(), instruments: inst.filter((n) => f.get('i_' + n)),
      limits: { max_order_notional_usd: +f.get('max_order'), max_daily_notional_usd: +f.get('max_daily'), max_open_orders: +f.get('max_open'),
        max_orders_per_minute: +f.get('rate'), collar_bps: Math.round(+f.get('collar') * 100) } };
    try {
      if (!want.instruments.length) throw new Error('pick at least one instrument');
      if (want.agent === ctx.owner) throw new Error('give the agent its own key, not this trading key');
      const d = await call('/agent/v1/grants/draft', { ...want, expires_in_s: Math.round(+f.get('hours') * 3600), label: f.get('label') });
      const id = await checkDraft(d, want);
      rv.innerHTML = `<div class="msg">${esc(d.consent)}</div><code class="dim">grant ${esc(d.id)}</code> <button type="button" class="btn agsign">Sign and activate</button>`;
      rv.querySelector('.agsign').onclick = async () => {
        const signed = { ...d.grant, signature: hex(await bip340Sign(id, ctx.key)) };
        await call('/agent/v1/grants', { grant: signed, label: f.get('label') });
        renderAgents(el, ctx);
      };
    } catch (x) { rv.innerHTML = `<div class="msg err">${esc(x.message)}</div>`; }
  };
}
