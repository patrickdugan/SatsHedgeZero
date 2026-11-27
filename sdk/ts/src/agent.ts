// Trading as a delegated agent key, and the owner-side grant helpers. The agent holds only
// its own key: it signs intents whose `owner` is the account owner (as the grant names),
// and signs the pending acknowledgements the venue lets it sign (batches whose every leg on
// the account is its own). The owner key is used only by createGrant / revokeGrant.
import { type Bytes, hex, pubkey, sign, unhex } from './signer.ts';
import { type Grant, type Instrument, type Intent, type Limits, type Template, ZERO32, grantId, intentId, revocationId } from './encoding.ts';
import { type Client, LightningerError } from './client.ts';

export class Agent {
  c: Client; sk: Bytes; pk: string; grantId: string; lastSeq = 0;
  owner = ''; channel: { txid: string; vout: number } = { txid: ZERO32, vout: 0 }; limits!: Limits; template!: Template; view: any;
  private constructor(c: Client, sk: Bytes, grant: string) { this.c = c; this.sk = sk; this.pk = hex(pubkey(sk)); this.grantId = grant; }
  static async open(c: Client, agentSk: Bytes, grant: string): Promise<Agent> { const a = new Agent(c, agentSk, grant); await a.refresh(); return a; }

  async refresh() {
    this.view = await this.c.grant(this.grantId);
    const g: Grant = this.view.grant;
    if (g.agent !== this.pk) throw new Error('this grant names another agent key');
    this.owner = g.owner; this.channel = g.channel; this.limits = g.limits;
    const m = await this.c.markets();
    this.template = { ...m.perp, spot_pair: m.spot?.enabled ? m.spot.pair : undefined };
    return this.view;
  }
  status() { return this.c.grant(this.grantId); }
  /** Millisecond clock like the browser and the MM bots (sequences are shared with the owner). */
  nextSeq() { this.lastSeq = Math.max(Date.now(), this.lastSeq + 1); return this.lastSeq; }

  signed(instrument: Instrument, fields: Intent, ttlS: number): { id: string; intent: Intent } {
    const i: Intent = { channel: this.channel, owner: this.owner, sequence: this.nextSeq(), expires_us: Math.round((Date.now() + ttlS * 1000) * 1000), ...fields };
    const id = intentId(instrument, i, this.template);
    i.signature = hex(sign(id, this.sk));
    return { id: hex(id), intent: i };
  }
  private async send(instrument: Instrument, fields: Intent, ttlS: number, cancel = false) {
    for (let attempt = 0; ; attempt++) {
      const { id, intent } = this.signed(instrument, fields, ttlS);
      try {
        const r = await (cancel ? this.c.cancel(this.grantId, instrument, intent) : this.c.place(this.grantId, instrument, intent));
        return { id, ...r };
      } catch (e) {
        if (attempt === 0 && e instanceof LightningerError && e.code === 'venue.rejected' && /Replay/.test(e.message)) continue;
        throw e;
      }
    }
  }
  private perp(action: string, side: string, qty: number, limitUsd: number, leverageBps: number): Intent {
    const t: any = this.template;
    return { action, side, tier: 'standard', quantity: qty, limit_usd: limitUsd, leverage_bps: leverageBps,
      max_fee_ppm: t.tariff[action === 'post' ? 'maker_ppm' : 'taker_ppm'][0], max_fee_sats: 100_000,
      max_mark_age_us: t.max_mark_age_us ?? 15_000_000, early_window_opt_in: false, cancel_target: ZERO32 };
  }
  perpPost(side: 'long' | 'short', qtyUsd: number, limitUsd: number, leverageBps = 20_000, ttlS = 120) { return this.send('perp', this.perp('post', side, qtyUsd, limitUsd, leverageBps), ttlS); }
  perpTake(side: 'long' | 'short', qtyUsd: number, limitUsd: number, leverageBps = 20_000, ttlS = 30) { return this.send('perp', this.perp('take', side, qtyUsd, limitUsd, leverageBps), ttlS); }
  perpCancel(orderId: string, ttlS = 30) {
    return this.send('perp', { action: 'cancel', side: 'long', tier: 'standard', quantity: 0, limit_usd: 0, leverage_bps: 0, max_fee_ppm: 0, max_fee_sats: 0,
      max_mark_age_us: 0, early_window_opt_in: false, cancel_target: orderId }, ttlS, true);
  }
  optionPost(series: string, long: boolean, qty: number, premiumMilli: number, ttlS = 300) {
    return this.send('option', { version: 7, action: 'post', legs: [{ series, long, qty }], premium_milli: premiumMilli, cancel_target: ZERO32 }, ttlS);
  }
  /** One leg or a combo of up to 4 legs, all-or-none. */
  optionTake(legs: { series: string; long: boolean; qty: number }[], premiumMilli: number, otherLimits?: unknown[], ttlS = 60) {
    const f: Intent = { version: 7, action: 'take', legs, premium_milli: premiumMilli, cancel_target: ZERO32 };
    if (otherLimits?.length) f.other_limits = otherLimits;
    return this.send('option', f, ttlS);
  }
  optionCancel(orderId: string, ttlS = 60) { return this.send('option', { version: 7, action: 'cancel', legs: [], premium_milli: 0, cancel_target: orderId }, ttlS, true); }
  /** `price`: quote base units per BTC (demo USDT has 6 decimals). */
  spotPost(buy: boolean, qtySats: number, price: number, ttlS = 300) {
    return this.send('spot', { version: 8, action: 'post', pair: this.template.spot_pair, buy, qty_sats: qtySats, price, cancel_target: ZERO32 }, ttlS);
  }
  spotTake(buy: boolean, qtySats: number, price: number, ttlS = 60) {
    return this.send('spot', { version: 8, action: 'take', pair: this.template.spot_pair, buy, qty_sats: qtySats, price, cancel_target: ZERO32 }, ttlS);
  }
  spotCancel(orderId: string, ttlS = 60) {
    return this.send('spot', { version: 8, action: 'cancel', pair: this.template.spot_pair, buy: false, qty_sats: 0, price: 0, cancel_target: orderId }, ttlS, true);
  }
  async signPendingAcks() {
    const pending: any[] = await this.c.pendingAcks(this.grantId);
    if (!pending.length) return { accepted: 0, refused: [] };
    return this.c.submitAcks(this.grantId, pending.map((p) => ({ id: p.id, signature: hex(sign(unhex(p.message, 32), this.sk)) })));
  }
  /** Background ack signer; returns stop(). */
  startAutosigner(intervalMs = 250): () => void {
    let on = true;
    const loop = async () => { while (on) { try { await this.signPendingAcks(); } catch { /* next round */ } await new Promise((r) => setTimeout(r, intervalMs)); } };
    void loop();
    return () => { on = false; };
  }
}

/** Refuse a server-drafted grant unless it is exactly what was asked and its id hashes its fields. */
export function checkDraft(draft: any, owner: string, agent: string, instruments: string[], limits: Limits): Bytes {
  const g: Grant = draft.grant, problems: string[] = [];
  if (g.owner !== owner) problems.push('owner differs');
  if (g.agent !== agent) problems.push('agent key differs');
  if ([...g.instruments].sort().join() !== [...instruments].sort().join()) problems.push('instruments differ');
  if (JSON.stringify(Object.entries(g.limits).sort()) !== JSON.stringify(Object.entries(limits).sort())) problems.push('limits differ');
  if (g.may_withdraw) problems.push('grant would allow withdrawals');
  if (hex(grantId(g)) !== draft.id) problems.push('server id is not the hash of the grant fields');
  if (problems.length) throw new Error('refusing to sign the drafted grant: ' + problems.join(', '));
  return unhex(draft.id, 32);
}
export async function createGrant(c: Client, ownerSk: Bytes, agentPk: string, instruments: string[], limits: Limits,
  opts: { expiresInS?: number; label?: string; confirm?: (consent: string) => boolean | Promise<boolean> } = {}) {
  const owner = hex(pubkey(ownerSk));
  const d = await c.grantDraft({ owner, agent: agentPk, instruments, limits, expires_in_s: opts.expiresInS ?? 86_400, label: opts.label ?? '' });
  const id = checkDraft(d, owner, agentPk, instruments, limits);
  if (opts.confirm && !(await opts.confirm(d.consent))) throw new Error('grant not confirmed');
  return c.grantCreate({ ...d.grant, signature: hex(sign(id, ownerSk)) }, opts.label ?? '');
}
export async function revokeGrant(c: Client, ownerSk: Bytes, grant: string) {
  const v = await c.grant(grant);
  const r: any = { version: 1, router: v.grant.router, grant, owner: hex(pubkey(ownerSk)), issued_us: Date.now() * 1000 };
  r.signature = hex(sign(revocationId(r, v.grant.scope), ownerSk));
  return c.grantRevoke(r);
}
