// Agent API v1 clients: REST (fetch) and JSON-RPC 2.0 over WebSocket (Node's global WebSocket).
// Errors carry the API's stable `code`. REST retries 429 after Retry-After and sends an
// Idempotency-Key with every write. The stream numbers each channel's events; on a gap it
// resyncs (replay or snapshot) before handing on anything newer.
import { randomBytes } from 'node:crypto';
import type { Grant, Instrument, Intent, Limits, Revocation } from './encoding.ts';

export class LightningerError extends Error {
  status: number; code: string; details: unknown; retryable: boolean;
  constructor(status: number, code: string, message: string, details?: unknown, retryable = false) {
    super(`${code}: ${message}`);
    this.status = status; this.code = code; this.details = details; this.retryable = retryable;
  }
}
export interface RateInfo { limit: number; remaining: number; reset_s: number }

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const idemKey = () => randomBytes(16).toString('hex');

export class Client {
  base: string; maxRetries: number; rate: RateInfo | null = null;
  constructor(base = 'http://127.0.0.1:8095', maxRetries = 3) { this.base = base.replace(/\/$/, ''); this.maxRetries = maxRetries; }

  async request(method: 'GET' | 'POST', path: string, params?: Record<string, unknown>, body?: unknown, idempotencyKey?: string): Promise<any> {
    const q = params ? '?' + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => [k, String(v)])).toString() : '';
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (idempotencyKey) headers['idempotency-key'] = idempotencyKey;
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(this.base + path + q, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      const rl = res.headers.get('x-ratelimit-remaining');
      if (rl !== null) this.rate = { limit: Number(res.headers.get('x-ratelimit-limit')), remaining: Number(rl), reset_s: Number(res.headers.get('x-ratelimit-reset')) };
      const text = await res.text();
      const json = text ? JSON.parse(text) : null;
      if (res.ok) return json;
      const e = json?.error ?? { code: 'http', message: text.slice(0, 200) };
      if (res.status === 429 && attempt < this.maxRetries) { await sleep(Math.max(Number(res.headers.get('retry-after') || 1) * 1000, 50)); continue; }
      throw new LightningerError(res.status, e.code, e.message, e.details, !!e.retryable);
    }
  }
  get(path: string, params?: Record<string, unknown>) { return this.request('GET', path, params); }
  post(path: string, body: unknown, idempotent = true) { return this.request('POST', path, undefined, body, idempotent ? idemKey() : undefined); }

  info() { return this.get('/agent/v1/info'); }
  time() { return this.get('/agent/v1/time'); }
  markets() { return this.get('/agent/v1/markets'); }
  book(instrument = 'perp', depth = 25) { return this.get('/agent/v1/book', { instrument, depth }); }
  trades(instrument = 'perp', limit = 100) { return this.get('/agent/v1/trades', { instrument, limit }); }
  mark() { return this.get('/agent/v1/mark'); }
  optionChain() { return this.get('/agent/v1/options/chain'); }
  account(owner: string) { return this.get('/agent/v1/account', { owner }); }
  grants(q: { owner?: string; agent?: string }) { return this.get('/agent/v1/grants', q); }
  grant(id: string) { return this.get('/agent/v1/grant', { id }); }
  orders(grant: string, limit = 100) { return this.get('/agent/v1/orders', { grant, limit }); }
  pendingAcks(grant: string) { return this.get('/agent/v1/acks', { grant }); }
  async intentId(instrument: Instrument, intent: Intent): Promise<string> { return (await this.post('/agent/v1/intent-id', { instrument, intent }, false)).id; }
  grantDraft(req: { owner: string; agent: string; instruments: string[]; limits: Limits; expires_in_s?: number; label?: string }) { return this.post('/agent/v1/grants/draft', req, false); }
  grantCreate(grant: Grant, label = '') { return this.post('/agent/v1/grants', { grant, label }); }
  grantRevoke(revocation: Revocation) { return this.post('/agent/v1/grants/revoke', { revocation }); }
  place(grant: string, instrument: Instrument, intent: Intent, idempotencyKey = idemKey()) { return this.request('POST', '/agent/v1/orders', undefined, { grant, instrument, intent }, idempotencyKey); }
  cancel(grant: string, instrument: Instrument, intent: Intent) { return this.post('/agent/v1/orders/cancel', { grant, instrument, intent }); }
  replace(grant: string, instrument: Instrument, cancel: Intent, place: Intent) { return this.post('/agent/v1/orders/replace', { grant, instrument, cancel, place }); }
  submitAcks(grant: string, items: { id: string; signature: string }[]) { return this.post('/agent/v1/acks', { grant, items }); }
}

export type Handler = (channel: string, kind: 'event' | 'replay' | 'snapshot', payload: any) => void;
export class RpcError extends Error {
  code: string; rpcCode: number; details: unknown;
  constructor(e: any) { super(`${e?.data?.code ?? e.code}: ${e.message}`); this.code = e?.data?.code ?? String(e.code); this.rpcCode = e.code; this.details = e?.data?.details; }
}

export class Stream {
  ws: WebSocket; seq = new Map<string, number>(); handlers = new Map<string, Handler>(); resyncs = 0;
  private nextId = 0; private waiting = new Map<number, (m: any) => void>();
  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.addEventListener('message', (ev) => this.onMessage(String(ev.data)));
  }
  static open(base = 'http://127.0.0.1:8095'): Promise<Stream> {
    const url = base.replace(/\/$/, '').replace(/^http/, 'ws') + '/agent/v1/ws';
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      const s = new Stream(ws);
      const onHello = (ev: MessageEvent) => { if (String(ev.data).includes('"hello"')) { ws.removeEventListener('message', onHello); resolve(s); } };
      ws.addEventListener('message', onHello);
      ws.addEventListener('error', () => reject(new Error('websocket error')));
    });
  }
  call(method: string, params: unknown = {}, timeoutMs = 10_000): Promise<any> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.waiting.delete(id); reject(new Error('rpc timeout: ' + method)); }, timeoutMs);
      this.waiting.set(id, (m) => { clearTimeout(t); 'error' in m ? reject(new RpcError(m.error)) : resolve(m.result); });
      this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    });
  }
  async subscribe(channels: string[], handler: Handler) {
    for (const c of channels) this.handlers.set(c, handler);
    const r = await this.call('subscribe', { channels });
    for (const c of r.channels) this.seq.set(c.channel, c.seq);
    return r;
  }
  async resync(channel: string) {
    this.resyncs++;
    const r = await this.call('resync', { channel, since: this.seq.get(channel) ?? 0 });
    this.seq.set(channel, r.seq);
    const h = this.handlers.get(channel);
    if (h) 'replay' in r ? h(channel, 'replay', r.replay) : h(channel, 'snapshot', r.snapshot);
    return r;
  }
  private onMessage(text: string) {
    const msg = JSON.parse(text);
    for (const m of Array.isArray(msg) ? msg : [msg]) {
      if (m.id !== undefined && this.waiting.has(m.id)) { this.waiting.get(m.id)!(m); this.waiting.delete(m.id); continue; }
      if (m.method === 'subscription') {
        const { channel, seq, data } = m.params;
        const last = this.seq.get(channel) ?? 0;
        if (seq <= last) continue;
        if (seq !== last + 1) { void this.resync(channel); continue; }
        this.seq.set(channel, seq);
        this.handlers.get(channel)?.(channel, 'event', data);
      } else if (m.method === 'gap') {
        for (const c of m.params.channels) void this.resync(c.channel);
      }
    }
  }
  close() { this.ws.close(); }
}
