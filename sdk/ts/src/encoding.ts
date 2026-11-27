// Canonical encodings and ids, byte for byte with the Rust `id()` of each structure:
//   perpIntentId    IntentV6        crates/shz-dex/src/routing/tiered.rs        SHZ/HFT06/INTENT/V1
//   optionIntentId  IntentV7        crates/shz-dex/src/routing/options.rs       SHZ/HFT06/INTENT/V7
//   spotIntentId    SpotIntent      crates/shz-dex/src/routing/options/spot.rs  SHZ/HFT06/SPOT-INTENT/V8
//   grantId         AgentGrant      crates/shz-dex/src/routing/agents.rs        SHZ/HFT06/AGENT-GRANT/V1
//   revocationId    AgentRevocation (same file)                                 SHZ/HFT06/AGENT-REVOKE/V1
// sdk/vectors/agent_vectors.json pins every id (test/vectors.test.ts).
import { type Bytes, concat, taggedHash, unhex } from './signer.ts';

export const ZERO32 = '0'.repeat(64);
export type Instrument = 'perp' | 'option' | 'spot';
export interface Outpoint { txid: string; vout: number }
export interface Scope { network: string; epoch: number; policy: string }
/** Signing context: GET /agent/v1/markets -> perp (plus spot_pair from spot.pair). */
export interface Template { scope: Scope; router: number; tariff_version: number; execution_policy: string; spot_pair?: string; [k: string]: unknown }
export interface Limits { max_order_notional_usd: number; max_daily_notional_usd: number; max_open_orders: number; max_orders_per_minute: number; collar_bps: number }
export interface Grant {
  version: number; scope: Scope; router: number; channel: Outpoint; owner: string; agent: string; nonce: number; issued_us: number; expires_us: number;
  instruments: string[]; may_withdraw: boolean; limits: Limits; signature?: string;
}
export interface Revocation { version?: number; router?: number; grant: string; owner: string; issued_us: number; signature?: string }
export type Intent = Record<string, any>;

const ACTION: Record<string, number> = { post: 1, take: 2, cancel: 3 };
const SIDE: Record<string, number> = { long: 1, short: 2 };
const TIER: Record<string, number> = { standard: 0, intermediate: 1, premium: 2 };
export const INSTRUMENT_BITS: Record<string, number> = { perps: 1, options: 2, spot: 4 };

function uN(n: number | bigint, bytes: number): Bytes {
  let v = BigInt(n);
  if (v < 0n || v >= 1n << BigInt(8 * bytes)) throw new RangeError('integer out of range');
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
const u8 = (n: number) => Uint8Array.of(n);
const u32 = (n: number) => uN(n, 4);
const u64 = (n: number | bigint) => uN(n, 8);
function i64(n: number | bigint): Bytes {
  let v = BigInt(n);
  if (v < -(1n << 63n) || v >= 1n << 63n) throw new RangeError('integer out of range');
  if (v < 0n) v += 1n << 64n;
  return uN(v, 8);
}
const scope = (s: Scope) => concat(unhex(s.network, 32), u64(s.epoch), unhex(s.policy, 32));
const outpoint = (c: Outpoint) => concat(unhex(c.txid, 32), u32(c.vout));
function action(a: string): Bytes { if (!(a in ACTION)) throw new Error('bad action'); return u8(ACTION[a]); }

export function assetBytes(a: any): Bytes {
  if (!a || a.kind === 'btc') return u8(1);
  const p = ({ rgb: 0, tap: 1 } as Record<string, number>)[a.protocol];
  if (a.kind !== 'stable' || p === undefined) throw new Error('bad asset');
  return concat(u8(2), u8(p), unhex(a.id, 32), u8(a.decimals));
}

export function perpIntentId(i: Intent, t: Template): Bytes {
  const tier = i.tier ?? 'standard';
  if (!(i.side in SIDE) || !(tier in TIER)) throw new Error('bad side or tier');
  const ent = tier === 'standard' ? ZERO32 : (i.entitlement_digest || ZERO32);
  return taggedHash('SHZ/HFT06/INTENT/V1', scope(t.scope), u32(t.router), outpoint(i.channel), unhex(i.owner, 32),
    u64(i.sequence), u64(i.expires_us), action(i.action), u8(SIDE[i.side]), u8(TIER[tier]),
    u32(t.tariff_version), unhex(ent, 32), unhex(t.execution_policy, 32),
    u64(i.quantity), u64(i.limit_usd), u32(i.leverage_bps), u32(i.max_fee_ppm), u64(i.max_fee_sats), u64(i.max_mark_age_us),
    u8(i.early_window_opt_in ? 1 : 0), unhex(i.cancel_target || ZERO32, 32));
}
export function optionIntentId(i: Intent, t: Template): Bytes {
  const parts: Bytes[] = [u32(i.version ?? 7), scope(t.scope), u32(t.router), outpoint(i.channel), unhex(i.owner, 32),
    u64(i.sequence), u64(i.expires_us), action(i.action), u64(i.legs.length)];
  for (const l of i.legs) parts.push(unhex(l.series, 32), u8(l.long ? 1 : 0), u64(l.qty));
  parts.push(i64(i.premium_milli ?? 0), unhex(i.cancel_target || ZERO32, 32));
  const ol = i.other_limits || [];
  if (ol.length) { parts.push(u64(ol.length)); for (const l of ol) parts.push(assetBytes(l.asset), i64(l.premium_milli)); }
  return taggedHash('SHZ/HFT06/INTENT/V7', ...parts);
}
export function spotIntentId(i: Intent, t: Template): Bytes {
  const pair = i.pair || t.spot_pair;
  if (!pair) throw new Error('spot pair unknown (template.spot_pair)');
  return taggedHash('SHZ/HFT06/SPOT-INTENT/V8', u32(i.version ?? 8), scope(t.scope), u32(t.router), outpoint(i.channel), unhex(i.owner, 32),
    u64(i.sequence), u64(i.expires_us), action(i.action), unhex(pair, 32), u8(i.buy ? 1 : 0), u64(i.qty_sats ?? 0), u64(i.price ?? 0),
    unhex(i.cancel_target || ZERO32, 32));
}
export function intentId(instrument: Instrument, i: Intent, t: Template): Bytes {
  return instrument === 'perp' ? perpIntentId(i, t) : instrument === 'option' ? optionIntentId(i, t) : spotIntentId(i, t);
}
export function instrumentBits(names: string[]): number {
  let b = 0;
  for (const n of names) { if (!(n in INSTRUMENT_BITS)) throw new Error('bad instrument ' + n); b |= INSTRUMENT_BITS[n]; }
  return b;
}
export function grantId(g: Grant): Bytes {
  const l = g.limits;
  return taggedHash('SHZ/HFT06/AGENT-GRANT/V1', u32(g.version), scope(g.scope), u32(g.router), outpoint(g.channel),
    unhex(g.owner, 32), unhex(g.agent, 32), u64(g.nonce), u64(g.issued_us), u64(g.expires_us),
    u8(instrumentBits(g.instruments)), u8(g.may_withdraw ? 1 : 0),
    u64(l.max_order_notional_usd), u64(l.max_daily_notional_usd), u32(l.max_open_orders), u32(l.max_orders_per_minute), u32(l.collar_bps));
}
export function revocationId(r: Revocation, s: Scope): Bytes {
  return taggedHash('SHZ/HFT06/AGENT-REVOKE/V1', u32(r.version ?? 1), scope(s), u32(r.router ?? 1), unhex(r.grant, 32), unhex(r.owner, 32), u64(r.issued_us));
}
