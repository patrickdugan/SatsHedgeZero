// BIP340 for the agent SDK. Secret-key operations run in sign.wasm (built from
// crates/shz-wasm-sign, byte-identical to ui/venue/sign.wasm; a test checks the copy);
// verification is plain BigInt arithmetic on public data.
import { readFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';

export type Bytes = Uint8Array;

export const hex = (u8: Bytes): string => Buffer.from(u8).toString('hex');
export function unhex(s: string, len?: number): Bytes {
  if (typeof s !== 'string' || !/^([0-9a-f]{2})*$/i.test(s)) throw new Error('bad hex');
  const b = new Uint8Array(Buffer.from(s, 'hex'));
  if (len !== undefined && b.length !== len) throw new Error(`expected ${len} bytes`);
  return b;
}
export const concat = (...parts: Bytes[]): Bytes => new Uint8Array(Buffer.concat(parts));
export const sha256 = (b: Bytes): Bytes => new Uint8Array(createHash('sha256').update(b).digest());
const tagCache = new Map<string, Bytes>();
export function taggedHash(tag: string, ...msgs: Bytes[]): Bytes {
  let t = tagCache.get(tag);
  if (!t) { const h = sha256(new TextEncoder().encode(tag)); t = concat(h, h); tagCache.set(tag, t); }
  return sha256(concat(t, ...msgs));
}

// ---------------------------------------------------------------- WASM signer
interface SignerExports { memory: WebAssembly.Memory; shz_buf(): number; shz_pubkey(): number; shz_sign(): number; shz_keygen(): number; shz_wipe(): void; }
const wasmBytes = await readFile(new URL('../sign.wasm', import.meta.url));
const W = (await WebAssembly.instantiate(wasmBytes, {})).instance.exports as unknown as SignerExports;
function wasmOp(op: 'shz_pubkey' | 'shz_sign' | 'shz_keygen', inputs: [number, Bytes][], outOff: number, outLen: number): Bytes | null {
  const io = () => new Uint8Array(W.memory.buffer, W.shz_buf(), 256);
  try {
    for (const [off, b] of inputs) io().set(b, off);
    return W[op]() === 0 ? io().slice(outOff, outOff + outLen) : null;
  } finally {
    W.shz_wipe();
  }
}
function secret32(sk: Bytes): Bytes {
  if (!(sk instanceof Uint8Array) || sk.length !== 32) throw new Error('invalid secret key');
  return sk;
}
export function pubkey(sk: Bytes): Bytes {
  const out = wasmOp('shz_pubkey', [[0, secret32(sk)]], 32, 32);
  if (!out) throw new Error('invalid secret key');
  return out;
}
/** BIP340 signature with fresh auxiliary randomness (or `aux`), self-verified. */
export function sign(msg: Bytes, sk: Bytes, aux: Bytes = new Uint8Array(randomBytes(32))): Bytes {
  if (msg.length !== 32 || aux.length !== 32) throw new Error('msg and aux must be 32 bytes');
  const sig = wasmOp('shz_sign', [[0, secret32(sk)], [32, msg], [64, aux]], 96, 64);
  if (!sig) throw new Error('invalid secret key');
  if (!verify(msg, pubkey(sk), sig)) throw new Error('signature self-check failed');
  return sig;
}
export function newKey(): Bytes {
  for (;;) {
    const e = new Uint8Array(randomBytes(64));
    const k = wasmOp('shz_keygen', [[0, e]], 64, 32);
    e.fill(0);
    if (k) return k;
  }
}

// ---------------------------------------------------------------- verify
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G: Pt = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
type Pt = [bigint, bigint];
type J = [bigint, bigint, bigint];
const mod = (a: bigint, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function powmod(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
const toInt = (b: Bytes) => (b.length ? BigInt('0x' + hex(b)) : 0n);
function jdouble([x, y, z]: J): J {
  if (y === 0n || z === 0n) return [0n, 1n, 0n];
  const ysq = (y * y) % P, s = (4n * x * ysq) % P, m = (3n * x * x) % P;
  const nx = mod(m * m - 2n * s);
  return [nx, mod(m * (s - nx) - 8n * ysq * ysq), (2n * y * z) % P];
}
function jadd(a: J, b: J): J {
  const [x1, y1, z1] = a, [x2, y2, z2] = b;
  if (z1 === 0n) return b;
  if (z2 === 0n) return a;
  const z1s = (z1 * z1) % P, z2s = (z2 * z2) % P;
  const u1 = (x1 * z2s) % P, u2 = (x2 * z1s) % P;
  const s1 = (((y1 * z2s) % P) * z2) % P, s2 = (((y2 * z1s) % P) * z1) % P;
  if (u1 === u2) return s1 === s2 ? jdouble(a) : [0n, 1n, 0n];
  const h = mod(u2 - u1), r = mod(s2 - s1);
  const h2 = (h * h) % P, h3 = (h * h2) % P, u1h2 = (u1 * h2) % P;
  const nx = mod(r * r - h3 - 2n * u1h2);
  return [nx, mod(r * (u1h2 - nx) - s1 * h3), (((h * z1) % P) * z2) % P];
}
function affine([x, y, z]: J): Pt | null {
  if (z === 0n) return null;
  const zi = powmod(z, P - 2n, P), zi2 = (zi * zi) % P;
  return [(x * zi2) % P, (((y * zi2) % P) * zi) % P];
}
function mul(pt: Pt, k: bigint): J {
  k = mod(k, N);
  let acc: J = [0n, 1n, 0n], base: J = [pt[0], pt[1], 1n];
  while (k > 0n) { if (k & 1n) acc = jadd(acc, base); base = jdouble(base); k >>= 1n; }
  return acc;
}
function liftX(x: bigint): Pt | null {
  if (x >= P) return null;
  const ysq = mod(powmod(x, 3n, P) + 7n), y = powmod(ysq, (P + 1n) / 4n, P);
  if ((y * y) % P !== ysq) return null;
  return [x, y % 2n === 0n ? y : P - y];
}
export function verify(msg: Bytes, pk: Bytes, sig: Bytes): boolean {
  if (msg.length !== 32 || pk.length !== 32 || sig.length !== 64) return false;
  const pt = liftX(toInt(pk));
  const r = toInt(sig.slice(0, 32)), s = toInt(sig.slice(32));
  if (!pt || r >= P || s >= N) return false;
  const e = toInt(taggedHash('BIP0340/challenge', sig.slice(0, 32), pk, msg)) % N;
  const rr = affine(jadd(mul(G, s), mul(pt, N - e)));
  return !!rr && rr[1] % 2n === 0n && rr[0] === r;
}
