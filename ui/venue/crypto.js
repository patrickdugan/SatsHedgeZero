// SHZ venue client crypto: SHA-256, BIP340 (Schnorr), BIP341 key-path tweak,
// bech32m, and IntentV6 id encoding. ES module for browser and node; no JS dependencies.
// Secret-key operations run in WebAssembly (sign.wasm, built from crates/shz-wasm-sign
// over the k256 crate, constant-time scalar arithmetic): pubkey, bip340Sign's signing
// step, taprootTweakSecret, randomKey (browser entropy reduced to a scalar in WASM).
// The module instantiates sign.wasm with top-level await, so importers see sync
// pubkey/randomKey as before. Verification, hashing, taproot output keys, bech32m and
// IntentV6 stay in JS BigInt (public data only; not constant-time). TESTNET ONLY: the
// page still holds the secret key in JS memory and localStorage.

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = [
  0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
];

// ---------- bytes / hex ----------
export const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
export function unhex(s, len) {
  if (typeof s !== 'string' || s.length % 2 || /[^0-9a-fA-F]/.test(s)) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  if (len !== undefined && out.length !== len) throw new Error(`expected ${len} bytes, got ${out.length}`);
  return out;
}
export const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const utf8 = (s) => new TextEncoder().encode(s);
export const bytesToInt = (b) => (b.length ? BigInt('0x' + hex(b)) : 0n);
export const intToBytes = (n, len = 32) => unhex(n.toString(16).padStart(len * 2, '0'), len);

// ---------- SHA-256 ----------
const K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

// Pure-JS fallback for insecure contexts (plain http on a LAN host) where crypto.subtle is absent.
function sha256Sync(msg) {
  const h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const l = msg.length;
  const padded = new Uint8Array(((l + 9 + 63) >> 6) << 6);
  padded.set(msg);
  padded[l] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(l / 0x20000000));
  dv.setUint32(padded.length - 4, (l << 3) >>> 0);
  const w = new Uint32Array(64);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i] >>> 0);
  return out;
}

export async function sha256(data) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (subtle) return new Uint8Array(await subtle.digest('SHA-256', data));
  return sha256Sync(data);
}
export { sha256Sync };

const tagCache = new Map();
export async function taggedHash(tag, ...msgs) {
  let t = tagCache.get(tag);
  if (!t) { const h = await sha256(typeof tag === 'string' ? utf8(tag) : tag); t = concat(h, h); tagCache.set(tag, t); }
  return sha256(concat(t, ...msgs));
}

// ---------- secp256k1 (Jacobian) ----------
const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function powmod(b, e, m) {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
const inv = (a, m = P) => powmod(a, m - 2n, m);

function jdouble([x, y, z]) {
  if (y === 0n || z === 0n) return [0n, 1n, 0n];
  const ysq = (y * y) % P;
  const s = (4n * x * ysq) % P;
  const m = (3n * x * x) % P;
  const nx = mod(m * m - 2n * s);
  return [nx, mod(m * (s - nx) - 8n * ysq * ysq), (2n * y * z) % P];
}
function jadd(a, b) {
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
function toAffine([x, y, z]) {
  if (z === 0n) return null;
  const zi = inv(z), zi2 = (zi * zi) % P;
  return [(x * zi2) % P, (((y * zi2) % P) * zi) % P];
}
export function mul(pt, k) {
  k = mod(k, N);
  if (!pt || k === 0n) return null;
  let acc = [0n, 1n, 0n], base = [pt[0], pt[1], 1n];
  while (k > 0n) {
    if (k & 1n) acc = jadd(acc, base);
    base = jdouble(base);
    k >>= 1n;
  }
  return toAffine(acc);
}
export function add(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  return toAffine(jadd([p1[0], p1[1], 1n], [p2[0], p2[1], 1n]));
}
export function liftX(x) {
  if (x >= P) return null;
  const ysq = mod(powmod(x, 3n, P) + 7n);
  const y = powmod(ysq, (P + 1n) / 4n, P);
  if ((y * y) % P !== ysq) return null;
  return [x, y % 2n === 0n ? y : P - y];
}

// ---------- WASM signer (crates/shz-wasm-sign) ----------
// One static 256-byte I/O buffer; layouts are documented in crates/shz-wasm-sign/src/lib.rs.
async function loadSigner() {
  const url = new URL('./sign.wasm', import.meta.url);
  let bytes;
  if (url.protocol === 'file:') {
    const { readFile } = await import('node:fs/promises');
    bytes = await readFile(url);
  } else {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('sign.wasm: HTTP ' + res.status);
    bytes = await res.arrayBuffer();
  }
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return instance.exports;
}
const W = await loadSigner();

function wasmOp(op, inputs, outOff, outLen) {
  const io = () => new Uint8Array(W.memory.buffer, W.shz_buf(), 256);
  try {
    for (const [off, b] of inputs) io().set(b, off);
    const rc = W[op]();
    return rc === 0 ? io().slice(outOff, outOff + outLen) : null;
  } finally {
    W.shz_wipe();
  }
}
const secret32 = (sk) => {
  if (!(sk instanceof Uint8Array) || sk.length !== 32) throw new Error('invalid secret key');
  return sk;
};

// ---------- BIP340 ----------
export function pubkey(seckey) {
  const out = wasmOp('shz_pubkey', [[0, secret32(seckey)]], 32, 32);
  if (!out) throw new Error('invalid secret key');
  return out;
}
export async function bip340Sign(msg, seckey, aux = new Uint8Array(32)) {
  if (msg.length !== 32 || aux.length !== 32) throw new Error('msg and aux must be 32 bytes');
  const sig = wasmOp('shz_sign', [[0, secret32(seckey)], [32, msg], [64, aux]], 96, 64);
  if (!sig) throw new Error('invalid secret key');
  if (!(await bip340Verify(msg, pubkey(seckey), sig))) throw new Error('signature self-check failed');
  return sig;
}
// BIP341 tweak of a secret key (key-path spend): returns d' with d'·G = taproot output key.
export function taprootTweakSecret(seckey, merkleRoot = null) {
  if (merkleRoot && merkleRoot.length !== 32) throw new Error('merkle root must be 32 bytes');
  const inputs = [[0, secret32(seckey)]];
  if (merkleRoot) inputs.push([32, merkleRoot], [64, Uint8Array.of(1)]);
  const out = wasmOp('shz_tweak_secret', inputs, 96, 32);
  if (!out) throw new Error('invalid secret key or tweak');
  return out;
}
export async function bip340Verify(msg, pk, sig) {
  if (msg.length !== 32 || pk.length !== 32 || sig.length !== 64) return false;
  const pt = liftX(bytesToInt(pk));
  const r = bytesToInt(sig.slice(0, 32)), s = bytesToInt(sig.slice(32));
  if (!pt || r >= P || s >= N) return false;
  const e = bytesToInt(await taggedHash('BIP0340/challenge', sig.slice(0, 32), pk, msg)) % N;
  const rr = add(mul(G, s), mul(pt, N - e));
  return !!rr && rr[1] % 2n === 0n && rr[0] === r;
}

// ---------- BIP341 key-path tweak, bech32m ----------
// Output key for an internal x-only key with no script tree: Q = P + H_TapTweak(P)*G.
export async function taprootOutputKey(internalX) {
  const pt = liftX(bytesToInt(internalX));
  if (!pt) throw new Error('invalid internal key');
  const t = bytesToInt(await taggedHash('TapTweak', internalX));
  if (t >= N) throw new Error('tweak out of range');
  const q = add(pt, mul(G, t));
  if (!q) throw new Error('tweaked key at infinity');
  return intToBytes(q[0]);
}

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
const hrpExpand = (hrp) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [], maxv = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
    acc &= (1 << bits) - 1;
  }
  if (pad && bits) out.push((acc << (to - bits)) & maxv);
  return out;
}
export function bech32mEncode(hrp, witnessVersion, program) {
  const data = [witnessVersion, ...convertBits(program, 8, 5, true)];
  const chk = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (chk >>> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map((d) => CHARSET[d]).join('');
}
export async function p2trAddress(internalX, hrp = 'tb') {
  return bech32mEncode(hrp, 1, await taprootOutputKey(internalX));
}

// ---------- IntentV6 ----------
const TAG_INTENT = 'SHZ/HFT06/INTENT/V1';
const ACTION = { post: 1, take: 2, cancel: 3 };
const SIDE = { long: 1, short: 2 };
const TIER = { standard: 0, intermediate: 1, premium: 2 };
const u8 = (n) => Uint8Array.of(n);
function uN(n, bytes) {
  let v = BigInt(n);
  if (v < 0n || v >= 1n << BigInt(8 * bytes)) throw new RangeError('integer out of range');
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
const u32 = (n) => uN(n, 4);
const u64 = (n) => uN(n, 8);
const ZERO32 = '0'.repeat(64);

// intent: IntentJson fields. template: GET /api/template. entitlementDigest: hex32 or null for standard.
export function intentPreimageParts(intent, template, entitlementDigest) {
  const sc = template.scope;
  const tier = intent.tier ?? 'standard';
  const ent = tier === 'standard' ? ZERO32 : (entitlementDigest || intent.entitlement_digest || ZERO32);
  return [
    unhex(sc.network, 32), u64(sc.epoch), unhex(sc.policy, 32),
    u32(template.router), unhex(intent.channel.txid, 32), u32(intent.channel.vout), unhex(intent.owner, 32),
    u64(intent.sequence), u64(intent.expires_us),
    u8(ACTION[intent.action]), u8(SIDE[intent.side]), u8(TIER[tier]),
    u32(template.tariff_version), unhex(ent, 32), unhex(template.execution_policy, 32),
    u64(intent.quantity), u64(intent.limit_usd), u32(intent.leverage_bps),
    u32(intent.max_fee_ppm), u64(intent.max_fee_sats), u64(intent.max_mark_age_us),
    u8(intent.early_window_opt_in ? 1 : 0), unhex(intent.cancel_target || ZERO32, 32),
  ];
}
export async function intentId(intent, template, entitlementDigest) {
  for (const [name, table, v] of [['action', ACTION, intent.action], ['side', SIDE, intent.side], ['tier', TIER, intent.tier ?? 'standard']])
    if (!(v in table)) throw new Error('bad ' + name);
  return taggedHash(TAG_INTENT, ...intentPreimageParts(intent, template, entitlementDigest));
}
// Returns the IntentJson ready to POST (signature added).
export async function signIntent(intent, template, seckey, entitlementDigest) {
  const id = await intentId(intent, template, entitlementDigest);
  const signature = await bip340Sign(id, seckey);
  const out = { ...intent, signature: hex(signature) };
  if (entitlementDigest) out.entitlement_digest = entitlementDigest;
  return { id: hex(id), intent: out };
}

// 64 bytes of browser entropy, reduced to a nonzero scalar inside WASM.
export function randomKey() {
  for (;;) {
    const e = crypto.getRandomValues(new Uint8Array(64));
    const k = wasmOp('shz_keygen', [[0, e]], 64, 32);
    e.fill(0);
    if (k) return k;
  }
}
