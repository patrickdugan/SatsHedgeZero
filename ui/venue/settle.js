// On-chain collateral accounts and epoch settlement packages (docs/SHZ_MVP_COLLATERAL.md).
// ES module for the browser and Node; no dependencies beyond crypto.js.
//
// The trader never signs a sighash the venue hands it: reviewPackage() parses the unsigned
// settlement, rebuilds the trader's own account scripts from its key, the batcher key and the
// refund heights, checks its input and outputs, and computes the BIP-341 script-path sighash
// itself. signPackage() signs only that locally computed message, in sign.wasm.
import { hex, unhex, concat, sha256, taggedHash, bytesToInt, intToBytes, mul, add, liftX, bip340Sign } from './crypto.js';

export const NUMS = unhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 32);
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = liftX(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n);
const HASH_TYPES = new Set([0x00, 0x01, 0x81, 0x83]);

export const compact = (n) => n < 0xfd ? Uint8Array.of(n) : n <= 0xffff ? Uint8Array.of(0xfd, n & 255, n >> 8) : Uint8Array.of(0xfe, n & 255, (n >> 8) & 255, (n >> 16) & 255, n >>> 24);
const u32 = (n) => Uint8Array.of(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, n >>> 24);
const u64 = (n) => { const b = new Uint8Array(8); let x = BigInt(n); for (let i = 0; i < 8; i++) { b[i] = Number(x & 255n); x >>= 8n; } return b; };
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Minimal CScriptNum push of a non-negative number. */
export function scriptNum(n) {
  if (n === 0) return Uint8Array.of(0);
  if (n <= 16) return Uint8Array.of(0x50 + n);
  const b = [];
  let x = n;
  while (x > 0) { b.push(x & 255); x = Math.floor(x / 256); }
  if (b[b.length - 1] & 0x80) b.push(0);
  return Uint8Array.of(b.length, ...b);
}
export const tapleaf = (script) => taggedHash('TapLeaf', Uint8Array.of(0xc0), compact(script.length), script);
async function branch(a, b) {
  const [x, y] = hex(a) < hex(b) ? [a, b] : [b, a];
  return taggedHash('TapBranch', x, y);
}

/** account(T, B, h): settle `<T> CHECKSIGVERIFY <B> CHECKSIG`, refund `<h> CLTV DROP <T> CHECKSIG`, NUMS key. */
export async function accountScript(T, B, refundHeight) {
  const t = typeof T === 'string' ? unhex(T, 32) : T, b = typeof B === 'string' ? unhex(B, 32) : B;
  const settle = concat(Uint8Array.of(0x20), t, Uint8Array.of(0xad, 0x20), b, Uint8Array.of(0xac));
  const refund = concat(scriptNum(refundHeight), Uint8Array.of(0xb1, 0x75, 0x20), t, Uint8Array.of(0xac));
  const [ls, lr] = [await tapleaf(settle), await tapleaf(refund)];
  const root = await branch(ls, lr);
  const tw = bytesToInt(await taggedHash('TapTweak', NUMS, root));
  if (tw >= N) throw new Error('tweak out of range');
  const q = add(liftX(bytesToInt(NUMS)), mul(G, tw));
  const outputKey = intToBytes(q[0]), parity = Number(q[1] & 1n);
  return {
    settle, refund, outputKey, settleLeaf: ls, refundLeaf: lr,
    spk: concat(Uint8Array.of(0x51, 0x20), outputKey),
    control: (leaf) => concat(Uint8Array.of(0xc0 | parity), NUMS, leaf === 0 ? lr : ls),
  };
}

// ---------- transactions ----------
/** Unsigned transaction (legacy serialization, empty scriptSigs). Values are BigInt. */
export function parseTx(raw) {
  const b = typeof raw === 'string' ? unhex(raw) : raw;
  let p = 0;
  const take = (n) => { if (p + n > b.length) throw new Error('transaction truncated'); const s = b.slice(p, p + n); p += n; return s; };
  const rd32 = () => { const s = take(4); return (s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24)) >>> 0; };
  const rd64 = () => { const s = take(8); let x = 0n; for (let i = 7; i >= 0; i--) x = (x << 8n) | BigInt(s[i]); return x; };
  const rdc = () => { const f = take(1)[0]; if (f < 0xfd) return f; if (f === 0xfd) { const s = take(2); return s[0] | (s[1] << 8); } if (f === 0xfe) return rd32(); throw new Error('oversized compact size'); };
  const version = rd32();
  const nin = rdc();
  if (nin === 0) throw new Error('witness serialization is not an unsigned transaction');
  const inputs = [];
  for (let i = 0; i < nin; i++) {
    const txid = take(32), vout = rd32();
    if (rdc() !== 0) throw new Error('scriptSig must be empty');
    inputs.push({ txid, vout, sequence: rd32() });
  }
  const nout = rdc(), outputs = [];
  for (let i = 0; i < nout; i++) { const value = rd64(); outputs.push({ value, spk: take(rdc()) }); }
  const locktime = rd32();
  if (p !== b.length) throw new Error('trailing bytes after transaction');
  return { version, inputs, outputs, locktime };
}
const serOut = (o) => concat(u64(o.value), compact(o.spk.length), o.spk);
export function serializeTx(tx) {
  return concat(u32(tx.version), compact(tx.inputs.length), ...tx.inputs.map((i) => concat(i.txid, u32(i.vout), Uint8Array.of(0), u32(i.sequence))),
    compact(tx.outputs.length), ...tx.outputs.map(serOut), u32(tx.locktime));
}
/** Display-order txid hex. */
export async function txid(tx) {
  const d = await sha256(await sha256(serializeTx(tx)));
  return hex(d.slice().reverse());
}
export const displayTxid = (internal) => hex(internal.slice().reverse());

/** BIP-341 script-path signature message (ext_flag 1, no annex, key version 0, no codeseparator). */
export async function tapSighash(tx, prevouts, i, hashType, leafHash) {
  if (![0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83].includes(hashType)) throw new Error('unsupported hash type');
  if (prevouts.length !== tx.inputs.length) throw new Error('prevouts do not match the inputs');
  const acp = (hashType & 0x80) !== 0, outType = hashType === 0 ? 1 : hashType & 3;
  const parts = [Uint8Array.of(0, hashType), u32(tx.version), u32(tx.locktime)];
  if (!acp) {
    parts.push(await sha256(concat(...tx.inputs.map((x) => concat(x.txid, u32(x.vout))))));
    parts.push(await sha256(concat(...prevouts.map((p) => u64(p.value)))));
    parts.push(await sha256(concat(...prevouts.map((p) => concat(compact(p.spk.length), p.spk)))));
    parts.push(await sha256(concat(...tx.inputs.map((x) => u32(x.sequence)))));
  }
  if (outType === 1) parts.push(await sha256(concat(...tx.outputs.map(serOut))));
  parts.push(Uint8Array.of(2));
  if (acp) {
    const x = tx.inputs[i], p = prevouts[i];
    parts.push(x.txid, u32(x.vout), u64(p.value), compact(p.spk.length), p.spk, u32(x.sequence));
  } else parts.push(u32(i));
  if (outType === 3) {
    if (!tx.outputs[i]) throw new Error('SIGHASH_SINGLE without a matching output');
    parts.push(await sha256(serOut(tx.outputs[i])));
  }
  parts.push(leafHash, Uint8Array.of(0), u32(0xffffffff));
  return taggedHash('TapSighash', ...parts);
}

// ---------- addresses ----------
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
export const HRP = { regtest: 'bcrt', testnet4: 'tb' };

/** scriptPubKey of a segwit address with prefix `hrp` (bech32 for v0, bech32m for v1+). */
export function decodeAddress(addr, hrp) {
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) throw new Error('mixed-case address');
  const s = addr.toLowerCase(), k = s.lastIndexOf('1');
  if (k < 1 || s.slice(0, k) !== hrp) throw new Error(`address must start with ${hrp}1`);
  const five = [...s.slice(k + 1)].map((c) => { const i = CHARSET.indexOf(c); if (i < 0) throw new Error('bad bech32 character'); return i; });
  if (five.length < 7) throw new Error('address too short');
  const ver = five[0];
  if (polymod([...hrpExpand(hrp), ...five]) !== (ver === 0 ? 1 : 0x2bc830a3)) throw new Error('address checksum does not verify');
  let acc = 0, bits = 0; const prog = [];
  for (const v of five.slice(1, -6)) { acc = (acc << 5) | v; bits += 5; if (bits >= 8) { bits -= 8; prog.push((acc >> bits) & 255); } acc &= (1 << bits) - 1; }
  if (bits >= 5 || acc !== 0) throw new Error('address has non-zero padding');
  if (ver > 16 || prog.length < 2 || prog.length > 40 || (ver === 0 && prog.length !== 20 && prog.length !== 32)) throw new Error('invalid witness program');
  return Uint8Array.of(ver === 0 ? 0 : 0x50 + ver, prog.length, ...prog);
}

// ---------- withdrawals ----------
export async function withdrawDigest(owner, sats, spk, nonceUs) {
  return taggedHash('LIGHTNINGER/WITHDRAW/V1', unhex(owner, 32), u64(sats), Uint8Array.of(spk.length), spk, u64(nonceUs));
}
/** Body of POST /api/collateral/withdraw, signed by the owner. */
export async function signWithdrawal({ owner, sats, address, network, nonceUs = Date.now() * 1000 }, seckey) {
  const spk = decodeAddress(address.trim(), HRP[network]);
  const sig = await bip340Sign(await withdrawDigest(owner, sats, spk, nonceUs), seckey);
  return { owner, sats, address: address.trim(), nonce_us: nonceUs, signature: hex(sig) };
}

// ---------- settlement packages ----------
/**
 * Check the settlement package from the trader's side and return what it pays.
 * `expect` (optional): { valueIn, refundHeightIn, withdrawAddress, network } the client already knows.
 * Throws when anything about the trader's own input or outputs differs.
 */
export async function reviewPackage(pkg, owner, expect = {}) {
  const a = (pkg.accounts || []).find((x) => x.owner === owner);
  if (!a) throw new Error('this key has no input in the package');
  if (!HASH_TYPES.has(a.hash_type)) throw new Error(`hash type ${a.hash_type} is not allowed`);
  const tx = parseTx(pkg.tx);
  const B = pkg.batcher_key;
  if (expect.batcherKey && expect.batcherKey !== B) throw new Error('package batcher key differs from the venue status');
  const prevouts = pkg.prevouts.map((p) => ({ value: BigInt(p.value), spk: unhex(p.spk) }));
  const inScript = await accountScript(owner, B, a.refund_height_in);
  const pin = prevouts[a.input];
  if (!pin || !eq(pin.spk, inScript.spk)) throw new Error('your input is not your collateral account');
  if (expect.valueIn !== undefined && pin.value !== BigInt(expect.valueIn)) throw new Error('your input amount differs from your account');
  if (expect.refundHeightIn !== undefined && a.refund_height_in !== expect.refundHeightIn) throw new Error('your input refund height differs from your account');
  if (expect.outpoint && (displayTxid(tx.inputs[a.input].txid) !== expect.outpoint.txid || tx.inputs[a.input].vout !== expect.outpoint.vout)) throw new Error('your input spends another outpoint');
  const mine = a.outputs.map((i) => ({ index: i, ...tx.outputs[i] }));
  if (mine.some((o) => !o.spk)) throw new Error('output index out of range');
  if (a.hash_type === 0x83 && !(a.outputs.length === 1 && a.outputs[0] === a.input)) throw new Error('SIGHASH_SINGLE|ACP needs your one output at your input index');
  const outScript = await accountScript(owner, B, pkg.refund_height);
  let rollover = null, withdraw = null;
  for (const o of mine) {
    if (eq(o.spk, outScript.spk) && !rollover) rollover = { index: o.index, value: o.value, refundHeight: pkg.refund_height };
    else if (!withdraw) withdraw = { index: o.index, value: o.value, spk: o.spk };
    else throw new Error('more than one output of yours is not your collateral account');
  }
  if (withdraw && expect.withdrawAddress) {
    const want = decodeAddress(expect.withdrawAddress, HRP[expect.network || pkg.network]);
    if (!eq(want, withdraw.spk)) throw new Error('withdrawal output does not pay your withdrawal address');
  }
  if (withdraw && !expect.withdrawAddress && a.withdraw?.address === undefined) throw new Error('unexpected payout output');
  const out = (rollover?.value || 0n) + (withdraw?.value || 0n);
  if (out !== pin.value + BigInt(a.net_sats)) throw new Error(`outputs ${out} differ from input ${pin.value} plus net ${a.net_sats}`);
  const sighash = await tapSighash(tx, prevouts, a.input, a.hash_type, inScript.settleLeaf);
  if (a.sighash && a.sighash !== hex(sighash)) throw new Error('venue sighash differs from the locally computed one');
  const fee = prevouts.reduce((s, p) => s + p.value, 0n) - tx.outputs.reduce((s, o) => s + o.value, 0n);
  return {
    packageId: pkg.package_id, txid: await txid(tx), input: a.input, hashType: a.hash_type, sighash,
    valueIn: pin.value, net: BigInt(a.net_sats), batches: a.batches, fromBatch: a.from_batch, throughBatch: pkg.through_batch,
    rollover, withdraw: withdraw && { ...withdraw, address: a.withdraw?.address }, refundHeightIn: a.refund_height_in,
    coversAllOutputs: a.hash_type !== 0x83, fee, inputs: tx.inputs.length, outputs: tx.outputs.length, eventId: pkg.event_id,
  };
}
/** Signature of the trader's own input over the locally computed sighash (64 bytes + hash type). */
export async function signPackage(pkg, owner, seckey, expect = {}) {
  const r = await reviewPackage(pkg, owner, expect);
  const sig = await bip340Sign(r.sighash, seckey);
  return { review: r, body: { package_id: pkg.package_id, owner, signature: hex(r.hashType === 0 ? sig : concat(sig, Uint8Array.of(r.hashType))) } };
}
