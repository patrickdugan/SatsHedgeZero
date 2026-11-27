// On-chain collateral accounts and epoch settlement packages (docs/SHZ_MVP_COLLATERAL.md).
// ES module for the browser and Node; no dependencies beyond crypto.js.
//
// The trader never signs a sighash the venue hands it: reviewEntry() rebuilds the trader's own
// account scripts from its key, the batcher key and the refund heights, checks its input and its
// output, and computes the BIP-341 SIGHASH_SINGLE|ANYONECANPAY script-path sighash itself.
// signEntry() signs only that locally computed message, in sign.wasm.
import { hex, unhex, concat, sha256, taggedHash, bytesToInt, intToBytes, mul, add, liftX, bip340Sign } from './crypto.js';

export const NUMS = unhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 32);
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = liftX(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n);

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
/** Owner's withdrawal message: tagged("SHZ/WITHDRAW/V1", owner || u32le(len spk) || spk || u64le(time_us)). */
export async function withdrawMsg(owner, spk, timeUs) {
  return taggedHash('SHZ/WITHDRAW/V1', unhex(owner, 32), u32(spk.length), spk, u64(timeUs));
}
/** Body of POST /api/settlement/withdraw: the whole account pays out to `address` at the next settlement. */
export async function signWithdrawal({ owner, address, network, timeUs = Date.now() * 1000 }, seckey) {
  const spk = decodeAddress(address.trim(), HRP[network]);
  const sig = await bip340Sign(await withdrawMsg(owner, spk, timeUs), seckey);
  return { owner, spk: hex(spk), address: address.trim(), time_us: timeUs, sig: hex(sig) };
}

// ---------- settlement packages (co-sign contract v1) ----------
/** SIGHASH_SINGLE|ANYONECANPAY sighash of one account entry: its own input and its own output only. */
export async function entrySighash(tx, entry) {
  const i = entry.input, o = entry.output;
  const t = { version: tx?.version ?? 2, locktime: tx?.locktime ?? 0, inputs: [{ txid: unhex(i.txid, 32).reverse(), vout: i.vout, sequence: i.sequence ?? 0xfffffffd }], outputs: [{ value: BigInt(o.value), spk: unhex(o.spk) }] };
  return tapSighash(t, [{ value: BigInt(i.amount), spk: unhex(i.spk) }], 0, 0x83, unhex(i.leaf_hash || hex(await tapleaf(unhex(i.leaf))), 32));
}

/**
 * Check the trader's entry of a settlement package (GET /api/settlement/package?owner=) and return
 * what it pays. `expect`: { batcherKey, account: {outpoint, value, refund_height}, withdrawAddress, network }.
 * Throws when the input is not the trader's collateral, the output is not its account script or its
 * withdrawal address, the payout is not input + carry + net, or the venue's sighash differs.
 */
export async function reviewEntry(pkg, owner, expect = {}) {
  const e = pkg.account;
  if (!e || e.owner !== owner) throw new Error('this key has no input in the package');
  if (e.sighash_type !== 0x83) throw new Error('only SIGHASH_SINGLE|ANYONECANPAY entries are signed here');
  const B = pkg.batcher_key;
  if (expect.batcherKey && expect.batcherKey !== B) throw new Error('package batcher key differs from the venue status');
  const net = expect.network || pkg.network;
  const acct = expect.account;
  const hIn = acct?.refund_height;
  if (hIn === undefined) throw new Error('your account is not loaded');
  const sIn = await accountScript(owner, B, hIn);
  if (e.input.spk !== hex(sIn.spk)) throw new Error('your input is not your collateral account');
  if (e.input.leaf !== hex(sIn.settle)) throw new Error('the input leaf is not your settle leaf');
  if (acct.outpoint && (e.input.txid !== acct.outpoint.txid || e.input.vout !== acct.outpoint.vout)) throw new Error('your input spends another outpoint than your collateral');
  if (acct.value !== undefined && e.input.amount !== acct.value) throw new Error('your input amount differs from your collateral');
  const o = e.output;
  let rollover = null, withdraw = null;
  if (o.kind === 'roll') {
    if (o.spk !== hex((await accountScript(owner, B, o.refund_height)).spk)) throw new Error('the roll output is not your collateral account');
    rollover = { value: BigInt(o.value), refundHeight: o.refund_height };
  } else if (o.kind === 'withdraw') {
    if (!expect.withdrawAddress) throw new Error('payout to an address you did not ask for');
    if (o.spk !== hex(decodeAddress(expect.withdrawAddress, HRP[net]))) throw new Error('the payout does not go to your withdrawal address');
    withdraw = { value: BigInt(o.value), address: expect.withdrawAddress };
  } else throw new Error('unknown output kind');
  const carryNet = BigInt(e.carry_in || 0) + BigInt(e.net || 0);
  if (BigInt(o.value) !== BigInt(e.input.amount) + carryNet) throw new Error(`payout ${o.value} differs from collateral ${e.input.amount} plus net ${carryNet}`);
  const sighash = await entrySighash(pkg.tx, e);
  if (e.sighash && e.sighash !== hex(sighash)) throw new Error('package sighash differs from the locally computed one');
  if (pkg.venue?.sighash && pkg.venue.sighash !== hex(sighash)) throw new Error('venue sighash differs from the locally computed one');
  return {
    epoch: pkg.epoch, segment: pkg.segment, firstSeq: pkg.first_seq, lastSeq: pkg.last_seq, deadlineUs: pkg.deadline_us,
    valueIn: BigInt(e.input.amount), net: carryNet, rows: e.rows || [], batches: pkg.venue?.batches || (e.rows || []).map((r) => r.seq),
    rollover, withdraw, sighash, refundHeightIn: hIn, signed: !!e.signed,
  };
}
/** The trader's 0x83 signature over the locally computed sighash: body of POST /api/settlement/signature. */
export async function signEntry(pkg, owner, seckey, expect = {}) {
  const r = await reviewEntry(pkg, owner, expect);
  const sig = await bip340Sign(r.sighash, seckey);
  return { review: r, body: { epoch: pkg.epoch, segment: pkg.segment, owner, sig: hex(concat(sig, Uint8Array.of(0x83))) } };
}

/** Single-leaf NUMS-keyed P2TR output of `script` (e.g. the operator's `<O> CHECKSIG` liquidity). */
export async function scriptOutput(script) {
  const tw = bytesToInt(await taggedHash('TapTweak', NUMS, await tapleaf(script)));
  const q = add(liftX(bytesToInt(NUMS)), mul(G, tw));
  return concat(Uint8Array.of(0x51, 0x20), intToBytes(q[0]));
}
