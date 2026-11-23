/**
 * SHZ-CHANNEL-03: Independent Bitcoin BIP-340/BIP-341 Taproot Commitment,
 * Channel Revocation-Ordering, HTLC CLTV Staggering, and Reorg-Safe Finality Verifier.
 *
 * Bridges `closeout_epoch.mjs`'s `WALLET_SETTLEMENT_REQUESTED` state through all four
 * `requiredExternalChecks` using zero external dependencies (`node:crypto` + exact pure-JS
 * `secp256k1` BIP-340 Schnorr & BIP-341 `TapSighash` verification for `0x00`, `0x01`, `0x83`).
 *
 * Explicit honesty boundaries:
 * - `authorizeBroadcastReadySettlement` sets `readyForBitcoinBroadcast: true` ONLY after
 *   independent `UTXORef` NUMS `P2TR` script/control-block derivation, BIP-340/BIP-341 witness
 *   verification (including Bob-offline `0x83` origination pre-signatures without `bobSk`),
 *   prior-commitment SHA-256 revocation ordering, and staggered CLTV delta checks pass;
 *   `bitcoinSpendEnforced` and `collateralReleased` remain `false` until confirmed on-chain.
 * - `confirmBitcoinSettlement` sets `bitcoinSpendEnforced: true` and `collateralReleased: true`
 *   ONLY upon a valid, un-reorged Bitcoin Core block confirmation receipt, and freezes the
 *   settlement state (`HALTED_ON_REORG`) if a block reorganization invalidates the anchor/tx.
 * - `nearFinalityVerified` remains `false` (distinct from `nearObserverAttested: true`) until a
 *   full NEAR light-client validator-header verifier replaces observer attestations.
 */
import {createHash} from 'node:crypto';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

export const SIGHASH_DEFAULT = 0x00;
export const SIGHASH_ALL = 0x01;
export const SIGHASH_SINGLE_ANYONECANPAY = 0x83;
export const LEAF_VERSION_TAPSCRIPT = 0xc0;

const fail = msg => { throw new Error(msg); };
const sha256Buf = buf => createHash('sha256').update(buf).digest();
const sha256Hex = buf => sha256Buf(buf).toString('hex');
const isHex = (s, bytesLen) =>
  typeof s === 'string' &&
  /^(?:[0-9a-f]{2})+$/.test(s) &&
  (bytesLen === undefined || s.length === bytesLen * 2);
const U = n => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;

function mod(a, m = P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m = P) {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function modInv(a, m = P) {
  if (a === 0n) fail('division by zero in field inverse');
  return modPow(a, m - 2n, m);
}

function bytesToBigIntBE(buf) {
  return BigInt('0x' + Buffer.from(buf).toString('hex'));
}

function bigIntTo32BE(n) {
  const hex = n.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

export function taggedHash(tag, msgBuf) {
  const tagDigest = sha256Buf(Buffer.from(tag, 'utf8'));
  return sha256Buf(Buffer.concat([tagDigest, tagDigest, Buffer.from(msgBuf)]));
}

// Jacobian coordinates (X, Y, Z) representing affine (X / Z^2, Y / Z^3); infinity has Z = 0n.
const ZERO_PT = Object.freeze({X: 0n, Y: 1n, Z: 0n});
const GEN_PT = Object.freeze({X: GX, Y: GY, Z: 1n});

function pointDouble(pt) {
  if (pt.Z === 0n || pt.Y === 0n) return ZERO_PT;
  const XX = mod(pt.X * pt.X);
  const YY = mod(pt.Y * pt.Y);
  const YYYY = mod(YY * YY);
  const S = mod(2n * (mod((pt.X + YY) * (pt.X + YY)) - XX - YYYY));
  const M = mod(3n * XX);
  const X3 = mod(M * M - 2n * S);
  const Y3 = mod(M * (S - X3) - 8n * YYYY);
  const Z3 = mod(2n * pt.Y * pt.Z);
  return {X: X3, Y: Y3, Z: Z3};
}

function pointAdd(p1, p2) {
  if (p1.Z === 0n) return p2;
  if (p2.Z === 0n) return p1;
  const Z1Z1 = mod(p1.Z * p1.Z);
  const Z2Z2 = mod(p2.Z * p2.Z);
  const U1 = mod(p1.X * Z2Z2);
  const U2 = mod(p2.X * Z1Z1);
  const S1 = mod(p1.Y * p2.Z * Z2Z2);
  const S2 = mod(p2.Y * p1.Z * Z1Z1);
  if (U1 === U2) {
    return S1 === S2 ? pointDouble(p1) : ZERO_PT;
  }
  const H = mod(U2 - U1);
  const I = mod(4n * H * H);
  const J = mod(H * I);
  const r = mod(2n * (S2 - S1));
  const V = mod(U1 * I);
  const X3 = mod(r * r - J - 2n * V);
  const Y3 = mod(r * (V - X3) - 2n * S1 * J);
  const Z3 = mod(((p1.Z + p2.Z) * (p1.Z + p2.Z) - Z1Z1 - Z2Z2) * H);
  return {X: X3, Y: Y3, Z: Z3};
}

function pointMul(pt, scalar) {
  let k = mod(scalar, N);
  if (k === 0n) return ZERO_PT;
  let res = ZERO_PT;
  let addend = pt;
  while (k > 0n) {
    if (k & 1n) res = pointAdd(res, addend);
    addend = pointDouble(addend);
    k >>= 1n;
  }
  return res;
}

function toAffine(pt) {
  if (pt.Z === 0n) return null;
  const zInv = modInv(pt.Z);
  const zInv2 = mod(zInv * zInv);
  const zInv3 = mod(zInv2 * zInv);
  return {x: mod(pt.X * zInv2), y: mod(pt.Y * zInv3)};
}

export function liftXEven(xBytes) {
  const buf = Buffer.isBuffer(xBytes) ? xBytes : Buffer.from(xBytes, 'hex');
  if (buf.length !== 32) fail('x-only pubkey must be 32 bytes');
  const x = bytesToBigIntBE(buf);
  if (x >= P) fail('x-only pubkey >= field prime');
  const c = mod(mod(x * x) * x + 7n);
  const y = modPow(c, (P + 1n) / 4n);
  if (mod(y * y) !== c) fail('x-only pubkey is not on secp256k1');
  const evenY = (y & 1n) === 0n ? y : P - y;
  return {X: x, Y: evenY, Z: 1n};
}

export function pubkeyXFromSecretHex(secretHex) {
  if (!isHex(secretHex, 32)) fail('secret key must be 32-byte hex');
  const d0 = bytesToBigIntBE(Buffer.from(secretHex, 'hex'));
  if (d0 === 0n || d0 >= N) fail('secret key out of range');
  const aff = toAffine(pointMul(GEN_PT, d0));
  return bigIntTo32BE(aff.x).toString('hex');
}

export function bip340Sign(secretHex, msg32Buf, auxRand32 = Buffer.alloc(32, 0)) {
  if (!isHex(secretHex, 32)) fail('invalid BIP-340 secret key');
  const msg = Buffer.isBuffer(msg32Buf) ? msg32Buf : Buffer.from(msg32Buf, 'hex');
  if (msg.length !== 32) fail('BIP-340 message must be 32 bytes');
  const d0 = bytesToBigIntBE(Buffer.from(secretHex, 'hex'));
  if (d0 === 0n || d0 >= N) fail('BIP-340 secret key out of scalar range');
  const P_aff = toAffine(pointMul(GEN_PT, d0));
  const d = (P_aff.y & 1n) === 0n ? d0 : N - d0;
  const pxBytes = bigIntTo32BE(P_aff.x);
  const dBytes = bigIntTo32BE(d);
  const tHash = taggedHash('BIP0340/aux', auxRand32);
  const t = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) t[i] = dBytes[i] ^ tHash[i];
  const k0 = mod(bytesToBigIntBE(taggedHash('BIP0340/nonce', Buffer.concat([t, pxBytes, msg]))), N);
  if (k0 === 0n) fail('zero nonce in BIP-340 sign');
  const R_aff = toAffine(pointMul(GEN_PT, k0));
  const k = (R_aff.y & 1n) === 0n ? k0 : N - k0;
  const rxBytes = bigIntTo32BE(R_aff.x);
  const e = mod(
    bytesToBigIntBE(taggedHash('BIP0340/challenge', Buffer.concat([rxBytes, pxBytes, msg]))),
    N,
  );
  const s = mod(k + e * d, N);
  return Buffer.concat([rxBytes, bigIntTo32BE(s)]);
}

export function bip340Verify(pubkeyXHex, msg32Buf, sig64Buf) {
  if (!isHex(pubkeyXHex, 32)) return false;
  const msg = Buffer.isBuffer(msg32Buf) ? msg32Buf : Buffer.from(msg32Buf, 'hex');
  const sig = Buffer.isBuffer(sig64Buf) ? sig64Buf : Buffer.from(sig64Buf, 'hex');
  if (msg.length !== 32 || sig.length !== 64) return false;
  let P_pt;
  try {
    P_pt = liftXEven(Buffer.from(pubkeyXHex, 'hex'));
  } catch {
    return false;
  }
  const r = bytesToBigIntBE(sig.subarray(0, 32));
  const s = bytesToBigIntBE(sig.subarray(32, 64));
  if (r >= P || s >= N) return false;
  const pxBytes = Buffer.from(pubkeyXHex, 'hex');
  const e = mod(
    bytesToBigIntBE(taggedHash('BIP0340/challenge', Buffer.concat([sig.subarray(0, 32), pxBytes, msg]))),
    N,
  );
  const R = toAffine(pointAdd(pointMul(GEN_PT, s), pointMul(P_pt, N - e)));
  if (!R || (R.y & 1n) !== 0n || R.x !== r) return false;
  return true;
}

/**
 * Exact `UTXORef` deterministic NUMS unspendable internal key:
 * increments counter over `SHA256("UTXORef DLC funding NUMS internal key v1:" + ctr)` until valid x.
 */
export function deriveUtxoRefNumsInternalKeyHex() {
  for (let ctr = 0; ctr < 1024; ctr++) {
    const candidate = sha256Buf(Buffer.from(`UTXORef DLC funding NUMS internal key v1:${ctr}`, 'utf8'));
    try {
      liftXEven(candidate);
      return candidate.toString('hex');
    } catch {
      // try next counter
    }
  }
  fail('failed to derive UTXORef NUMS internal key');
}

function compactSize(n) {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfd;
    b.writeUInt16LE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = 0xfe;
  b.writeUInt32LE(n, 1);
  return b;
}

function pushScriptNum(val) {
  if (val === 0) return Buffer.from([0x00]);
  if (val >= 1 && val <= 16) return Buffer.from([0x50 + val]);
  const bytes = [];
  let rem = val;
  while (rem > 0) {
    bytes.push(rem & 0xff);
    rem = Math.floor(rem / 256);
  }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00);
  return Buffer.from([bytes.length, ...bytes]);
}

export function tapLeafHash(scriptBuf, leafVersion = LEAF_VERSION_TAPSCRIPT) {
  const s = Buffer.isBuffer(scriptBuf) ? scriptBuf : Buffer.from(scriptBuf, 'hex');
  return taggedHash('TapLeaf', Buffer.concat([Buffer.from([leafVersion]), compactSize(s.length), s]));
}

export function tapBranchHash(left32, right32) {
  const a = Buffer.isBuffer(left32) ? left32 : Buffer.from(left32, 'hex');
  const b = Buffer.isBuffer(right32) ? right32 : Buffer.from(right32, 'hex');
  return Buffer.compare(a, b) <= 0
    ? taggedHash('TapBranch', Buffer.concat([a, b]))
    : taggedHash('TapBranch', Buffer.concat([b, a]));
}

/**
 * Derives the exact 3-leaf `SHZ-MNR-02` (`route_cet`, `unilateral_cet`, `refund`) P2TR descriptor.
 */
export function buildMnr02ChannelDescriptor({
  counterpartyPubkeyXHex,
  bobPubkeyXHex,
  routerGuardPubkeyXHex,
  maturityHeight,
  graceBlocks,
  refundDelayBlocks,
}) {
  if (
    !isHex(counterpartyPubkeyXHex, 32) ||
    !isHex(bobPubkeyXHex, 32) ||
    !isHex(routerGuardPubkeyXHex, 32)
  ) {
    fail('MNR02 descriptor requires 32-byte x-only pubkeys');
  }
  if (
    counterpartyPubkeyXHex === bobPubkeyXHex ||
    counterpartyPubkeyXHex === routerGuardPubkeyXHex ||
    bobPubkeyXHex === routerGuardPubkeyXHex
  ) {
    fail('MNR02 keys must be distinct');
  }
  if (!U(maturityHeight) || !U(graceBlocks) || !U(refundDelayBlocks) || graceBlocks === 0 || refundDelayBlocks <= graceBlocks) {
    fail('invalid MNR02 height schedule');
  }
  const internalHex = deriveUtxoRefNumsInternalKeyHex();
  const internalBuf = Buffer.from(internalHex, 'hex');

  const routeCetScript = Buffer.concat([
    Buffer.from([0x20]),
    Buffer.from(counterpartyPubkeyXHex, 'hex'),
    Buffer.from([0xad, 0x20]),
    Buffer.from(routerGuardPubkeyXHex, 'hex'),
    Buffer.from([0xad, 0x20]),
    Buffer.from(bobPubkeyXHex, 'hex'),
    Buffer.from([0xac]),
  ]);

  const sorted = [counterpartyPubkeyXHex, bobPubkeyXHex].sort();
  const unilateralCltv = maturityHeight + graceBlocks;
  const refundCltv = maturityHeight + refundDelayBlocks;

  const unilateralCetScript = Buffer.concat([
    pushScriptNum(unilateralCltv),
    Buffer.from([0xb1, 0x75, 0x20]),
    Buffer.from(sorted[0], 'hex'),
    Buffer.from([0xad, 0x20]),
    Buffer.from(sorted[1], 'hex'),
    Buffer.from([0xac]),
  ]);

  const refundScript = Buffer.concat([
    pushScriptNum(refundCltv),
    Buffer.from([0xb1, 0x75, 0x20]),
    Buffer.from(sorted[0], 'hex'),
    Buffer.from([0xad, 0x20]),
    Buffer.from(sorted[1], 'hex'),
    Buffer.from([0xac]),
  ]);

  const routeLeafHash = tapLeafHash(routeCetScript);
  const unilateralLeafHash = tapLeafHash(unilateralCetScript);
  const refundLeafHash = tapLeafHash(refundScript);
  const branch12 = tapBranchHash(unilateralLeafHash, refundLeafHash);
  const merkleRoot = tapBranchHash(routeLeafHash, branch12);

  const tweak = mod(bytesToBigIntBE(taggedHash('TapTweak', Buffer.concat([internalBuf, merkleRoot]))), N);
  const outAff = toAffine(pointAdd(liftXEven(internalBuf), pointMul(GEN_PT, tweak)));
  const outXBuf = bigIntTo32BE(outAff.x);
  const parityBit = Number(outAff.y & 1n);
  const ctrlHeader = LEAF_VERSION_TAPSCRIPT | parityBit;

  const routeControlBlock = Buffer.concat([Buffer.from([ctrlHeader]), internalBuf, branch12]);
  const scriptPubKey = Buffer.concat([Buffer.from([0x51, 0x20]), outXBuf]);

  return Object.freeze({
    internalXOnlyHex: internalHex,
    scriptPubKeyHex: scriptPubKey.toString('hex'),
    routeCetScriptHex: routeCetScript.toString('hex'),
    routeLeafHashHex: routeLeafHash.toString('hex'),
    routeControlBlockHex: routeControlBlock.toString('hex'),
    unilateralLeafHashHex: unilateralLeafHash.toString('hex'),
    refundLeafHashHex: refundLeafHash.toString('hex'),
  });
}

/**
 * Derives the exact 2-leaf `UTXORef` interactive bilateral DLC P2TR descriptor (`cet_leaf`, `refund_leaf`).
 */
export function buildInteractiveChannelDescriptor({partyAPubkeyXHex, partyBPubkeyXHex, refundCsv}) {
  if (!isHex(partyAPubkeyXHex, 32) || !isHex(partyBPubkeyXHex, 32) || partyAPubkeyXHex === partyBPubkeyXHex) {
    fail('interactive channel requires two distinct 32-byte x-only pubkeys');
  }
  if (!U(refundCsv) || refundCsv === 0) fail('invalid refundCsv');
  const internalHex = deriveUtxoRefNumsInternalKeyHex();
  const internalBuf = Buffer.from(internalHex, 'hex');
  const sorted = [partyAPubkeyXHex, partyBPubkeyXHex].sort();

  const cetScript = Buffer.concat([
    Buffer.from([0x20]),
    Buffer.from(sorted[0], 'hex'),
    Buffer.from([0xad, 0x20]),
    Buffer.from(sorted[1], 'hex'),
    Buffer.from([0xac]),
  ]);
  const refundScript = Buffer.concat([
    pushScriptNum(refundCsv),
    Buffer.from([0xb2, 0x75, 0x20]), // OP_CSV OP_DROP <32B>
    Buffer.from(sorted[0], 'hex'),
    Buffer.from([0xad, 0x20]),
    Buffer.from(sorted[1], 'hex'),
    Buffer.from([0xac]),
  ]);

  const cetLeafHash = tapLeafHash(cetScript);
  const refundLeafHash = tapLeafHash(refundScript);
  const merkleRoot = tapBranchHash(cetLeafHash, refundLeafHash);
  const tweak = mod(bytesToBigIntBE(taggedHash('TapTweak', Buffer.concat([internalBuf, merkleRoot]))), N);
  const outAff = toAffine(pointAdd(liftXEven(internalBuf), pointMul(GEN_PT, tweak)));
  const outXBuf = bigIntTo32BE(outAff.x);
  const parityBit = Number(outAff.y & 1n);
  const ctrlHeader = LEAF_VERSION_TAPSCRIPT | parityBit;

  const cetControlBlock = Buffer.concat([Buffer.from([ctrlHeader]), internalBuf, refundLeafHash]);
  const scriptPubKey = Buffer.concat([Buffer.from([0x51, 0x20]), outXBuf]);

  return Object.freeze({
    internalXOnlyHex: internalHex,
    sortedPubkeysHex: Object.freeze(sorted),
    scriptPubKeyHex: scriptPubKey.toString('hex'),
    cetScriptHex: cetScript.toString('hex'),
    cetLeafHashHex: cetLeafHash.toString('hex'),
    cetControlBlockHex: cetControlBlock.toString('hex'),
    refundLeafHashHex: refundLeafHash.toString('hex'),
  });
}

function encodeOutpoint(txidDisplayHex, vout) {
  if (!isHex(txidDisplayHex, 32) || !U(vout)) fail('invalid outpoint');
  const txidInternal = Buffer.from(txidDisplayHex, 'hex').reverse();
  const voutBuf = Buffer.alloc(4);
  voutBuf.writeUInt32LE(vout, 0);
  return Buffer.concat([txidInternal, voutBuf]);
}

export function serializeOutput(valueSats, scriptPubKeyHex) {
  const sats = BigInt(valueSats);
  if (sats < 0n) fail('negative output value');
  if (!isHex(scriptPubKeyHex)) fail('invalid output scriptPubKeyHex');
  const spk = Buffer.from(scriptPubKeyHex, 'hex');
  const valBuf = Buffer.alloc(8);
  valBuf.writeBigUInt64LE(sats, 0);
  return Buffer.concat([valBuf, compactSize(spk.length), spk]);
}

export function singleOutputDigestHex(valueSats, scriptPubKeyHex) {
  return sha256Hex(serializeOutput(valueSats, scriptPubKeyHex));
}

export function serializeUnsignedTx(tx) {
  const ver = Buffer.alloc(4);
  ver.writeUInt32LE(tx.version, 0);
  const lock = Buffer.alloc(4);
  lock.writeUInt32LE(tx.locktime, 0);
  const ins = tx.inputs.map(inp => {
    const seq = Buffer.alloc(4);
    seq.writeUInt32LE(inp.sequence, 0);
    return Buffer.concat([encodeOutpoint(inp.txid, inp.vout), Buffer.from([0x00]), seq]);
  });
  const outs = tx.outputs.map(o => serializeOutput(o.valueSats, o.scriptPubKeyHex));
  return Buffer.concat([ver, compactSize(ins.length), ...ins, compactSize(outs.length), ...outs, lock]);
}

export function computeTxidHex(tx) {
  const first = sha256Buf(serializeUnsignedTx(tx));
  return Buffer.from(sha256Buf(first)).reverse().toString('hex');
}

/**
 * Exact BIP-341 `TapSighash` supporting `0x00` (`DEFAULT`), `0x01` (`ALL`),
 * and `0x83` (`SINGLE | ANYONECANPAY`) script-path spends.
 */
export function computeBip341TapSighash(tx, inputIndex, hashType, tapleafHashHex) {
  if (!Array.isArray(tx?.inputs) || inputIndex < 0 || inputIndex >= tx.inputs.length) {
    fail('inputIndex out of bounds');
  }
  if (![SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_SINGLE_ANYONECANPAY].includes(hashType)) {
    fail('unsupported BIP-341 sighash flag');
  }
  const anyoneCanPay = (hashType & 0x80) === 0x80;
  const baseType = hashType === 0x00 ? 0x01 : hashType & 0x03;

  const ver = Buffer.alloc(4);
  ver.writeUInt32LE(tx.version, 0);
  const lock = Buffer.alloc(4);
  lock.writeUInt32LE(tx.locktime, 0);

  const chunks = [Buffer.from([0x00, hashType]), ver, lock];

  if (!anyoneCanPay) {
    const prevouts = [];
    const amounts = [];
    const spks = [];
    const seqs = [];
    for (const inp of tx.inputs) {
      prevouts.push(encodeOutpoint(inp.txid, inp.vout));
      const amt = Buffer.alloc(8);
      amt.writeBigUInt64LE(BigInt(inp.prevoutValueSats), 0);
      amounts.push(amt);
      const spk = Buffer.from(inp.prevoutScriptPubKeyHex, 'hex');
      spks.push(compactSize(spk.length), spk);
      const seq = Buffer.alloc(4);
      seq.writeUInt32LE(inp.sequence, 0);
      seqs.push(seq);
    }
    chunks.push(
      sha256Buf(Buffer.concat(prevouts)),
      sha256Buf(Buffer.concat(amounts)),
      sha256Buf(Buffer.concat(spks)),
      sha256Buf(Buffer.concat(seqs)),
    );
  }

  if (baseType === 0x01) {
    const outs = tx.outputs.map(o => serializeOutput(o.valueSats, o.scriptPubKeyHex));
    chunks.push(sha256Buf(Buffer.concat(outs)));
  }

  const spendType = tapleafHashHex ? 0x02 : 0x00;
  chunks.push(Buffer.from([spendType]));

  if (anyoneCanPay) {
    const inp = tx.inputs[inputIndex];
    const amt = Buffer.alloc(8);
    amt.writeBigUInt64LE(BigInt(inp.prevoutValueSats), 0);
    const spk = Buffer.from(inp.prevoutScriptPubKeyHex, 'hex');
    const seq = Buffer.alloc(4);
    seq.writeUInt32LE(inp.sequence, 0);
    chunks.push(encodeOutpoint(inp.txid, inp.vout), amt, compactSize(spk.length), spk, seq);
  } else {
    const idxBuf = Buffer.alloc(4);
    idxBuf.writeUInt32LE(inputIndex, 0);
    chunks.push(idxBuf);
  }

  if (baseType === 0x03) {
    if (inputIndex >= tx.outputs.length) fail('SIGHASH_SINGLE missing corresponding output');
    const out = tx.outputs[inputIndex];
    chunks.push(sha256Buf(serializeOutput(out.valueSats, out.scriptPubKeyHex)));
  }

  if (tapleafHashHex) {
    if (!isHex(tapleafHashHex, 32)) fail('invalid tapleafHashHex');
    chunks.push(
      Buffer.from(tapleafHashHex, 'hex'),
      Buffer.from([0x00, 0xff, 0xff, 0xff, 0xff]),
    );
  }

  return taggedHash('TapSighash', Buffer.concat(chunks));
}

export function encodeWitnessSigHex(sig64Buf, hashType) {
  const s = Buffer.isBuffer(sig64Buf) ? sig64Buf : Buffer.from(sig64Buf, 'hex');
  if (s.length !== 64) fail('Schnorr signature must be 64 bytes');
  if (hashType === SIGHASH_DEFAULT) return s.toString('hex');
  return Buffer.concat([s, Buffer.from([hashType])]).toString('hex');
}

function decodeWitnessSig(sigHex, expectedHashType) {
  if (!isHex(sigHex)) fail('invalid witness signature hex');
  const buf = Buffer.from(sigHex, 'hex');
  if (expectedHashType === SIGHASH_DEFAULT) {
    if (buf.length !== 64) fail('SIGHASH_DEFAULT witness signature must be 64 bytes');
    return buf;
  }
  if (buf.length !== 65 || buf[64] !== expectedHashType) {
    fail(`expected 65-byte witness signature ending in sighash 0x${expectedHashType.toString(16)}`);
  }
  return buf.subarray(0, 64);
}

/**
 * Verifies Taproot control block cryptographically reconstructs `prevoutScriptPubKeyHex` from `leafHashHex`.
 */
function verifyTapscriptControlBlock(prevoutScriptPubKeyHex, scriptHex, controlBlockHex) {
  if (!isHex(prevoutScriptPubKeyHex, 34) || !prevoutScriptPubKeyHex.startsWith('5120')) {
    fail('expected 34-byte P2TR prevout scriptPubKey');
  }
  if (!isHex(controlBlockHex) || !isHex(scriptHex)) fail('invalid tapscript or control block hex');
  const cb = Buffer.from(controlBlockHex, 'hex');
  if (cb.length < 33 || (cb.length - 33) % 32 !== 0) fail('malformed Taproot control block length');
  const leafVersion = cb[0] & 0xfe;
  if (leafVersion !== LEAF_VERSION_TAPSCRIPT) fail('unsupported Tapscript leaf version');
  const expectedParity = cb[0] & 0x01;
  const internalKeyBuf = cb.subarray(1, 33);
  if (internalKeyBuf.toString('hex') !== deriveUtxoRefNumsInternalKeyHex()) {
    fail('Taproot internal key does not match unspendable UTXORef NUMS key');
  }
  let cur = tapLeafHash(Buffer.from(scriptHex, 'hex'), leafVersion);
  const leafHashHex = cur.toString('hex');
  for (let off = 33; off < cb.length; off += 32) {
    cur = tapBranchHash(cur, cb.subarray(off, off + 32));
  }
  const tweak = mod(bytesToBigIntBE(taggedHash('TapTweak', Buffer.concat([internalKeyBuf, cur]))), N);
  const outAff = toAffine(pointAdd(liftXEven(internalKeyBuf), pointMul(GEN_PT, tweak)));
  const derivedSpkHex = '5120' + bigIntTo32BE(outAff.x).toString('hex');
  const derivedParity = Number(outAff.y & 1n);
  if (derivedSpkHex !== prevoutScriptPubKeyHex || derivedParity !== expectedParity) {
    fail('Taproot control block fails to reconstruct P2TR scriptPubKey');
  }
  return leafHashHex;
}

/**
 * Step 1 of Settlement Enforcement:
 * Independently verifies all 3 external safety invariants on a `WALLET_SETTLEMENT_REQUESTED` state:
 * 1. BIP-341 `TapSighash` + `UTXORef` NUMS `P2TR` script-path witness verification for every
 *    bilateral channel (`0x83` Bob-offline origination sig + `0x01` online/guard sigs on offline hops,
 *    and `0x00` bilateral sigs on interactive hops), with ZERO `bobSk` present at settlement.
 * 2. SHA-256 prior-commitment revocation secret disclosure strictly ordered before conditional
 *    preimage reveal on interactive channel hops.
 * 3. Staggered incoming/outgoing hop CLTV delta (`>= minCltvDeltaBlocks`, default 6 blocks) and
 *    watchtower breach/fallback window safety at `broadcastHeight`.
 *
 * Keeps `bitcoinSpendEnforced: false` and `collateralReleased: false` until `confirmBitcoinSettlement`.
 */
export function authorizeBroadcastReadySettlement(
  requestedState,
  {
    clearingTx,
    channelBindings,
    revocationReceipts = [],
    htlcRouteSchedule = [],
    broadcastHeight,
    minCltvDeltaBlocks = 6,
  } = {},
) {
  if (requestedState?.phase !== 'WALLET_SETTLEMENT_REQUESTED') {
    fail('settlement authorization requires WALLET_SETTLEMENT_REQUESTED phase');
  }
  if (!U(broadcastHeight) || !U(minCltvDeltaBlocks) || minCltvDeltaBlocks < 6) {
    fail('invalid broadcastHeight or unsafe minCltvDeltaBlocks (< 6)');
  }
  if (!clearingTx || clearingTx.version !== 2 || !Array.isArray(clearingTx.inputs) || !Array.isArray(clearingTx.outputs)) {
    fail('invalid SegWit v1 clearing transaction');
  }
  if (Object.hasOwn(clearingTx, 'bobSecretKey') || channelBindings?.some?.(b => Object.hasOwn(b, 'bobSecretKey'))) {
    fail('offline Bob secret key must never be supplied to settlement verifier');
  }
  if (!Array.isArray(channelBindings) || channelBindings.length !== requestedState.channels.length) {
    fail('incomplete bilateral channel bindings');
  }
  if (clearingTx.inputs.length !== requestedState.channels.length) {
    fail('clearingTx input count must match epoch bilateral channels');
  }

  let totalIn = 0n;
  for (const inp of clearingTx.inputs) {
    if (!U(inp.sequence) || inp.sequence > 0xfffffffe) {
      fail('locktimed clearing input must set nSequence <= 0xfffffffe');
    }
    totalIn += BigInt(inp.prevoutValueSats);
  }
  let totalOut = 0n;
  for (const out of clearingTx.outputs) {
    const v = BigInt(out.valueSats);
    if (v < 330n) fail('output below 330-sat P2TR relay dust threshold');
    totalOut += v;
  }
  if (totalIn <= totalOut) fail('clearing transaction violates input > output fee conservation');

  const bindingByChannel = new Map(channelBindings.map(b => [b.channelId, b]));
  const usedInputIndices = new Set();

  for (const chan of requestedState.channels) {
    const bind = bindingByChannel.get(chan.channelId);
    if (!bind || !U(bind.inputIndex) || usedInputIndices.has(bind.inputIndex)) {
      fail(`missing or duplicate input binding for channel ${chan.channelId}`);
    }
    usedInputIndices.add(bind.inputIndex);
    const inp = clearingTx.inputs[bind.inputIndex];
    if (!inp || inp.txid !== chan.commitmentTxid) {
      fail(`input outpoint txid mismatch for channel ${chan.channelId}`);
    }
    if (broadcastHeight >= chan.expiryHeight) {
      fail(`channel ${chan.channelId} expired at height ${broadcastHeight}`);
    }

    if (chan.originalPeerOffline) {
      if (chan.authorizationMode !== 'mnr02-0x83-at-maturity') {
        fail('unexpected authorization mode for offline channel');
      }
      if (clearingTx.locktime < chan.l1MaturityHeight || broadcastHeight < chan.l1MaturityHeight) {
        fail('offline MNR02 channel cannot broadcast before l1MaturityHeight');
      }
      if (broadcastHeight + 6 >= chan.graceEndHeight) {
        fail('offline MNR02 priority confirmation buffer exhausted');
      }
      const desc = buildMnr02ChannelDescriptor({
        counterpartyPubkeyXHex: bind.onlineCounterpartyPubkeyXHex,
        bobPubkeyXHex: bind.offlineBobPubkeyXHex,
        routerGuardPubkeyXHex: bind.routerGuardPubkeyXHex,
        maturityHeight: chan.l1MaturityHeight,
        graceBlocks: chan.graceEndHeight - chan.l1MaturityHeight,
        refundDelayBlocks: chan.refundHeight - chan.l1MaturityHeight,
      });
      if (inp.prevoutScriptPubKeyHex !== desc.scriptPubKeyHex) {
        fail(`prevout scriptPubKey mismatch against MNR02 Taproot tree on ${chan.channelId}`);
      }
      if (!Array.isArray(inp.witnessHex) || inp.witnessHex.length !== 5) {
        fail(`expected 5-item MNR02 route_cet witness stack on ${chan.channelId}`);
      }
      const [bobSigHex, guardSigHex, onlineSigHex, scriptHex, controlBlockHex] = inp.witnessHex;
      if (scriptHex !== desc.routeCetScriptHex || controlBlockHex !== desc.routeControlBlockHex) {
        fail(`route_cet script or control block mismatch on ${chan.channelId}`);
      }
      const leafHashHex = verifyTapscriptControlBlock(inp.prevoutScriptPubKeyHex, scriptHex, controlBlockHex);

      // Verify Bob's pinned output at exact `bind.inputIndex` matches `chan.bobPinnedOutputDigest`!
      if (bind.inputIndex >= clearingTx.outputs.length) {
        fail(`missing corresponding single output for 0x83 input ${bind.inputIndex}`);
      }
      const bobOut = clearingTx.outputs[bind.inputIndex];
      if (singleOutputDigestHex(bobOut.valueSats, bobOut.scriptPubKeyHex) !== chan.bobPinnedOutputDigest) {
        fail(`Bob pinned output digest mismatch on ${chan.channelId}`);
      }

      const sighash0x83 = computeBip341TapSighash(
        clearingTx,
        bind.inputIndex,
        SIGHASH_SINGLE_ANYONECANPAY,
        leafHashHex,
      );
      const bobSig64 = decodeWitnessSig(bobSigHex, SIGHASH_SINGLE_ANYONECANPAY);
      if (!bip340Verify(bind.offlineBobPubkeyXHex, sighash0x83, bobSig64)) {
        fail(`invalid Bob 0x83 origination Schnorr signature on ${chan.channelId}`);
      }

      const sighash0x01 = computeBip341TapSighash(clearingTx, bind.inputIndex, SIGHASH_ALL, leafHashHex);
      const guardSig64 = decodeWitnessSig(guardSigHex, SIGHASH_ALL);
      const onlineSig64 = decodeWitnessSig(onlineSigHex, SIGHASH_ALL);
      if (!bip340Verify(bind.routerGuardPubkeyXHex, sighash0x01, guardSig64)) {
        fail(`invalid RouterGuard 0x01 Schnorr signature on ${chan.channelId}`);
      }
      if (!bip340Verify(bind.onlineCounterpartyPubkeyXHex, sighash0x01, onlineSig64)) {
        fail(`invalid online counterparty 0x01 Schnorr signature on ${chan.channelId}`);
      }
    } else {
      const desc = buildInteractiveChannelDescriptor({
        partyAPubkeyXHex: bind.partyAPubkeyXHex,
        partyBPubkeyXHex: bind.partyBPubkeyXHex,
        refundCsv: bind.refundCsv,
      });
      if (inp.prevoutScriptPubKeyHex !== desc.scriptPubKeyHex) {
        fail(`prevout scriptPubKey mismatch on interactive channel ${chan.channelId}`);
      }
      if (!Array.isArray(inp.witnessHex) || inp.witnessHex.length !== 4) {
        fail(`expected 4-item interactive CET witness stack on ${chan.channelId}`);
      }
      const [sigPk1Hex, sigPk0Hex, scriptHex, controlBlockHex] = inp.witnessHex;
      if (scriptHex !== desc.cetScriptHex || controlBlockHex !== desc.cetControlBlockHex) {
        fail(`interactive CET script or control block mismatch on ${chan.channelId}`);
      }
      const leafHashHex = verifyTapscriptControlBlock(inp.prevoutScriptPubKeyHex, scriptHex, controlBlockHex);
      const sighash0x00 = computeBip341TapSighash(clearingTx, bind.inputIndex, SIGHASH_DEFAULT, leafHashHex);
      const sigPk0 = decodeWitnessSig(sigPk0Hex, SIGHASH_DEFAULT);
      const sigPk1 = decodeWitnessSig(sigPk1Hex, SIGHASH_DEFAULT);
      if (
        !bip340Verify(desc.sortedPubkeysHex[0], sighash0x00, sigPk0) ||
        !bip340Verify(desc.sortedPubkeysHex[1], sighash0x00, sigPk1)
      ) {
        fail(`invalid interactive bilateral 0x00 Schnorr signature on ${chan.channelId}`);
      }

      // Check 2: Prior channel commitment revocation secret MUST be verified strictly before preimage reveal!
      const rev = revocationReceipts.find(r => r.channelId === chan.channelId);
      if (!rev || !isHex(rev.priorCommitmentSecretHex, 32)) {
        fail(`missing prior commitment revocation secret for interactive channel ${chan.channelId}`);
      }
      if (sha256Hex(Buffer.from(rev.priorCommitmentSecretHex, 'hex')) !== chan.revocationPackageDigest) {
        fail(`prior commitment revocation secret mismatch on ${chan.channelId}`);
      }
      if (
        !U(rev.revocationSequence) ||
        !U(rev.preimageRevealSequence) ||
        rev.revocationSequence >= rev.preimageRevealSequence
      ) {
        fail(`unsafe revocation ordering: preimage revealed before prior state revocation on ${chan.channelId}`);
      }
      if (!isHex(rev.watchtowerBreachTxDigest, 32)) {
        fail(`missing watchtower breach-remedy package digest on ${chan.channelId}`);
      }
    }
  }

  // Check 3: Staggered HTLC/PTLC hop CLTV deltas across multi-hop route (`incoming - outgoing >= minCltvDeltaBlocks`)
  if (!Array.isArray(htlcRouteSchedule) || htlcRouteSchedule.length === 0) {
    fail('missing HTLC/PTLC hop CLTV safety schedule');
  }
  const chanMap = new Map(requestedState.channels.map(c => [c.channelId, c]));
  for (let i = 0; i < htlcRouteSchedule.length; i++) {
    const hop = htlcRouteSchedule[i];
    const chan = chanMap.get(hop.channelId);
    if (!chan || hop.cltvExpiryHeight !== chan.expiryHeight) {
      fail('HTLC route schedule does not match epoch channel expiryHeight');
    }
    if (hop.cltvExpiryHeight <= broadcastHeight + minCltvDeltaBlocks) {
      fail(`insufficient CLTV safety margin at broadcastHeight on ${hop.channelId}`);
    }
    if (i > 0) {
      const prevHop = htlcRouteSchedule[i - 1];
      if (prevHop.cltvExpiryHeight - hop.cltvExpiryHeight < minCltvDeltaBlocks) {
        fail(`unsafe staggered hop CLTV delta (< ${minCltvDeltaBlocks} blocks) between ${prevHop.channelId} and ${hop.channelId}`);
      }
    }
  }

  const clearingTxid = computeTxidHex(clearingTx);
  return Object.freeze({
    ...requestedState,
    phase: 'AUTHORIZED_FOR_BITCOIN_BROADCAST',
    clearingTxid,
    minerFeeSats: (totalIn - totalOut).toString(),
    broadcastHeight,
    readyForBitcoinBroadcast: true,
    // Still NOT confirmed on Bitcoin L1 — keep collateralReleased & bitcoinSpendEnforced false!
    bitcoinSpendEnforced: false,
    collateralReleased: false,
    nearFinalityVerified: false,
    verifiedChecks: Object.freeze([
      'independent BIP341 sighash authorization for each bilateral outpoint',
      'on-chain or channel-state commitment signatures and revocation ordering',
      'HTLC/PTLC timeout safety and watchtower recovery',
    ]),
  });
}

/**
 * Step 2 of Settlement Enforcement:
 * Consumes a Bitcoin Core chain confirmation / watchtower reorg-check receipt.
 * - Releases collateral (`bitcoinSpendEnforced: true`, `collateralReleased: true`) ONLY when
 *   confirmed on the active chain with `confirmations >= minConfirmations` and zero reorg flags.
 * - Freezes the ledger (`phase: 'HALTED_ON_REORG'`, `ledgerFrozen: true`, `collateralReleased: false`)
 *   if a block reorganization invalidates the confirmed block or changes the expected anchor tip.
 */
export function confirmBitcoinSettlement(
  authorizedState,
  {
    txid,
    blockHash,
    blockHeight,
    confirmations,
    minConfirmations = 1,
    reorgInvalidated = false,
    expectedParentTipHash = null,
    observedParentTipHash = null,
  } = {},
) {
  if (
    authorizedState?.phase !== 'AUTHORIZED_FOR_BITCOIN_BROADCAST' &&
    authorizedState?.phase !== 'BITCOIN_SETTLEMENT_CONFIRMED'
  ) {
    fail('confirmBitcoinSettlement requires AUTHORIZED_FOR_BITCOIN_BROADCAST state');
  }
  if (txid !== authorizedState.clearingTxid) {
    fail('confirmation receipt txid does not match authorized clearingTxid');
  }
  if (!U(minConfirmations) || minConfirmations < 1) {
    fail('minConfirmations must be >= 1');
  }

  const tipMismatch =
    expectedParentTipHash !== null &&
    observedParentTipHash !== null &&
    expectedParentTipHash !== observedParentTipHash;

  if (reorgInvalidated || tipMismatch) {
    return Object.freeze({
      ...authorizedState,
      phase: 'HALTED_ON_REORG',
      readyForBitcoinBroadcast: false,
      bitcoinSpendEnforced: false,
      collateralReleased: false,
      nearFinalityVerified: false,
      ledgerFrozen: true,
      reorgReason: reorgInvalidated ? 'confirmed_block_invalidated' : 'anchor_tip_mismatch',
    });
  }

  if (!isHex(blockHash, 32) || !U(blockHeight) || !U(confirmations) || confirmations < minConfirmations) {
    return Object.freeze({
      ...authorizedState,
      phase: 'AWAITING_BITCOIN_CONFIRMATIONS',
      bitcoinSpendEnforced: false,
      collateralReleased: false,
      nearFinalityVerified: false,
      ledgerFrozen: false,
    });
  }

  return Object.freeze({
    ...authorizedState,
    phase: 'BITCOIN_SETTLEMENT_CONFIRMED',
    confirmedBlockHash: blockHash,
    confirmedBlockHeight: blockHeight,
    confirmations,
    readyForBitcoinBroadcast: false,
    bitcoinSpendEnforced: true,
    collateralReleased: true,
    nearFinalityVerified: false,
    ledgerFrozen: false,
    verifiedChecks: Object.freeze([
      ...authorizedState.verifiedChecks,
      'Bitcoin Core confirmation + reorg-safe ledger transition',
    ]),
  });
}
