import { createHash, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { quoteConversion } from './adapter.mjs';

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const SQRT_EXP = (P + 1n) >> 2n;

const RECEIPT_SCHEMA_V1 = 'SHZ/WITHDRAWAL-RECEIPT/V1';
const QUOTE_SCHEMA_V1 = 'SHZ/RGB/CONVERSION-QUOTE/V1';
const RECEIPT_FIELDS = [
  'schema', 'network', 'network_id', 'router_config', 'router_id', 'channel',
  'owner', 'nonce', 'amount_sats', 'destination_script', 'reserved_at_us',
  'expires_us', 'clearing_sequence', 'batch_digest', 'clearing_digest',
  'journal_tip', 'state', 'withdrawal_id', 'owner_sig', 'router_signer',
  'receipt_digest', 'router_sig'
];
const QUOTE_FIELDS = [
  'schema', 'withdrawalId', 'receiptDigest', 'network', 'sats',
  'assetId', 'assetPrecision', 'assetUnits', 'carrierMsat',
  'providerId', 'oracleSnapshot', 'feeCeilingSats', 'quotedFeeSats',
  'destination', 'btcScriptPubKey', 'paymentHash', 'issuedAt', 'expiresAt'
];
const ORACLE_FIELDS = ['source', 'sequence', 'timestampUs', 'btcUsdCents', 'assetUsdCents', 'digest'];

const check = (ok, msg) => { if (!ok) throw new Error(msg); };
const hex64 = s => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const nonZeroHex64 = s => hex64(s) && !/^0+$/.test(s);
const hex128 = s => typeof s === 'string' && /^[0-9a-f]{128}$/.test(s);
const pubkeyCompressed = s => typeof s === 'string' && /^(02|03)[0-9a-f]{64}$/.test(s);
const nativeSegwitHex = s => typeof s === 'string' && /^(0014[0-9a-f]{40}|0020[0-9a-f]{64}|5120[0-9a-f]{64})$/.test(s);
const uint64Str = s => typeof s === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(s) && BigInt(s) <= 18446744073709551615n;
const posUint64Str = s => uint64Str(s) && BigInt(s) > 0n;

function exactShape(o, keys) {
  check(
    o && Object.getPrototypeOf(o) === Object.prototype &&
    Object.keys(o).length === keys.length &&
    keys.every(k => Object.hasOwn(o, k)),
    'unexpected object fields'
  );
}

function canonical(o) {
  if (Array.isArray(o)) return o.map(canonical);
  if (o && typeof o === 'object') {
    return Object.fromEntries(Object.keys(o).sort().map(k => [k, canonical(o[k])]));
  }
  check(typeof o === 'string' || (typeof o === 'number' && Number.isSafeInteger(o)) || typeof o === 'boolean', 'unsupported canonical value');
  return o;
}

const canonicalJson = o => JSON.stringify(canonical(o));

function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}

function taggedHash(tag, payload) {
  const th = sha256(typeof tag === 'string' ? Buffer.from(tag, 'utf8') : tag);
  return createHash('sha256').update(th).update(th).update(payload).digest();
}

function networkId(name) {
  check(typeof name === 'string' && name.length > 0 && name.length <= 64, 'invalid network name');
  return taggedHash('SHZ/NETWORK/V1', Buffer.from(name, 'utf8')).toString('hex');
}

// --- Pure BigInt secp256k1 BIP340 Schnorr verification ---
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
  return modPow(a, m - 2n, m);
}

function pointAdd(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2) {
    if (y1 !== y2 || y1 === 0n) return null;
    const lam = mod((3n * x1 * x1) * modInv(2n * y1));
    const x3 = mod(lam * lam - 2n * x1);
    const y3 = mod(lam * (x1 - x3) - y1);
    return [x3, y3];
  }
  const lam = mod((y2 - y1) * modInv(x2 - x1));
  const x3 = mod(lam * lam - x1 - x2);
  const y3 = mod(lam * (x1 - x3) - y1);
  return [x3, y3];
}

function pointMul(k, pt) {
  let r = null;
  let addend = pt;
  let n = k;
  while (n > 0n) {
    if (n & 1n) r = pointAdd(r, addend);
    addend = pointAdd(addend, addend);
    n >>= 1n;
  }
  return r;
}

function liftXEven(x) {
  if (x < 0n || x >= P) return null;
  const c = mod(modPow(x, 3n) + 7n);
  let y = modPow(c, SQRT_EXP);
  if (mod(y * y) !== c) return null;
  if (y & 1n) y = P - y;
  return [x, y];
}

function bip340Verify(pubkeyHex, msgHex, sigHex) {
  if (!hex64(pubkeyHex) || !hex64(msgHex) || !hex128(sigHex)) return false;
  const px = BigInt('0x' + pubkeyHex);
  const r = BigInt('0x' + sigHex.slice(0, 64));
  const s = BigInt('0x' + sigHex.slice(64, 128));
  if (r >= P || s >= N) return false;
  const pt = liftXEven(px);
  if (!pt) return false;
  const rBytes = Buffer.from(sigHex.slice(0, 64), 'hex');
  const pBytes = Buffer.from(pubkeyHex, 'hex');
  const mBytes = Buffer.from(msgHex, 'hex');
  const eBuf = taggedHash('BIP0340/challenge', Buffer.concat([rBytes, pBytes, mBytes]));
  const e = BigInt('0x' + eBuf.toString('hex')) % N;
  const sG = pointMul(s, [GX, GY]);
  const negEP = pointMul(mod(N - e, N), pt);
  const R = pointAdd(sG, negEP);
  if (!R) return false;
  if (R[1] & 1n) return false;
  return R[0] === r;
}

// --- Canonical binary preimages matching crates/shz-dex/src/routing/withdrawal.rs ---
function u32le(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
}

function u64le(v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v), 0);
  return b;
}

function withdrawalPreimage(r) {
  const script = Buffer.from(r.destination_script, 'hex');
  return Buffer.concat([
    Buffer.from(r.network_id, 'hex'),
    Buffer.from(r.router_config, 'hex'),
    u32le(r.router_id),
    Buffer.from(r.channel.txid, 'hex'),
    u32le(r.channel.vout),
    Buffer.from(r.owner, 'hex'),
    u64le(r.nonce),
    u64le(r.amount_sats),
    u32le(script.length),
    script,
    u64le(r.expires_us),
    u64le(r.clearing_sequence),
    Buffer.from(r.batch_digest, 'hex'),
    Buffer.from(r.clearing_digest, 'hex'),
  ]);
}

function computeWithdrawalId(r) {
  return taggedHash('SHZ/HFT06/WITHDRAWAL-REQ/V1', withdrawalPreimage(r)).toString('hex');
}

function computeReceiptDigest(r) {
  const netBytes = Buffer.from(r.network, 'utf8');
  const stBytes = Buffer.from(r.state, 'utf8');
  const buf = Buffer.concat([
    u32le(netBytes.length),
    netBytes,
    Buffer.from(r.withdrawal_id, 'hex'),
    u64le(r.reserved_at_us),
    u64le(r.journal_tip.records),
    Buffer.from(r.journal_tip.digest, 'hex'),
    u32le(stBytes.length),
    stBytes,
    Buffer.from(r.router_signer, 'hex'),
  ]);
  return taggedHash('SHZ/HFT06/WITHDRAWAL-RECEIPT/V1', buf).toString('hex');
}

function rejectExplorerOrSimulated(obj) {
  check(obj && typeof obj === 'object', 'missing withdrawal receipt');
  if (
    obj.scope === 'explorer-candidate-only' ||
    obj.simulatedChannel === true ||
    obj.withdrawalAuthorized === false ||
    obj.receiptEligible === false ||
    Object.hasOwn(obj, 'candidateSats')
  ) {
    throw new Error('explorer observation or simulated channel ack cannot authorize asset movement');
  }
}

function verifyWithdrawalReceipt(receipt, policy) {
  rejectExplorerOrSimulated(receipt);
  exactShape(receipt, RECEIPT_FIELDS);
  exactShape(receipt.channel, ['txid', 'vout']);
  exactShape(receipt.journal_tip, ['records', 'digest']);
  check(receipt.schema === RECEIPT_SCHEMA_V1, 'unsupported withdrawal receipt schema');
  const expectedNetwork = policy?.network ?? 'regtest';
  check(expectedNetwork === 'regtest', 'only regtest network is permitted for RGB settlement');
  check(receipt.network === expectedNetwork, 'cross-network withdrawal receipt rejected');
  check(nonZeroHex64(receipt.network_id) && receipt.network_id === networkId(receipt.network), 'network_id mismatch');
  check(nonZeroHex64(receipt.router_config), 'invalid router_config');
  if (policy?.routerConfig) check(receipt.router_config === policy.routerConfig, 'router_config mismatch');
  check(Number.isInteger(receipt.router_id) && receipt.router_id > 0 && receipt.router_id <= 0xffffffff, 'invalid router_id');
  if (policy?.routerId !== undefined) check(receipt.router_id === policy.routerId, 'router_id mismatch');
  check(nonZeroHex64(receipt.channel.txid) && Number.isInteger(receipt.channel.vout) && receipt.channel.vout >= 0 && receipt.channel.vout <= 0xffffffff, 'invalid channel outpoint');
  check(nonZeroHex64(receipt.owner), 'invalid owner pubkey');
  check(posUint64Str(receipt.nonce) && posUint64Str(receipt.amount_sats), 'invalid nonce or amount_sats');
  check(nativeSegwitHex(receipt.destination_script), 'invalid destination native SegWit script');
  check(uint64Str(receipt.reserved_at_us) && posUint64Str(receipt.expires_us) && BigInt(receipt.expires_us) > BigInt(receipt.reserved_at_us), 'invalid reservation timestamps');
  check(uint64Str(receipt.clearing_sequence) && hex64(receipt.batch_digest) && hex64(receipt.clearing_digest), 'invalid clearing fields');
  if (BigInt(receipt.clearing_sequence) === 0n) {
    check(/^0+$/.test(receipt.batch_digest) && /^0+$/.test(receipt.clearing_digest), 'non-zero digest with zero clearing_sequence');
  } else {
    check(nonZeroHex64(receipt.batch_digest), 'missing batch_digest for clearing_sequence');
  }
  check(posUint64Str(receipt.journal_tip.records) && nonZeroHex64(receipt.journal_tip.digest), 'invalid journal_tip');
  const requireState = policy?.requireState ?? 'reserved';
  if (requireState) check(receipt.state === requireState, `unexpected receipt state: ${receipt.state}`);
  check(nonZeroHex64(receipt.withdrawal_id) && hex128(receipt.owner_sig), 'invalid withdrawal_id or owner_sig');
  check(nonZeroHex64(receipt.router_signer) && nonZeroHex64(receipt.receipt_digest) && hex128(receipt.router_sig), 'invalid router attestation fields');
  if (policy?.routerSigner) check(receipt.router_signer === policy.routerSigner, 'untrusted router_signer');
  if (policy?.nowUs !== undefined) {
    const nowUs = BigInt(policy.nowUs);
    check(nowUs >= BigInt(receipt.reserved_at_us), 'receipt reserved_at_us in future');
    check(nowUs < BigInt(receipt.expires_us), 'stale/expired withdrawal receipt');
  }

  const computedId = computeWithdrawalId(receipt);
  check(computedId === receipt.withdrawal_id, 'withdrawal_id preimage mismatch');
  check(bip340Verify(receipt.owner, computedId, receipt.owner_sig), 'owner BIP340 signature rejected');

  const computedDigest = computeReceiptDigest(receipt);
  check(computedDigest === receipt.receipt_digest, 'receipt_digest mismatch');
  check(bip340Verify(receipt.router_signer, computedDigest, receipt.router_sig), 'router BIP340 signature rejected');

  return Object.freeze({
    withdrawalId: computedId,
    receiptDigest: computedDigest,
    laneKey: `${receipt.channel.txid}:${receipt.channel.vout}:${receipt.nonce}`,
    canonicalJson: canonicalJson(receipt),
  });
}

function quoteMessage(quote) {
  exactShape(quote, QUOTE_FIELDS);
  exactShape(quote.oracleSnapshot, ORACLE_FIELDS);
  return Buffer.from(canonicalJson(['SHZ/RGB/CONVERSION-QUOTE/ATTEST/V1', quote]));
}

function quoteDigest(quote) {
  return sha256(quoteMessage(quote)).toString('hex');
}

function signConversionQuote(quote, providerPrivateKey) {
  return edSign(null, quoteMessage(quote), providerPrivateKey).toString('hex');
}

function verifyConversionQuote(quote, providerSig, receipt, policy) {
  check(quote && typeof quote === 'object', 'missing conversion quote');
  exactShape(quote, QUOTE_FIELDS);
  exactShape(quote.oracleSnapshot, ORACLE_FIELDS);
  check(quote.schema === QUOTE_SCHEMA_V1, 'unsupported conversion quote schema');
  const expectedNetwork = policy?.network ?? 'regtest';
  check(expectedNetwork === 'regtest' && quote.network === expectedNetwork, 'quote network mismatch');
  check(quote.withdrawalId === receipt.withdrawal_id, 'quote withdrawalId mismatch');
  check(quote.receiptDigest === receipt.receipt_digest, 'quote receiptDigest mismatch');
  check(posUint64Str(quote.sats) && quote.sats === receipt.amount_sats, 'quote sats mismatch');
  check(typeof quote.assetId === 'string' && /^rgb:[A-Za-z0-9_~\-]+$/.test(quote.assetId), 'invalid RGB contract ID');
  check(Number.isInteger(quote.assetPrecision) && quote.assetPrecision >= 0 && quote.assetPrecision <= 18, 'invalid asset precision');
  if (policy?.assetAllowlist) {
    const allowed = policy.assetAllowlist[quote.assetId];
    check(allowed && allowed.precision === quote.assetPrecision, 'asset ID or precision not allowlisted');
  }
  check(posUint64Str(quote.assetUnits), 'invalid assetUnits');
  check(posUint64Str(quote.carrierMsat) && BigInt(quote.carrierMsat) >= 3000000n, 'invalid carrierMsat');
  check(typeof quote.providerId === 'string' && quote.providerId.length > 0 && quote.providerId.length <= 128, 'invalid providerId');
  check(policy?.providerKeys && Object.hasOwn(policy.providerKeys, quote.providerId), 'untrusted conversion provider');
  check(uint64Str(quote.feeCeilingSats) && uint64Str(quote.quotedFeeSats), 'invalid fee fields');
  check(BigInt(quote.quotedFeeSats) <= BigInt(quote.feeCeilingSats), 'quoted fee exceeds fee ceiling');
  if (policy?.maxFeeCeilingSats !== undefined) {
    check(BigInt(quote.feeCeilingSats) <= BigInt(policy.maxFeeCeilingSats), 'fee ceiling exceeds policy');
  }
  check(BigInt(quote.quotedFeeSats) < BigInt(quote.sats), 'quoted fee consumes entire withdrawal');
  check(pubkeyCompressed(quote.destination), 'invalid destination payee');
  check(nativeSegwitHex(quote.btcScriptPubKey) && quote.btcScriptPubKey === receipt.destination_script, 'quote btcScriptPubKey mismatch');
  check(nonZeroHex64(quote.paymentHash), 'invalid paymentHash');
  check(Number.isSafeInteger(quote.issuedAt) && quote.issuedAt >= 0 && Number.isSafeInteger(quote.expiresAt) && quote.expiresAt > quote.issuedAt, 'invalid quote timestamps');
  check(BigInt(quote.expiresAt) * 1000000n <= BigInt(receipt.expires_us), 'quote outlives withdrawal receipt');

  // Oracle snapshot validation & freshness
  const o = quote.oracleSnapshot;
  check(typeof o.source === 'string' && o.source.length > 0 && o.source.length <= 128, 'invalid oracle source');
  check(Number.isSafeInteger(o.sequence) && o.sequence > 0, 'invalid oracle sequence');
  check(posUint64Str(o.timestampUs) && posUint64Str(o.btcUsdCents) && posUint64Str(o.assetUsdCents) && nonZeroHex64(o.digest), 'invalid oracle snapshot');
  if (policy?.nowSec !== undefined) {
    const nowSec = policy.nowSec;
    check(quote.issuedAt <= nowSec && nowSec < quote.expiresAt, 'stale or not-yet-valid conversion quote');
    const nowUs = BigInt(nowSec) * 1000000n;
    const maxAgeUs = BigInt(policy.maxOracleAgeUs ?? 60_000_000);
    const snapUs = BigInt(o.timestampUs);
    check(snapUs <= nowUs && nowUs - snapUs <= maxAgeUs, 'stale oracle snapshot');
  }

  // Verify exact conversion quote arithmetic on net sats (`sats - quotedFeeSats`).
  const netSats = BigInt(quote.sats) - BigInt(quote.quotedFeeSats);
  const expected = quoteConversion({
    sats: netSats,
    btcUsdCents: o.btcUsdCents,
    assetUsdCents: o.assetUsdCents,
    decimals: quote.assetPrecision,
  });
  check(BigInt(quote.assetUnits) === expected.assetUnits, 'conversion quote arithmetic mismatch');

  // Verify provider Ed25519 signature over canonical quote.
  const pubKey = createPublicKey(policy.providerKeys[quote.providerId]);
  check(pubKey.asymmetricKeyType === 'ed25519' && hex128(providerSig), 'invalid provider key or signature');
  check(edVerify(null, quoteMessage(quote), pubKey, Buffer.from(providerSig, 'hex')), 'provider quote signature rejected');

  return Object.freeze({ quoteDigest: quoteDigest(quote), netSats: netSats.toString() });
}

export {
  RECEIPT_SCHEMA_V1,
  QUOTE_SCHEMA_V1,
  taggedHash,
  networkId,
  bip340Verify,
  canonical,
  canonicalJson,
  withdrawalPreimage,
  computeWithdrawalId,
  computeReceiptDigest,
  rejectExplorerOrSimulated,
  verifyWithdrawalReceipt,
  quoteMessage,
  quoteDigest,
  signConversionQuote,
  verifyConversionQuote,
};
