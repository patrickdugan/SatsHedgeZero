/**
 * SHZ/TL dollar-proof research profile. All claims are reference checks.
 * Signed evidence is an assertion by a PINNED observer, not chain consensus or ZK verification.
 */
import { createHash, createPublicKey, verify } from 'node:crypto';

export function demand(condition, why) { if (!condition) throw new Error(why); }
export const HEX32 = /^[a-f0-9]{64}$/;
export function u64(v, name = 'amount') {
  demand(typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v), `${name}: noncanonical unsigned decimal`);
  const n = BigInt(v);
  demand(n <= 18446744073709551615n, `${name}: exceeds uint64`);
  return n;
}
export function positive(v, name) { const n = u64(v, name); demand(n > 0n, `${name}: must be positive`); return n; }
export function hex32(v, name) { demand(typeof v === 'string' && HEX32.test(v), `${name}: must be 32-byte lowercase hex`); return v; }
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    demand(Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null, 'non-plain commitment object');
    const keys = Object.keys(v).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  demand(v === null || typeof v === 'string' || typeof v === 'boolean' || (typeof v === 'number' && Number.isSafeInteger(v)), 'unsupported commitment scalar');
  return JSON.stringify(v);
}
export function digest(tag, v) {
  demand(typeof tag === 'string' && /^[A-Z0-9/-]+$/.test(tag), 'invalid domain tag');
  return createHash('sha256').update(tag).update(Buffer.from([0])).update(canonical(v), 'utf8').digest('hex');
}
export function authSigned(cert, keys, tag, role) {
  demand(cert && typeof cert === 'object' && typeof cert.keyId === 'string' && Object.hasOwn(keys, cert.keyId), `${role}: untrusted evidence signer`);
  demand(typeof cert.signatureHex === 'string' && /^[a-f0-9]{128}$/.test(cert.signatureHex), `${role}: malformed Ed25519 signature`);
  const key = createPublicKey(keys[cert.keyId]);
  demand(key.asymmetricKeyType === 'ed25519', `${role}: wrong signature algorithm`);
  const message = Buffer.from(digest(tag, cert.payload), 'hex');
  demand(verify(null, message, key, Buffer.from(cert.signatureHex, 'hex')), `${role}: invalid evidence signature`);
  return cert.payload;
}
export function makeCertificate(payload, keyId, privateKey, tag, sign) {
  return { payload, keyId, signatureHex: sign(null, Buffer.from(digest(tag, payload), 'hex'), privateKey).toString('hex') };
}
export function assertDistinctRoles(roleKeys) {
  const all = [];
  for (const [role, registry] of Object.entries(roleKeys)) {
    for (const value of Object.values(registry)) {
      const keyBytes = createPublicKey(value).export({ type: 'spki', format: 'der' }).toString('hex');
      demand(!all.includes(keyBytes), `same evidence key reused between observer roles: ${role}`);
      all.push(keyBytes);
    }
  }
}
export function bitcoinOutpoint(network, txid, vout) {
  demand(typeof network === 'string' && /^bitcoin-(?:testnet4|regtest|mainnet)$/.test(network), 'invalid Bitcoin network');
  hex32(txid, 'funding txid');
  demand(Number.isSafeInteger(vout) && vout >= 0 && vout <= 0xffffffff, 'invalid vout');
  return `bitcoin:${network}:${txid}:${vout}`;
}
export function halfAway(n, d) {
  demand(d > 0n, 'division denominator');
  const abs = n < 0n ? -n : n;
  const result = (abs * 2n + d) / (d * 2n);
  return n < 0n ? -result : result;
}
export function min(a,b) { return a < b ? a : b; }
export function max(a,b) { return a > b ? a : b; }
