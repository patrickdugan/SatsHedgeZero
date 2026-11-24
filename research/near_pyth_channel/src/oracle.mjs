/**
 * SHZ-ORACLE-01: auditable Pyth import / NEAR relay reference implementation.
 * 
 * A signature from an independent verifier is NOT a native Pyth signature.
 * NEAR finality and Bitcoin spending require separate verified adapters.
 * Uses only built-in Node 20+ crypto and exact integer arithmetic.
 */
import { createHash, createPublicKey, verify } from 'node:crypto';

export const PYTH_PRO_BTC_USD_FEED_ID = 1; // Official Pyth Pro Crypto.BTC/USD feed identifier (u32).
export const SOURCE_DOMAIN = 'SHZ/PYTH-INDEPENDENT-VERIFIER/V1';
export const RELAY_DOMAIN = 'SHZ/NEAR-PRICE-IMPORT/V1';

function fail(message) { throw new Error(message); }
export const digestHex = bytes => createHash('sha256').update(bytes).digest('hex');
const hex64 = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const u64 = (v, label) => {
  if (!/^(0|[1-9][0-9]*)$/.test(String(v))) fail(`${label} must be unsigned decimal`);
  const n = BigInt(v);
  if (n > 18446744073709551615n) fail(`${label} exceeds uint64`);
  return n;
};
const i64 = (v, label) => {
  if (!/^-?(0|[1-9][0-9]*)$/.test(String(v))) fail(`${label} must be integer decimal`);
  const n = BigInt(v);
  if (n < -9223372036854775808n || n > 9223372036854775807n) fail(`${label} exceeds int64`);
  return n;
};
function keyOf(keys, id) {
  if (!keys || !Object.hasOwn(keys,id)) fail('unregistered signer');
  return createPublicKey(keys[id]);
}
function ed25519Check(keys, signer, signatureHex, payload) {
  if (typeof signatureHex !== 'string' || !/^[0-9a-f]{128}$/.test(signatureHex)) fail('invalid signature encoding');
  if (keyOf(keys, signer).asymmetricKeyType !== 'ed25519') fail('expected Ed25519 signer');
  if (!verify(null, payload, keyOf(keys, signer), Buffer.from(signatureHex,'hex'))) fail('invalid signer signature');
}
export function canonicalSource(receipt) {
  const p=receipt.point;
  return Buffer.from(JSON.stringify([
    SOURCE_DOMAIN, receipt.verifierId, receipt.signedPayloadSha256,
    p.feedId, String(p.rawPrice), String(p.conf), p.expo,
    String(p.publishTimeUs), String(p.feedUpdateTimeUs), receipt.requestId
  ]));
}
export function canonicalRelay(relay) {
  return Buffer.from(JSON.stringify([
    RELAY_DOMAIN, relay.nearChainId, relay.nearContract, relay.relayerId,
    relay.requestId, relay.eventId, relay.round, relay.receiptHash,
    relay.claimedPriceE8, String(relay.publishTimeUs), relay.precommitRoot,
  ]));
}
export function normalizePoint(point) {
  if (!Number.isSafeInteger(point?.feedId) || point.feedId < 1 || point.feedId > 0xffffffff) fail('invalid Pyth Pro numeric feed ID');
  if (!Number.isInteger(point.expo) || point.expo < -18 || point.expo > 12) fail('unsupported exponent');
  const raw=i64(point.rawPrice,'price');
  const conf=u64(point.conf,'confidence');
  if (raw <= 0n) fail('non-positive price');
  const pub=u64(point.publishTimeUs,'publish timestamp');
  const feed=u64(point.feedUpdateTimeUs,'feed-update timestamp');
  if (feed > pub) fail('feed-update timestamp exceeds publish timestamp');
  const power=point.expo+8;
  const e8=power>=0 ? raw*(10n**BigInt(power)) : (raw+5n*(10n**BigInt(-power-1)))/(10n**BigInt(-power));
  if (e8<=0n || e8>18446744073709551615n) fail('normalized price out of uint64 range');
  const confBps=(conf*10000n+raw-1n)/raw;
  return { priceE8:e8.toString(), confBps:confBps.toString(), publishTimeUs:pub, feedUpdateTimeUs:feed };
}
/** Verifies an independent source-verifier signature over exact payload hash and values.
 * The verifier's own code must independently verify the upstream Pyth signed payload.
 * This module cannot validate a Pyth native signature or a NEAR state proof.
 */
export function verifySourceReceipt({ receipt, signedPayloadHex, policy, nowUs }) {
  if (!receipt || typeof receipt.requestId !== 'string' || !receipt.requestId ||
      typeof receipt.verifierId !== 'string') fail('invalid receipt identity');
  if (!hex64(receipt.signedPayloadSha256) ||
      typeof signedPayloadHex !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(signedPayloadHex) ||
      signedPayloadHex.length > 32768) fail('missing or invalid signed payload');
  if (digestHex(Buffer.from(signedPayloadHex,'hex')) !== receipt.signedPayloadSha256) fail('payload hash mismatch');
  const p=receipt.point;
  const normalized=normalizePoint(p);
  if (p.feedId !== policy.feedId) fail('unexpected feed ID');
  const now=u64(nowUs,'now');
  if (normalized.publishTimeUs > now+u64(policy.maxFutureSkewUs,'future skew')) fail('future price');
  if (now>normalized.publishTimeUs && now-normalized.publishTimeUs > u64(policy.maxAgeUs,'age')) fail('stale price');
  if (normalized.publishTimeUs-normalized.feedUpdateTimeUs > u64(policy.maxCarryForwardUs,'carry')) fail('stale carried-forward feed');
  if (BigInt(normalized.confBps)>u64(policy.maxConfBps,'max confidence')) fail('excessive confidence interval');
  ed25519Check(policy.independentVerifierKeys,receipt.verifierId,receipt.signatureHex,canonicalSource(receipt));
  return Object.freeze({
    receiptHash:digestHex(Buffer.concat([canonicalSource(receipt),Buffer.from(receipt.signatureHex,'hex')])),
    ...normalized,
    feedId:p.feedId,
    provenanceGrade:'INDEPENDENT_VERIFIER_ATTESTED',
    nativePythSignatureVerified:false,
    nearFinalityVerified:false,
    bitcoinSpendEnforced:false,
    productionReady:false,
  });
}
/** Binds independent source receipt to NEAR relay identity, round, event and state root.
 * A NEAR finality verifier must separately authenticate on-chain inclusion.
 */
export function verifyNearImport({ relay, receipt, signedPayloadHex, policy, nowUs }) {
  const source=verifySourceReceipt({receipt,signedPayloadHex,policy,nowUs});
  if (relay.nearChainId!==policy.nearChainId || relay.nearContract!==policy.nearContract) fail('NEAR domain mismatch');
  if (relay.requestId!==receipt.requestId || relay.receiptHash!==source.receiptHash) fail('receipt binding mismatch');
  if (!hex64(relay.precommitRoot) || typeof relay.eventId!=='string' || !relay.eventId ||
      !Number.isSafeInteger(relay.round) || relay.round<0) fail('invalid event, round or commitment');
  if (String(relay.publishTimeUs)!==String(receipt.point.publishTimeUs)) fail('publish time substitution');
  if (relay.claimedPriceE8!==source.priceE8) fail('relay price substitution');
  ed25519Check(policy.relayerKeys,relay.relayerId,relay.signatureHex,canonicalRelay(relay));
  return Object.freeze({ ...source, nearChainId:relay.nearChainId, nearContract:relay.nearContract,
    eventId:relay.eventId, round:relay.round, precommitRoot:relay.precommitRoot,
    signedImportHash:digestHex(Buffer.concat([canonicalRelay(relay), Buffer.from(relay.signatureHex,'hex')])),
    independentlyValidatedStateRoot:false,
  });
}
/** Cryptographic proof of two incompatible relay claims for the same round/event/source.
 * This makes the relayer's misbehavior objective, pending independent NEAR stake execution.
 */
export function proveEquivocation(a,b,policy) {
  if (a.nearChainId!==b.nearChainId || a.nearContract!==b.nearContract ||
      a.relayerId!==b.relayerId || a.eventId!==b.eventId || a.round!==b.round ||
      a.requestId!==b.requestId) fail('different relay round or signer');
  if(a.nearChainId!==policy.nearChainId || a.nearContract!==policy.nearContract) fail('NEAR domain mismatch');
  ed25519Check(policy.relayerKeys,a.relayerId,a.signatureHex,canonicalRelay(a));
  ed25519Check(policy.relayerKeys,b.relayerId,b.signatureHex,canonicalRelay(b));
  if (a.receiptHash===b.receiptHash && a.claimedPriceE8===b.claimedPriceE8 &&
      a.precommitRoot===b.precommitRoot && String(a.publishTimeUs)===String(b.publishTimeUs)) fail('identical relay claims');
  return Object.freeze({fraudType:'RELAY_EQUIVOCATION', signer:a.relayerId,
    evidenceHashes:[digestHex(canonicalRelay(a)),digestHex(canonicalRelay(b))],
    slashEligibleUnderSpecifiedNEARContract:true, nearSlashExecuted:false, bitcoinBondSlashed:false});
}
/** Planned fraud proof: a relay signs a value inconsistent with a separately verified source.
 * Such a claim is rejected by verifyNearImport. This verifier can construct the challenge
 * without assuming that the Pyth verification service itself is honest.
 */
export function proveSourceSubstitution({relay,receipt,signedPayloadHex,policy,nowUs}) {
  const source=verifySourceReceipt({receipt,signedPayloadHex,policy,nowUs});
  if (relay.receiptHash!==source.receiptHash || relay.requestId!==receipt.requestId) fail('source receipt not bound');
  if (relay.nearChainId!==policy.nearChainId || relay.nearContract!==policy.nearContract) fail('domain mismatch');
  ed25519Check(policy.relayerKeys,relay.relayerId,relay.signatureHex,canonicalRelay(relay));
  if (relay.claimedPriceE8===source.priceE8 && String(relay.publishTimeUs)===String(receipt.point.publishTimeUs)) fail('no substitution found');
  return Object.freeze({fraudType:'RELAY_SOURCE_SUBSTITUTION',signer:relay.relayerId,
    evidenceHashes:[source.receiptHash,digestHex(canonicalRelay(relay))],
    slashEligibleUnderSpecifiedNEARContract:true,nearSlashExecuted:false,bitcoinBondSlashed:false});
}
