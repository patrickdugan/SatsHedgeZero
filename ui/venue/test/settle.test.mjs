// ui/venue/settle.js rebuilds collateral account scripts, parses the settlement, and computes
// BIP-341 script-path sighashes exactly as the venue does (sdk/vectors/collateral_vectors.json,
// written by the Rust test shared_collateral_vectors); reviewPackage refuses packages that pay
// the trader anything other than input + net to its own scripts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex, unhex, bip340Verify, taggedHash, concat, bech32mEncode } from '../crypto.js';
import { accountScript, parseTx, serializeTx, txid, tapSighash, decodeAddress, withdrawDigest, signWithdrawal, reviewPackage, signPackage, HRP } from '../settle.js';

const V = JSON.parse(readFileSync(new URL('../../../sdk/vectors/collateral_vectors.json', import.meta.url), 'utf8'));
const TRADER_SK = unhex('31'.repeat(32), 32);

test('account script, control blocks and addresses match the Rust vectors', async () => {
  const s = await accountScript(V.trader, V.batcher, V.refund_height_in);
  assert.equal(hex(s.spk), V.account_in.spk);
  assert.equal(hex(s.settle), V.account_in.settle_script);
  assert.equal(hex(s.refund), V.account_in.refund_script);
  assert.equal(hex(s.control(0)), V.account_in.settle_control);
  assert.equal(hex(s.control(1)), V.account_in.refund_control);
  assert.equal(hex(s.settleLeaf), V.account_in.settle_leaf);
  assert.equal(bech32mEncode('bcrt', 1, s.outputKey), V.account_in.address_regtest);
  assert.equal(bech32mEncode('tb', 1, s.outputKey), V.account_in.address_testnet4);
  assert.equal(hex(decodeAddress(V.account_in.address_regtest, HRP.regtest)), V.account_in.spk);
  assert.throws(() => decodeAddress(V.account_in.address_regtest, HRP.testnet4));
  assert.equal(hex((await accountScript(V.trader, V.batcher, V.refund_height_next)).spk), V.account_next_spk);
});

test('transaction parse, txid and sighash per hash type match the Rust vectors', async () => {
  const tx = parseTx(V.tx);
  assert.equal(hex(serializeTx(tx)), V.tx);
  assert.equal(await txid(tx), V.txid);
  const pv = V.prevouts.map((p) => ({ value: BigInt(p.value), spk: unhex(p.spk) }));
  const leaf = unhex(V.account_in.settle_leaf, 32);
  for (const [ht, want] of Object.entries(V.sighash_input0)) assert.equal(hex(await tapSighash(tx, pv, 0, Number(ht), leaf)), want, 'hash type ' + ht);
  assert.equal(hex(await taggedHash('LIGHTNINGER/SETTLE-PACKAGE/V1', concat(unhex(V.tx), Uint8Array.of(19, 0, 0, 0, 0, 0, 0, 0)))), V.package_id_through_19);
});

test('withdrawal digest and signed body', async () => {
  const w = V.withdraw;
  const spk = decodeAddress(w.address_regtest, 'bcrt');
  assert.equal(hex(spk), w.spk);
  assert.equal(hex(await withdrawDigest(V.trader, w.sats, spk, w.nonce_us)), w.digest);
  const body = await signWithdrawal({ owner: V.trader, sats: w.sats, address: w.address_regtest, network: 'regtest', nonceUs: w.nonce_us }, TRADER_SK);
  assert.ok(await bip340Verify(unhex(w.digest, 32), unhex(V.trader, 32), unhex(body.signature, 64)));
});

function pkgFor(hashType, outputs = [0], over = {}) {
  return {
    package_id: 'ab'.repeat(32), network: 'regtest', through_batch: 19, refund_height: V.refund_height_next, batcher_key: V.batcher, event_id: 'SHZ-BTCUSD-TEST',
    tx: V.tx, prevouts: V.prevouts,
    accounts: [{ owner: V.trader, input: 0, hash_type: hashType, outputs, from_batch: 12, net_sats: -28, value_in: 20000, refund_height_in: V.refund_height_in, batches: [13, 15], ...over }],
  };
}

test('reviewPackage: honest package reviews, signs the local sighash, refuses tampering', async () => {
  const r = await reviewPackage(pkgFor(0x83), V.trader, { valueIn: 20000, refundHeightIn: V.refund_height_in });
  assert.equal(r.rollover.value, 19972n);
  assert.equal(r.net, -28n);
  assert.equal(hex(r.sighash), V.sighash_input0['131']);
  const { body } = await signPackage(pkgFor(0x83), V.trader, TRADER_SK);
  assert.equal(body.signature.length, 130);
  assert.ok(body.signature.endsWith('83'));
  assert.ok(await bip340Verify(r.sighash, unhex(V.trader, 32), unhex(body.signature.slice(0, 128), 64)));
  // Net claimed differently from what the outputs pay.
  await assert.rejects(reviewPackage(pkgFor(0x83, [0], { net_sats: -27 }), V.trader), /differ/);
  // Another trader's output claimed as ours (pays someone else's script).
  await assert.rejects(reviewPackage(pkgFor(0x83, [1], { net_sats: 28 }), V.trader), /SINGLE|output/);
  // Wrong input refund height: the prevout script is not our account.
  await assert.rejects(reviewPackage(pkgFor(0x83, [0], { refund_height_in: 141 }), V.trader), /not your collateral/);
  // Venue sighash that is not the local one.
  await assert.rejects(reviewPackage(pkgFor(0x83, [0], { sighash: '00'.repeat(32) }), V.trader), /sighash/);
  // Disallowed hash type.
  await assert.rejects(reviewPackage(pkgFor(0x02), V.trader), /not allowed/);
  // Rollover + withdrawal under ALL|ACP; the payout must be our address.
  const w = pkgFor(0x81, [0, 4], { net_sats: 472, withdraw: { address: V.withdraw.address_regtest } });
  const rw = await reviewPackage(w, V.trader, { withdrawAddress: V.withdraw.address_regtest, network: 'regtest' });
  assert.equal(rw.withdraw.value, 500n);
  assert.equal(hex(rw.sighash), V.sighash_input0['129']);
  await assert.rejects(reviewPackage(w, V.trader, { withdrawAddress: V.account_in.address_regtest, network: 'regtest' }), /withdrawal address/);
});
