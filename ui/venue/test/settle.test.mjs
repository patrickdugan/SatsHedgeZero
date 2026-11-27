// ui/venue/settle.js rebuilds collateral account scripts, parses the settlement, and computes
// BIP-341 script-path sighashes exactly as the venue does (sdk/vectors/collateral_vectors.json,
// written by the Rust test shared_collateral_vectors); reviewEntry refuses entries that pay the
// trader anything other than input + net to its own account script or withdrawal address.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex, unhex, bip340Verify, taggedHash, concat, bech32mEncode } from '../crypto.js';
import { accountScript, parseTx, serializeTx, txid, tapSighash, decodeAddress, withdrawMsg, signWithdrawal, reviewEntry, signEntry, entrySighash, HRP } from '../settle.js';

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
  assert.equal(hex(await entrySighash({ version: 2, locktime: 0 }, V.entry)), V.entry.sighash);
});

test('withdrawal message and signed body', async () => {
  const w = V.withdraw;
  const spk = decodeAddress(w.address_regtest, 'bcrt');
  assert.equal(hex(spk), w.spk);
  assert.equal(hex(await withdrawMsg(V.trader, spk, w.time_us)), w.message);
  const body = await signWithdrawal({ owner: V.trader, address: w.address_regtest, network: 'regtest', timeUs: w.time_us }, TRADER_SK);
  assert.equal(body.spk, w.spk);
  assert.ok(await bip340Verify(unhex(w.message, 32), unhex(V.trader, 32), unhex(body.sig, 64)));
  assert.equal(hex(await taggedHash('SHZ/BATCHER/POST/V1', new TextEncoder().encode(V.tx))), V.post_digest_of_tx_hex);
});

const ACCT = { outpoint: { txid: V.entry.input.txid, vout: V.entry.input.vout }, value: V.entry.input.amount, refund_height: V.refund_height_in };
function pkgFor(over = {}, out = {}) {
  return {
    epoch: 'SHZ-BTCUSD-TEST', segment: 0, first_seq: 13, last_seq: 19, deadline_us: 0, network: 'regtest', batcher_key: V.batcher, tx: { version: 2, locktime: 0 },
    account: { owner: V.trader, input: V.entry.input, output: { ...V.entry.output, ...out }, collateral: 20000, carry_in: 0, net: -28, rows: [{ seq: 15, net: -28 }], sighash_type: 131, sighash: V.entry.sighash, ...over },
  };
}

test('reviewEntry: honest entry reviews and signs the local sighash; tampering is refused', async () => {
  const r = await reviewEntry(pkgFor(), V.trader, { account: ACCT, batcherKey: V.batcher });
  assert.equal(r.rollover.value, 19972n);
  assert.equal(r.net, -28n);
  assert.equal(hex(r.sighash), V.sighash_input0['131'], 'entry sighash = full-transaction 0x83 sighash');
  const { body } = await signEntry(pkgFor(), V.trader, TRADER_SK, { account: ACCT });
  assert.ok(body.sig.endsWith('83') && body.sig.length === 130);
  assert.ok(await bip340Verify(r.sighash, unhex(V.trader, 32), unhex(body.sig.slice(0, 128), 64)));
  await assert.rejects(reviewEntry(pkgFor({ net: -27 }), V.trader, { account: ACCT }), /differs from collateral/);
  await assert.rejects(reviewEntry(pkgFor({}, { spk: V.account_in.spk }), V.trader, { account: ACCT }), /roll output/);
  await assert.rejects(reviewEntry(pkgFor(), V.trader, { account: { ...ACCT, refund_height: 141 } }), /not your collateral/);
  await assert.rejects(reviewEntry(pkgFor(), V.trader, { account: { ...ACCT, value: 20001 } }), /amount/);
  await assert.rejects(reviewEntry(pkgFor({ sighash: '00'.repeat(32) }), V.trader, { account: ACCT }), /sighash/);
  await assert.rejects(reviewEntry(pkgFor({ sighash_type: 129 }), V.trader, { account: ACCT }), /SINGLE/);
  await assert.rejects(reviewEntry(pkgFor(), V.trader, { account: ACCT, batcherKey: V.trader }), /batcher key/);
  // Withdrawal entry: pays only the address the trader asked for.
  const wout = { kind: 'withdraw', spk: V.withdraw.spk, value: 19972, refund_height: undefined };
  await assert.rejects(reviewEntry(pkgFor({ sighash: undefined }, wout), V.trader, { account: ACCT }), /did not ask/);
  const rw = await reviewEntry(pkgFor({ sighash: undefined }, wout), V.trader, { account: ACCT, withdrawAddress: V.withdraw.address_regtest });
  assert.equal(rw.withdraw.value, 19972n);
  await assert.rejects(reviewEntry(pkgFor({ sighash: undefined }, wout), V.trader, { account: ACCT, withdrawAddress: V.account_in.address_regtest }), /withdrawal address/);
});
