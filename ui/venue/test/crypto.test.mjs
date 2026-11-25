import test from 'node:test';
import assert from 'node:assert/strict';
import { hex, unhex, sha256, sha256Sync, bip340Sign, bip340Verify, pubkey, taprootOutputKey, p2trAddress, intentId, signIntent } from '../crypto.js';

test('sha256 WebCrypto and pure-JS agree (abc)', async () => {
  const m = new TextEncoder().encode('abc');
  const want = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  assert.equal(hex(await sha256(m)), want);
  assert.equal(hex(sha256Sync(m)), want);
  const big = new Uint8Array(1000).map((_, i) => i * 7);
  assert.equal(hex(sha256Sync(big)), hex(await sha256(big)));
});

test('BIP340 test vector 0', async () => {
  const sk = unhex('00'.repeat(31) + '03');
  const msg = new Uint8Array(32);
  assert.equal(hex(pubkey(sk)).toUpperCase(), 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
  const sig = await bip340Sign(msg, sk, new Uint8Array(32));
  assert.equal(hex(sig).toUpperCase(), 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0');
  assert.ok(await bip340Verify(msg, pubkey(sk), sig));
  const bad = sig.slice(); bad[63] ^= 1;
  assert.ok(!(await bip340Verify(msg, pubkey(sk), bad)));
});

test('BIP86 key-path tweak and bech32m address (vector cross-checked in Python)', async () => {
  const ik = unhex('cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
  assert.equal(hex(await taprootOutputKey(ik)), 'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c');
  assert.equal(await p2trAddress(ik, 'bc'), 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
  assert.equal(await p2trAddress(ik, 'tb'), 'tb1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqp3mvzv');
});

const template = { scope: { network: '11'.repeat(32), epoch: 7, policy: '22'.repeat(32) }, router: 3, tariff_version: 1, execution_policy: '44'.repeat(32) };
const owner = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const base = { owner, channel: { txid: '33'.repeat(32), vout: 1 }, sequence: 1700000000123, expires_us: 1700000060000000,
  action: 'post', side: 'long', tier: 'standard', quantity: 1000, limit_usd: 95000, leverage_bps: 50000,
  max_fee_ppm: 500, max_fee_sats: 100, max_mark_age_us: 5000000, early_window_opt_in: true, cancel_target: '00'.repeat(32) };

test('IntentV6 id matches the Python port (confirm against POST /api/intent-id on the Rust server)', async () => {
  assert.equal(hex(await intentId(base, template)), 'ff0fb8113face4983092ad7a2d514bebe6e00678741900f98caca1358609280d');
  const i2 = { ...base, action: 'cancel', side: 'short', tier: 'premium', cancel_target: '55'.repeat(32), early_window_opt_in: false };
  assert.equal(hex(await intentId(i2, template, '66'.repeat(32))), '040cec7354efd7510a995ad19ba2beb6e5868b8b5f1063174ee0e1b7664d60ce');
});

test('signIntent produces a verifying signature over the id', async () => {
  const sk = unhex('00'.repeat(31) + '03');
  const { id, intent } = await signIntent(base, template, sk);
  assert.ok(await bip340Verify(unhex(id), unhex(owner), unhex(intent.signature)));
});
