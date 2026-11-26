import test from 'node:test';
import assert from 'node:assert/strict';
import { hex, unhex, sha256, sha256Sync, bip340Sign, bip340Verify, pubkey, taprootOutputKey, taprootTweakSecret, p2trAddress, intentId, signIntent, randomKey } from '../crypto.js';

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

// BIP340 test-vectors.csv signing rows 1-3 (seckey, pubkey, aux, msg, sig); signing runs in sign.wasm.
const BIP340 = [
  ['B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF', 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '0000000000000000000000000000000000000000000000000000000000000001', '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'],
  ['C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9', 'DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8',
    'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906', '7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    '5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7'],
  ['0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710', '25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3'],
];

test('BIP340 test vectors 1-3 (WASM signer)', async () => {
  for (const [sk, pk, aux, msg, sig] of BIP340) {
    assert.equal(hex(pubkey(unhex(sk))).toUpperCase(), pk);
    const got = await bip340Sign(unhex(msg), unhex(sk), unhex(aux));
    assert.equal(hex(got).toUpperCase(), sig);
    assert.ok(await bip340Verify(unhex(msg), unhex(pk), got));
  }
});

test('WASM signer rejects out-of-range and malformed secrets', async () => {
  const n = unhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  assert.throws(() => pubkey(new Uint8Array(32)), /invalid secret key/);
  assert.throws(() => pubkey(n), /invalid secret key/);
  assert.throws(() => pubkey(new Uint8Array(31).fill(1)), /invalid secret key/);
  await assert.rejects(bip340Sign(new Uint8Array(32), n), /invalid secret key/);
});

test('BIP86 secret tweak matches the JS taproot output key', async () => {
  const sk = unhex('41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361');
  const ik = pubkey(sk);
  assert.equal(hex(ik), 'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
  const tsk = taprootTweakSecret(sk);
  assert.equal(hex(pubkey(tsk)), hex(await taprootOutputKey(ik)));
  const msg = new Uint8Array(32).fill(7);
  assert.ok(await bip340Verify(msg, await taprootOutputKey(ik), await bip340Sign(msg, tsk)));
  assert.notEqual(hex(taprootTweakSecret(sk, new Uint8Array(32).fill(9))), hex(tsk));
});

test('randomKey returns distinct valid keys from WASM keygen', async () => {
  const a = randomKey(), b = randomKey();
  assert.equal(a.length, 32);
  assert.notEqual(hex(a), hex(b));
  const msg = new Uint8Array(32).fill(3);
  assert.ok(await bip340Verify(msg, pubkey(a), await bip340Sign(msg, a)));
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
