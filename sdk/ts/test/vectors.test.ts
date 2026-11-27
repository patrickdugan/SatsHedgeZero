// The TypeScript encoders reproduce every id in sdk/vectors/agent_vectors.json (Rust test
// shared_agent_vectors), verify the Rust signatures, sign through the same WASM signer the
// browser ships, and refuse a tampered draft.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkDraft, grantId, hex, intentId, pubkey, revocationId, sign, unhex, verify } from '../src/index.ts';

const V = JSON.parse(readFileSync(new URL('../../vectors/agent_vectors.json', import.meta.url), 'utf8'));
const AUX0_SIG = '68a0876694901ce65759974f33d1eb1818ffe12e84abc5a4e94656ea6da57553263d39374f1f4a46167d306a42d3630972c56a612e34ed7c3e73eed14cd73f9b';

test('sign.wasm is the browser signer, byte for byte', () => {
  assert.deepEqual(readFileSync(new URL('../sign.wasm', import.meta.url)), readFileSync(new URL('../../../ui/venue/sign.wasm', import.meta.url)));
});
test('keys', () => {
  assert.equal(hex(pubkey(unhex(V.keys.owner_sk))), V.keys.owner_pk);
  assert.equal(hex(pubkey(unhex(V.keys.agent_sk))), V.keys.agent_pk);
});
test('grant and revocation ids and owner signatures', () => {
  const g = V.grant.wire;
  assert.equal(hex(grantId(g)), V.grant.id);
  assert.ok(verify(unhex(V.grant.id), unhex(g.owner), unhex(g.signature)));
  const r = V.revocation.wire;
  assert.equal(hex(revocationId(r, g.scope)), V.revocation.id);
  assert.ok(verify(unhex(V.revocation.id), unhex(r.owner), unhex(r.signature)));
});
test('intent ids and agent signatures (perp, option combo, spot)', () => {
  for (const inst of ['perp', 'option', 'spot'] as const) {
    const i = V[inst].intent;
    const id = intentId(inst, i, V.template);
    assert.equal(hex(id), V[inst].id, inst);
    assert.ok(verify(id, unhex(V.keys.agent_pk), unhex(i.signature)), inst);
    const mine = sign(id, unhex(V.keys.agent_sk));
    assert.ok(verify(id, unhex(V.keys.agent_pk), mine));
    assert.ok(!verify(id, unhex(V.keys.owner_pk), mine), 'an agent signature is not the owner\'s');
  }
});
test('BIP340 with zero aux matches the reference algorithm (Python ops/public-relay/bip340.py)', () => {
  // Same constant in sdk/python/tests/test_vectors.py: sign(grant id, agent sk, aux = 0^32).
  const sig = sign(unhex(V.grant.id), unhex(V.keys.agent_sk), new Uint8Array(32));
  assert.equal(hex(sig), AUX0_SIG);
});
test('draft check refuses tampering', () => {
  const { signature: _s, ...g } = V.grant.wire;
  const d = { grant: g, id: V.grant.id, consent: '' };
  assert.equal(hex(checkDraft(d, g.owner, g.agent, g.instruments, g.limits)), V.grant.id);
  for (const bad of [{ agent: '00'.repeat(32) }, { may_withdraw: true }, { limits: { ...g.limits, max_order_notional_usd: 1e9 } }])
    assert.throws(() => checkDraft({ ...d, grant: { ...g, ...bad } }, g.owner, g.agent, g.instruments, g.limits));
  assert.throws(() => checkDraft({ ...d, id: '11'.repeat(32) }, g.owner, g.agent, g.instruments, g.limits));
});
