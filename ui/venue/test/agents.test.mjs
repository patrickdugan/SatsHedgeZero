// ui/venue/agents.js encodes grants and revocations exactly as the router does
// (sdk/vectors/agent_vectors.json, written by the Rust test shared_agent_vectors), and its
// draft check refuses a grant that differs from the request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex } from '../crypto.js';
import { grantId, revocationId, checkDraft } from '../agents.js';

const V = JSON.parse(readFileSync(new URL('../../../sdk/vectors/agent_vectors.json', import.meta.url), 'utf8'));

test('grant and revocation ids match the Rust vectors', async () => {
  assert.equal(hex(await grantId(V.grant.wire)), V.grant.id);
  assert.equal(hex(await revocationId(V.revocation.wire, V.grant.wire.scope)), V.revocation.id);
});
test('the draft check signs only what was asked', async () => {
  const { signature: _s, ...g } = V.grant.wire;
  const want = { owner: g.owner, agent: g.agent, instruments: g.instruments, limits: g.limits };
  const d = { grant: g, id: V.grant.id };
  assert.equal(hex(await checkDraft(d, want)), V.grant.id);
  await assert.rejects(checkDraft({ ...d, grant: { ...g, may_withdraw: true } }, want));
  await assert.rejects(checkDraft({ ...d, grant: { ...g, limits: { ...g.limits, collar_bps: 9000 } } }, want));
  await assert.rejects(checkDraft({ ...d, id: '00'.repeat(32) }, want));
});
