import test from "node:test";
import assert from "node:assert/strict";
import { createAppServer } from "./server.mjs";

test("Protocol Explorer UI and /v1/explorer/* telemetry & chaos endpoints", async () => {
  const { server } = createAppServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  try {
    // 1. Trading terminal `/` links to `/explorer`:
    const homeRes = await fetch(`${base}/`);
    assert.equal(homeRes.status, 200);
    const homeHtml = await homeRes.text();
    assert.match(homeHtml, /href="\/explorer"/);

    // 2. `/explorer` serves the 5-pane Protocol Explorer HTML + assets:
    const expRes = await fetch(`${base}/explorer`);
    assert.equal(expRes.status, 200);
    const expHtml = await expRes.text();
    assert.match(expHtml, /id="pane-hft"/);
    assert.match(expHtml, /id="pane-ln"/);
    assert.match(expHtml, /id="pane-netting"/);
    assert.match(expHtml, /id="pane-oracle"/);
    assert.match(expHtml, /id="pane-nova-bitvm3"/);

    const jsRes = await fetch(`${base}/explorer.js`);
    assert.equal(jsRes.status, 200);

    // 3. `/v1/explorer/snapshot` returns all 5 backend tiers:
    const snapRes = await fetch(`${base}/v1/explorer/snapshot`);
    assert.equal(snapRes.status, 200);
    const snap = await snapRes.json();
    assert.equal(snap.nova_bitvm3.secq256k1_proof_bytes, 11_980);
    assert.equal(snap.nova_bitvm3.bn254_proof_bytes, 12_784);
    assert.equal(snap.netting.n_party_packing.total_vault_inputs, 5);
    assert.equal(snap.near_optimistic.happy_path_tx_count, 2);

    // 4. `/v1/explorer/action` executes HFT burst, PTLC swap, and BitVM3 slash drills:
    for (const action of [
      "hft_burst",
      "ptlc_withdraw",
      "toggle_bob_offline",
      "inject_bad_boundary",
      "inject_garbled_gate_lie",
      "trigger_near_bisection",
    ]) {
      const actRes = await fetch(`${base}/v1/explorer/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, count: 200 }),
      });
      assert.equal(actRes.status, 200);
    }

    const postSnap = await (await fetch(`${base}/v1/explorer/snapshot`)).json();
    assert.ok(postSnap.latency.total_intents_processed >= 212);
    assert.ok(postSnap.nova_bitvm3.watchtower_events.length >= 2);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
