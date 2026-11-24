import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createAppServer, createSession } from "./server.mjs";

describe("SatsHedgeZero Terminal HTTP API & Exact Protocol Parity", () => {
  let server;
  let baseUrl;

  before(async () => {
    const app = createAppServer(createSession());
    server = app.server;
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it("GET /api/state serves markets, orderbook, oracle feeds, FROST quorum, and real evidence JSON", async () => {
    const res = await fetch(`${baseUrl}/api/state`);
    assert.equal(res.status, 200);
    const data = await res.json();

    assert.equal(data.instrument, "BTC-INVERSE-PERP");
    const symbols = data.instruments.map((i) => i.symbol);
    assert.deepEqual(symbols, ["BTC-INVERSE-PERP", "BTC-27DEC26-DLC", "BTC-28MAR27-DLC"]);

    assert.equal(data.market.feeBps, 0);
    assert.equal(data.market.makerFeeBps, 0);
    assert.equal(data.market.takerFeeBps, 0);
    assert.equal(
      data.market.tradelayerMerkleRootHex,
      "5dbc792917c799a91be81689dcf26aa16f0f5978e9dde3a5f16f82fc1cace605"
    );
    assert.equal(data.market.frost.threshold, 3);
    assert.equal(data.market.frost.total, 5);
    assert.equal(data.market.frost.signers.length, 5);
    assert.equal(data.market.pythConfBps, 20);

    assert.equal(data.orderbook.feeBps, 0);
    assert.ok(data.orderbook.asks.length >= 8);
    assert.ok(data.orderbook.bids.length >= 8);
    assert.ok(data.orderbook.recentTrades.length >= 5);

    assert.equal(data.baselineEvidence.protocol, "SatsHedgeZero v0.2.0");
    assert.equal(data.baselineEvidence.dex_simulation.compressed_cet_count, 5749);
    assert.equal(
      data.mnr02Receipt.bob_offline_routed_settlement_60k.txid,
      "479c905ce4fb52b1cd3e98404405843a9510a46ba162a4b8d83216e4ae985e36"
    );
  });

  it("serves static terminal shell assets (index.html, styles.css, app.js)", async () => {
    const [htmlRes, cssRes, jsRes] = await Promise.all([
      fetch(`${baseUrl}/`),
      fetch(`${baseUrl}/styles.css`),
      fetch(`${baseUrl}/app.js`),
    ]);
    assert.equal(htmlRes.status, 200);
    assert.equal(cssRes.status, 200);
    assert.equal(jsRes.status, 200);

    const html = await htmlRes.text();
    assert.match(html, /id="shz-main-canvas"/);
    assert.match(html, /id="shz-workbench-root"/);
    assert.match(html, /src="\/charts\.js"/);
    assert.match(html, /src="\/workbench\.js"/);
  });

  it("POST /api/quote returns null Short liquidation for 1x SatsHedge and exact 10x liq + 643 CET parity", async () => {
    // Case A: 1x Covered Synthetic USD Short ($1,000 @ $100,000, 5x Long / 1x Short)
    const res1x = await fetch(`${baseUrl}/api/quote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usdNotional: 1_000,
        entryPriceUsd: 100_000,
        longLevX: 5,
        shortLevX: 1,
        side: "Short",
      }),
    });
    assert.equal(res1x.status, 200);
    const q1x = await res1x.json();
    assert.equal(q1x.longMarginSats, 200_000);
    assert.equal(q1x.shortMarginSats, 1_000_000);
    assert.equal(q1x.protocolFeeSats, 0);
    assert.equal(q1x.longLiquidationPriceUsd, 83_333);
    assert.equal(q1x.shortLiquidationPriceUsd, null);
    assert.equal(q1x.userLiquidationPriceUsd, null);
    assert.equal(q1x.shortIsCoveredSyntheticUsd, true);

    const pt200k = q1x.payoffCurve.find((p) => p.priceUsd === 200_000);
    assert.ok(pt200k, "payoffCurve must include $200,000 sample");
    assert.equal(pt200k.shortSats, 500_000);
    assert.equal(pt200k.shortUsdValue, 1_000);

    // Case B: 10x Long vs 10x Short ($1,000 @ $100,000) -> exact Rust shz-margin 643 CETs
    const res10x = await fetch(`${baseUrl}/api/quote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usdNotional: 1_000,
        entryPriceUsd: 100_000,
        longLevX: 10,
        shortLevX: 10,
        side: "Long",
      }),
    });
    assert.equal(res10x.status, 200);
    const q10x = await res10x.json();
    assert.equal(q10x.longLiquidationPriceUsd, 90_909);
    assert.equal(q10x.shortLiquidationPriceUsd, 111_112);
    assert.equal(q10x.shortIsCoveredSyntheticUsd, false);
    assert.equal(q10x.compressed20BitCetCount, 643);

    // Case C: Baseline verify_all parity ($2,000 @ $100,000, 10x Long / 1x Short -> 5,749 CETs)
    const resBase = await fetch(`${baseUrl}/api/quote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usdNotional: 2_000,
        entryPriceUsd: 100_000,
        longLevX: 10,
        shortLevX: 1,
        side: "Long",
      }),
    });
    const qBase = await resBase.json();
    assert.equal(qBase.compressed20BitCetCount, 5749);
  });

  it("POST /api/orders matches at exact maker price with 0 fee and enforces v0 TAP guard", async () => {
    // Reject TAP v1 collateral in v0
    const tapRes = await fetch(`${baseUrl}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        instrument: "BTC-INVERSE-PERP",
        side: "Long",
        orderType: "limit",
        usdNotional: 5_000,
        limitPriceUsd: 100_050,
        leverageX: 10,
        collateral: "TaprootAsset",
      }),
    });
    assert.equal(tapRes.status, 400);
    const tapErr = await tapRes.json();
    assert.match(tapErr.error, /TAP collateral is reserved for v1/i);

    // Cross resting best ask ($100,010) with a $5,000 Long limit @ $100,050 -> fills at maker $100,010, 0 fee!
    const orderRes = await fetch(`${baseUrl}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        instrument: "BTC-INVERSE-PERP",
        side: "Long",
        orderType: "limit",
        usdNotional: 5_000,
        limitPriceUsd: 100_050,
        leverageX: 10,
        oraclePolicy: "FrostBondedWithFallback",
        collateral: "VanillaBtc",
      }),
    });
    assert.equal(orderRes.status, 200);
    const orderData = await orderRes.json();
    assert.equal(orderData.filledUsdNotional, 5_000);
    assert.equal(orderData.restingUsdNotional, 0);
    assert.equal(orderData.makerFeeSats, 0);
    assert.equal(orderData.takerFeeSats, 0);
    assert.equal(orderData.protocolFeeSats, 0);
    assert.equal(orderData.fills.length, 1);
    assert.equal(orderData.fills[0].executionPriceUsd, 100_010);
    assert.equal(orderData.positionsCreated.length, 1);
    assert.equal(orderData.positionsCreated[0].entryPriceUsd, 100_010);
    assert.equal(orderData.positionsCreated[0].protocolFeeSats, 0);
    assert.ok(orderData.positionsCreated[0].subchannelId.startsWith("sub_"));
  });

  it("POST /api/closeout-mnr02 matches exact SHZ-MNR-02 parity (7,575,757 + 9,090,909 = 16,666,666 sats)", async () => {
    const res = await fetch(`${baseUrl}/api/closeout-mnr02`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        positionId: "pos-mnr02-ref",
        carolQuotePriceUsd: 55_000,
        maturityPriceUsd: 60_000,
        bobOffline: true,
      }),
    });
    assert.equal(res.status, 200);
    const receipt = await res.json();

    assert.equal(receipt.bobOffline, true);
    assert.equal(receipt.candidate, "2-origination-0x83-two-tier-cltv");
    assert.equal(receipt.bobToCarolSats, 7_575_757);
    assert.equal(receipt.bobToAliceSats, 9_090_909);
    assert.equal(receipt.carolPlusAliceSats, 16_666_666);
    assert.equal(receipt.bobOutflowSats, 16_666_666);
    assert.equal(receipt.roundingResidualSats, 0);
    assert.equal(receipt.protocolFeeSats, 0);
    assert.equal(receipt.conservationVerified, true);
    assert.equal(receipt.isExactCanonicalCoreVector, true);

    // Exact Bitcoin Core v31.1 regtest Leaf 0 output vector parity!
    assert.deepEqual(receipt.outputsSats, [83_333_334, 7_575_757, 59_089_579, 330]);
    assert.ok(receipt.sighashFlags.some((f) => f.includes("0x83")));

    const updatedPos = receipt.state.positions.find((p) => p.id === "pos-mnr02-ref");
    assert.equal(updatedPos.status, "MNR-02 Routed (Leaf 0 0x83)");
  });
});
