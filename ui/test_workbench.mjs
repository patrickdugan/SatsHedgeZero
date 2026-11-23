import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  ShzChartController,
  THEME,
  buildInverseSpec,
  compressDyadicCetRanges,
  computeInversePayout,
  computeLiquidationPrices,
  generateDeterministicCandles,
  generateInversePayoffCurve,
  lookupCetForPrice,
} from "./public/charts.js";

import {
  CandleTickAnimator,
  CLEARED_LEVEL_TTL_MS,
} from "./public/bitcorn/market-motion.js";

import {
  OrderBookLevelTracker,
  annotateOrderBookLadder,
  diffOrderBookLevels,
} from "./public/bitcorn/orderbook.js";

import { CHART_COLORS } from "./public/bitcorn/workspace.js";
import { createAppServer, createSession } from "./server.mjs";

import {
  BITVM3_STATEMENT_MAGIC,
  DEFAULT_BASELINE_EVIDENCE,
  DEFAULT_MNR02_RECEIPT,
  MAX_ROW_AMOUNT_51BIT,
  NOVA_TRANSCRIPT_DOMAIN,
  UTXOREF_NUMS_INTERNAL_KEY_HEX,
  WORKBENCH_CSS,
  buildLnmJournal276B,
  buildNovaTranscript600B,
  buildSecqBip340Claim,
  bytesToHex,
  computeEdmondsKarpClearingPreview,
  computeMnr02CloseoutPreview,
  computePositionNovationPreview,
  encodeBitvm3SettlementStatement304B,
  formatBitvm3Groth16PublicInputs,
  formatExtractedKeyHex,
  injectWorkbenchStyles,
  mountWorkbench,
  sha256Bytes,
  sliceNovaTranscript600B,
} from "./public/workbench.js";

test("Inverse payoff curve: 1x SatsHedge Short is unliquidatable and holds flat USD value", () => {
  const curve = generateInversePayoffCurve(
    { usdNotional: 1_000, entryPriceUsd: 100_000, longLevX: 5, shortLevX: 1 },
    { minPrice: 20_000, maxPrice: 200_000, steps: 90 }
  );

  assert.equal(curve.isCoveredSyntheticUsd, true);
  assert.equal(curve.shortLiqUsd, null);
  assert.equal(curve.longLiqUsd, 83_333);
  assert.equal(curve.points[0].priceUsd, 20_000);
  assert.equal(curve.points[curve.points.length - 1].priceUsd, 200_000);

  // At $200,000 BTC (2x entry), Short holds 500,000 sats = 0.005 BTC * $200,000 = $1,000 USD!
  const p200k = computeInversePayout(curve.spec, 200_000);
  assert.equal(p200k.shortSats, 500_000);
  assert.equal(p200k.longSats, 700_000);
  assert.equal(p200k.protocolFeeSats, 0);
  assert.equal(Math.round(p200k.shortUsdValue), 1_000);

  // Above long liquidation ($83,333), Short USD value stays pinned at ~$1,000 across the entire upside.
  for (const pt of curve.points) {
    assert.equal(pt.longSats + pt.shortSats, curve.spec.totalCollateralSats);
    assert.equal(pt.protocolFeeSats, 0);
    if (pt.priceUsd >= 85_000) {
      assert.ok(
        Math.abs(pt.shortUsdValue - 1_000) < 0.5,
        `expected flat $1,000 at $${pt.priceUsd}, got $${pt.shortUsdValue}`
      );
    }
  }
});

test("Dyadic 20-bit CET compression matches Rust shz-margin (1,048,576 -> 643 prefixes)", () => {
  const spec = buildInverseSpec({
    usdNotional: 1_000,
    entryPriceUsd: 100_000,
    longLevX: 10,
    shortLevX: 10,
  });
  const liq = computeLiquidationPrices(spec);
  assert.equal(liq.longLiqUsd, 90_909);
  assert.equal(liq.shortLiqUsd, 111_112);

  const cets = compressDyadicCetRanges(spec, 20, 250);
  assert.equal(cets.length, 643);
  assert.equal(cets[0].minPriceUsd, 0);
  assert.equal(cets[cets.length - 1].maxPriceUsd, (1 << 20) - 1);

  for (let i = 1; i < cets.length; i++) {
    assert.equal(cets[i - 1].maxPriceUsd + 1, cets[i].minPriceUsd);
  }
  const hit = lookupCetForPrice(cets, 100_000, 20);
  assert.ok(hit);
  assert.ok(hit.minPriceUsd <= 100_000 && hit.maxPriceUsd >= 100_000);
  assert.equal(hit.longSats + hit.shortSats, spec.totalCollateralSats);
  assert.equal(hit.protocolFeeSats, 0);
});

test("Deterministic BTC/USD candles anchor final close, TradeLayer VWAP, and Pyth band", () => {
  const candles = generateDeterministicCandles({
    markPriceUsd: 100_000,
    vwapPriceUsd: 108_200,
    pythConfBps: 20,
    count: 64,
  });
  assert.equal(candles.length, 64);
  const last = candles[candles.length - 1];
  assert.equal(last.close, 100_000);
  assert.equal(last.vwap, 108_200);
  for (const c of candles) {
    assert.ok(c.high >= Math.max(c.open, c.close));
    assert.ok(c.low <= Math.min(c.open, c.close));
    assert.ok(c.pythLower < c.close && c.pythUpper > c.close);
  }
});

test("Pure-JS SHA-256 matches node:crypto exactly", () => {
  for (const sample of ["", NOVA_TRANSCRIPT_DOMAIN, BITVM3_STATEMENT_MAGIC, "SatsHedgeZero"]) {
    const expected = crypto.createHash("sha256").update(sample, "utf8").digest("hex");
    const actual = bytesToHex(sha256Bytes(sample));
    assert.equal(actual, expected);
  }
});

test("600-byte Nova v2 validated-signed-row/v1 transcript slice map & 51-bit overflow guard", () => {
  const tx = buildNovaTranscript600B({
    outcomeIndex: 60_000,
    traderSats: 59_089_579,
    makerSats: 83_333_334,
    anchorSats: 330,
    feeSats: 1_000,
    oracle0Index: 0,
    oracle1Index: 2,
    fundingTxidHex: DEFAULT_MNR02_RECEIPT.alice_bob_funding_txid,
    fundingVout: 1,
  });

  assert.equal(tx.length, 600);
  assert.equal(tx.hex.length, 1200);

  const expectedSha = crypto.createHash("sha256").update(tx.bytes).digest("hex");
  assert.equal(tx.transcriptSha256Hex, expectedSha);

  const slices = sliceNovaTranscript600B(tx.hex);
  assert.equal(slices.length, 8);
  assert.deepEqual(
    slices.map((s) => s.rangeLabel),
    ["0..46", "46..78", "78..110", "110..238", "238..366", "366..496", "496..564", "564..600"]
  );

  // Verify exact contiguity 0 -> 600
  let cursor = 0;
  for (const s of slices) {
    assert.equal(s.start, cursor);
    assert.equal(s.hex.length, (s.end - s.start) * 2);
    cursor = s.end;
  }
  assert.equal(cursor, 600);

  assert.equal(slices[0].decoded.ascii, NOVA_TRANSCRIPT_DOMAIN);
  assert.equal(slices[0].decoded.matchesCanonicalHeader, true);
  assert.equal(slices[5].decoded.oracle0Index, 0);
  assert.equal(slices[5].decoded.oracle1Index, 2);
  assert.equal(slices[5].decoded.strictlySorted, true);
  assert.equal(slices[6].decoded.outcomeIndex, 60_000);
  assert.equal(slices[6].decoded.traderSats, 59_089_579);
  assert.equal(slices[6].decoded.makerSats, 83_333_334);
  assert.equal(slices[6].decoded.anchorSats, 330);
  assert.equal(slices[6].decoded.feeSats, 1_000);
  assert.equal(slices[6].decoded.allUnder51Bit, true);
  assert.equal(slices[7].decoded.fundingTxidDisplayHex, DEFAULT_MNR02_RECEIPT.alice_bob_funding_txid);
  assert.equal(slices[7].decoded.fundingVout, 1);

  // 51-bit overflow rejection
  assert.throws(
    () => buildNovaTranscript600B({ traderSats: MAX_ROW_AMOUNT_51BIT + 1n }),
    /51-bit/
  );
  // Unsorted oracle rejection
  assert.throws(
    () => buildNovaTranscript600B({ oracle0Index: 2, oracle1Index: 1 }),
    /strictly sorted/
  );
});

test("276B LNMJNL01 journal + 8-field Pallas state, Secq 3-field claim, and 304B BitVM3 Groth16 limbs", () => {
  const transcript = buildNovaTranscript600B();
  const journal = buildLnmJournal276B({
    rowCount: 2,
    totalCollateralSats: 150_000_000,
    totalPayoutSats: 149_998_670,
    totalFeeSats: 1_000,
    epoch: 200,
    transcriptHex: transcript.hex,
  });
  assert.equal(journal.length, 276);
  assert.equal(journal.magic, "LNMJNL01");
  assert.equal(journal.pallas8Fields.length, 8);
  assert.equal(journal.cumulativeWithin56Bit, true);

  const secq = buildSecqBip340Claim({
    pubkeyXHex: UTXOREF_NUMS_INTERNAL_KEY_HEX,
    msg32Hex: transcript.slices[1].hex,
    sig64Hex: transcript.slices[3].hex.slice(0, 128),
  });
  assert.equal(secq.fields.length, 3);
  assert.equal(secq.fields[0], "1");

  const bitvm3 = encodeBitvm3SettlementStatement304B({
    epochId: 200,
    assertionVout: 1,
  });
  assert.equal(bitvm3.length, 304);
  assert.equal(bitvm3.statementHex.length, 608);

  // Cross-check [u128_be(d[0..16]), u128_be(d[16..32])] against node:crypto SHA-256
  const refDigest = crypto.createHash("sha256").update(bitvm3.bytes).digest();
  assert.equal(bitvm3.sha256Hex, refDigest.toString("hex"));
  const expectedLimb0 = BigInt("0x" + refDigest.subarray(0, 16).toString("hex")).toString(10);
  const expectedLimb1 = BigInt("0x" + refDigest.subarray(16, 32).toString("hex")).toString(10);
  assert.deepEqual(bitvm3.limbs, [expectedLimb0, expectedLimb1]);

  // Round-trip format from hex
  const reparsed = formatBitvm3Groth16PublicInputs(bitvm3.statementHex);
  assert.deepEqual(reparsed.limbs, bitvm3.limbs);
  assert.deepEqual(reparsed.honestyFlags, {
    native_statement_verified: true,
    nova_snark_verified: false,
    bitvm3_onchain_verified: false,
    production_ready: false,
  });
});

test("MNR-02 closeout math, fraud key formatting, and interactive 4-tab rendering in minimal DOM stub", () => {
  // Exact SHZ-MNR-02 Bitcoin Core v31.1 parity ($50k @ $50k -> Carol $55k -> Maturity $60k)
  const preview = computeMnr02CloseoutPreview({
    notionalUsd: 50_000,
    entryPriceUsd: 50_000,
    carolClosePriceUsd: 55_000,
    maturityPriceUsd: 60_000,
    aliceMarginSats: 50_000_000,
    bobMarginSats: 100_000_000,
  });
  assert.equal(preview.bobOutput0Sats, 83_333_334);
  assert.equal(preview.carolOutput1Sats, 7_575_757);
  assert.equal(preview.aliceLockedPnlSats, 9_090_909);
  assert.equal(preview.aliceOutput2Sats, 59_089_579);
  assert.equal(preview.anchorOutput3Sats, 330);
  assert.equal(preview.protocolFeeSats, 0);

  // Equivocation extracted secp256k1 key hex parity
  const extractedHex = formatExtractedKeyHex(
    DEFAULT_BASELINE_EVIDENCE.fraud_simulation.equivocation_verdict
      .extracted_btc_slash_secret_key
  );
  assert.equal(
    extractedHex,
    "999999999999999999999999999999985448768048e239d5596bf82669cfdadb"
  );

  // Scoped style injection check (Deribit dark palette, zero purple gradients)
  const appendedStyles = [];
  const fakeDoc = {
    head: { appendChild: (el) => appendedStyles.push(el) },
    getElementById: (id) => appendedStyles.find((s) => s.id === id) || null,
    createElement: (tag) => ({ tag, id: "", textContent: "" }),
  };
  injectWorkbenchStyles(fakeDoc);
  injectWorkbenchStyles(fakeDoc); // idempotent
  assert.equal(appendedStyles.length, 1);
  assert.equal(appendedStyles[0].id, "shz-workbench-styles");
  assert.ok(WORKBENCH_CSS.includes("#0a0e14"));
  assert.ok(WORKBENCH_CSS.includes("#00d285"));
  assert.ok(!/linear-gradient.*purple|#7c3aed|#9333ea/i.test(WORKBENCH_CSS));

  // Minimal DOM stub for ShzWorkbenchController
  const listeners = new Map();
  const rootStub = {
    innerHTML: "",
    addEventListener(type, fn) {
      listeners.set(type, fn);
    },
  };

  const ctrl = mountWorkbench(rootStub, {
    market: { symbol: "BTC-INVERSE-PERP", markPriceUsd: 100_000, pythConfBps: 20 },
    quote: { usdNotional: 1_000, entryPriceUsd: 100_000, longLevX: 10, shortLevX: 1 },
    baselineEvidence: DEFAULT_BASELINE_EVIDENCE,
    mnr02Receipt: DEFAULT_MNR02_RECEIPT,
  });

  // Tab 1 default + MNR-02 Closeout Inspector
  assert.ok(rootStub.innerHTML.includes("Close Out via Carol (MNR-02 0x83)"));
  assert.ok(rootStub.innerHTML.includes("∞ UNLIQUIDATABLE"));
  ctrl.openMnr02Closeout("pos-mnr02-alice-bob");
  assert.ok(rootStub.innerHTML.includes("479c905ce4fb"));
  assert.ok(rootStub.innerHTML.includes("83,333,334"));
  assert.ok(rootStub.innerHTML.includes("7,575,757"));
  assert.ok(rootStub.innerHTML.includes("59,089,579"));
  assert.ok(rootStub.innerHTML.includes("330"));
  assert.ok(rootStub.innerHTML.includes("CLTV 206"));
  assert.ok(rootStub.innerHTML.includes("CLTV 240"));
  assert.ok(rootStub.innerHTML.includes("Invalid Schnorr signature"));
  assert.ok(rootStub.innerHTML.includes("non-final"));

  // Simulate clicking Tab 2 (LN-DLC Subchannels & CET Tree)
  const fireClick = (attrs) => {
    const target = {
      closest: () => ({ getAttribute: (k) => attrs[k] ?? null }),
    };
    listeners.get("click")({ target });
  };
  fireClick({ "data-action": "switch-tab", "data-tab": "subchannels" });
  assert.ok(rootStub.innerHTML.includes("c99e9965166e7ff80516"));
  assert.ok(rootStub.innerHTML.includes("Instant 0-Fee LN Coop Close"));
  assert.ok(rootStub.innerHTML.includes("Broadcast L1 Adaptor CET"));
  fireClick({ "data-action": "cet-sim-mode", "data-mode": "l1" });
  assert.ok(rootStub.innerHTML.includes("351,562"));
  assert.ok(rootStub.innerHTML.includes("1,848,438"));

  // Simulate clicking Tab 3 (FROST & NEAR Fraud Guard)
  fireClick({ "data-action": "switch-tab", "data-tab": "fraud" });
  assert.ok(rootStub.innerHTML.includes("TVL ≤ 10× Stake"));
  assert.ok(rootStub.innerHTML.includes("5dbc792917c799"));
  assert.ok(rootStub.innerHTML.includes(extractedHex));
  assert.ok(rootStub.innerHTML.includes("10,000 NEAR"));
  fireClick({ "data-action": "fraud-verdict", "data-verdict": "deviation" });
  assert.ok(rootStub.innerHTML.includes("2799B BORSH"));
  assert.ok(rootStub.innerHTML.includes("105,470"));

  // Simulate clicking Tab 4 (Nova v2 & BitVM3 Proof Inspector)
  fireClick({ "data-action": "switch-tab", "data-tab": "nova" });
  assert.ok(rootStub.innerHTML.includes("validated-signed-row/v1"));
  assert.ok(rootStub.innerHTML.includes("LNMJNL01"));
  assert.ok(rootStub.innerHTML.includes("UTXOREF_L2_SETTLEMENT_GROTH16_V0"));
  assert.ok(rootStub.innerHTML.includes("native_statement_verified: true"));
  assert.ok(rootStub.innerHTML.includes("nova_snark_verified: false"));
  assert.ok(rootStub.innerHTML.includes("bitvm3_onchain_verified: false"));
  assert.ok(rootStub.innerHTML.includes("production_ready: false"));
});

test("ShzChartController renders both candles and payoff modes with crosshair hover without errors", () => {
  const drawnTexts = [];
  const noop = () => {};
  const ctxStub = {
    save: noop,
    restore: noop,
    setTransform: noop,
    fillRect: noop,
    strokeRect: noop,
    beginPath: noop,
    closePath: noop,
    moveTo: noop,
    lineTo: noop,
    quadraticCurveTo: noop,
    arc: noop,
    fill: noop,
    stroke: noop,
    setLineDash: noop,
    measureText: (txt) => ({ width: String(txt).length * 6.5 }),
    fillText: (txt) => drawnTexts.push(String(txt)),
    fillStyle: "",
    strokeStyle: "",
    lineWidth: 1,
    font: "",
    textAlign: "left",
    textBaseline: "middle",
  };
  const listeners = new Map();
  const canvasStub = {
    width: 0,
    height: 0,
    clientWidth: 800,
    clientHeight: 360,
    style: {},
    parentElement: { clientWidth: 800, clientHeight: 360 },
    getContext: () => ctxStub,
    getBoundingClientRect: () => ({ left: 0, top: 0 }),
    addEventListener: (t, fn) => listeners.set(t, fn),
    removeEventListener: (t) => listeners.delete(t),
  };

  const ctrl = new ShzChartController(canvasStub);
  ctrl.setState({
    chartMode: "candles",
    market: { symbol: "BTC-INVERSE-PERP", markPriceUsd: 100_000, tradelayerVwapUsd: 108_200, pythConfBps: 20 },
    quote: { usdNotional: 1_000, entryPriceUsd: 100_000, longLevX: 10, shortLevX: 1 },
  });
  listeners.get("mousemove")({ clientX: 320, clientY: 160 });
  assert.ok(drawnTexts.some((t) => t.includes("∞ UNLIQUIDATABLE (1x SatsHedge)")));
  assert.ok(drawnTexts.some((t) => t.includes("TL tx14 VWAP")));

  drawnTexts.length = 0;
  ctrl.setState({
    chartMode: "payoff",
    market: { symbol: "BTC-INVERSE-PERP", markPriceUsd: 100_000 },
    quote: { usdNotional: 1_000, entryPriceUsd: 100_000, longLevX: 10, shortLevX: 1 },
  });
  listeners.get("mousemove")({ clientX: 410, clientY: 150 });
  assert.ok(drawnTexts.some((t) => t.includes("DYADIC CETs")));
  assert.ok(drawnTexts.some((t) => /SHORT USD \(\$1(?:\.0)?k FLAT\)/.test(t)));
  assert.ok(drawnTexts.some((t) => t.includes("0 sats (0 bps)")));
  ctrl.destroy();
});

test("OG bitcoinwisdom.com palette, 60fps CandleTickAnimator, OrderBookLevelTracker, and Option Strike chart overlays", () => {
  // 1. OG bitcoinwisdom.com color palette parity
  assert.equal(THEME.bg, "#0a0c0e");
  assert.equal(THEME.panel, "#111418");
  assert.equal(THEME.border, "#232830");
  assert.equal(THEME.long, "#66cc66");
  assert.equal(THEME.short, "#dd4444");
  assert.equal(THEME.amber, "#ff9900");
  assert.ok(THEME.fontMono.includes("Tahoma"));
  assert.equal(CHART_COLORS["og-wisdom"].bg, "#0a0c0e");
  assert.equal(CHART_COLORS["og-wisdom"].ma7, "#ff9900");
  assert.equal(CHART_COLORS["og-wisdom"].ma25, "#cc66ff");
  assert.equal(CHART_COLORS["og-wisdom"].ma99, "#4ea1ff");

  // 2. 60fps CandleTickAnimator smooth lerping + flash & volume pulse
  const tickAnim = new CandleTickAnimator({ lerpDurationMs: 220, flashDurationMs: 380 });
  tickAnim.seed({ time: 1_700_000_000_000, open: 100_000, high: 100_050, low: 99_950, close: 100_000, volume: 12 });
  tickAnim.onTrade({ time: 1_700_000_000_050, price: 100_200, quantity: 1.5, side: "buy" }, null, 1_000);

  const midFrame = tickAnim.sample(1_080);
  assert.ok(midFrame.displayedClose > 100_000 && midFrame.displayedClose < 100_200);
  assert.equal(midFrame.direction, "up");
  assert.ok(midFrame.flashIntensity > 0 && midFrame.flashIntensity <= 1);
  assert.ok(midFrame.volumePulse > 0);
  assert.equal(tickAnim.isActive(1_080), true);

  const settledFrame = tickAnim.sample(1_500);
  assert.equal(settledFrame.displayedClose, 100_200);
  assert.equal(settledFrame.displayedHigh, 100_200);
  assert.equal(settledFrame.displayedVolume, 13.5);
  assert.equal(tickAnim.isActive(1_500), false);

  // 3. OrderBookLevelTracker wiped (prev > 0 -> 0) and swept (>= 25% reduction) diff & TTL decay
  assert.ok(CLEARED_LEVEL_TTL_MS >= 350 && CLEARED_LEVEL_TTL_MS <= 500);
  const diff = diffOrderBookLevels(
    {
      asks: [
        [100_010, 25_000],
        [100_030, 40_000],
        [100_060, 68_000],
      ],
      bids: [[99_990, 28_000]],
    },
    {
      asks: [
        [100_030, 20_000], // 50% swept (>= 25%)
        [100_060, 68_000], // unchanged
      ],
      bids: [[99_990, 28_000]],
    },
    { now: 5_000, ttlMs: 420 }
  );
  const wipedAsk = diff.clearedLevels.find((c) => c.price === 100_010);
  const sweptAsk = diff.clearedLevels.find((c) => c.price === 100_030);
  assert.ok(wipedAsk && wipedAsk.kind === "wiped" && wipedAsk.clearedRatio === 1);
  assert.ok(sweptAsk && sweptAsk.kind === "swept" && Math.abs(sweptAsk.clearedRatio - 0.5) < 1e-6);

  const tracker = new OrderBookLevelTracker({ ttlMs: 420 });
  tracker.observe(
    {
      asks: [
        [100_010, 25_000],
        [100_030, 40_000],
        [100_060, 68_000],
        [100_100, 95_000],
      ],
      bids: [[99_990, 28_000]],
    },
    10_000
  );
  const observed = tracker.observe(
    {
      asks: [
        [100_030, 20_000],
        [100_060, 68_000],
        [100_100, 95_000],
      ],
      bids: [[99_990, 28_000]],
    },
    10_100
  );
  const ladderAt150ms = annotateOrderBookLadder(
    [
      [100_030, 20_000],
      [100_060, 68_000],
      [100_100, 95_000],
    ],
    "ask",
    observed.activeCleared,
    observed.activeWalls,
    8
  );
  assert.ok(ladderAt150ms.some((r) => r.price === 100_010 && r.status === "wiped" && r.decay > 0));
  assert.ok(ladderAt150ms.some((r) => r.price === 100_030 && r.status === "swept" && r.decay > 0));
  tracker.prune(10_600);
  assert.equal(tracker.clearedByKey.size, 0);

  // 4. ShzChartController renders MA(7)/MA(25)/MA(99), Option Strike/Breakeven, and L2 SWEPT overlays
  const drawnTexts = [];
  const noop = () => {};
  const ctxStub = {
    save: noop,
    restore: noop,
    setTransform: noop,
    clearRect: noop,
    fillRect: noop,
    strokeRect: noop,
    beginPath: noop,
    closePath: noop,
    moveTo: noop,
    lineTo: noop,
    quadraticCurveTo: noop,
    arc: noop,
    fill: noop,
    stroke: noop,
    setLineDash: noop,
    createLinearGradient: () => ({ addColorStop: noop }),
    measureText: (txt) => ({ width: String(txt).length * 6.5 }),
    fillText: (txt) => drawnTexts.push(String(txt)),
    fillStyle: "",
    strokeStyle: "",
    lineWidth: 1,
    font: "",
    textAlign: "left",
    textBaseline: "middle",
  };
  const canvasStub = {
    width: 0,
    height: 0,
    clientWidth: 920,
    clientHeight: 420,
    style: {},
    parentElement: { clientWidth: 920, clientHeight: 420 },
    getContext: () => ctxStub,
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 920, height: 420 }),
    addEventListener: noop,
    removeEventListener: noop,
  };

  const ctrl = new ShzChartController(canvasStub, { liveFeed: false });
  ctrl.setState({
    chartMode: "candles",
    market: {
      symbol: "BTC-27DEC26-110000-C",
      contractKind: "Option",
      markPriceUsd: 100_000,
      tradelayerVwapUsd: 108_200,
      pythConfBps: 20,
    },
    quote: { usdNotional: 2_000, entryPriceUsd: 100_000, longLevX: 5, shortLevX: 1 },
    optionQuote: {
      symbol: "BTC-27DEC26-110000-C",
      optionType: "Call",
      strikeUsd: 110_000,
      breakevenUsd: 114_820,
      ivPct: 58.2,
    },
    orderbook: {
      asks: [
        { priceUsd: 100_020, sizeUsd: 30_000 },
        { priceUsd: 100_080, sizeUsd: 55_000 },
      ],
      bids: [
        { priceUsd: 99_980, sizeUsd: 32_000 },
        { priceUsd: 99_920, sizeUsd: 60_000 },
      ],
    },
  });
  ctrl.ingestClearedLevels([
    { side: "ask", price: 100_010, prevSize: 25_000, nextSize: 0, deltaSize: 25_000, clearedRatio: 1, kind: "wiped" },
  ]);
  ctrl.candleChart.draw();

  assert.ok(ctrl.getActiveClearedLevels().length >= 1);
  assert.ok(ctrl.getTickState() !== null);
  assert.ok(drawnTexts.some((t) => t.includes("MA(7)")));
  assert.ok(drawnTexts.some((t) => t.includes("MA(25)")));
  assert.ok(drawnTexts.some((t) => t.includes("MA(99)")));
  assert.ok(drawnTexts.some((t) => t.includes("OPT STRIKE")));
  assert.ok(drawnTexts.some((t) => t.includes("OPT BREAKEVEN")));
  assert.ok(drawnTexts.some((t) => t.includes("SWEPT · P2P L2")));
  ctrl.destroy();
});

test("Deribit-style Options Chain ($90k-$125k), Oracle Checker, L2 Sweep, Novation & Edmonds-Karp API + UI", async () => {
  const app = createAppServer(createSession());
  const server = app.server;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    // 1. Static OG bitcoinwisdom.com + Deribit Options & Oracle Checker UI shell verification
    const [htmlRes, cssRes] = await Promise.all([
      fetch(`${baseUrl}/`),
      fetch(`${baseUrl}/styles.css`),
    ]);
    assert.equal(htmlRes.status, 200);
    assert.equal(cssRes.status, 200);
    const html = await htmlRes.text();
    const css = await cssRes.text();
    assert.match(html, /id="shz-options-chain-panel"/);
    assert.match(html, /id="shz-oracle-strip"/);
    assert.match(html, /id="btn-sweep-book"/);
    assert.match(html, /data-bc-toggle="ma"/);
    assert.ok(css.includes("#0a0c0e"));
    assert.ok(css.includes("#111418"));
    assert.ok(css.includes("#232830"));
    assert.ok(css.includes("#66cc66"));
    assert.ok(css.includes("#dd4444"));
    assert.ok(css.includes("#ff9900"));

    // 2. GET /api/options + POST /api/options/quote across $90k, $100k, $110k, $120k, $125k Calls & Puts
    const optRes = await fetch(`${baseUrl}/api/options`);
    assert.equal(optRes.status, 200);
    const optData = await optRes.json();
    assert.equal(optData.feeBps, 0);
    assert.deepEqual(optData.strikes, [90_000, 100_000, 110_000, 120_000, 125_000]);
    assert.equal(optData.optionChain.length, 5);
    for (const row of optData.optionChain) {
      assert.ok(row.call.markBtc > 0 && row.call.delta > 0 && row.call.openInterestBtc > 0);
      assert.ok(row.put.markBtc > 0 && row.put.delta < 0 && row.put.openInterestBtc > 0);
      assert.equal(row.call.protocolFeeSats, 0);
      assert.equal(row.put.protocolFeeSats, 0);
    }

    const optQuoteRes = await fetch(`${baseUrl}/api/options/quote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        optionType: "Call",
        strikeUsd: 110_000,
        spotUsd: 100_000,
        ivPct: 58.2,
        daysToExpiry: 34,
        contractsBtc: 0.25,
      }),
    });
    assert.equal(optQuoteRes.status, 200);
    const oq = await optQuoteRes.json();
    assert.equal(oq.symbol, "BTC-27DEC26-110000-C");
    assert.equal(oq.protocolFeeSats, 0);
    assert.equal(oq.buyerPremiumSats + oq.writerCollateralSats, oq.totalP2trFundingSats);

    // 3. Bilateral Taproot Option order matching + L2 Orderbook Sweep emitting clearedLevels
    const optOrderRes = await fetch(`${baseUrl}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        instrument: "BTC-27DEC26-110000-C",
        side: "Long",
        orderType: "rfq",
        usdNotional: 30_000,
        leverageX: 5,
        collateral: "VanillaBtc",
      }),
    });
    assert.equal(optOrderRes.status, 200);
    const optOrder = await optOrderRes.json();
    assert.equal(optOrder.contractKind, "Option");
    assert.equal(optOrder.protocolFeeSats, 0);
    assert.ok(optOrder.filledUsdNotional > 0);
    assert.ok(Array.isArray(optOrder.clearedLevels) && optOrder.clearedLevels.length >= 1);

    const sweepRes = await fetch(`${baseUrl}/api/orderbook/sweep`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ instrument: "BTC-INVERSE-PERP", side: "Long" }),
    });
    assert.equal(sweepRes.status, 200);
    const sweepData = await sweepRes.json();
    assert.equal(sweepData.protocolFeeSats, 0);
    assert.ok(sweepData.clearedLevels.some((c) => c.kind === "wiped" || c.kind === "swept"));

    // 4. Oracle Checker System endpoint (Pyth Pro Ed25519 #1, TradeLayer tx14 VWAP, 3-of-5 FROST, NEAR IPA/Groth16)
    const ocRes = await fetch(`${baseUrl}/api/oracle-check`, { method: "POST", body: "{}" });
    assert.equal(ocRes.status, 200);
    const oc = await ocRes.json();
    assert.equal(oc.allHealthy, true);
    assert.equal(oc.pythPro.channel, "pyth-lazer");
    assert.equal(oc.pythPro.scheme, "Ed25519");
    assert.equal(oc.pythPro.feedId, 1);
    assert.equal(oc.tradelayerVwap.txType, "tx14");
    assert.equal(oc.frostQuorum.threshold, 3);
    assert.equal(oc.frostQuorum.total, 5);
    assert.equal(oc.nearGateways.fraudGuard.bondedStakeNear, 10_000);
    assert.equal(oc.nearGateways.transparentIpa.gasUsedTGas, 21.69);
    assert.equal(oc.nearGateways.groth16Gateway.statementBytes, 304);

    // 5. P2TR Position Transfer / Novation + Edmonds-Karp Margin Clearing (Bob 0x83 offline + online)
    const xferRes = await fetch(`${baseUrl}/api/positions/transfer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ positionId: "pos-opt-110k-c", assignee: "dave-lp-desk.p2tr" }),
    });
    assert.equal(xferRes.status, 200);
    const xfer = await xferRes.json();
    assert.equal(xfer.positionId, "pos-opt-110k-c");
    assert.equal(xfer.assignee, "dave-lp-desk.p2tr");
    assert.equal(xfer.protocolFeeSats, 0);
    assert.equal(xfer.conservationVerified, true);

    const ekRes = await fetch(`${baseUrl}/api/clearing/edmonds-karp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ includeOfflineBob: true }),
    });
    assert.equal(ekRes.status, 200);
    const ek = await ekRes.json();
    assert.equal(ek.bobFreedCollateralSats, 90_000_000);
    assert.equal(ek.onlineCounterpartiesFreedSats, 42_000_000);
    assert.equal(ek.totalFreedMarginSats, 132_000_000);
    assert.equal(ek.protocolFeeSats, 0);

    // 6. Workbench UI actions for Transfer/Novation, Edmonds-Karp Clearing, and Oracle Checker strip
    const listeners = new Map();
    const rootStub = {
      innerHTML: "",
      addEventListener(type, fn) {
        listeners.set(type, fn);
      },
    };
    const wb = mountWorkbench(rootStub, {
      market: { symbol: "BTC-INVERSE-PERP", markPriceUsd: 100_000 },
      oracleChecker: oc,
    });
    assert.ok(rootStub.innerHTML.includes("Transfer / Novate P2TR"));
    assert.ok(rootStub.innerHTML.includes("Edmonds-Karp Margin Clearing"));
    assert.ok(rootStub.innerHTML.includes("BTC-27DEC26-110000-C"));

    wb.openTransferNovation("pos-opt-110k-c", "dave-lp-desk.p2tr");
    assert.ok(rootStub.innerHTML.includes('data-novation-inspector="open"'));
    assert.ok(rootStub.innerHTML.includes("dave-lp-desk.p2tr"));
    assert.ok(rootStub.innerHTML.includes("0x83 SIGHASH_SINGLE|ANYONECANPAY"));

    wb.runEdmondsKarpClearing();
    assert.ok(rootStub.innerHTML.includes('data-clearing-inspector="open"'));
    assert.ok(rootStub.innerHTML.includes("90,000,000"));
    assert.ok(rootStub.innerHTML.includes("132,000,000"));

    const fireClick = (attrs) => {
      listeners.get("click")({
        target: { closest: () => ({ getAttribute: (k) => attrs[k] ?? null }) },
      });
    };
    fireClick({ "data-action": "switch-tab", "data-tab": "fraud" });
    assert.ok(rootStub.innerHTML.includes('data-oracle-checker-strip="true"'));
    assert.ok(rootStub.innerHTML.includes("pyth-lazer"));
    assert.ok(rootStub.innerHTML.includes("21.69 TGas"));

    const novPreview = computePositionNovationPreview({ id: "pos-1", marginSats: 500_000, counterpartyMarginSats: 500_000 });
    assert.equal(novPreview.totalP2trCollateralSats, 1_000_000);
    const ekPreview = computeEdmondsKarpClearingPreview([]);
    assert.equal(ekPreview.totalFreedCollateralSats, 132_000_000);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
