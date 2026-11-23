import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  ShzChartController,
  buildInverseSpec,
  compressDyadicCetRanges,
  computeInversePayout,
  computeLiquidationPrices,
  generateDeterministicCandles,
  generateInversePayoffCurve,
  lookupCetForPrice,
} from "./public/charts.js";

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
  computeMnr02CloseoutPreview,
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
