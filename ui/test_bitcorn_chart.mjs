import test from "node:test";
import assert from "node:assert/strict";

import {
  CandleChart,
  coordinateMap,
  createPriceScale,
  viewRange,
} from "./public/bitcorn/chart.js";
import { ema, sma, rsi, bollingerBands } from "./public/bitcorn/indicators.js";
import {
  MarketRenderMetrics,
  interpolateDepthProfile,
  prepareDepthProfile,
  sampleDepthProfile,
} from "./public/bitcorn/market-motion.js";
import {
  FIB_RATIOS,
  fibonacciPrices,
  makeDrawing,
  moveDrawing,
} from "./public/bitcorn/drawings.js";
import { makeDemoCandles } from "./public/bitcorn/demo.js";
import { feedPlan } from "./public/bitcorn/feed-policy.js";
import { FeedRouter } from "./public/bitcorn/feed-router.js";
import { CHART_COLORS } from "./public/bitcorn/workspace.js";
import {
  BITCORN_INTERVALS,
  ShzChartController,
  generateSyntheticCandles,
  mapOrderbookToDepth,
} from "./public/charts.js";
import { createAppServer, createSession } from "./server.mjs";

function makeCanvasStub(width = 820, height = 420) {
  const drawnTexts = [];
  const ops = [];
  const noop = () => {};
  const ctx = {
    save: noop,
    restore: noop,
    setTransform: noop,
    clearRect: noop,
    fillRect: (...args) => ops.push(["fillRect", ...args]),
    strokeRect: noop,
    rect: noop,
    clip: noop,
    beginPath: noop,
    closePath: noop,
    moveTo: noop,
    lineTo: noop,
    quadraticCurveTo: noop,
    arc: noop,
    fill: noop,
    stroke: noop,
    setLineDash: noop,
    measureText: (txt) => ({ width: String(txt).length * 6.4 }),
    fillText: (txt) => drawnTexts.push(String(txt)),
    fillStyle: "",
    strokeStyle: "",
    globalAlpha: 1,
    lineWidth: 1,
    font: "",
    textAlign: "left",
    textBaseline: "middle",
  };
  const listeners = new Map();
  const canvas = {
    width: 0,
    height: 0,
    clientWidth: width,
    clientHeight: height,
    style: {},
    parentElement: {
      clientWidth: width,
      clientHeight: height,
      getBoundingClientRect: () => ({ left: 0, top: 0, width, height }),
    },
    getContext: () => ctx,
    getBoundingClientRect: () => ({ left: 0, top: 0, width, height }),
    addEventListener: (type, fn) => {
      const list = listeners.get(type) || [];
      list.push(fn);
      listeners.set(type, list);
    },
    removeEventListener: (type, fn) => {
      const list = listeners.get(type) || [];
      listeners.set(
        type,
        list.filter((f) => f !== fn)
      );
    },
    focus: noop,
    setPointerCapture: noop,
  };
  const emit = (type, event) => {
    for (const fn of listeners.get(type) || []) fn(event);
  };
  return { canvas, ctx, drawnTexts, ops, listeners, emit };
}

test("BitcornWisdom coordinate mapping and linear/logarithmic price scales round-trip accurately", () => {
  const range = viewRange(200, 600, 8, 0, 11);
  assert.ok(range.start >= 0 && range.end === 199);

  const map = coordinateMap({ length: 200, plotRight: 700, barWidth: 8, offsetBars: 5, gap: 11 });
  for (const idx of [0, 50, 125.5, 199]) {
    const x = map.x(idx);
    assert.ok(Math.abs(map.index(x) - idx) < 1e-9);
  }

  const lin = createPriceScale(50_000, 150_000, 20, 320, false);
  assert.ok(Math.abs(lin.y(100_000) - 170) < 1e-9);
  assert.ok(Math.abs(lin.price(170) - 100_000) < 1e-6);

  const log = createPriceScale(50_000, 200_000, 20, 320, true);
  // Geometric mean sqrt(50k * 200k) = 100k maps to exact vertical midpoint 170
  assert.ok(Math.abs(log.y(100_000) - 170) < 1e-9);
  assert.ok(Math.abs(log.price(log.y(83_333)) - 83_333) < 1e-6);
  assert.ok(CHART_COLORS.shz.bg === "#0a0e14" && CHART_COLORS.shz.up === "#00d285");
});

test("BitcornWisdom EMA 20, SMA 50, Bollinger Bands 20/2σ, and RSI 14 indicators", () => {
  const candles = makeDemoCandles("15m", 120, 1_795_100_000_000, 100_000);
  const ema20 = ema(candles, 20);
  const sma50 = sma(candles, 50);
  const bb = bollingerBands(candles, 20, 2);
  const rsi14 = rsi(candles, 14);

  assert.equal(ema20[18], null);
  assert.ok(Number.isFinite(ema20[19]));
  assert.equal(sma50[48], null);
  assert.ok(Number.isFinite(sma50[49]));
  assert.equal(bb.basis[18], null);
  assert.ok(bb.upper[119] > bb.basis[119] && bb.basis[119] > bb.lower[119]);
  assert.ok(
    Math.abs((bb.upper[119] - bb.basis[119]) - (bb.basis[119] - bb.lower[119])) < 1e-9
  );
  assert.equal(rsi14[13], null);
  assert.ok(rsi14[119] >= 0 && rsi14[119] <= 100);

  // Monotonically rising closes yield RSI = 100
  const rising = Array.from({ length: 20 }, (_, i) => ({ close: 100 + i * 5 }));
  assert.equal(rsi(rising, 14)[19], 100);
});

test("BitcornWisdom L2 depth profile sampling, interpolation, and P2P orderbook mapping", () => {
  const depth = mapOrderbookToDepth({
    bids: [
      { priceUsd: 99_990, btcValue: 1.5 },
      { priceUsd: 99_950, valueBtc: 2.5 },
    ],
    asks: [
      { priceUsd: 100_010, btcValue: 1.2 },
      { priceUsd: 100_060, valueBtc: 3.8 },
    ],
  });
  assert.deepEqual(depth.bids, [
    [99_990, 1.5],
    [99_950, 2.5],
  ]);
  assert.deepEqual(depth.asks, [
    [100_010, 1.2],
    [100_060, 3.8],
  ]);

  const preparedA = prepareDepthProfile(depth);
  const preparedB = prepareDepthProfile({
    bids: [
      [99_990, 3.5],
      [99_950, 4.5],
    ],
    asks: [
      [100_010, 2.2],
      [100_060, 5.8],
    ],
  });
  const samples = [100_100, 100_020, 100_000, 99_980, 99_900];
  const profA = sampleDepthProfile(preparedA, samples);
  const profB = sampleDepthProfile(preparedB, samples);

  assert.equal(profA.asks[0], 5.0);
  assert.equal(profA.asks[1], 1.2);
  assert.equal(profA.asks[2], 0);
  assert.equal(profA.bids[3], 1.5);
  assert.equal(profA.bids[4], 4.0);

  const mid = interpolateDepthProfile(profA, profB, 0.5);
  assert.equal(mid.bids[4], 6.0);
  assert.equal(mid.asks[0], 6.5);
});

test("BitcornWisdom CandleChart drawings (trend, hline, fib), Shift-snap, and Ctrl+Z undo", () => {
  const { canvas, drawnTexts, emit } = makeCanvasStub(820, 400);
  const chart = new CandleChart(canvas);
  const candles = makeDemoCandles("15m", 80, 1_795_100_000_000, 100_000);
  chart.setCandles(candles, "15m", true);
  chart.setDepth(
    [
      [99_900, 2],
      [99_500, 5],
    ],
    [
      [100_100, 2],
      [100_500, 5],
    ],
    "P2P L2"
  );
  assert.ok(drawnTexts.some((t) => t.includes("L2 DEPTH")));
  assert.ok(drawnTexts.some((t) => t.includes("P2P L2")));

  // 1. Place a trend line (two clicks)
  chart.setTool("line");
  emit("pointerdown", { button: 0, clientX: 200, clientY: 160, shiftKey: false });
  emit("pointerdown", { button: 0, clientX: 380, clientY: 120, shiftKey: false });
  assert.equal(chart.drawings.length, 1);
  assert.equal(chart.drawings[0].type, "line");

  // 2. Place a horizontal line (one click)
  chart.setTool("horizontal");
  emit("pointerdown", { button: 0, clientX: 300, clientY: 150, shiftKey: false });
  assert.equal(chart.drawings.length, 2);
  assert.equal(chart.drawings[1].type, "horizontal");

  // 3. Place a Fibonacci retracement (two clicks) & verify 7 ratios
  chart.setTool("fib");
  emit("pointerdown", { button: 0, clientX: 240, clientY: 220, shiftKey: false });
  emit("pointerdown", { button: 0, clientX: 440, clientY: 90, shiftKey: false });
  assert.equal(chart.drawings.length, 3);
  assert.equal(chart.drawings[2].type, "fib");
  const fibLevels = fibonacciPrices(chart.drawings[2]);
  assert.equal(fibLevels.length, FIB_RATIOS.length);

  // 4. Shift-snap snaps precisely to candle high when pointer is within 11px
  const targetIdx = candles.length - 5;
  const targetCandle = candles[targetIdx];
  const snapX = chart.frame.coordinates.x(targetIdx);
  const snapY = chart.frame.prices.y(targetCandle.high) + 2;
  const snapped = chart.snapPoint(snapX, snapY, true);
  assert.equal(snapped.price, targetCandle.high);

  // 5. Move drawing preserves horizontal semantics
  const movedH = moveDrawing(makeDrawing("horizontal", { time: 1000, price: 95_000 }), 500, 1000);
  assert.equal(movedH.a.time, 1000);
  assert.equal(movedH.a.price, 96_000);

  // 6. Ctrl+Z undo removes last drawing; clearDrawings + undo restores remaining
  emit("keydown", { key: "z", ctrlKey: true, preventDefault() {} });
  assert.equal(chart.drawings.length, 2);
  chart.clearDrawings();
  assert.equal(chart.drawings.length, 0);
  chart.undoDrawing();
  assert.equal(chart.drawings.length, 2);

  chart.destroy();
});

test("BitcornWisdom FeedRouter fails over Kraken -> Coinbase -> unavailable cleanly", async () => {
  const plan15m = feedPlan({ instrument: "BTC-USD-SPOT", interval: "15m" });
  assert.deepEqual(
    plan15m.map((s) => s.id),
    ["kraken:BTCUSD", "coinbase:BTCUSD"]
  );
  // 4h is supported by Kraken natively without throwing
  const plan4h = feedPlan({ instrument: "BTC-USD-SPOT", interval: "4h" });
  assert.deepEqual(
    plan4h.map((s) => s.id),
    ["kraken:BTCUSD"]
  );

  let now = 1_795_100_000_000;
  const attempted = [];
  const receivedCandles = [];
  const history = makeDemoCandles("15m", 25, now, 100_000);

  const router = new FeedRouter({
    sources: plan15m,
    clock: () => now,
    schedule: () => 1,
    cancel: () => {},
    openSource: async (source, callbacks) => {
      attempted.push(source.id);
      if (source.market === "kraken") {
        throw new Error("Simulated Kraken offline");
      }
      callbacks.onHistory(history);
      callbacks.onStatus("live");
      callbacks.onCandle({ ...history.at(-1), close: history.at(-1).close + 25, high: history.at(-1).high + 25 });
      return { close() {} };
    },
    onCandle: (c, src) => receivedCandles.push({ c, venue: src.market }),
  });

  const ok = await router.start();
  assert.equal(ok, true);
  assert.deepEqual(attempted, ["kraken:BTCUSD", "coinbase:BTCUSD"]);
  assert.equal(router.snapshot().state, "live");
  assert.equal(router.snapshot().source.venue, "coinbase");
  assert.equal(receivedCandles.length, 1);
  router.stop();

  // MarketRenderMetrics snapshot checks
  const metrics = new MarketRenderMetrics();
  metrics.noteUpdate(100);
  metrics.noteDraw(104, 1.8);
  metrics.noteUpdate(120);
  metrics.noteDraw(125, 2.4);
  const snap = metrics.snapshot();
  assert.equal(snap.samples, 2);
  assert.ok(snap.canvasDrawMs >= 2.4);
  assert.ok(snap.updateToDrawMs >= 4);
  assert.ok(snap.activeFps > 0);
});

test("ShzChartController integrates BitcornWisdom candles, clearing markers, FeedRouter failover, and payoff mode", async () => {
  const { canvas, drawnTexts, emit } = makeCanvasStub(820, 420);
  const failingAdapter = async () => {
    throw new Error("Offline sandbox");
  };
  const ctrl = new ShzChartController(canvas, {
    liveFeed: true,
    openSource: failingAdapter,
  });

  // Wait a microtask for FeedRouter failover -> BITCORN DEMO
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(ctrl.feedState, "demo");
  assert.equal(ctrl.sourceLabel, "BITCORN DEMO");
  assert.ok(ctrl.candleChart instanceof CandleChart);
  assert.equal(ctrl.candleChart.depthProfileEnabled, true);
  assert.equal(typeof generateSyntheticCandles, "function");

  drawnTexts.length = 0;
  ctrl.setState({
    chartMode: "candles",
    market: {
      symbol: "BTC-INVERSE-PERP",
      markPriceUsd: 55_000,
      tradelayerVwapUsd: 56_200,
      pythConfBps: 20,
    },
    quote: {
      usdNotional: 50_000,
      entryPriceUsd: 50_000,
      longLevX: 5,
      shortLevX: 1,
    },
    orderbook: {
      bids: [
        { priceUsd: 54_950, btcValue: 2.2 },
        { priceUsd: 54_800, btcValue: 4.1 },
      ],
      asks: [
        { priceUsd: 55_050, btcValue: 1.8 },
        { priceUsd: 55_200, btcValue: 3.6 },
      ],
    },
    clearingTrades: [
      { label: "Trade 1", priceUsd: 50_000 },
      { label: "Trade 2", priceUsd: 54_000 },
      { label: "Trade 3 Closeout", priceUsd: 60_000 },
    ],
  });

  assert.ok(ctrl.candleChart.depthPrepared);
  assert.ok(drawnTexts.some((t) => t.includes("∞ UNLIQUIDATABLE (1x SatsHedge)")));
  assert.ok(drawnTexts.some((t) => t.includes("TL tx14 VWAP")));
  assert.ok(drawnTexts.some((t) => t.includes("ENTRY P0")));
  assert.ok(drawnTexts.some((t) => t.includes("LONG LIQ")));
  assert.ok(drawnTexts.some((t) => t.includes("Trade 1")));
  assert.ok(drawnTexts.some((t) => t.includes("Trade 2")));
  assert.ok(drawnTexts.some((t) => t.includes("Trade 3 Closeout")));

  // Test indicator, scale, interval, and tool controls
  ctrl.toggleIndicator("sma");
  ctrl.toggleIndicator("bb");
  ctrl.toggleIndicator("rsi");
  ctrl.toggleLog();
  assert.equal(ctrl.candleChart.showSMA, true);
  assert.equal(ctrl.candleChart.showBB, true);
  assert.equal(ctrl.candleChart.showRSI, true);
  assert.equal(ctrl.candleChart.logarithmic, true);

  for (const iv of BITCORN_INTERVALS) {
    ctrl.setInterval(iv);
    assert.equal(ctrl.interval, iv);
  }

  ctrl.setTool("trend");
  assert.equal(ctrl.candleChart.tool, "line");
  ctrl.setTool("hline");
  assert.equal(ctrl.candleChart.tool, "horizontal");
  ctrl.setTool("fib");
  assert.equal(ctrl.candleChart.tool, "fib");
  ctrl.setTool("pan");
  assert.equal(ctrl.candleChart.tool, "pan");

  // Switch to payoff mode -> pauses CandleChart and renders Dyadic CETs
  drawnTexts.length = 0;
  ctrl.setState({
    chartMode: "payoff",
    market: { symbol: "BTC-INVERSE-PERP", markPriceUsd: 100_000 },
    quote: { usdNotional: 1_000, entryPriceUsd: 100_000, longLevX: 10, shortLevX: 2 },
  });
  assert.equal(ctrl.candleChart.paused, true);
  emit("mousemove", { clientX: 400, clientY: 160 });
  assert.ok(drawnTexts.some((t) => t.includes("DYADIC CETs")));
  assert.ok(drawnTexts.some((t) => t.includes("SHORT LIQ CLAMP")));

  // Switch back to candles mode -> unpauses CandleChart and renders Short Liq overlay
  drawnTexts.length = 0;
  ctrl.setState({
    chartMode: "candles",
    market: { symbol: "BTC-INVERSE-PERP", markPriceUsd: 100_000, tradelayerVwapUsd: 101_000 },
    quote: { usdNotional: 1_000, entryPriceUsd: 100_000, longLevX: 10, shortLevX: 2 },
  });
  assert.equal(ctrl.candleChart.paused, false);
  assert.ok(drawnTexts.some((t) => t.includes("SHORT LIQ (2x)")));

  ctrl.destroy();
});

test("HTTP server serves vendored BitcornWisdom ES modules and control bar HTML cleanly", async () => {
  const app = createAppServer(createSession());
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const { port } = app.server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    const [htmlRes, chartModRes, routerModRes] = await Promise.all([
      fetch(`${baseUrl}/`),
      fetch(`${baseUrl}/bitcorn/chart.js`),
      fetch(`${baseUrl}/bitcorn/feed-router.js`),
    ]);
    assert.equal(htmlRes.status, 200);
    assert.equal(chartModRes.status, 200);
    assert.equal(routerModRes.status, 200);
    assert.match(chartModRes.headers.get("content-type") || "", /javascript/);

    const html = await htmlRes.text();
    assert.match(html, /id="shz-bitcorn-bar"/);
    assert.match(html, /data-bc-interval="15m"/);
    assert.match(html, /data-bc-toggle="depth"/);
    assert.match(html, /data-bc-tool="fib"/);
    assert.match(html, /id="bc-feed-badge"/);
  } finally {
    await new Promise((resolve) => app.server.close(resolve));
  }
});
