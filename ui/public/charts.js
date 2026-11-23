// SatsHedgeZero Interactive Canvas Chart Engine (`ui/public/charts.js`)
// Powered by patrickdugan/BitcornWisdom (MIT License, Copyright (c) 2026 Patrick Dugan)
//   1. "candles": Real BitcornWisdom `CandleChart` (EMA 20, SMA 50, BB 20/2σ, RSI 14, log/linear scale,
//                 cumulative L2 bid/ask depth profile, pan/zoom/drawings, Kraken+Coinbase FeedRouter
//                 with Bitcorn Synthetic failover) + SatsHedgeZero protocol overlays
//                 (Mark, TradeLayer tx14 VWAP, Pyth NEAR Relay ±conf band, Entry P0, Long/Short Liq,
//                 1x SatsHedge ∞ UNLIQUIDATABLE badge, optional 3-party clearing markers).
//   2. "payoff":  Dual-axis Inverse DLC Payoff (sats + USD purchasing power) & 20-bit Dyadic CET Visualizer.
//
// Zero external dependencies. Safe for both browser ES module import and Node.js unit testing.

import { CandleChart } from "./bitcorn/chart.js";
import { makeDemoCandles, makeDemoDepth, nextDemoCandle } from "./bitcorn/demo.js";
import { feedPlan } from "./bitcorn/feed-policy.js";
import { FeedRouter } from "./bitcorn/feed-router.js";
import { openFeedSource } from "./bitcorn/feed-adapters.js";

export const SATS_PER_BTC = 100_000_000n;
export const BPS_DENOMINATOR = 10_000n;
export const DEFAULT_CET_BITS = 20;
export const DEFAULT_CET_DOMAIN_SIZE = 1 << DEFAULT_CET_BITS; // 1,048,576
export const DEFAULT_CET_MAX_ERROR_SATS = 250;
export const BITCORN_INTERVALS = Object.freeze(["1m", "5m", "15m", "1h", "4h", "1d"]);

export const THEME = Object.freeze({
  bg: "#0a0e14",
  panel: "#10151e",
  border: "#1d2635",
  grid: "#161f2d",
  gridStrong: "#223047",
  textPrimary: "#e6edf7",
  textSecondary: "#8fa2bc",
  textMuted: "#5e718d",
  long: "#00d285",
  longSoft: "rgba(0, 210, 133, 0.14)",
  short: "#ff4d6d",
  shortSoft: "rgba(255, 77, 109, 0.14)",
  amber: "#f59e0b",
  amberSoft: "rgba(245, 158, 11, 0.15)",
  cyan: "#38bdf8",
  cyanSoft: "rgba(56, 189, 248, 0.10)",
  whiteSoft: "rgba(230, 237, 247, 0.72)",
  fontMono:
    '"JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace',
});

// ---------------------------------------------------------------------------
// Exact BigInt Inverse DLC Math (parity with crates/shz-margin/src/lib.rs)
// ---------------------------------------------------------------------------

function toBigIntFloor(value, fallback = 0n) {
  if (typeof value === "bigint") return value;
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return BigInt(Math.floor(n));
}

function divCeilBigInt(num, den) {
  if (den <= 0n) throw new RangeError("denominator must be > 0");
  if (num <= 0n) return 0n;
  return (num + den - 1n) / den;
}

/**
 * Exact round-half-to-even division for non-negative BigInts (`round_div_nearest_u128` parity).
 */
export function roundDivNearestBigInt(num, den) {
  const q = num / den;
  const r = num % den;
  const twiceR = r * 2n;
  if (twiceR > den || (twiceR === den && (q & 1n) === 1n)) {
    return q + 1n;
  }
  return q;
}

/**
 * Computes required initial margin in satoshis (rounded up) for given USD notional,
 * entry BTC/USD price, and leverage in basis points (`10_000` = 1.0x, `100_000` = 10.0x).
 */
export function computeMarginSats(usdNotional, entryPriceUsd, leverageBps) {
  const q = toBigIntFloor(usdNotional);
  const p0 = toBigIntFloor(entryPriceUsd);
  const lev = toBigIntFloor(leverageBps);
  if (q <= 0n || p0 <= 0n || lev <= 0n) {
    throw new RangeError("usdNotional, entryPriceUsd, and leverageBps must be > 0");
  }
  const num = q * SATS_PER_BTC * BPS_DENOMINATOR;
  const den = p0 * lev;
  return Number(divCeilBigInt(num, den));
}

/**
 * Builds a normalized inverse contract specification from leverage multiples or explicit margins.
 */
export function buildInverseSpec({
  usdNotional = 1_000,
  entryPriceUsd = 100_000,
  longLevX = 10,
  shortLevX = 1,
  longMarginSats = null,
  shortMarginSats = null,
} = {}) {
  const q = Math.max(1, Math.round(Number(usdNotional) || 1_000));
  const p0 = Math.max(1, Math.round(Number(entryPriceUsd) || 100_000));
  const lBps = Math.max(100, Math.round((Number(longLevX) || 10) * 10_000));
  const sBps = Math.max(100, Math.round((Number(shortLevX) || 1) * 10_000));
  const lMargin =
    longMarginSats != null && Number(longMarginSats) > 0
      ? Math.round(Number(longMarginSats))
      : computeMarginSats(q, p0, lBps);
  const sMargin =
    shortMarginSats != null && Number(shortMarginSats) > 0
      ? Math.round(Number(shortMarginSats))
      : computeMarginSats(q, p0, sBps);
  return {
    usdNotional: q,
    entryPriceUsd: p0,
    longLevX: lBps / 10_000,
    shortLevX: sBps / 10_000,
    longMarginSats: lMargin,
    shortMarginSats: sMargin,
    totalCollateralSats: lMargin + sMargin,
  };
}

/**
 * Returns `true` when Short has posted >= 1.0x BTC value (`M_short * P_0 >= Q * 1e8`),
 * creating an unliquidatable synthetic-USD SatsHedge.
 */
export function isCoveredSyntheticUsdShort(spec) {
  const lhs = BigInt(spec.shortMarginSats) * BigInt(spec.entryPriceUsd);
  const rhs = BigInt(spec.usdNotional) * SATS_PER_BTC;
  return lhs >= rhs;
}

/**
 * Exact liquidation prices matching `InverseContractSpec`:
 * - Long liq: `floor(P0 * Q * 1e8 / (Q * 1e8 + M_long * P0))`
 * - Short liq: `null` if covered <=1x SatsHedge, else `ceil(P0 * Q * 1e8 / (Q * 1e8 - M_short * P0))`
 */
export function computeLiquidationPrices(spec) {
  const qSats = BigInt(spec.usdNotional) * SATS_PER_BTC;
  const p0 = BigInt(spec.entryPriceUsd);
  const longLiqUsd = Number((p0 * qSats) / (qSats + BigInt(spec.longMarginSats) * p0));

  const covered = isCoveredSyntheticUsdShort(spec);
  if (covered) {
    return {
      longLiqUsd,
      shortLiqUsd: null,
      isCoveredSyntheticUsd: true,
    };
  }
  const den = qSats - BigInt(spec.shortMarginSats) * p0;
  const shortLiqUsd = Number(divCeilBigInt(p0 * qSats, den));
  return {
    longLiqUsd,
    shortLiqUsd,
    isCoveredSyntheticUsd: false,
  };
}

/**
 * Exact unclamped Long PnL in satoshis: `round_half_even(Q * 1e8 * (P_T - P_0) / (P_0 * P_T))`.
 */
export function unclampedLongPnlSats(spec, settlementPriceUsd) {
  const pt = toBigIntFloor(settlementPriceUsd);
  const total = BigInt(spec.totalCollateralSats ?? spec.longMarginSats + spec.shortMarginSats);
  if (pt <= 0n) return -Number(total);
  const qSats = BigInt(spec.usdNotional) * SATS_PER_BTC;
  const p0 = BigInt(spec.entryPriceUsd);
  const den = p0 * pt;
  if (pt >= p0) {
    return Number(roundDivNearestBigInt(qSats * (pt - p0), den));
  }
  return -Number(roundDivNearestBigInt(qSats * (p0 - pt), den));
}

/**
 * Exact clamped DLC payout split and USD purchasing power at `settlementPriceUsd`.
 * Preserves `longSats + shortSats === totalCollateralSats` and `protocolFeeSats === 0`.
 */
export function computeInversePayout(spec, settlementPriceUsd) {
  const total = spec.longMarginSats + spec.shortMarginSats;
  const pt = Math.max(0, Math.floor(Number(settlementPriceUsd) || 0));
  if (pt === 0) {
    return {
      priceUsd: 0,
      longSats: 0,
      shortSats: total,
      longPnlSats: -spec.longMarginSats,
      shortPnlSats: spec.longMarginSats,
      unclampedLongPnlSats: -total,
      longUsdValue: 0,
      shortUsdValue: 0,
      protocolFeeSats: 0,
    };
  }
  const unclamped = unclampedLongPnlSats(spec, pt);
  const rawLong = spec.longMarginSats + unclamped;
  const longSats = Math.max(0, Math.min(total, rawLong));
  const shortSats = total - longSats;
  const longPnlSats = longSats - spec.longMarginSats;
  const shortPnlSats = shortSats - spec.shortMarginSats;
  const longUsdValue = (longSats / 1e8) * pt;
  const shortUsdValue = (shortSats / 1e8) * pt;

  return {
    priceUsd: pt,
    longSats,
    shortSats,
    longPnlSats,
    shortPnlSats,
    unclampedLongPnlSats: unclamped,
    longUsdValue,
    shortUsdValue,
    protocolFeeSats: 0,
  };
}

/**
 * Exact port of `compress_cet_ranges` from `crates/shz-margin/src/lib.rs`.
 * Partitions `[0, 2^numBits - 1]` into disjoint dyadic binary prefixes with payout error <= maxPayoutErrorSats.
 * For `$1,000` @ `$100,000` `10x/10x`, 20-bit, `maxError = 250`, produces exact 643 CETs out of 1,048,576 prices.
 */
export function compressDyadicCetRanges(
  spec,
  numBits = DEFAULT_CET_BITS,
  maxPayoutErrorSats = DEFAULT_CET_MAX_ERROR_SATS
) {
  if (numBits < 4 || numBits > 30) {
    throw new RangeError(`numBits ${numBits} must be in 4..=30`);
  }
  const total = spec.longMarginSats + spec.shortMarginSats;
  const maxDomainPrice = (1 << numBits) - 1;
  const out = [];
  const prefix = [];

  function walk(minPrice, maxPrice) {
    const low = computeInversePayout(spec, minPrice);
    const high = computeInversePayout(spec, maxPrice);
    const spread = Math.max(0, high.longSats - low.longSats);
    const worstErr = Math.ceil(spread / 2);

    if (
      prefix.length > 0 &&
      (minPrice === maxPrice || prefix.length === numBits || worstErr <= maxPayoutErrorSats)
    ) {
      const repLong = Math.floor((low.longSats + high.longSats) / 2);
      out.push({
        prefix: prefix.join(""),
        prefixLen: prefix.length,
        minPriceUsd: minPrice,
        maxPriceUsd: maxPrice,
        longSats: repLong,
        shortSats: total - repLong,
        protocolFeeSats: 0,
      });
      return;
    }

    const mid = minPrice + ((maxPrice - minPrice) >> 1);
    prefix.push("0");
    walk(minPrice, mid);
    prefix.pop();

    prefix.push("1");
    walk(mid + 1, maxPrice);
    prefix.pop();
  }

  walk(0, maxDomainPrice);
  return out;
}

/**
 * Binary search lookup of the unique compressed CET covering `priceUsd`.
 */
export function lookupCetForPrice(cets, priceUsd, numBits = DEFAULT_CET_BITS) {
  if (!Array.isArray(cets) || cets.length === 0) return null;
  const clamped = Math.max(0, Math.min((1 << numBits) - 1, Math.floor(priceUsd)));
  let lo = 0;
  let hi = cets.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const cet = cets[mid];
    if (clamped < cet.minPriceUsd) {
      hi = mid - 1;
    } else if (clamped > cet.maxPriceUsd) {
      lo = mid + 1;
    } else {
      return cet;
    }
  }
  return null;
}

/**
 * Generates the dual-axis Inverse DLC payoff curve across `$20,000 .. $200,000`
 * alongside exact liquidation cliffs and compressed 20-bit dyadic CET prefix intervals.
 */
export function generateInversePayoffCurve(
  rawSpec,
  {
    minPrice = 20_000,
    maxPrice = 200_000,
    steps = 180,
    numBits = DEFAULT_CET_BITS,
    maxPayoutErrorSats = DEFAULT_CET_MAX_ERROR_SATS,
  } = {}
) {
  const spec = buildInverseSpec(rawSpec);
  const liq = computeLiquidationPrices(spec);

  const priceSet = new Set();
  for (let i = 0; i <= steps; i++) {
    const p = Math.round(minPrice + ((maxPrice - minPrice) * i) / steps);
    priceSet.add(p);
  }
  for (const critical of [
    spec.entryPriceUsd,
    liq.longLiqUsd,
    liq.longLiqUsd + 1,
    liq.shortLiqUsd,
    liq.shortLiqUsd != null ? liq.shortLiqUsd - 1 : null,
  ]) {
    if (critical != null && critical >= minPrice && critical <= maxPrice) {
      priceSet.add(Math.round(critical));
    }
  }

  const sortedPrices = Array.from(priceSet).sort((a, b) => a - b);
  const points = sortedPrices.map((p) => computeInversePayout(spec, p));

  const allCets = compressDyadicCetRanges(spec, numBits, maxPayoutErrorSats);
  const visibleCets = allCets.filter(
    (c) => c.maxPriceUsd >= minPrice && c.minPriceUsd <= maxPrice
  );
  const domainSize = 1 << numBits;
  const compressionRatioPct = Number((((domainSize - allCets.length) / domainSize) * 100).toFixed(2));

  return {
    spec,
    minPrice,
    maxPrice,
    longLiqUsd: liq.longLiqUsd,
    shortLiqUsd: liq.shortLiqUsd,
    isCoveredSyntheticUsd: liq.isCoveredSyntheticUsd,
    points,
    cetStats: {
      numBits,
      domainSize,
      totalCompressedCets: allCets.length,
      visibleCetCount: visibleCets.length,
      maxPayoutErrorSats,
      compressionRatioPct,
    },
    allCets,
    visibleCets,
  };
}

// ---------------------------------------------------------------------------
// Deterministic BTC/USD OHLCV + TradeLayer VWAP + Pyth Confidence Band
// (Preserved for pure-math tests and deterministic offline fallback)
// ---------------------------------------------------------------------------

function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Generates deterministic institutional 15m OHLCV candles ending at `markPriceUsd`,
 * with anchored TradeLayer L1 VWAP (`tx14`) line and Pyth confidence band (`±confBps`).
 */
export function generateDeterministicCandles({
  markPriceUsd = 100_000,
  vwapPriceUsd = 100_420,
  pythConfBps = 22,
  count = 72,
  seed = 0x53485a30,
  endTimestampSec = 1_795_100_000,
} = {}) {
  const rand = mulberry32(seed);
  const rawCloses = new Array(count);
  let walk = 0;
  for (let i = 0; i < count; i++) {
    const wave = Math.sin(i * 0.22) * 1450 + Math.cos(i * 0.085) * 950;
    const step = (rand() - 0.495) * 620;
    walk = walk * 0.86 + step;
    rawCloses[i] = wave + walk;
  }
  const shift = markPriceUsd - rawCloses[count - 1];
  const confRatio = Math.max(4, Number(pythConfBps) || 22) / 10_000;

  const candles = [];
  let cumPV = 0;
  let cumV = 0;
  for (let i = 0; i < count; i++) {
    const close = Math.max(10_000, Math.round(rawCloses[i] + shift));
    const open = i === 0 ? Math.round(close - (rand() - 0.5) * 320) : candles[i - 1].close;
    const wickUp = Math.round(80 + rand() * 440);
    const wickDn = Math.round(80 + rand() * 440);
    const high = Math.max(open, close) + wickUp;
    const low = Math.max(5_000, Math.min(open, close) - wickDn);
    const volumeUsd = Math.round(180_000 + Math.abs(close - open) * 520 + rand() * 420_000);
    const typical = (high + low + close) / 3;
    cumPV += typical * volumeUsd;
    cumV += volumeUsd;
    const runningVwap = cumPV / cumV;
    candles.push({
      index: i,
      timeSec: endTimestampSec - (count - 1 - i) * 900,
      open,
      high,
      low,
      close,
      volumeUsd,
      rawVwap: runningVwap,
    });
  }

  const finalDelta = vwapPriceUsd - candles[count - 1].rawVwap;
  for (let i = 0; i < count; i++) {
    const blend = (i + 1) / count;
    const vwap = Math.round(candles[i].rawVwap + finalDelta * blend);
    const bandHalf = Math.max(120, Math.round(candles[i].close * confRatio * 2.5));
    candles[i].vwap = vwap;
    candles[i].pythUpper = candles[i].close + bandHalf;
    candles[i].pythLower = Math.max(1_000, candles[i].close - bandHalf);
  }

  return candles;
}

export const generateSyntheticCandles = generateDeterministicCandles;

// ---------------------------------------------------------------------------
// Orderbook & State Normalization
// ---------------------------------------------------------------------------

/**
 * Maps SatsHedgeZero P2P orderbook entries (`{ priceUsd, valueBtc | btcValue | sizeUsd }` or `[price, qty]`)
 * into BitcornWisdom's `[price, qty]` depth arrays.
 */
export function mapOrderbookToDepth(orderbook) {
  if (!orderbook || typeof orderbook !== "object") return { bids: [], asks: [] };
  const mapSide = (rows) => {
    if (!Array.isArray(rows)) return [];
    const out = [];
    for (const r of rows) {
      if (Array.isArray(r) && r.length >= 2) {
        const p = Number(r[0]);
        const q = Number(r[1]);
        if (Number.isFinite(p) && p > 0 && Number.isFinite(q) && q > 0) out.push([p, q]);
      } else if (r && typeof r === "object") {
        const p = Number(r.priceUsd ?? r.price);
        const q = Number(
          r.btcValue ??
            r.valueBtc ??
            r.qty ??
            (Number.isFinite(Number(r.sizeUsd)) && p > 0 ? Number(r.sizeUsd) / p : NaN)
        );
        if (Number.isFinite(p) && p > 0 && Number.isFinite(q) && q > 0) out.push([p, q]);
      }
    }
    return out;
  };
  return {
    bids: mapSide(orderbook.bids),
    asks: mapSide(orderbook.asks),
  };
}

function normalizeClearingTrades(rawTrades) {
  if (!Array.isArray(rawTrades)) return [];
  const out = [];
  for (let i = 0; i < rawTrades.length; i++) {
    const t = rawTrades[i];
    if (!t || typeof t !== "object") continue;
    const priceUsd = Number(t.priceUsd ?? t.price ?? t.price_usd);
    if (!Number.isFinite(priceUsd) || priceUsd <= 0) continue;
    out.push({
      label: String(t.label || `Trade ${i + 1}`),
      priceUsd,
      side: t.side || null,
      color: t.color || (i === rawTrades.length - 1 ? THEME.amber : THEME.cyan),
      timeSec: Number.isFinite(Number(t.timeSec ?? t.time_sec))
        ? Number(t.timeSec ?? t.time_sec)
        : null,
    });
  }
  return out;
}

export function normalizeChartState(rawState = {}) {
  const state = rawState && typeof rawState === "object" ? rawState : {};
  const market = state.market || {};
  const quote = state.quote || {};
  const dexSim = state.baselineEvidence?.dex_simulation || {};

  const chartMode =
    state.chartMode === "payoff" || state.chart_mode === "payoff" ? "payoff" : "candles";

  const symbol =
    market.symbol ||
    market.instrument ||
    state.instrument ||
    "BTC-INVERSE-PERP";

  const markPriceUsd = Number(
    market.markPriceUsd ??
      market.markPrice ??
      market.mark_price_usd ??
      quote.entryPriceUsd ??
      quote.entry_price_usd ??
      100_000
  );

  const vwapPriceUsd = Number(
    market.tradelayerVwapUsd ??
      market.tradelayerVwap ??
      market.vwapPriceUsd ??
      market.vwap ??
      dexSim.tradelayer_vwap_price_usd ??
      Math.round(markPriceUsd * 1.0025)
  );

  const pythConfBps = Number(
    market.pythConfBps ??
      market.pythConfidenceBps ??
      market.pyth_conf_bps ??
      20
  );

  const usdNotional = Number(quote.usdNotional ?? quote.usd_notional ?? 1_000);
  const entryPriceUsd = Number(quote.entryPriceUsd ?? quote.entry_price_usd ?? markPriceUsd);
  const longLevX = Number(quote.longLevX ?? quote.long_lev_x ?? 10);
  const shortLevX = Number(quote.shortLevX ?? quote.short_lev_x ?? 1);
  const side = (quote.side || "short").toLowerCase();

  const spec = buildInverseSpec({
    usdNotional,
    entryPriceUsd,
    longLevX,
    shortLevX,
    longMarginSats: quote.longMarginSats ?? quote.long_margin_sats ?? null,
    shortMarginSats: quote.shortMarginSats ?? quote.short_margin_sats ?? null,
  });
  const liq = computeLiquidationPrices(spec);

  return {
    chartMode,
    symbol,
    markPriceUsd,
    vwapPriceUsd,
    pythConfBps,
    side,
    spec,
    longLiqUsd: liq.longLiqUsd,
    shortLiqUsd: liq.shortLiqUsd,
    isCoveredSyntheticUsd: liq.isCoveredSyntheticUsd,
    depth: mapOrderbookToDepth(state.orderbook),
    clearingTrades: normalizeClearingTrades(state.clearingTrades || state.clearing_trades),
  };
}

// ---------------------------------------------------------------------------
// Formatting & Canvas Overlay Primitives
// ---------------------------------------------------------------------------

function fmtUsd(val, compact = false) {
  if (val == null || !Number.isFinite(val)) return "—";
  if (compact && Math.abs(val) >= 1_000) {
    return `$${(val / 1_000).toFixed(val % 1_000 === 0 ? 0 : 1)}k`;
  }
  return `$${Math.round(val).toLocaleString("en-US")}`;
}

function fmtSats(val, signed = false) {
  if (val == null || !Number.isFinite(val)) return "—";
  const rounded = Math.round(val);
  const prefix = signed && rounded > 0 ? "+" : "";
  return `${prefix}${rounded.toLocaleString("en-US")} sats`;
}

function fmtCompactSats(val) {
  const abs = Math.abs(val);
  const sign = val > 0 ? "+" : val < 0 ? "-" : "";
  if (abs >= 1_000_000) return `${sign}${(abs / 1_000_000).toFixed(2)}M`;
  if (abs >= 1_000) return `${sign}${(abs / 1_000).toFixed(0)}k`;
  return `${sign}${Math.round(abs)}`;
}

function drawRoundedRect(ctx, x, y, w, h, r = 3) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

function drawBadge(ctx, text, x, y, bg, border, fg, alignRight = false) {
  ctx.save();
  ctx.font = `600 10px ${THEME.fontMono}`;
  const padX = 6;
  const h = 17;
  const w = ctx.measureText(text).width + padX * 2;
  const bx = alignRight ? x - w : x;
  drawRoundedRect(ctx, bx, y, w, h, 3);
  ctx.fillStyle = bg;
  ctx.fill();
  ctx.strokeStyle = border;
  ctx.lineWidth = 1;
  ctx.stroke();
  ctx.fillStyle = fg;
  ctx.textAlign = "left";
  ctx.textBaseline = "middle";
  ctx.fillText(text, bx + padX, y + h / 2 + 0.5);
  ctx.restore();
  return w;
}

function drawTooltipBox(ctx, lines, anchorX, anchorY, width, height) {
  ctx.save();
  ctx.font = `500 11px ${THEME.fontMono}`;
  let maxW = 0;
  for (const line of lines) {
    const labelW = ctx.measureText(line.label + " ").width;
    const valW = ctx.measureText(line.value).width;
    if (labelW + valW > maxW) maxW = labelW + valW;
  }
  const padX = 10;
  const padY = 8;
  const rowH = 16;
  const boxW = Math.max(185, maxW + padX * 2 + 12);
  const boxH = lines.length * rowH + padY * 2;

  let bx = anchorX + 14;
  let by = anchorY - boxH - 10;
  if (bx + boxW > width - 8) bx = anchorX - boxW - 14;
  if (bx < 8) bx = 8;
  if (by < 34) by = anchorY + 14;
  if (by + boxH > height - 8) by = height - boxH - 8;

  drawRoundedRect(ctx, bx, by, boxW, boxH, 4);
  ctx.fillStyle = "rgba(10, 14, 20, 0.94)";
  ctx.fill();
  ctx.strokeStyle = "#29374d";
  ctx.lineWidth = 1;
  ctx.stroke();

  ctx.textBaseline = "middle";
  for (let i = 0; i < lines.length; i++) {
    const rowY = by + padY + i * rowH + rowH / 2;
    ctx.textAlign = "left";
    ctx.fillStyle = lines[i].labelColor || THEME.textSecondary;
    ctx.fillText(lines[i].label, bx + padX, rowY);

    ctx.textAlign = "right";
    ctx.fillStyle = lines[i].valueColor || THEME.textPrimary;
    ctx.fillText(lines[i].value, bx + boxW - padX, rowY);
  }
  ctx.restore();
}

function queryParamDemo() {
  if (typeof window === "undefined" || !window.location?.search) return false;
  try {
    return new URLSearchParams(window.location.search).get("demo") === "1";
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// ShzChartController (BitcornWisdom CandleChart + SatsHedgeZero Payoff Mode)
// ---------------------------------------------------------------------------

export class ShzChartController {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.ctx = canvas ? canvas.getContext("2d") : null;
    this.state = normalizeChartState({});
    this.pointer = null;
    this.cachedPayoffKey = "";
    this.cachedPayoff = null;
    this._resizeObserver = null;
    this._onWindowResize = null;
    this._uiListeners = [];
    this._demoTimer = null;
    this._demoTick = 0;
    this._router = null;
    this._feedEpoch = 0;
    this._lastTelemetryPush = 0;

    const isBrowser =
      typeof window !== "undefined" &&
      typeof document !== "undefined" &&
      typeof fetch === "function";

    this.interval = BITCORN_INTERVALS.includes(options.interval) ? options.interval : "15m";
    this.forceDemo = options.demo === true || queryParamDemo();
    this.liveFeedEnabled =
      options.liveFeed !== undefined ? Boolean(options.liveFeed) : isBrowser && !this.forceDemo;
    this.openSource = options.openSource || null;
    this.onTelemetry = typeof options.onTelemetry === "function" ? options.onTelemetry : null;

    this.feedState = this.forceDemo || !this.liveFeedEnabled ? "demo" : "connecting";
    this.sourceLabel = this.feedState === "demo" ? "BITCORN DEMO" : "CONNECTING";
    this.hasLiveVenueCandles = false;
    this.hasLiveVenueDepth = false;
    this.lastMetrics = { samples: 0, canvasDrawMs: null, updateToDrawMs: null, activeFps: null };
    this._syntheticAnchor = null;

    this.candleChart = canvas
      ? new CandleChart(canvas, {
          onDrawingsChange: () => this._syncControlBar(),
        })
      : null;

    if (this.candleChart) {
      this.candleChart.setOptions({
        theme: "shz",
        interval: this.interval,
        depthProfileEnabled: true,
        showEMA: true,
        showSMA: false,
        showBB: false,
        showRSI: false,
        logarithmic: false,
      });
      this.candleChart.onPaint = (metrics, frame, ctx) => {
        this.lastMetrics = metrics || this.lastMetrics;
        this._paintProtocolOverlays(metrics, frame, ctx);
        this._notifyTelemetry(false);
      };
      this._seedSyntheticCandles(this.state.markPriceUsd, true);
    }

    if (canvas) {
      this._bindEvents();
      this.resizeAndRender();
      if (this.liveFeedEnabled) {
        this._startFeedRouter();
      } else if (isBrowser && this.forceDemo) {
        this._startDemoTicker();
      }
    }
  }

  _bindEvents() {
    this._onMove = (ev) => {
      const rect = this.canvas.getBoundingClientRect?.() || { left: 0, top: 0 };
      const pt = {
        x: ev.clientX - rect.left,
        y: ev.clientY - rect.top,
      };
      this.pointer = pt;
      if (this.state.chartMode === "payoff") {
        this.render();
      } else if (this.candleChart) {
        this.candleChart.pointerMove(ev);
      }
    };
    this._onLeave = () => {
      this.pointer = null;
      if (this.state.chartMode === "payoff") {
        this.render();
      } else if (this.candleChart && !this.candleChart.drag) {
        this.candleChart.pointer = null;
        this.candleChart.requestDraw();
      }
    };
    this.canvas.addEventListener?.("mousemove", this._onMove);
    this.canvas.addEventListener?.("mouseleave", this._onLeave);

    if (typeof ResizeObserver !== "undefined") {
      this._resizeObserver = new ResizeObserver(() => {
        if (this.state.chartMode === "payoff") this.resizeAndRender();
      });
      this._resizeObserver.observe(this.canvas.parentElement || this.canvas);
    } else if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
      this._onWindowResize = () => {
        if (this.state.chartMode === "payoff") this.resizeAndRender();
      };
      window.addEventListener("resize", this._onWindowResize);
    }
  }

  bindControls(container) {
    if (!container || typeof container.querySelectorAll !== "function") return;
    this._controlsRoot = container;
    this._unbindControls();

    const listen = (el, type, fn) => {
      el.addEventListener(type, fn);
      this._uiListeners.push([el, type, fn]);
    };

    container.querySelectorAll("[data-bc-interval]").forEach((btn) => {
      listen(btn, "click", () => {
        const iv = btn.getAttribute("data-bc-interval");
        if (iv) this.setInterval(iv);
      });
    });

    container.querySelectorAll("[data-bc-toggle]").forEach((btn) => {
      listen(btn, "click", () => {
        const key = btn.getAttribute("data-bc-toggle");
        if (key === "log") this.toggleLog();
        else if (key === "depth") this.toggleDepth();
        else if (key) this.toggleIndicator(key);
      });
    });

    container.querySelectorAll("[data-bc-tool]").forEach((btn) => {
      listen(btn, "click", () => {
        const tool = btn.getAttribute("data-bc-tool");
        if (tool) this.setTool(tool);
      });
    });

    container.querySelectorAll("[data-bc-action]").forEach((btn) => {
      listen(btn, "click", () => {
        const act = btn.getAttribute("data-bc-action");
        if (act === "undo") this.undoDrawing();
        else if (act === "clear") this.clearDrawings();
        else if (act === "reset") this.resetView();
        else if (act === "feed") this.toggleDemoFeed();
      });
    });

    this._syncControlBar();
  }

  _unbindControls() {
    for (const [el, type, fn] of this._uiListeners) {
      el.removeEventListener?.(type, fn);
    }
    this._uiListeners = [];
  }

  _syncControlBar() {
    const root = this._controlsRoot;
    if (!root) return;
    root.hidden = this.state.chartMode === "payoff";

    root.querySelectorAll("[data-bc-interval]").forEach((btn) => {
      btn.classList.toggle("is-active", btn.getAttribute("data-bc-interval") === this.interval);
    });

    const chart = this.candleChart;
    if (chart) {
      const toggleMap = {
        ema: chart.showEMA,
        sma: chart.showSMA,
        bb: chart.showBB,
        rsi: chart.showRSI,
        log: chart.logarithmic,
        depth: chart.depthProfileEnabled,
      };
      root.querySelectorAll("[data-bc-toggle]").forEach((btn) => {
        const key = btn.getAttribute("data-bc-toggle");
        btn.classList.toggle("is-active", Boolean(toggleMap[key]));
      });
      root.querySelectorAll("[data-bc-tool]").forEach((btn) => {
        btn.classList.toggle("is-active", btn.getAttribute("data-bc-tool") === chart.tool);
      });
    }

    const srcEl = root.querySelector("#bc-feed-badge");
    if (srcEl) {
      srcEl.textContent = this.sourceLabel;
      srcEl.dataset.state = this.feedState;
    }

    const perfEl = root.querySelector("#bc-perf-badge");
    if (perfEl) {
      const p95 = this.lastMetrics?.canvasDrawMs;
      perfEl.textContent = Number.isFinite(p95) ? `p95 ${p95.toFixed(1)}ms` : "p95 —";
    }
  }

  _notifyTelemetry(force = false) {
    const now = Date.now();
    if (!force && now - this._lastTelemetryPush < 200) return;
    this._lastTelemetryPush = now;
    this._syncControlBar();
    if (this.onTelemetry) {
      this.onTelemetry({
        sourceLabel: this.sourceLabel,
        feedState: this.feedState,
        p95Ms: this.lastMetrics?.canvasDrawMs ?? null,
        fps: this.lastMetrics?.activeFps ?? null,
        interval: this.interval,
        tool: this.candleChart?.tool ?? "pan",
      });
    }
  }

  _stopFeed() {
    ++this._feedEpoch;
    this._router?.stop();
    this._router = null;
    if (this._demoTimer !== null) {
      clearInterval(this._demoTimer);
      this._demoTimer = null;
    }
  }

  _seedSyntheticCandles(anchorPriceUsd, reset = true) {
    if (!this.candleChart) return;
    const anchor = Number.isFinite(anchorPriceUsd) && anchorPriceUsd > 0 ? anchorPriceUsd : 100_000;
    this._syntheticAnchor = anchor;
    const rows = makeDemoCandles(this.interval, 160, Date.now(), anchor);
    this.candleChart.setCandles(rows, this.interval, reset);
    if (!this.hasLiveVenueDepth) {
      if (this.state.depth.bids.length || this.state.depth.asks.length) {
        this.candleChart.setDepth(this.state.depth.bids, this.state.depth.asks, "P2P L2");
      } else {
        const d = makeDemoDepth(anchor);
        this.candleChart.setDepth(d.bids, d.asks, "P2P L2");
      }
    }
  }

  _startDemoTicker() {
    this._stopFeed();
    const epoch = this._feedEpoch;
    this.feedState = "demo";
    this.sourceLabel = "BITCORN DEMO";
    this.hasLiveVenueCandles = false;
    this.hasLiveVenueDepth = false;
    this._seedSyntheticCandles(this.state.markPriceUsd, true);
    this._notifyTelemetry(true);

    if (typeof window === "undefined") return;
    this._demoTimer = setInterval(() => {
      if (epoch !== this._feedEpoch || !this.candleChart) return;
      if (this.state.chartMode !== "candles") return;
      const last = this.candleChart.candles.at(-1);
      if (!last) return;
      const next = nextDemoCandle(last, this.interval, this._demoTick++);
      this.candleChart.updateCandle(next);
    }, 1400);
  }

  _startFeedRouter() {
    this._stopFeed();
    const epoch = this._feedEpoch;
    this.feedState = "connecting";
    this.sourceLabel = "CONNECTING";
    this.hasLiveVenueCandles = false;
    this.hasLiveVenueDepth = false;
    this._notifyTelemetry(true);

    let sources;
    try {
      sources = feedPlan({ instrument: "BTC-USD-SPOT", interval: this.interval });
    } catch {
      this._startDemoTicker();
      return;
    }

    const adapter =
      this.openSource ||
      ((source, callbacks, signal) =>
        openFeedSource(source, callbacks, signal, { includeDepth: true }));

    this._router = new FeedRouter({
      sources,
      openSource: adapter,
      connectTimeoutMs: 7000,
      staleMs: 25000,
      onSource: (snapshot) => {
        if (epoch !== this._feedEpoch) return;
        if (snapshot.source?.venue) {
          this.sourceLabel = `${snapshot.source.venue.toUpperCase()} SYNC`;
          this.feedState = "connecting";
        }
        this._notifyTelemetry(true);
      },
      onStatus: (snapshot) => {
        if (epoch !== this._feedEpoch) return;
        if (snapshot.state === "live" && snapshot.source?.venue) {
          this.feedState = "live";
          this.sourceLabel = `${snapshot.source.venue.toUpperCase()} LIVE`;
          this._notifyTelemetry(true);
        } else if (snapshot.state === "unavailable") {
          // Automatic failover to Bitcorn Synthetic when offline or venues unreachable
          this._startDemoTicker();
        } else if (snapshot.state === "disrupted" || snapshot.state === "stale") {
          this.feedState = snapshot.state;
          this.sourceLabel = snapshot.source?.venue
            ? `${snapshot.source.venue.toUpperCase()} RETRY`
            : "RECONNECTING";
          this._notifyTelemetry(true);
        }
      },
      onHistory: (candles, source) => {
        if (epoch !== this._feedEpoch || !this.candleChart) return;
        this.hasLiveVenueCandles = true;
        this.feedState = "live";
        this.sourceLabel = `${source.market.toUpperCase()} LIVE`;
        this.candleChart.setCandles(candles, this.interval, true);
        this._notifyTelemetry(true);
      },
      onCandle: (candle, source) => {
        if (epoch !== this._feedEpoch || !this.candleChart) return;
        this.hasLiveVenueCandles = true;
        this.feedState = "live";
        this.sourceLabel = `${source.market.toUpperCase()} LIVE`;
        this.candleChart.updateCandle(candle);
        this._notifyTelemetry(false);
      },
      onTrade: (trade) => {
        if (epoch !== this._feedEpoch || !this.candleChart) return;
        this.candleChart.updateTrade(trade);
      },
      onDepth: (book) => {
        if (epoch !== this._feedEpoch || !this.candleChart) return;
        this.hasLiveVenueDepth = true;
        this.candleChart.setDepthBook({ ...book, label: "LIVE L2" });
      },
      onError: () => {
        // FeedRouter manages venue failover and demo fallback cleanly.
      },
    });

    void this._router.start().then((ok) => {
      if (epoch !== this._feedEpoch) return;
      if (!ok && this._router?.snapshot().state === "unavailable") {
        this._startDemoTicker();
      }
    });
  }

  // --- Public BitcornWisdom Control API ---

  setInterval(interval) {
    if (!BITCORN_INTERVALS.includes(interval)) return;
    if (this.interval === interval) return;
    this.interval = interval;
    if (this.candleChart) this.candleChart.interval = interval;
    if (this.liveFeedEnabled && !this.forceDemo) {
      this._seedSyntheticCandles(this.state.markPriceUsd, true);
      this._startFeedRouter();
    } else {
      this._seedSyntheticCandles(this.state.markPriceUsd, true);
      if (typeof window !== "undefined") this._startDemoTicker();
    }
    this._notifyTelemetry(true);
  }

  toggleIndicator(name) {
    if (!this.candleChart) return;
    const map = { ema: "showEMA", sma: "showSMA", bb: "showBB", rsi: "showRSI" };
    const prop = map[name];
    if (!prop) return;
    this.candleChart.setOptions({ [prop]: !this.candleChart[prop] });
    this._syncControlBar();
  }

  toggleLog() {
    if (!this.candleChart) return;
    this.candleChart.setOptions({ logarithmic: !this.candleChart.logarithmic });
    this._syncControlBar();
  }

  toggleDepth() {
    if (!this.candleChart) return;
    this.candleChart.setOptions({ depthProfileEnabled: !this.candleChart.depthProfileEnabled });
    this._syncControlBar();
  }

  setTool(tool) {
    if (!this.candleChart) return;
    const normalized = tool === "trend" ? "line" : tool === "hline" ? "horizontal" : tool === "vline" ? "vertical" : tool;
    this.candleChart.setTool(normalized);
    this._syncControlBar();
  }

  undoDrawing() {
    this.candleChart?.undoDrawing();
    this._syncControlBar();
  }

  clearDrawings() {
    this.candleChart?.clearDrawings();
    this._syncControlBar();
  }

  resetView() {
    this.candleChart?.resetView();
  }

  toggleDemoFeed() {
    this.forceDemo = !this.forceDemo;
    if (this.forceDemo) {
      this._startDemoTicker();
    } else {
      this.liveFeedEnabled = true;
      this._startFeedRouter();
    }
    this._syncControlBar();
  }

  destroy() {
    this._stopFeed();
    this._unbindControls();
    if (this.candleChart) {
      this.candleChart.destroy();
      this.candleChart = null;
    }
    if (this.canvas && this._onMove) {
      this.canvas.removeEventListener?.("mousemove", this._onMove);
      this.canvas.removeEventListener?.("mouseleave", this._onLeave);
    }
    if (this._resizeObserver) this._resizeObserver.disconnect();
    if (this._onWindowResize && typeof window !== "undefined") {
      window.removeEventListener?.("resize", this._onWindowResize);
    }
  }

  setState(rawState) {
    const prevMode = this.state.chartMode;
    this.state = normalizeChartState(rawState);

    if (this.candleChart) {
      if (!this.hasLiveVenueCandles && this._syntheticAnchor !== this.state.markPriceUsd) {
        this._seedSyntheticCandles(this.state.markPriceUsd, false);
      }
      if (!this.hasLiveVenueDepth && (this.state.depth.bids.length || this.state.depth.asks.length)) {
        this.candleChart.setDepth(this.state.depth.bids, this.state.depth.asks, "P2P L2");
      }
      if (this.state.chartMode === "payoff") {
        this.candleChart.setPaused(true);
      } else {
        this.candleChart.setPaused(false);
        if (prevMode === "payoff") {
          this.candleChart.resize();
        }
      }
    }

    this._syncControlBar();
    this.render();
  }

  resizeAndRender() {
    if (!this.canvas || !this.ctx) return;
    if (this.state.chartMode === "candles" && this.candleChart) {
      this.candleChart.setPaused(false);
      this.candleChart.resize();
      return;
    }
    const parent = this.canvas.parentElement;
    const cssW = Math.max(
      320,
      Math.floor((parent ? parent.clientWidth : this.canvas.clientWidth) || 720)
    );
    const cssH = Math.max(
      240,
      Math.floor((parent ? parent.clientHeight : this.canvas.clientHeight) || 340)
    );
    const dpr = Math.min(3, (typeof window !== "undefined" ? window.devicePixelRatio : 1) || 1);
    const targetW = Math.floor(cssW * dpr);
    const targetH = Math.floor(cssH * dpr);

    if (this.canvas.width !== targetW || this.canvas.height !== targetH) {
      this.canvas.width = targetW;
      this.canvas.height = targetH;
      if (this.canvas.style) {
        this.canvas.style.width = `${cssW}px`;
        this.canvas.style.height = `${cssH}px`;
      }
    }
    this.cssWidth = cssW;
    this.cssHeight = cssH;
    this.dpr = dpr;
    this.render();
  }

  _getPayoffData() {
    const sp = this.state.spec;
    const key = `${sp.usdNotional}|${sp.entryPriceUsd}|${sp.longMarginSats}|${sp.shortMarginSats}`;
    if (key !== this.cachedPayoffKey) {
      this.cachedPayoff = generateInversePayoffCurve(sp, {
        minPrice: 20_000,
        maxPrice: 200_000,
        steps: 180,
      });
      this.cachedPayoffKey = key;
    }
    return this.cachedPayoff;
  }

  render() {
    if (!this.canvas || !this.ctx) return;
    if (this.state.chartMode === "payoff") {
      if (this.candleChart) this.candleChart.setPaused(true);
      const ctx = this.ctx;
      const w = this.cssWidth || this.canvas.clientWidth || 720;
      const h = this.cssHeight || this.canvas.clientHeight || 340;
      const dpr = this.dpr || 1;
      ctx.save();
      ctx.setTransform?.(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = THEME.bg;
      ctx.fillRect(0, 0, w, h);
      this._renderPayoffMode(ctx, w, h);
      ctx.restore();
      return;
    }
    if (this.candleChart) {
      this.candleChart.setPaused(false);
      this.candleChart.requestDraw();
    }
  }

  // -------------------------------------------------------------------------
  // Mode 1 Overlay: SatsHedgeZero Protocol Overlays on BitcornWisdom CandleChart
  // -------------------------------------------------------------------------
  _paintProtocolOverlays(_metrics, frame, ctx) {
    if (!frame || !ctx || this.state.chartMode !== "candles") return;
    const s = this.state;
    const { plotLeft: left, plotRight: right, priceTop: top, priceBottom: bottom, prices, low, high } = frame;
    if (!(right > left) || !(bottom > top)) return;

    ctx.save();

    // 1. Pyth NEAR Relay ±conf confidence band around Mark Price
    const confRatio = Math.max(4, Number(s.pythConfBps) || 20) / 10_000;
    const pythUpper = s.markPriceUsd * (1 + confRatio);
    const pythLower = s.markPriceUsd * (1 - confRatio);
    if (pythUpper >= low && pythLower <= high) {
      const yTop = Math.max(top, Math.min(bottom, prices.y(pythUpper)));
      const yBot = Math.max(top, Math.min(bottom, prices.y(pythLower)));
      const bandH = Math.max(2, yBot - yTop);
      ctx.fillStyle = "rgba(56, 189, 248, 0.09)";
      ctx.fillRect(left, yTop, right - left, bandH);
      ctx.strokeStyle = "rgba(56, 189, 248, 0.36)";
      ctx.setLineDash([2, 3]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(left, Math.round(yTop) + 0.5);
      ctx.lineTo(right, Math.round(yTop) + 0.5);
      ctx.moveTo(left, Math.round(yBot) + 0.5);
      ctx.lineTo(right, Math.round(yBot) + 0.5);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // 2. Protocol Levels: TradeLayer tx14 VWAP, Mark, Entry P0, Long Liq, Short Liq
    const occupiedBadgeY = [];
    const pickBadgeY = (preferredY) => {
      let y = Math.max(top + 22, Math.min(bottom - 20, preferredY));
      for (let guard = 0; guard < 12; guard++) {
        if (occupiedBadgeY.every((prev) => Math.abs(prev - y) >= 19)) break;
        y += y + 19 <= bottom - 20 ? 19 : -19;
      }
      occupiedBadgeY.push(y);
      return y;
    };

    const drawProtocolLevel = (price, label, color, dash = [5, 4]) => {
      if (price == null || !Number.isFinite(price) || price <= 0) return;
      const outOfView = price < low || price > high;
      const rawY = prices.y(price);
      const clampedY = Math.max(top + 8, Math.min(bottom - 8, rawY));

      ctx.save();
      ctx.strokeStyle = color;
      ctx.globalAlpha = outOfView ? 0.5 : 0.9;
      ctx.lineWidth = outOfView ? 1 : 1.15;
      ctx.setLineDash(dash);
      ctx.beginPath();
      ctx.moveTo(left, Math.round(clampedY) + 0.5);
      ctx.lineTo(right, Math.round(clampedY) + 0.5);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;

      const suffix = outOfView ? (price < low ? " ↓" : " ↑") : "";
      const badgeY = pickBadgeY(clampedY - 19);
      drawBadge(
        ctx,
        `${label} ${fmtUsd(price)}${suffix}`,
        left + 6,
        badgeY,
        "rgba(10, 14, 20, 0.90)",
        color,
        color,
        false
      );

      if (!outOfView) {
        const tagW = 70;
        drawRoundedRect(ctx, right + 2, clampedY - 8.5, tagW, 17, 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.fillStyle = "#0a0e14";
        ctx.font = `700 9.5px ${THEME.fontMono}`;
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillText(fmtUsd(price), right + 5, clampedY + 0.5);
      }
      ctx.restore();
    };

    drawProtocolLevel(s.vwapPriceUsd, "TL tx14 VWAP", THEME.amber, [3, 3]);
    drawProtocolLevel(s.spec.entryPriceUsd, "ENTRY P0", THEME.cyan, [4, 4]);
    if (Math.abs(s.markPriceUsd - s.spec.entryPriceUsd) > 1) {
      drawProtocolLevel(s.markPriceUsd, "MARK", "rgba(56, 189, 248, 0.78)", [2, 4]);
    }
    drawProtocolLevel(s.longLiqUsd, `LONG LIQ (${s.spec.longLevX}x)`, THEME.long, [6, 4]);
    if (s.shortLiqUsd != null) {
      drawProtocolLevel(s.shortLiqUsd, `SHORT LIQ (${s.spec.shortLevX}x)`, THEME.short, [6, 4]);
    }

    // 3. Optional 3-Party Multilateral Clearing Markers (e.g. Trade 1 $50k, Trade 2 $55k, Trade 3 $60k closeout)
    const occupiedRightBadgeY = [];
    const pickRightBadgeY = (preferredY) => {
      let y = Math.max(top + 27, Math.min(bottom - 20, preferredY));
      for (let guard = 0; guard < 12; guard++) {
        if (occupiedRightBadgeY.every((prev) => Math.abs(prev - y) >= 19)) break;
        y += y + 19 <= bottom - 20 ? 19 : -19;
      }
      occupiedRightBadgeY.push(y);
      return y;
    };

    if (s.clearingTrades.length) {
      const count = s.clearingTrades.length;
      for (let i = 0; i < count; i++) {
        const tr = s.clearingTrades[i];
        const outOfView = tr.priceUsd < low || tr.priceUsd > high;
        const y = Math.max(top + 10, Math.min(bottom - 10, prices.y(tr.priceUsd)));
        const mx =
          tr.timeSec != null && this.candleChart
            ? Math.max(left + 16, Math.min(right - 16, frame.coordinates.x(this.candleChart.timeToIndex(tr.timeSec * 1000))))
            : right - 24 - (count - 1 - i) * 38;

        ctx.save();
        ctx.strokeStyle = tr.color;
        ctx.globalAlpha = outOfView ? 0.35 : 0.78;
        ctx.setLineDash([2, 3]);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(left, Math.round(y) + 0.5);
        ctx.lineTo(right, Math.round(y) + 0.5);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;

        // Diamond marker
        ctx.fillStyle = tr.color;
        ctx.beginPath();
        ctx.moveTo(mx, y - 5);
        ctx.lineTo(mx + 5, y);
        ctx.lineTo(mx, y + 5);
        ctx.lineTo(mx - 5, y);
        ctx.closePath();
        ctx.fill();
        ctx.strokeStyle = THEME.bg;
        ctx.lineWidth = 1.2;
        ctx.stroke();

        const suffix = outOfView ? (tr.priceUsd < low ? " ↓" : " ↑") : "";
        const rightBadgeY = pickRightBadgeY(y - 9);
        drawBadge(
          ctx,
          `${tr.label} ${fmtUsd(tr.priceUsd)}${suffix}`,
          right - 6,
          rightBadgeY,
          "rgba(10, 14, 20, 0.92)",
          tr.color,
          tr.color,
          true
        );
        ctx.restore();
      }
    }

    // 4. Compact SatsHedgeZero Protocol Telemetry HUD + 1x SatsHedge Badge
    const hudY = top + 3;
    let rightCursor = right - 6;

    if (s.shortLiqUsd === null) {
      const badgeW = drawBadge(
        ctx,
        "∞ UNLIQUIDATABLE (1x SatsHedge)",
        rightCursor,
        hudY,
        "rgba(0, 210, 133, 0.14)",
        THEME.long,
        THEME.long,
        true
      );
      rightCursor -= badgeW + 6;
    }

    const telemetryText = `MARK ${fmtUsd(s.markPriceUsd)} · TL tx14 VWAP ${fmtUsd(s.vwapPriceUsd)} · PYTH ±${s.pythConfBps}bps`;
    ctx.font = `600 9.5px ${THEME.fontMono}`;
    const telW = ctx.measureText(telemetryText).width + 12;
    if (rightCursor - telW > left + 120) {
      drawBadge(
        ctx,
        telemetryText,
        rightCursor,
        hudY,
        "rgba(10, 14, 20, 0.86)",
        THEME.border,
        THEME.textSecondary,
        true
      );
    }

    ctx.restore();
  }

  // -------------------------------------------------------------------------
  // Mode 2: Dual-Axis Inverse DLC Payoff & Dyadic CET Prefix Visualizer
  // -------------------------------------------------------------------------
  _renderPayoffMode(ctx, w, h) {
    const data = this._getPayoffData();
    const { spec, minPrice, maxPrice, points, longLiqUsd, shortLiqUsd, cetStats, visibleCets } = data;

    const pad = { top: 38, right: 74, bottom: 44, left: 70 };
    const plotW = Math.max(100, w - pad.left - pad.right);
    const cetStripH = 18;
    const plotH = Math.max(90, h - pad.top - pad.bottom - cetStripH);

    let minSats = -Math.max(spec.longMarginSats, spec.shortMarginSats);
    let maxSats = Math.max(spec.longMarginSats, spec.shortMarginSats);
    let maxUsd = spec.usdNotional * 2.2;
    for (const pt of points) {
      minSats = Math.min(minSats, pt.longPnlSats, pt.shortPnlSats);
      maxSats = Math.max(maxSats, pt.longPnlSats, pt.shortPnlSats);
      maxUsd = Math.max(maxUsd, pt.shortUsdValue, pt.longUsdValue);
    }
    const satSpan = Math.max(10_000, maxSats - minSats);
    minSats -= satSpan * 0.1;
    maxSats += satSpan * 0.12;
    maxUsd = Math.max(spec.usdNotional * 1.6, maxUsd * 1.12);

    const xOf = (price) => pad.left + ((price - minPrice) / (maxPrice - minPrice)) * plotW;
    const ySats = (sats) => pad.top + ((maxSats - sats) / (maxSats - minSats)) * plotH;
    const yUsd = (usd) => pad.top + ((maxUsd - usd) / maxUsd) * plotH;

    ctx.font = `500 10px ${THEME.fontMono}`;
    const yTicks = 5;
    for (let i = 0; i <= yTicks; i++) {
      const frac = i / yTicks;
      const y = Math.round(pad.top + frac * plotH) + 0.5;
      const satVal = maxSats - frac * (maxSats - minSats);
      const usdVal = maxUsd * (1 - frac);

      ctx.strokeStyle = THEME.grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(w - pad.right, y);
      ctx.stroke();

      ctx.fillStyle = THEME.textSecondary;
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      ctx.fillText(fmtCompactSats(satVal), pad.left - 8, y);

      ctx.fillStyle = THEME.cyan;
      ctx.textAlign = "left";
      ctx.fillText(fmtUsd(usdVal, true), w - pad.right + 8, y);
    }

    const yZero = Math.round(ySats(0)) + 0.5;
    ctx.strokeStyle = THEME.gridStrong;
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    ctx.moveTo(pad.left, yZero);
    ctx.lineTo(w - pad.right, yZero);
    ctx.stroke();

    for (let p = 20_000; p <= 200_000; p += 20_000) {
      const x = Math.round(xOf(p)) + 0.5;
      ctx.strokeStyle = THEME.grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x, pad.top);
      ctx.lineTo(x, pad.top + plotH);
      ctx.stroke();

      ctx.fillStyle = THEME.textMuted;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillText(fmtUsd(p, true), x, pad.top + plotH + cetStripH + 6);
    }

    const stripTop = pad.top + plotH + 3;
    ctx.fillStyle = "#0d131d";
    ctx.fillRect(pad.left, stripTop, plotW, cetStripH - 3);
    ctx.strokeStyle = THEME.border;
    ctx.strokeRect(pad.left + 0.5, stripTop + 0.5, plotW - 1, cetStripH - 4);

    let lastTickX = -10;
    for (let i = 0; i < visibleCets.length; i++) {
      const cet = visibleCets[i];
      const px = Math.max(minPrice, Math.min(maxPrice, cet.minPriceUsd));
      const x = xOf(px);
      if (x - lastTickX >= 1.75) {
        ctx.strokeStyle =
          cet.prefixLen >= 13
            ? "rgba(245, 158, 11, 0.72)"
            : cet.prefixLen >= 9
              ? "rgba(56, 189, 248, 0.55)"
              : "rgba(94, 113, 141, 0.45)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, stripTop + 1);
        ctx.lineTo(x, stripTop + cetStripH - 4);
        ctx.stroke();

        if (x - lastTickX >= 12) {
          ctx.strokeStyle = "rgba(56, 189, 248, 0.06)";
          ctx.beginPath();
          ctx.moveTo(x, pad.top);
          ctx.lineTo(x, pad.top + plotH);
          ctx.stroke();
        }
        lastTickX = x;
      }
    }
    const cetBanner = `DYADIC CETs (${cetStats.domainSize.toLocaleString("en-US")} -> ${cetStats.totalCompressedCets.toLocaleString("en-US")} prefixes, -${cetStats.compressionRatioPct}%)`;
    ctx.font = `600 9.5px ${THEME.fontMono}`;
    const cetTextW = ctx.measureText(cetBanner).width;
    ctx.fillStyle = "rgba(10, 14, 20, 0.88)";
    ctx.fillRect(pad.left + 3, stripTop + 1, cetTextW + 10, cetStripH - 5);
    ctx.fillStyle = "#b8c7dc";
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    ctx.fillText(cetBanner, pad.left + 8, stripTop + (cetStripH - 3) / 2);

    const drawVLine = (price, label, color, dash = [4, 4]) => {
      if (price == null || price < minPrice || price > maxPrice) return;
      const x = Math.round(xOf(price)) + 0.5;
      ctx.save();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.15;
      ctx.setLineDash(dash);
      ctx.beginPath();
      ctx.moveTo(x, pad.top);
      ctx.lineTo(x, pad.top + plotH);
      ctx.stroke();
      ctx.setLineDash([]);
      drawBadge(
        ctx,
        label,
        x + 4,
        pad.top + 6,
        "rgba(10, 14, 20, 0.9)",
        color,
        color,
        x > w - pad.right - 130
      );
      ctx.restore();
    };

    drawVLine(spec.entryPriceUsd, `P0 ${fmtUsd(spec.entryPriceUsd)}`, THEME.whiteSoft, [3, 4]);
    drawVLine(longLiqUsd, `LONG LIQ CLAMP ${fmtUsd(longLiqUsd)}`, THEME.long, [5, 3]);
    if (shortLiqUsd != null) {
      drawVLine(shortLiqUsd, `SHORT LIQ CLAMP ${fmtUsd(shortLiqUsd)}`, THEME.short, [5, 3]);
    }

    ctx.save();
    ctx.strokeStyle = THEME.long;
    ctx.lineWidth = 2;
    ctx.beginPath();
    points.forEach((pt, i) => {
      const x = xOf(pt.priceUsd);
      const y = ySats(pt.longPnlSats);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.strokeStyle = THEME.short;
    ctx.lineWidth = 2;
    ctx.beginPath();
    points.forEach((pt, i) => {
      const x = xOf(pt.priceUsd);
      const y = ySats(pt.shortPnlSats);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.strokeStyle = THEME.cyan;
    ctx.lineWidth = 2.25;
    ctx.beginPath();
    points.forEach((pt, i) => {
      const x = xOf(pt.priceUsd);
      const y = yUsd(pt.shortUsdValue);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.strokeStyle = "rgba(245, 158, 11, 0.72)";
    ctx.lineWidth = 1.25;
    ctx.setLineDash([4, 3]);
    ctx.beginPath();
    points.forEach((pt, i) => {
      const x = xOf(pt.priceUsd);
      const y = yUsd(pt.longUsdValue);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.restore();

    ctx.fillStyle = THEME.textSecondary;
    ctx.font = `600 9.5px ${THEME.fontMono}`;
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    ctx.fillText("PNL (SATS)", 8, pad.top - 10);
    ctx.fillStyle = THEME.cyan;
    ctx.textAlign = "right";
    ctx.fillText("USD VALUE", w - 8, pad.top - 10);

    ctx.save();
    ctx.font = `600 10.5px ${THEME.fontMono}`;
    ctx.textBaseline = "middle";
    let lx = pad.left;
    const ly = 14;
    const addKey = (label, color) => {
      ctx.fillStyle = color;
      ctx.textAlign = "left";
      ctx.fillText(label, lx, ly);
      lx += ctx.measureText(label).width + 12;
    };
    addKey("INVERSE PnL", THEME.textPrimary);
    addKey("■ LONG SATS", THEME.long);
    addKey("■ SHORT SATS", THEME.short);
    addKey(
      data.isCoveredSyntheticUsd
        ? `━ SHORT USD (${fmtUsd(spec.usdNotional, true)} FLAT)`
        : "━ SHORT USD",
      THEME.cyan
    );

    if (shortLiqUsd === null) {
      drawBadge(
        ctx,
        "∞ UNLIQUIDATABLE (1x SatsHedge)",
        w - pad.right,
        4,
        "rgba(10, 14, 20, 0.92)",
        THEME.long,
        THEME.long,
        true
      );
    }
    ctx.restore();

    if (
      this.pointer &&
      this.pointer.x >= pad.left &&
      this.pointer.x <= w - pad.right &&
      this.pointer.y >= pad.top &&
      this.pointer.y <= pad.top + plotH + cetStripH
    ) {
      const hoverPrice = Math.max(
        minPrice,
        Math.min(
          maxPrice,
          Math.round(minPrice + ((this.pointer.x - pad.left) / plotW) * (maxPrice - minPrice))
        )
      );
      const payout = computeInversePayout(spec, hoverPrice);
      const cet = lookupCetForPrice(data.allCets, hoverPrice, cetStats.numBits);
      const cx = Math.round(xOf(hoverPrice)) + 0.5;

      ctx.save();
      ctx.strokeStyle = "rgba(143, 162, 188, 0.5)";
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(cx, pad.top);
      ctx.lineTo(cx, pad.top + plotH + cetStripH);
      ctx.stroke();

      const dot = (y, col) => {
        ctx.beginPath();
        ctx.arc(cx, y, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = col;
        ctx.fill();
        ctx.strokeStyle = THEME.bg;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      };
      dot(ySats(payout.longPnlSats), THEME.long);
      dot(ySats(payout.shortPnlSats), THEME.short);
      dot(yUsd(payout.shortUsdValue), THEME.cyan);
      ctx.restore();

      const rows = [
        { label: "Expiry P_T", value: fmtUsd(hoverPrice), valueColor: THEME.textPrimary },
        {
          label: "Long PnL",
          value: fmtSats(payout.longPnlSats, true),
          valueColor: payout.longPnlSats >= 0 ? THEME.long : THEME.short,
        },
        {
          label: "Short PnL",
          value: fmtSats(payout.shortPnlSats, true),
          valueColor: payout.shortPnlSats >= 0 ? THEME.long : THEME.short,
        },
        { label: "Short USD Val", value: `$${payout.shortUsdValue.toFixed(2)}`, valueColor: THEME.cyan },
        { label: "Long USD Val", value: `$${payout.longUsdValue.toFixed(2)}`, valueColor: THEME.amber },
        {
          label: "Dyadic CET",
          value: cet
            ? `${cet.prefix} [${fmtUsd(cet.minPriceUsd, true)}..${fmtUsd(cet.maxPriceUsd, true)}]`
            : "—",
          valueColor: THEME.textPrimary,
        },
        { label: "Protocol Fee", value: "0 sats (0 bps)", valueColor: THEME.long },
      ];
      drawTooltipBox(ctx, rows, cx, this.pointer.y, w, h);
    }
  }
}

// ---------------------------------------------------------------------------
// Auto-Mount in Browser (Shared SHZ_STATE & "shz:state" Event Contract)
// ---------------------------------------------------------------------------

let activeController = null;

export function mountCharts(canvasId = "shz-main-canvas", initialState = null, options = {}) {
  if (typeof document === "undefined") return null;
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  const fb =
    typeof document.getElementById === "function"
      ? document.getElementById("shz-chart-fallback")
      : null;
  if (fb) {
    fb.hidden = true;
    if (fb.style) fb.style.display = "none";
  }
  if (activeController) activeController.destroy();
  activeController = new ShzChartController(canvas, options);
  const toolbar =
    typeof document.getElementById === "function"
      ? document.getElementById("shz-bitcorn-bar")
      : null;
  if (toolbar) activeController.bindControls(toolbar);
  const seed = initialState || (typeof window !== "undefined" ? window.SHZ_STATE : null);
  if (seed) activeController.setState(seed);
  return activeController;
}

function bootChartsInBrowser() {
  if (typeof window === "undefined" || typeof document === "undefined") return;

  const init = () => {
    const ctrl = mountCharts("shz-main-canvas", window.SHZ_STATE || null);
    window.SHZ_CHARTS = ctrl;
  };

  window.addEventListener("shz:state", (ev) => {
    if (!activeController) {
      init();
    }
    if (activeController && ev?.detail) {
      activeController.setState(ev.detail);
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
}

bootChartsInBrowser();
