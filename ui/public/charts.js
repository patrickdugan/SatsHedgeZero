// SatsHedgeZero Interactive Canvas Chart Engine (`ui/public/charts.js`)
// Institutional Deribit-dark HiDPI renderer for:
//   1. "candles": Deterministic BTC/USD OHLCV + TradeLayer L1 VWAP (tx14) + Pyth confidence band + Liq levels
//   2. "payoff":  Dual-axis Inverse DLC Payoff (sats + USD purchasing power) & 20-bit Dyadic CET Visualizer
//
// Zero external dependencies. Safe for both browser ES module import and Node.js unit testing.

export const SATS_PER_BTC = 100_000_000n;
export const BPS_DENOMINATOR = 10_000n;
export const DEFAULT_CET_BITS = 20;
export const DEFAULT_CET_DOMAIN_SIZE = 1 << DEFAULT_CET_BITS; // 1,048,576
export const DEFAULT_CET_MAX_ERROR_SATS = 250;

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
  // Ensure exact critical inflection prices sit on the plotted polyline.
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

  // Smoothly anchor final VWAP to the authoritative TradeLayer tx14 VWAP.
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

// ---------------------------------------------------------------------------
// State Normalization (defensive across camelCase / snake_case SHZ_STATE shapes)
// ---------------------------------------------------------------------------

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

  const usdNotional = Number(
    quote.usdNotional ?? quote.usd_notional ?? 1_000
  );
  const entryPriceUsd = Number(
    quote.entryPriceUsd ?? quote.entry_price_usd ?? markPriceUsd
  );
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
  };
}

// ---------------------------------------------------------------------------
// Formatting Helpers
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

function fmtTime(sec) {
  const d = new Date(sec * 1000);
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

// ---------------------------------------------------------------------------
// Canvas Rendering Engine (HiDPI + Crosshair + Candles & Inverse Payoff Modes)
// ---------------------------------------------------------------------------

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
  ctx.font = `600 10.5px ${THEME.fontMono}`;
  const padX = 7;
  const h = 19;
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

export class ShzChartController {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas ? canvas.getContext("2d") : null;
    this.state = normalizeChartState({});
    this.pointer = null;
    this.cachedPayoffKey = "";
    this.cachedPayoff = null;
    this.cachedCandlesKey = "";
    this.cachedCandles = null;
    this._resizeObserver = null;

    if (canvas) {
      this._bindEvents();
      this.resizeAndRender();
    }
  }

  _bindEvents() {
    this._onMove = (ev) => {
      const rect = this.canvas.getBoundingClientRect();
      this.pointer = {
        x: ev.clientX - rect.left,
        y: ev.clientY - rect.top,
      };
      this.render();
    };
    this._onLeave = () => {
      this.pointer = null;
      this.render();
    };
    this.canvas.addEventListener("mousemove", this._onMove);
    this.canvas.addEventListener("mouseleave", this._onLeave);

    if (typeof ResizeObserver !== "undefined") {
      this._resizeObserver = new ResizeObserver(() => this.resizeAndRender());
      this._resizeObserver.observe(this.canvas.parentElement || this.canvas);
    } else if (typeof window !== "undefined") {
      this._onWindowResize = () => this.resizeAndRender();
      window.addEventListener("resize", this._onWindowResize);
    }
  }

  destroy() {
    if (this.canvas && this._onMove) {
      this.canvas.removeEventListener("mousemove", this._onMove);
      this.canvas.removeEventListener("mouseleave", this._onLeave);
    }
    if (this._resizeObserver) this._resizeObserver.disconnect();
    if (this._onWindowResize && typeof window !== "undefined") {
      window.removeEventListener("resize", this._onWindowResize);
    }
  }

  setState(rawState) {
    this.state = normalizeChartState(rawState);
    this.render();
  }

  resizeAndRender() {
    if (!this.canvas || !this.ctx) return;
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
      this.canvas.style.width = `${cssW}px`;
      this.canvas.style.height = `${cssH}px`;
    }
    this.cssWidth = cssW;
    this.cssHeight = cssH;
    this.dpr = dpr;
    this.render();
  }

  _getCandles() {
    const s = this.state;
    const key = `${s.symbol}|${s.markPriceUsd}|${s.vwapPriceUsd}|${s.pythConfBps}`;
    if (key !== this.cachedCandlesKey) {
      let seed = 0x53485a30;
      for (let i = 0; i < s.symbol.length; i++) {
        seed = (seed * 31 + s.symbol.charCodeAt(i)) >>> 0;
      }
      this.cachedCandles = generateDeterministicCandles({
        markPriceUsd: s.markPriceUsd,
        vwapPriceUsd: s.vwapPriceUsd,
        pythConfBps: s.pythConfBps,
        count: 72,
        seed,
      });
      this.cachedCandlesKey = key;
    }
    return this.cachedCandles;
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
    const ctx = this.ctx;
    const w = this.cssWidth || this.canvas.clientWidth || 720;
    const h = this.cssHeight || this.canvas.clientHeight || 340;
    const dpr = this.dpr || 1;

    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = THEME.bg;
    ctx.fillRect(0, 0, w, h);

    if (this.state.chartMode === "payoff") {
      this._renderPayoffMode(ctx, w, h);
    } else {
      this._renderCandlesMode(ctx, w, h);
    }
    ctx.restore();
  }

  // -------------------------------------------------------------------------
  // Mode 1: BTC/USD Candles + TradeLayer VWAP (tx14) + Pyth Band + Liq Levels
  // -------------------------------------------------------------------------
  _renderCandlesMode(ctx, w, h) {
    const s = this.state;
    const candles = this._getCandles();
    const pad = { top: 34, right: 78, bottom: 26, left: 12 };
    const plotW = Math.max(80, w - pad.left - pad.right);
    const plotH = Math.max(80, h - pad.top - pad.bottom);
    const volH = Math.round(plotH * 0.16);
    const priceH = plotH - volH - 6;

    // Price domain includes candles, VWAP, entry, and nearby liquidation lines
    let minP = Infinity;
    let maxP = -Infinity;
    let maxVol = 1;
    for (const c of candles) {
      minP = Math.min(minP, c.low, c.pythLower, c.vwap);
      maxP = Math.max(maxP, c.high, c.pythUpper, c.vwap);
      if (c.volumeUsd > maxVol) maxVol = c.volumeUsd;
    }
    minP = Math.min(minP, s.spec.entryPriceUsd);
    maxP = Math.max(maxP, s.spec.entryPriceUsd);
    if (s.longLiqUsd >= minP * 0.72) minP = Math.min(minP, s.longLiqUsd);
    if (s.shortLiqUsd != null && s.shortLiqUsd <= maxP * 1.35) {
      maxP = Math.max(maxP, s.shortLiqUsd);
    }
    const span = Math.max(1_000, maxP - minP);
    minP -= span * 0.08;
    maxP += span * 0.08;

    const yOf = (price) => pad.top + ((maxP - price) / (maxP - minP)) * priceH;
    const xStep = plotW / candles.length;
    const xOf = (idx) => pad.left + (idx + 0.5) * xStep;

    // Gridlines & Y-axis ticks
    ctx.strokeStyle = THEME.grid;
    ctx.lineWidth = 1;
    ctx.font = `500 10px ${THEME.fontMono}`;
    const yTicks = 6;
    const entryY = Math.max(pad.top + 8, Math.min(pad.top + priceH - 8, yOf(s.spec.entryPriceUsd)));
    for (let i = 0; i <= yTicks; i++) {
      const p = maxP - ((maxP - minP) * i) / yTicks;
      const y = Math.round(yOf(p)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(w - pad.right, y);
      ctx.stroke();

      if (Math.abs(y - entryY) > 13) {
        ctx.fillStyle = THEME.textMuted;
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillText(fmtUsd(p), w - pad.right + 6, y);
      }
    }

    // Vertical time gridlines
    const xTickEvery = Math.max(8, Math.floor(candles.length / 6));
    for (let i = 0; i < candles.length; i += xTickEvery) {
      const x = Math.round(xOf(i)) + 0.5;
      ctx.strokeStyle = THEME.grid;
      ctx.beginPath();
      ctx.moveTo(x, pad.top);
      ctx.lineTo(x, pad.top + plotH);
      ctx.stroke();

      ctx.fillStyle = THEME.textMuted;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillText(fmtTime(candles[i].timeSec), x, pad.top + plotH + 6);
    }

    // Pyth Confidence Band
    ctx.save();
    ctx.beginPath();
    for (let i = 0; i < candles.length; i++) {
      const x = xOf(i);
      const y = yOf(candles[i].pythUpper);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    for (let i = candles.length - 1; i >= 0; i--) {
      ctx.lineTo(xOf(i), yOf(candles[i].pythLower));
    }
    ctx.closePath();
    ctx.fillStyle = "rgba(56, 189, 248, 0.08)";
    ctx.fill();

    ctx.strokeStyle = "rgba(56, 189, 248, 0.34)";
    ctx.setLineDash([2, 3]);
    ctx.lineWidth = 1;
    ctx.beginPath();
    candles.forEach((c, i) => (i === 0 ? ctx.moveTo(xOf(i), yOf(c.pythUpper)) : ctx.lineTo(xOf(i), yOf(c.pythUpper))));
    ctx.stroke();
    ctx.beginPath();
    candles.forEach((c, i) => (i === 0 ? ctx.moveTo(xOf(i), yOf(c.pythLower)) : ctx.lineTo(xOf(i), yOf(c.pythLower))));
    ctx.stroke();
    ctx.restore();

    // Volume bars
    const bodyW = Math.max(2, Math.min(10, xStep * 0.64));
    const volBaseY = pad.top + plotH;
    for (let i = 0; i < candles.length; i++) {
      const c = candles[i];
      const up = c.close >= c.open;
      const barH = Math.max(2, (c.volumeUsd / maxVol) * volH);
      ctx.fillStyle = up ? "rgba(0, 210, 133, 0.22)" : "rgba(255, 77, 109, 0.22)";
      ctx.fillRect(xOf(i) - bodyW / 2, volBaseY - barH, bodyW, barH);
    }

    // OHLCV Candlesticks
    for (let i = 0; i < candles.length; i++) {
      const c = candles[i];
      const x = xOf(i);
      const up = c.close >= c.open;
      const col = up ? THEME.long : THEME.short;
      const yHigh = yOf(c.high);
      const yLow = yOf(c.low);
      const yOpen = yOf(c.open);
      const yClose = yOf(c.close);

      ctx.strokeStyle = col;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(Math.round(x) + 0.5, yHigh);
      ctx.lineTo(Math.round(x) + 0.5, yLow);
      ctx.stroke();

      const topY = Math.min(yOpen, yClose);
      const rectH = Math.max(1.5, Math.abs(yClose - yOpen));
      ctx.fillStyle = col;
      ctx.fillRect(x - bodyW / 2, topY, bodyW, rectH);
    }

    // TradeLayer L1 VWAP (tx14) Line
    ctx.save();
    ctx.strokeStyle = THEME.amber;
    ctx.lineWidth = 1.75;
    ctx.beginPath();
    for (let i = 0; i < candles.length; i++) {
      const x = xOf(i);
      const y = yOf(candles[i].vwap);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.restore();

    // Dashed Horizontal Levels: Entry, Long Liq, Short Liq
    const drawLevel = (price, label, color, dash = [5, 4]) => {
      if (price == null || !Number.isFinite(price)) return;
      const clampedY = Math.max(pad.top + 6, Math.min(pad.top + priceH - 6, yOf(price)));
      const outOfView = price < minP || price > maxP;
      ctx.save();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.1;
      ctx.setLineDash(dash);
      ctx.beginPath();
      ctx.moveTo(pad.left, Math.round(clampedY) + 0.5);
      ctx.lineTo(w - pad.right, Math.round(clampedY) + 0.5);
      ctx.stroke();
      ctx.setLineDash([]);

      // Right axis price tag
      const tagX = w - pad.right + 2;
      drawRoundedRect(ctx, tagX, clampedY - 9, pad.right - 5, 18, 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.fillStyle = "#0a0e14";
      ctx.font = `700 10px ${THEME.fontMono}`;
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      ctx.fillText(fmtUsd(price), tagX + 4, clampedY + 0.5);

      // Left inline label
      const suffix = outOfView ? (price < minP ? " ↓" : " ↑") : "";
      drawBadge(
        ctx,
        `${label} ${fmtUsd(price)}${suffix}`,
        pad.left + 6,
        clampedY - 21,
        "rgba(10, 14, 20, 0.88)",
        color,
        color,
        false
      );
      ctx.restore();
    };

    drawLevel(s.spec.entryPriceUsd, "ENTRY", THEME.cyan, [4, 4]);
    drawLevel(s.longLiqUsd, `LONG LIQ (${s.spec.longLevX}x)`, THEME.long, [6, 4]);
    if (s.shortLiqUsd != null) {
      drawLevel(s.shortLiqUsd, `SHORT LIQ (${s.spec.shortLevX}x)`, THEME.short, [6, 4]);
    }

    // Top HUD Legend Bar
    ctx.save();
    ctx.font = `600 11px ${THEME.fontMono}`;
    ctx.textBaseline = "middle";
    let lx = pad.left + 4;
    const ly = 16;
    const drawLegendItem = (text, color) => {
      ctx.fillStyle = color;
      ctx.textAlign = "left";
      ctx.fillText(text, lx, ly);
      lx += ctx.measureText(text).width + 12;
    };
    drawLegendItem(`${s.symbol} 15m`, THEME.textPrimary);
    drawLegendItem(`MARK ${fmtUsd(s.markPriceUsd)}`, THEME.cyan);
    drawLegendItem(`TL tx14 VWAP ${fmtUsd(s.vwapPriceUsd)}`, THEME.amber);
    drawLegendItem(`PYTH ±${s.pythConfBps}bps`, "rgba(56, 189, 248, 0.85)");

    if (s.shortLiqUsd === null) {
      drawBadge(
        ctx,
        "∞ UNLIQUIDATABLE (1x SatsHedge)",
        w - pad.right - 2,
        6,
        "rgba(0, 210, 133, 0.14)",
        THEME.long,
        THEME.long,
        true
      );
    }
    ctx.restore();

    // Interactive Crosshair & Hover Tooltip
    if (
      this.pointer &&
      this.pointer.x >= pad.left &&
      this.pointer.x <= w - pad.right &&
      this.pointer.y >= pad.top &&
      this.pointer.y <= pad.top + plotH
    ) {
      const idx = Math.max(
        0,
        Math.min(candles.length - 1, Math.floor((this.pointer.x - pad.left) / xStep))
      );
      const c = candles[idx];
      const cx = Math.round(xOf(idx)) + 0.5;
      const cy = Math.round(this.pointer.y) + 0.5;

      ctx.save();
      ctx.strokeStyle = "rgba(143, 162, 188, 0.45)";
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(cx, pad.top);
      ctx.lineTo(cx, pad.top + plotH);
      ctx.moveTo(pad.left, cy);
      ctx.lineTo(w - pad.right, cy);
      ctx.stroke();
      ctx.restore();

      const cursorPrice = maxP - ((this.pointer.y - pad.top) / priceH) * (maxP - minP);
      if (this.pointer.y <= pad.top + priceH) {
        drawRoundedRect(ctx, w - pad.right + 2, cy - 9, pad.right - 5, 18, 2);
        ctx.fillStyle = "#29374d";
        ctx.fill();
        ctx.fillStyle = THEME.textPrimary;
        ctx.font = `600 10px ${THEME.fontMono}`;
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillText(fmtUsd(cursorPrice), w - pad.right + 6, cy + 0.5);
      }

      const up = c.close >= c.open;
      drawTooltipBox(
        ctx,
        [
          { label: "UTC", value: fmtTime(c.timeSec), valueColor: THEME.textPrimary },
          { label: "O / H", value: `${fmtUsd(c.open)} / ${fmtUsd(c.high)}` },
          { label: "L / C", value: `${fmtUsd(c.low)} / ${fmtUsd(c.close)}`, valueColor: up ? THEME.long : THEME.short },
          { label: "TL VWAP", value: fmtUsd(c.vwap), valueColor: THEME.amber },
          { label: "Pyth Band", value: `${fmtUsd(c.pythLower)}..${fmtUsd(c.pythUpper)}`, valueColor: THEME.cyan },
          { label: "Vol", value: fmtUsd(c.volumeUsd, true), valueColor: THEME.textSecondary },
        ],
        cx,
        Math.min(cy, yOf(c.close)),
        w,
        h
      );
    }
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

    // Left Y-axis: Satoshi PnL
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

    // Horizontal gridlines + Dual Y-Axes (Left = Sats PnL, Right = USD Value)
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

    // Zero PnL baseline
    const yZero = Math.round(ySats(0)) + 0.5;
    ctx.strokeStyle = THEME.gridStrong;
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    ctx.moveTo(pad.left, yZero);
    ctx.lineTo(w - pad.right, yZero);
    ctx.stroke();

    // Vertical price axis gridlines ($20k .. $200k)
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

    // Dyadic CET Prefix Ticks Strip + subtle interval walls
    const stripTop = pad.top + plotH + 3;
    ctx.fillStyle = "#0d131d";
    ctx.fillRect(pad.left, stripTop, plotW, cetStripH - 3);
    ctx.strokeStyle = THEME.border;
    ctx.strokeRect(pad.left + 0.5, stripTop + 0.5, plotW - 1, cetStripH - 4);

    // Draw dyadic CET boundary ticks (stride gracefully if hundreds fall in tight pixel band)
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

        // Subtle vertical wall inside chart for wider prefixes
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
    ctx.fillText(
      cetBanner,
      pad.left + 8,
      stripTop + (cetStripH - 3) / 2
    );

    // Liquidation Clamp Cliffs & Entry Line
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
      drawBadge(ctx, label, x + 4, pad.top + 6, "rgba(10, 14, 20, 0.9)", color, color, x > w - pad.right - 130);
      ctx.restore();
    };

    drawVLine(spec.entryPriceUsd, `P0 ${fmtUsd(spec.entryPriceUsd)}`, THEME.whiteSoft, [3, 4]);
    drawVLine(longLiqUsd, `LONG LIQ CLAMP ${fmtUsd(longLiqUsd)}`, THEME.long, [5, 3]);
    if (shortLiqUsd != null) {
      drawVLine(shortLiqUsd, `SHORT LIQ CLAMP ${fmtUsd(shortLiqUsd)}`, THEME.short, [5, 3]);
    }

    // Curve 1: Long Satoshi PnL (Hyperbolic)
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

    // Curve 2: Short Satoshi PnL (Hyperbolic)
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

    // Curve 3: Overlaid Short USD Purchasing Power (flat $N across all prices at 1x SatsHedge!)
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

    // Curve 4: Overlaid Long USD Value (subtle amber dashed)
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

    // Axis Titles
    ctx.fillStyle = THEME.textSecondary;
    ctx.font = `600 9.5px ${THEME.fontMono}`;
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    ctx.fillText("PNL (SATS)", 8, pad.top - 10);
    ctx.fillStyle = THEME.cyan;
    ctx.textAlign = "right";
    ctx.fillText("USD VALUE", w - 8, pad.top - 10);

    // Top HUD Legend
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
    addKey(`INVERSE PnL`, THEME.textPrimary);
    addKey(`■ LONG SATS`, THEME.long);
    addKey(`■ SHORT SATS`, THEME.short);
    addKey(
      data.isCoveredSyntheticUsd
        ? `━ SHORT USD (${fmtUsd(spec.usdNotional, true)} FLAT)`
        : `━ SHORT USD`,
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

    // Crosshair Hover Tooltip
    if (
      this.pointer &&
      this.pointer.x >= pad.left &&
      this.pointer.x <= w - pad.right &&
      this.pointer.y >= pad.top &&
      this.pointer.y <= pad.top + plotH + cetStripH
    ) {
      const hoverPrice = Math.max(
        minPrice,
        Math.min(maxPrice, Math.round(minPrice + ((this.pointer.x - pad.left) / plotW) * (maxPrice - minPrice)))
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

      // Highlight dots on curves
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
        { label: "Long PnL", value: fmtSats(payout.longPnlSats, true), valueColor: payout.longPnlSats >= 0 ? THEME.long : THEME.short },
        { label: "Short PnL", value: fmtSats(payout.shortPnlSats, true), valueColor: payout.shortPnlSats >= 0 ? THEME.long : THEME.short },
        { label: "Short USD Val", value: `$${payout.shortUsdValue.toFixed(2)}`, valueColor: THEME.cyan },
        { label: "Long USD Val", value: `$${payout.longUsdValue.toFixed(2)}`, valueColor: THEME.amber },
        {
          label: "Dyadic CET",
          value: cet ? `${cet.prefix} [${fmtUsd(cet.minPriceUsd, true)}..${fmtUsd(cet.maxPriceUsd, true)}]` : "—",
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

export function mountCharts(canvasId = "shz-main-canvas", initialState = null) {
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
  activeController = new ShzChartController(canvas);
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
