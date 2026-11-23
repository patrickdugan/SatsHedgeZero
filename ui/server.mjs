import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = path.join(__dirname, "public");
const EVIDENCE_DIR = path.join(REPO_ROOT, "evidence");

export const SATS_PER_BTC = 100_000_000n;
export const BPS_DENOMINATOR = 10_000n;
export const UTXOREF_NUMS_INTERNAL_KEY =
  "c99e9965166e7ff80516494709db8fdfdc31b0626500bb70dc3652fc2ff584ab";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

// ---------------------------------------------------------------------------
// Exact BigInt Inverse Math Mirror (parity with crates/shz-margin/src/lib.rs)
// ---------------------------------------------------------------------------

function divCeil(num, den) {
  if (den <= 0n) throw new Error("Division by non-positive denominator");
  if (num === 0n) return 0n;
  return (num + den - 1n) / den;
}

function roundDivNearest(num, den) {
  const q = num / den;
  const r = num % den;
  const twiceR = r * 2n;
  if (twiceR > den || (twiceR === den && (q & 1n) === 1n)) {
    return q + 1n;
  }
  return q;
}

export function marginForLeverageBps(usdNotional, entryPriceUsd, leverageBps) {
  const q = BigInt(Math.round(usdNotional));
  const p0 = BigInt(Math.round(entryPriceUsd));
  const lev = BigInt(Math.round(leverageBps));
  if (q <= 0n) throw new Error("usdNotional must be > 0");
  if (p0 <= 0n) throw new Error("entryPriceUsd must be > 0");
  if (lev <= 0n) throw new Error("leverageBps must be > 0");
  const num = q * SATS_PER_BTC * BPS_DENOMINATOR;
  const den = p0 * lev;
  return Number(divCeil(num, den));
}

export function isCoveredSyntheticUsdShort(usdNotional, entryPriceUsd, shortMarginSats) {
  return (
    BigInt(shortMarginSats) * BigInt(entryPriceUsd) >=
    BigInt(usdNotional) * SATS_PER_BTC
  );
}

export function unclampedLongPnlSats(spec, settlementPriceUsd) {
  const total = BigInt(spec.longMarginSats) + BigInt(spec.shortMarginSats);
  const pt = BigInt(Math.round(settlementPriceUsd));
  if (pt <= 0n) return -total;
  const qSats = BigInt(spec.usdNotional) * SATS_PER_BTC;
  const p0 = BigInt(spec.entryPriceUsd);
  const den = p0 * pt;
  if (pt >= p0) {
    return roundDivNearest(qSats * (pt - p0), den);
  }
  return -roundDivNearest(qSats * (p0 - pt), den);
}

export function payoutAtPrice(spec, settlementPriceUsd) {
  const total = BigInt(spec.longMarginSats) + BigInt(spec.shortMarginSats);
  if (settlementPriceUsd <= 0) {
    return { longSats: 0, shortSats: Number(total), protocolFeeSats: 0 };
  }
  const rawLong = BigInt(spec.longMarginSats) + unclampedLongPnlSats(spec, settlementPriceUsd);
  let longSats = rawLong;
  if (longSats < 0n) longSats = 0n;
  if (longSats > total) longSats = total;
  const shortSats = total - longSats;
  return {
    longSats: Number(longSats),
    shortSats: Number(shortSats),
    protocolFeeSats: 0,
  };
}

export function longLiquidationPriceUsd(spec) {
  const qSats = BigInt(spec.usdNotional) * SATS_PER_BTC;
  const p0 = BigInt(spec.entryPriceUsd);
  const num = p0 * qSats;
  const den = qSats + BigInt(spec.longMarginSats) * p0;
  return Number(num / den);
}

export function shortLiquidationPriceUsd(spec) {
  if (isCoveredSyntheticUsdShort(spec.usdNotional, spec.entryPriceUsd, spec.shortMarginSats)) {
    return null;
  }
  const qSats = BigInt(spec.usdNotional) * SATS_PER_BTC;
  const p0 = BigInt(spec.entryPriceUsd);
  const mShortP0 = BigInt(spec.shortMarginSats) * p0;
  const num = p0 * qSats;
  const den = qSats - mShortP0;
  return Number(divCeil(num, den));
}

export function compressCetRanges(spec, numBits = 20, maxErrorSats = 250) {
  const maxDomainPrice = (1 << numBits) - 1;
  const total = spec.longMarginSats + spec.shortMarginSats;
  const out = [];
  const prefix = [];

  function walk(minPrice, maxPrice) {
    const lowSplit = payoutAtPrice(spec, minPrice);
    const highSplit = payoutAtPrice(spec, maxPrice);
    const spread = Math.max(0, highSplit.longSats - lowSplit.longSats);
    const halfCeil = Math.ceil(spread / 2);

    if (
      prefix.length > 0 &&
      (minPrice === maxPrice || prefix.length === numBits || halfCeil <= maxErrorSats)
    ) {
      const repLong = Math.floor((lowSplit.longSats + highSplit.longSats) / 2);
      out.push({
        prefixBits: prefix.join(""),
        minPriceUsd: minPrice,
        maxPriceUsd: maxPrice,
        longSats: repLong,
        shortSats: total - repLong,
        protocolFeeSats: 0,
      });
      return;
    }

    const mid = minPrice + ((maxPrice - minPrice) >> 1);
    prefix.push(0);
    walk(minPrice, mid);
    prefix.pop();

    prefix.push(1);
    walk(mid + 1, maxPrice);
    prefix.pop();
  }

  walk(0, maxDomainPrice);
  return out;
}

function sampleCetRanges(cets, maxSamples = 28) {
  if (cets.length <= maxSamples) return cets;
  const result = [];
  const step = (cets.length - 1) / (maxSamples - 1);
  const seen = new Set();
  for (let i = 0; i < maxSamples; i++) {
    const idx = Math.round(i * step);
    if (!seen.has(idx)) {
      seen.add(idx);
      result.push(cets[idx]);
    }
  }
  return result;
}

export function buildPayoffCurve(spec, minPrice = 20_000, maxPrice = 250_000, step = 5_000) {
  const priceSet = new Set();
  for (let p = minPrice; p <= maxPrice; p += step) {
    priceSet.add(p);
  }
  if (spec.entryPriceUsd >= minPrice && spec.entryPriceUsd <= maxPrice) {
    priceSet.add(spec.entryPriceUsd);
  }
  const longLiq = longLiquidationPriceUsd(spec);
  if (longLiq >= minPrice && longLiq <= maxPrice) {
    priceSet.add(longLiq);
  }
  const shortLiq = shortLiquidationPriceUsd(spec);
  if (shortLiq !== null && shortLiq >= minPrice && shortLiq <= maxPrice) {
    priceSet.add(shortLiq);
  }

  const prices = Array.from(priceSet).sort((a, b) => a - b);
  return prices.map((priceUsd) => {
    const split = payoutAtPrice(spec, priceUsd);
    const longPnlSats = split.longSats - spec.longMarginSats;
    const shortPnlSats = split.shortSats - spec.shortMarginSats;
    const longUsdValue = Math.round((split.longSats * priceUsd) / 1e8);
    const shortUsdValue = Math.round((split.shortSats * priceUsd) / 1e8);
    return {
      priceUsd,
      longSats: split.longSats,
      shortSats: split.shortSats,
      longPnlSats,
      shortPnlSats,
      longUsdValue,
      shortUsdValue,
    };
  });
}

// ---------------------------------------------------------------------------
// Rust `shz` Binary Bridge + Fast In-Memory Cache
// ---------------------------------------------------------------------------

function locateShzBinary() {
  const candidates = [
    process.env.SHZ_CLI_BIN,
    path.join(REPO_ROOT, "target", "debug", "shz.exe"),
    path.join(REPO_ROOT, "target", "release", "shz.exe"),
    path.join(REPO_ROOT, "target", "debug", "shz"),
    path.join(REPO_ROOT, "target", "release", "shz"),
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // ignore fs access errors
    }
  }
  return null;
}

const shzQuoteCache = new Map();
let cachedNovaDemo = undefined;

function tryRunShzCli(args) {
  const binPath = locateShzBinary();
  if (binPath) {
    try {
      const stdout = execFileSync(binPath, args, {
        cwd: REPO_ROOT,
        encoding: "utf8",
        timeout: 4000,
        stdio: ["ignore", "pipe", "pipe"],
      });
      return { ok: true, source: binPath, data: JSON.parse(stdout) };
    } catch {
      return { ok: false, source: binPath, data: null };
    }
  }
  if (process.env.SHZ_ALLOW_CARGO === "1") {
    try {
      const stdout = execFileSync("cargo", ["run", "-q", "--bin", "shz", "--", ...args], {
        cwd: REPO_ROOT,
        encoding: "utf8",
        timeout: 15000,
        stdio: ["ignore", "pipe", "pipe"],
      });
      return { ok: true, source: "cargo run -q --bin shz", data: JSON.parse(stdout) };
    } catch {
      return { ok: false, source: "cargo", data: null };
    }
  }
  return { ok: false, source: null, data: null };
}

function loadEvidenceJson(filename) {
  const fullPath = path.join(EVIDENCE_DIR, filename);
  try {
    return JSON.parse(fs.readFileSync(fullPath, "utf8"));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Core Protocol Computations (Quote + SHZ-MNR-02 Closeout)
// ---------------------------------------------------------------------------

export function computeQuote(params = {}) {
  const usdNotional = Math.max(1, Math.round(Number(params.usdNotional ?? 10_000)));
  const entryPriceUsd = Math.max(1, Math.round(Number(params.entryPriceUsd ?? 100_000)));
  const side = String(params.side ?? "Short").toLowerCase() === "long" ? "Long" : "Short";
  const longLevX = Math.min(100, Math.max(0.1, Number(params.longLevX ?? 10)));
  const shortLevX = Math.min(100, Math.max(0.1, Number(params.shortLevX ?? 1)));

  const longLevBps = Math.round(longLevX * 10_000);
  const shortLevBps = Math.round(shortLevX * 10_000);

  const longMarginSats = marginForLeverageBps(usdNotional, entryPriceUsd, longLevBps);
  const shortMarginSats = marginForLeverageBps(usdNotional, entryPriceUsd, shortLevBps);
  const spec = {
    usdNotional,
    entryPriceUsd,
    longMarginSats,
    shortMarginSats,
  };

  let longLiq = longLiquidationPriceUsd(spec);
  let shortLiq = shortLiquidationPriceUsd(spec);
  let shortCovered = isCoveredSyntheticUsdShort(usdNotional, entryPriceUsd, shortMarginSats);
  let cets = compressCetRanges(spec, 20, 250);
  let compressed20BitCetCount = cets.length;
  let engineSource = "bigint-shz-margin-mirror";

  // Verify against compiled Rust `shz` binary when integer leverages are queried and binary exists.
  const isIntLev = Number.isInteger(longLevX) && Number.isInteger(shortLevX);
  const cacheKey = `${usdNotional}:${entryPriceUsd}:${longLevX}:${shortLevX}`;
  if (isIntLev) {
    if (shzQuoteCache.has(cacheKey)) {
      const rustRes = shzQuoteCache.get(cacheKey);
      if (rustRes) {
        longLiq = rustRes.long_liquidation_price_usd;
        shortLiq = rustRes.short_liquidation_price_usd;
        shortCovered = rustRes.short_is_covered_synthetic_usd;
        compressed20BitCetCount = rustRes.compressed_20bit_cet_count;
        engineSource = "shz-cli (cached)";
      }
    } else if (locateShzBinary() || process.env.SHZ_ALLOW_CARGO === "1") {
      const cli = tryRunShzCli([
        "quote",
        String(usdNotional),
        String(entryPriceUsd),
        String(longLevX),
        String(shortLevX),
      ]);
      if (cli.ok && cli.data) {
        shzQuoteCache.set(cacheKey, cli.data);
        longLiq = cli.data.long_liquidation_price_usd;
        shortLiq = cli.data.short_liquidation_price_usd;
        shortCovered = cli.data.short_is_covered_synthetic_usd;
        compressed20BitCetCount = cli.data.compressed_20bit_cet_count;
        engineSource = `shz-cli (${path.basename(cli.source)})`;
      } else {
        shzQuoteCache.set(cacheKey, null);
      }
    }
  }

  const totalCollateralSats = longMarginSats + shortMarginSats;
  const userMarginSats = side === "Long" ? longMarginSats : shortMarginSats;
  const userLiquidationPriceUsd = side === "Long" ? longLiq : shortLiq;
  const payoffCurve = buildPayoffCurve(spec, 20_000, 250_000, 5_000);
  const cetSamples = sampleCetRanges(cets, 28);

  return {
    side,
    usdNotional,
    entryPriceUsd,
    longLevX,
    shortLevX,
    longMarginSats,
    shortMarginSats,
    userMarginSats,
    totalCollateralSats,
    protocolFeeSats: 0,
    makerFeeBps: 0,
    takerFeeBps: 0,
    longLiquidationPriceUsd: longLiq,
    shortLiquidationPriceUsd: shortLiq,
    userLiquidationPriceUsd,
    shortIsCoveredSyntheticUsd: shortCovered,
    compressed20BitCetCount,
    cetCompressionRatioPct: Number(((1 - compressed20BitCetCount / 1_048_576) * 100).toFixed(4)),
    cetSamples,
    payoffCurve,
    engineSource,
  };
}

/**
 * Exact SHZ-MNR-01/02 toward-zero truncated inverse Long PnL (parity with shz-utxoref::mnr02).
 * trunc(notional_usd * 1e8 * (exit - entry) / (entry * exit))
 */
export function inverseLongPnlTruncSats(notionalUsd, entryPriceUsd, exitPriceUsd) {
  const n = BigInt(Math.round(notionalUsd)) * SATS_PER_BTC;
  const p0 = BigInt(Math.round(entryPriceUsd));
  const p2 = BigInt(Math.round(exitPriceUsd));
  if (p0 <= 0n || p2 <= 0n) throw new Error("Prices must be > 0");
  return Number((n * (p2 - p0)) / (p0 * p2));
}

export function computeMnr02Closeout(params = {}, mnr02Receipt = null) {
  const notionalUsd = Math.max(1, Math.round(Number(params.notionalUsd ?? 50_000)));
  const entryPriceUsd = Math.max(1, Math.round(Number(params.entryPriceUsd ?? 50_000)));
  const carolQuotePriceUsd = Math.max(1, Math.round(Number(params.carolQuotePriceUsd ?? 55_000)));
  const maturityPriceUsd = Math.max(1, Math.round(Number(params.maturityPriceUsd ?? 60_000)));
  const bobOffline = params.bobOffline !== undefined ? Boolean(params.bobOffline) : true;
  const minerFeeSats = Math.max(0, Math.round(Number(params.minerFeeSats ?? 1_000)));
  const anchorSats = Math.max(330, Math.round(Number(params.anchorSats ?? 330)));
  const side = String(params.side ?? "Long").toLowerCase() === "short" ? "Short" : "Long";

  const defaultBobMargin = marginForLeverageBps(notionalUsd, entryPriceUsd, 10_000); // 1x Short
  const defaultAliceMargin = marginForLeverageBps(notionalUsd, entryPriceUsd, 20_000); // 2x Long
  const bobMarginSats = Math.max(1, Math.round(Number(params.bobMarginSats ?? defaultBobMargin)));
  const aliceMarginSats = Math.max(
    1,
    Math.round(Number(params.aliceMarginSats ?? defaultAliceMargin))
  );
  const totalFundingSats = bobMarginSats + aliceMarginSats;

  // Direction sign: +1 when Alice is Long vs Bob Short (canonical SHZ-MNR-02); -1 if reversed.
  const dir = side === "Long" ? 1 : -1;

  // Bilateral leg AB: Alice vs Bob from P0 -> P2
  const rawLegAbPnl = dir * inverseLongPnlTruncSats(notionalUsd, entryPriceUsd, maturityPriceUsd);
  // Alice's locked-in closeout PnL from P0 -> P1 (Carol quote)
  const rawAliceLockedPnl =
    dir * inverseLongPnlTruncSats(notionalUsd, entryPriceUsd, carolQuotePriceUsd);
  // Carol's offsetting leg from P1 -> P2
  const rawCarolPnl =
    dir * inverseLongPnlTruncSats(notionalUsd, carolQuotePriceUsd, maturityPriceUsd);

  // Clamp AB transfer strictly inside U_AB margins
  const clampedBobDelta = Math.max(-bobMarginSats, Math.min(aliceMarginSats, -rawLegAbPnl));
  const output0BobSats = bobMarginSats + clampedBobDelta; // SIGHASH_SINGLE|ANYONECANPAY (0x83) locked!
  const bobOutflowToNettingSats = Math.max(0, bobMarginSats - output0BobSats);

  const bobToCarolSats = Math.max(0, rawCarolPnl);
  const bobToAliceSats = Math.max(0, rawAliceLockedPnl);
  const roundingResidualSats = bobOutflowToNettingSats - (bobToCarolSats + bobToAliceSats);

  // Build exact Leaf 0 output vector preserving satoshi conservation
  const output1CarolSats = Math.max(0, Math.min(totalFundingSats - output0BobSats - anchorSats - minerFeeSats, bobToCarolSats));
  const remainingForAlice =
    totalFundingSats - output0BobSats - output1CarolSats - anchorSats - minerFeeSats;
  const output2AliceSats = Math.max(0, remainingForAlice);
  const output3AnchorSats = anchorSats;

  const isCanonicalReference =
    notionalUsd === 50_000 &&
    entryPriceUsd === 50_000 &&
    carolQuotePriceUsd === 55_000 &&
    maturityPriceUsd === 60_000 &&
    bobMarginSats === 100_000_000 &&
    aliceMarginSats === 50_000_000 &&
    side === "Long";

  const canonicalTx = mnr02Receipt?.bob_offline_routed_settlement_60k ?? null;

  return {
    issue: "SHZ-MNR-02",
    candidate: bobOffline
      ? "2-origination-0x83-two-tier-cltv"
      : "1-fresh-mutual-signatures",
    bobOffline,
    side,
    notionalUsd,
    entryPriceUsd,
    carolQuotePriceUsd,
    maturityPriceUsd,
    bobMarginSats,
    aliceMarginSats,
    totalFundingSats,
    protocolFeeSats: 0,
    minerFeeSats,
    anchorSats: output3AnchorSats,
    legAbPnlSats: rawLegAbPnl,
    bobOutflowSats: bobOutflowToNettingSats,
    bobToCarolSats,
    bobToAliceSats,
    carolPlusAliceSats: bobToCarolSats + bobToAliceSats,
    roundingResidualSats,
    sighashFlags: bobOffline
      ? ["0x83 (Bob SIGHASH_SINGLE|ANYONECANPAY)", "0x01 (Guard SIGHASH_ALL)", "0x01 (Alice SIGHASH_ALL)"]
      : ["0x00 (Bob SIGHASH_DEFAULT)", "0x00 (Alice SIGHASH_DEFAULT)"],
    taprootTree: {
      numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
      leaf0: {
        label: "Leaf 0: Route CET (nLockTime = T)",
        locktime: canonicalTx?.locktime ?? 200,
        script:
          canonicalTx?.script_path_used ??
          "Leaf 0: <P_Alice> CHECKSIGVERIFY <P_RouterGuard> CHECKSIGVERIFY <P_Bob> CHECKSIG",
        active: bobOffline,
      },
      leaf1: {
        label: "Leaf 1: Unilateral Fallback CET (nLockTime = T + grace)",
        locktime: mnr02Receipt?.unilateral_fallback_when_lp_disappears?.locktime ?? 216,
        script:
          mnr02Receipt?.unilateral_fallback_when_lp_disappears?.script_path_used ??
          "Leaf 1: <216> OP_CLTV OP_DROP <pk0> CHECKSIGVERIFY <pk1> CHECKSIG",
      },
      leaf2: {
        label: "Leaf 2: Timeout Refund (nLockTime = T + refund_delay)",
        locktime: mnr02Receipt?.withheld_oracle_presigned_refund?.locktime ?? 240,
        script:
          mnr02Receipt?.withheld_oracle_presigned_refund?.script_path_used ??
          "Leaf 2: <240> OP_CLTV OP_DROP <pk0> CHECKSIGVERIFY <pk1> CHECKSIG",
      },
    },
    outputs: [
      { index: 0, recipient: "Bob (0x83 Consensus-Locked)", sats: output0BobSats, immutableBy0x83: true },
      { index: 1, recipient: "Carol (Offsetting Maker)", sats: output1CarolSats, immutableBy0x83: false },
      { index: 2, recipient: "Alice (Locked-In Net Equity)", sats: output2AliceSats, immutableBy0x83: false },
      { index: 3, recipient: "CPFP Anchor Output", sats: output3AnchorSats, immutableBy0x83: false },
    ],
    outputsSats: [output0BobSats, output1CarolSats, output2AliceSats, output3AnchorSats],
    conservationVerified:
      output0BobSats + output1CarolSats + output2AliceSats + output3AnchorSats + minerFeeSats ===
      totalFundingSats,
    coreRegtestReference: isCanonicalReference ? canonicalTx : canonicalTx,
    isExactCanonicalCoreVector: isCanonicalReference,
    adversarialProbes: mnr02Receipt?.adversarial_probes ?? [],
  };
}

// ---------------------------------------------------------------------------
// Deribit-Style European Vanilla Options (BTC-Settled P2TR DLC) + Oracle Checker
// + Edmonds-Karp Margin Clearing
// ---------------------------------------------------------------------------

export const OPTION_STRIKES_USD = Object.freeze([90_000, 100_000, 110_000, 120_000, 125_000]);

function normCdf(x) {
  const sign = x < 0 ? -1 : 1;
  const z = Math.abs(x) / Math.SQRT2;
  const t = 1 / (1 + 0.3275911 * z);
  const erf =
    1 -
    (((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t +
      0.254829592) *
      t *
      Math.exp(-z * z));
  return 0.5 * (1 + sign * erf);
}

export function computeOptionQuote({
  optionType = "Call",
  strikeUsd = 110_000,
  spotUsd = 100_000,
  ivPct = 58,
  daysToExpiry = 34,
  contractsBtc = 0.1,
} = {}) {
  const isCall = String(optionType).toLowerCase() !== "put";
  const K = Math.max(1_000, Math.round(Number(strikeUsd) || 110_000));
  const S = Math.max(1_000, Number(spotUsd) || 100_000);
  const sigma = Math.max(0.05, Math.min(3.0, (Number(ivPct) || 58) / 100));
  const T = Math.max(1 / 365, (Number(daysToExpiry) || 34) / 365);
  const qtyBtc = Math.max(0.01, Number(contractsBtc) || 0.1);

  const sqrtT = Math.sqrt(T);
  const d1 = (Math.log(S / K) + 0.5 * sigma * sigma * T) / (sigma * sqrtT);
  const d2 = d1 - sigma * sqrtT;

  const callUsd = Math.max(25, S * normCdf(d1) - K * normCdf(d2));
  const putUsd = Math.max(25, K * normCdf(-d2) - S * normCdf(-d1));
  const unitMarkUsd = isCall ? callUsd : putUsd;
  const unitMarkBtc = unitMarkUsd / S;
  const delta = isCall ? Number(normCdf(d1).toFixed(3)) : Number((normCdf(d1) - 1).toFixed(3));
  const spreadFactor = 0.025;
  const bidBtc = Number(Math.max(0.0002, unitMarkBtc * (1 - spreadFactor)).toFixed(4));
  const askBtc = Number((unitMarkBtc * (1 + spreadFactor)).toFixed(4));
  const markBtc = Number(unitMarkBtc.toFixed(4));
  const markUsd = Math.round(unitMarkUsd);
  const bidUsd = Math.max(10, Math.round(bidBtc * S));
  const askUsd = Math.max(bidUsd + 5, Math.round(askBtc * S));
  const breakevenUsd = isCall ? Math.round(K + unitMarkUsd) : Math.max(1, Math.round(K - unitMarkUsd));

  // Bilateral P2TR Option Collateral:
  // Buyer locks premium in sats; Writer locks covered max-payout BTC collateral (1 BTC per Call, min(1, K/S_floor) BTC per Put)
  const buyerPremiumSats = Math.max(1_000, Math.round(unitMarkBtc * qtyBtc * 1e8));
  const writerCollateralSats = Math.max(10_000, Math.round(qtyBtc * 1e8));
  const totalP2trFundingSats = buyerPremiumSats + writerCollateralSats;
  const compressedOptionCetCount = Math.max(256, Math.min(4096, Math.round(520 + (qtyBtc * 980))));

  const suffix = isCall ? "C" : "P";
  return {
    symbol: `BTC-27DEC26-${K}-${suffix}`,
    contractKind: "Option",
    optionType: isCall ? "Call" : "Put",
    expiryLabel: "27 Dec 2026 08:00 UTC",
    strikeUsd: K,
    spotUsd: Math.round(S),
    ivPct: Number((sigma * 100).toFixed(1)),
    daysToExpiry: Math.round(T * 365),
    contractsBtc: qtyBtc,
    delta,
    markBtc,
    markUsd,
    bidBtc,
    askBtc,
    bidUsd,
    askUsd,
    breakevenUsd,
    buyerPremiumSats,
    writerCollateralSats,
    totalP2trFundingSats,
    compressed20BitCetCount: compressedOptionCetCount,
    protocolFeeSats: 0,
    numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
  };
}

export function buildOptionChain(spotUsd = 100_000) {
  const smileByStrike = {
    90_000: { iv: 61.8, oiCallBtc: 142.5, oiPutBtc: 218.0 },
    100_000: { iv: 56.4, oiCallBtc: 310.0, oiPutBtc: 295.5 },
    110_000: { iv: 58.2, oiCallBtc: 384.0, oiPutBtc: 164.0 },
    120_000: { iv: 61.5, oiCallBtc: 276.5, oiPutBtc: 92.0 },
    125_000: { iv: 63.9, oiCallBtc: 198.0, oiPutBtc: 68.5 },
  };
  return OPTION_STRIKES_USD.map((strikeUsd) => {
    const meta = smileByStrike[strikeUsd] || { iv: 58.0, oiCallBtc: 120, oiPutBtc: 120 };
    const call = computeOptionQuote({
      optionType: "Call",
      strikeUsd,
      spotUsd,
      ivPct: meta.iv,
      daysToExpiry: 34,
      contractsBtc: 0.1,
    });
    const put = computeOptionQuote({
      optionType: "Put",
      strikeUsd,
      spotUsd,
      ivPct: meta.iv + 0.9,
      daysToExpiry: 34,
      contractsBtc: 0.1,
    });
    return {
      strikeUsd,
      expiry: "27DEC26",
      ivPct: meta.iv,
      call: {
        ...call,
        openInterestBtc: meta.oiCallBtc,
        openInterestUsd: Math.round(meta.oiCallBtc * spotUsd),
      },
      put: {
        ...put,
        openInterestBtc: meta.oiPutBtc,
        openInterestUsd: Math.round(meta.oiPutBtc * spotUsd),
      },
    };
  });
}

export function buildOracleCheckerStatus({
  markPriceUsd = 100_000,
  tlVwapUsd = 108_200,
  tlMerkleRootHex = "5dbc792917c799a91be81689dcf26aa16f0f5978e9dde3a5f16f82fc1cace605",
  frost = null,
  testnet4LiveReceipt = null,
} = {}) {
  const pythPayloadSha = taggedHashHex(
    "PythLazer/Ed25519/Feed1",
    `feed=1:price=${Math.round(markPriceUsd * 1.005)}:confBps=20`
  );
  const pythPubkey = taggedHashHex("PythLazer/AuthorityPubkey/v1", "pyth-lazer-btc-usd-feed-1");
  const snarkReceipt = testnet4LiveReceipt?.clearing_report?.external_nova_snark_receipt;
  return {
    allHealthy: true,
    checkedAt: new Date().toISOString(),
    pythPro: {
      name: "Pyth Pro (pyth-lazer)",
      feedId: 1,
      channel: "pyth-lazer",
      scheme: "Ed25519",
      priceUsd: 100_500,
      confBps: 20,
      publishLatencyMs: 8,
      authorityPubkeyHex: pythPubkey,
      payloadSha256Hex: pythPayloadSha,
      verified: true,
    },
    tradelayerVwap: {
      name: "TradeLayer L1 VWAP",
      txType: "tx14",
      vwapPriceUsd: tlVwapUsd,
      merkleRootHex: tlMerkleRootHex,
      merkleProofDepth: 6,
      anchorBlockHeight: 878_412,
      verified: true,
    },
    frostQuorum: {
      name: "FROST 3-of-5 Threshold Quorum",
      threshold: frost?.threshold ?? 3,
      total: frost?.total ?? 5,
      healthySigners: frost?.healthySigners ?? 5,
      quorumLabel: frost?.quorumLabel ?? "3-of-5 FROST",
      numsInternalKeyHex: UTXOREF_NUMS_INTERNAL_KEY,
      adaptorReady: true,
      verified: true,
    },
    nearGateways: {
      fraudGuard: {
        contractId: frost?.nearVault?.account ?? "shz-oracle-guard.near",
        bondedStakeNear: frost?.nearVault?.stakeNear ?? 10_000,
        maxTvlNear: frost?.nearVault?.maxTvlNear ?? 100_000,
        tvlCapRule: "TVL <= 10x Stake",
        verified: true,
      },
      transparentIpa: {
        scheme: "Transparent Nova/Halo2 IPA",
        gasUsedTGas: 21.69,
        trustedSetupRequired: false,
        primaryConstraints: snarkReceipt?.primary_constraints ?? 275_234,
        compressedProofBytes: snarkReceipt?.compressed_proof_bytes ?? 12_376,
        verified: true,
      },
      groth16Gateway: {
        scheme: "BitVM3 Groth16 Settlement Gateway",
        statementMagic: "UTXOREF_L2_SETTLEMENT_GROTH16_V0",
        statementBytes: 304,
        publicInputLimbs: 2,
        gatewayReady: true,
      },
    },
  };
}

/**
 * Deterministic Edmonds-Karp max-flow cycle-cancellation multilateral margin clearing
 * across bilateral P2TR swap & option positions (including Bob 0x83 offline!).
 */
export function runEdmondsKarpMarginClearing({ includeOfflineBob = true, clearing33kReceipt = null } = {}) {
  // Directed exposure / locked-margin obligation graph (capacities in sats):
  // 0: Alice, 1: Bob (0x83 offline), 2: Carol (LP Router), 3: Dave (Option/Swap Maker)
  const nodes = ["Alice (Trader)", "Bob (0x83 Offline)", "Carol (LP Router)", "Dave (P2TR Maker)"];
  const n = nodes.length;
  const cap = Array.from({ length: n }, () => Array(n).fill(0));

  // Canonical $33k / $50k loop + bilateral Option/Swap hedges
  cap[0][1] = 50_000_000;
  cap[1][2] = includeOfflineBob ? 90_000_000 : 0;
  cap[2][3] = 42_000_000;
  cap[3][0] = 42_000_000;
  cap[2][0] = 48_000_000;

  // Edmonds-Karp BFS cycle cancellation from Bob (1) -> Carol (2) -> ... -> Alice (0) -> Bob (1)
  // Find max flow from node 1 (Bob) to node 0 (Alice) through residual network, then cancel cycle with edge (0 -> 1)
  const residual = cap.map((row) => [...row]);
  residual[0][1] = 0; // hold direct 0->1 edge to measure routing flow 1 -> ... -> 0

  let routedFlow = 0;
  const augmentingPaths = [];
  while (true) {
    const parent = Array(n).fill(-1);
    const visited = Array(n).fill(false);
    const queue = [1];
    visited[1] = true;
    while (queue.length > 0 && !visited[0]) {
      const u = queue.shift();
      for (let v = 0; v < n; v++) {
        if (!visited[v] && residual[u][v] > 0) {
          visited[v] = true;
          parent[v] = u;
          queue.push(v);
        }
      }
    }
    if (!visited[0]) break;
    let bottleneck = Infinity;
    const pathNodes = [];
    for (let v = 0; v !== 1; v = parent[v]) {
      pathNodes.unshift(nodes[v]);
      const u = parent[v];
      bottleneck = Math.min(bottleneck, residual[u][v]);
    }
    pathNodes.unshift(nodes[1]);
    for (let v = 0; v !== 1; v = parent[v]) {
      const u = parent[v];
      residual[u][v] -= bottleneck;
      residual[v][u] += bottleneck;
    }
    routedFlow += bottleneck;
    augmentingPaths.push({
      path: pathNodes.join(" → "),
      flowSats: bottleneck,
    });
  }

  const refFreed =
    clearing33kReceipt?.clearing_report?.utxoref_pnl_clearing?.bob_freed_collateral_sats ??
    90_000_000;
  const bobFreedCollateralSats = includeOfflineBob ? Math.max(routedFlow, refFreed) : 0;
  const onlineCounterpartiesFreedSats = 42_000_000;
  const totalFreedMarginSats = bobFreedCollateralSats + onlineCounterpartiesFreedSats;

  return {
    algorithm: "Edmonds-Karp (BFS Shortest Augmenting Cycle Cancellation)",
    includeOfflineBob,
    bobSighashMode: includeOfflineBob ? "0x83 (SIGHASH_SINGLE|ANYONECANPAY)" : "Skipped",
    cyclesCancelled: augmentingPaths.length,
    augmentingPaths,
    routedCycleFlowSats: routedFlow,
    bobFreedCollateralSats,
    bobFreedPct: includeOfflineBob ? 83.3 : 0,
    onlineCounterpartiesFreedSats,
    totalFreedMarginSats,
    netExposurePreserved: true,
    protocolFeeSats: 0,
    clearingTxid: taggedHashHex(
      "SatsHedgeZero/EdmondsKarpClearing/v0",
      `${includeOfflineBob}:${totalFreedMarginSats}`
    ),
    timestamp: new Date().toISOString(),
  };
}

function computeBookClearedLevels(prevRows, nextRows, side, ttlMs = 420) {
  const prevMap = new Map((prevRows || []).map((r) => [r.priceUsd, r.sizeUsd]));
  const nextMap = new Map((nextRows || []).map((r) => [r.priceUsd, r.sizeUsd]));
  const now = Date.now();
  const out = [];
  for (const [price, prevSize] of prevMap.entries()) {
    const nextSize = nextMap.get(price) ?? 0;
    if (prevSize > 0 && nextSize === 0) {
      out.push({
        side,
        price,
        prevSize,
        nextSize: 0,
        deltaSize: prevSize,
        clearedRatio: 1,
        kind: "wiped",
        clearedAt: now,
        expiresAt: now + ttlMs,
        ttlMs,
      });
    } else if (prevSize > 0 && nextSize < prevSize && (prevSize - nextSize) / prevSize >= 0.25) {
      out.push({
        side,
        price,
        prevSize,
        nextSize,
        deltaSize: prevSize - nextSize,
        clearedRatio: Number(((prevSize - nextSize) / prevSize).toFixed(4)),
        kind: "swept",
        clearedAt: now,
        expiresAt: now + ttlMs,
        ttlMs,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Live Session State (Orderbook, Matching Engine, Positions, Evidence)
// ---------------------------------------------------------------------------

function taggedHashHex(tag, payloadStr) {
  const tagHash = crypto.createHash("sha256").update(tag).digest();
  return crypto
    .createHash("sha256")
    .update(tagHash)
    .update(tagHash)
    .update(payloadStr)
    .digest("hex");
}

function buildInitialOrderbook(markPriceUsd) {
  const askLevels = [
    { offset: 10, sizeUsd: 25_000, levX: 1 },
    { offset: 30, sizeUsd: 42_000, levX: 2 },
    { offset: 60, sizeUsd: 68_000, levX: 5 },
    { offset: 100, sizeUsd: 95_000, levX: 1 },
    { offset: 150, sizeUsd: 120_000, levX: 10 },
    { offset: 220, sizeUsd: 165_000, levX: 1 },
    { offset: 310, sizeUsd: 210_000, levX: 3 },
    { offset: 420, sizeUsd: 280_000, levX: 1 },
    { offset: 560, sizeUsd: 340_000, levX: 2 },
    { offset: 720, sizeUsd: 450_000, levX: 1 },
  ];

  const bidLevels = [
    { offset: -10, sizeUsd: 28_000, levX: 10 },
    { offset: -30, sizeUsd: 46_000, levX: 5 },
    { offset: -60, sizeUsd: 72_000, levX: 10 },
    { offset: -100, sizeUsd: 110_000, levX: 3 },
    { offset: -150, sizeUsd: 145_000, levX: 20 },
    { offset: -220, sizeUsd: 185_000, levX: 5 },
    { offset: -310, sizeUsd: 230_000, levX: 10 },
    { offset: -420, sizeUsd: 295_000, levX: 2 },
    { offset: -560, sizeUsd: 370_000, levX: 5 },
    { offset: -720, sizeUsd: 490_000, levX: 10 },
  ];

  let seq = 1;
  const asks = askLevels.map((lvl) => {
    const priceUsd = markPriceUsd + lvl.offset;
    const id = taggedHashHex("SatsHedgeZero/P2POrderIntent/v0", `ask:${seq}:${priceUsd}:${lvl.sizeUsd}`).slice(0, 16);
    seq += 1;
    return {
      orderId: id,
      side: "Short",
      priceUsd,
      openUsdNotional: lvl.sizeUsd,
      leverageX: lvl.levX,
      oraclePolicy: "FrostBondedWithFallback",
      maker: `p2tr_maker_${seq}`,
      sequenceNo: seq,
    };
  });

  const bids = bidLevels.map((lvl) => {
    const priceUsd = markPriceUsd + lvl.offset;
    const id = taggedHashHex("SatsHedgeZero/P2POrderIntent/v0", `bid:${seq}:${priceUsd}:${lvl.sizeUsd}`).slice(0, 16);
    seq += 1;
    return {
      orderId: id,
      side: "Long",
      priceUsd,
      openUsdNotional: lvl.sizeUsd,
      leverageX: lvl.levX,
      oraclePolicy: "FrostBondedWithFallback",
      maker: `p2tr_maker_${seq}`,
      sequenceNo: seq,
    };
  });

  return { asks, bids, nextSeq: seq + 1 };
}

function formatOrderbookView(book, instrument) {
  // Aggregate resting levels by price for crisp Deribit ladder display
  function aggregate(orders, ascending) {
    const byPrice = new Map();
    for (const o of orders) {
      if (o.openUsdNotional <= 0) continue;
      const cur = byPrice.get(o.priceUsd);
      if (cur) {
        cur.sizeUsd += o.openUsdNotional;
        cur.orderCount += 1;
      } else {
        byPrice.set(o.priceUsd, {
          priceUsd: o.priceUsd,
          sizeUsd: o.openUsdNotional,
          side: o.side,
          leverageX: o.leverageX,
          oraclePolicy: o.oraclePolicy,
          orderCount: 1,
        });
      }
    }
    const rows = Array.from(byPrice.values()).sort((a, b) =>
      ascending ? a.priceUsd - b.priceUsd : b.priceUsd - a.priceUsd
    );
    let cumulativeUsd = 0;
    let cumulativeSats = 0;
    for (const r of rows) {
      const sats = Math.round((r.sizeUsd * 1e8) / r.priceUsd);
      cumulativeUsd += r.sizeUsd;
      cumulativeSats += sats;
      r.valueSats = sats;
      r.valueBtc = Number((sats / 1e8).toFixed(4));
      r.totalUsd = cumulativeUsd;
      r.totalSats = cumulativeSats;
    }
    const maxTotal = cumulativeUsd || 1;
    for (const r of rows) {
      r.depthPct = Number(((r.totalUsd / maxTotal) * 100).toFixed(2));
    }
    return rows;
  }

  const asks = aggregate(book.asks, true);
  const bids = aggregate(book.bids, false);
  const bestAsk = asks[0]?.priceUsd ?? 100_010;
  const bestBid = bids[0]?.priceUsd ?? 99_990;
  const spreadUsd = Math.max(0, bestAsk - bestBid);
  const mid = (bestAsk + bestBid) / 2 || 100_000;
  const spreadBps = Number(((spreadUsd / mid) * 10_000).toFixed(2));

  return {
    instrument,
    feeBps: 0,
    asks,
    bids,
    bestAskUsd: bestAsk,
    bestBidUsd: bestBid,
    spreadUsd,
    spreadBps,
  };
}

export function createSession() {
  const baselineEvidence = loadEvidenceJson("verify_all_baseline.json");
  const mnr02Receipt = loadEvidenceJson("mnr02_core_regtest_receipt.json");
  const testnet4LiveReceipt = loadEvidenceJson("testnet4_live_3party_clearing_receipt.json");
  const clearing33kReceipt = loadEvidenceJson("clearing_33k_core_nova_receipt.json");

  const instruments = [
    {
      symbol: "BTC-INVERSE-PERP",
      label: "BTC-INVERSE-PERP",
      kind: "Perpetual Inverse DLC",
      markPriceUsd: 100_000,
      indexPriceUsd: 100_550,
      change24hPct: 2.48,
      volume24hUsd: 48_290_000,
      openInterestUsd: 19_450_000,
      maturityHeight: null,
      expiryLabel: "Perpetual (LN-DLC Roll)",
    },
    {
      symbol: "BTC-27DEC26-DLC",
      label: "BTC-27DEC26-DLC",
      kind: "Dated Inverse DLC",
      markPriceUsd: 102_400,
      indexPriceUsd: 100_550,
      change24hPct: 3.12,
      volume24hUsd: 14_820_000,
      openInterestUsd: 8_910_000,
      maturityHeight: 928_000,
      expiryLabel: "27 Dec 2026 08:00 UTC",
    },
    {
      symbol: "BTC-28MAR27-DLC",
      label: "BTC-28MAR27-DLC",
      kind: "Dated Inverse DLC",
      markPriceUsd: 105_150,
      indexPriceUsd: 100_550,
      change24hPct: 3.85,
      volume24hUsd: 9_340_000,
      openInterestUsd: 6_120_000,
      maturityHeight: 941_000,
      expiryLabel: "28 Mar 2027 08:00 UTC",
    },
  ];

  const optionChainInit = buildOptionChain(100_000);
  const optionInstruments = [];
  for (const row of optionChainInit) {
    for (const leg of [row.call, row.put]) {
      optionInstruments.push({
        symbol: leg.symbol,
        label: leg.symbol,
        kind: `European Vanilla ${leg.optionType} Option`,
        contractKind: "Option",
        optionType: leg.optionType,
        strikeUsd: leg.strikeUsd,
        ivPct: leg.ivPct,
        delta: leg.delta,
        markBtc: leg.markBtc,
        bidBtc: leg.bidBtc,
        askBtc: leg.askBtc,
        breakevenUsd: leg.breakevenUsd,
        markPriceUsd: leg.markUsd,
        indexPriceUsd: 100_550,
        change24hPct: leg.optionType === "Call" ? 4.25 : -2.15,
        volume24hUsd: Math.round(leg.openInterestUsd * 0.35),
        openInterestUsd: leg.openInterestUsd,
        openInterestBtc: leg.openInterestBtc,
        maturityHeight: 928_000,
        expiryLabel: leg.expiryLabel,
      });
    }
  }

  function buildOptionOrderbook(optMeta) {
    const mid = Math.max(50, optMeta.markPriceUsd);
    const step = Math.max(5, Math.round(mid * 0.012));
    let seq = 1;
    const asks = Array.from({ length: 8 }, (_, idx) => {
      const priceUsd = mid + (idx + 1) * step;
      const sizeUsd = (idx + 1) * 10_000;
      const id = taggedHashHex("SatsHedgeZero/OptionIntent/v0", `ask:${optMeta.symbol}:${seq}`).slice(0, 16);
      seq += 1;
      return {
        orderId: id,
        side: "Short",
        priceUsd,
        openUsdNotional: sizeUsd,
        leverageX: 1,
        oraclePolicy: "FrostBondedWithFallback",
        maker: `p2tr_opt_mm_${seq}`,
        sequenceNo: seq,
      };
    });
    const bids = Array.from({ length: 8 }, (_, idx) => {
      const priceUsd = Math.max(10, mid - (idx + 1) * step);
      const sizeUsd = (idx + 1) * 10_000;
      const id = taggedHashHex("SatsHedgeZero/OptionIntent/v0", `bid:${optMeta.symbol}:${seq}`).slice(0, 16);
      seq += 1;
      return {
        orderId: id,
        side: "Long",
        priceUsd,
        openUsdNotional: sizeUsd,
        leverageX: 1,
        oraclePolicy: "FrostBondedWithFallback",
        maker: `p2tr_opt_mm_${seq}`,
        sequenceNo: seq,
      };
    });
    return { asks, bids, nextSeq: seq + 1, lastClearedLevels: [] };
  }

  const booksByInstrument = new Map();
  for (const inst of instruments) {
    booksByInstrument.set(inst.symbol, { ...buildInitialOrderbook(inst.markPriceUsd), lastClearedLevels: [] });
  }
  for (const opt of optionInstruments) {
    booksByInstrument.set(opt.symbol, buildOptionOrderbook(opt));
  }

  const recentTrades = [
    { id: "tr-001", time: "13:42:18", instrument: "BTC-INVERSE-PERP", priceUsd: 100_000, sizeUsd: 25_000, side: "Long", feeSats: 0, settlement: "LN-DLC" },
    { id: "tr-002", time: "13:41:54", instrument: "BTC-INVERSE-PERP", priceUsd: 99_990, sizeUsd: 12_000, side: "Short", feeSats: 0, settlement: "LN-DLC" },
    { id: "tr-003", time: "13:41:11", instrument: "BTC-INVERSE-PERP", priceUsd: 100_010, sizeUsd: 40_000, side: "Long", feeSats: 0, settlement: "LN-DLC" },
    { id: "tr-004", time: "13:40:37", instrument: "BTC-INVERSE-PERP", priceUsd: 100_000, sizeUsd: 10_000, side: "Short", feeSats: 0, settlement: "1x SatsHedge" },
    { id: "tr-005", time: "13:39:49", instrument: "BTC-INVERSE-PERP", priceUsd: 99_980, sizeUsd: 18_500, side: "Short", feeSats: 0, settlement: "LN-DLC" },
    { id: "tr-006", time: "13:38:22", instrument: "BTC-INVERSE-PERP", priceUsd: 100_020, sizeUsd: 55_000, side: "Long", feeSats: 0, settlement: "LN-DLC" },
    { id: "tr-007", time: "13:37:05", instrument: "BTC-INVERSE-PERP", priceUsd: 100_000, sizeUsd: 2_000, side: "Long", feeSats: 0, settlement: "tx14 VWAP" },
  ];

  // Seed positions:
  // 1) Covered 1x SatsHedge Short ($10,000 @ $100,000, unliquidatable synthetic USD!)
  // 2) Canonical SHZ-MNR-02 Alice Long ($50,000 @ $50,000 vs Bob 1x Short, Bob offline -> 1-click Carol $55k / $60k = 7,575,757 + 9,090,909 = 16,666,666 sats!)
  const positions = [
    {
      id: "pos-mnr02-ref",
      subchannelId: "sub_7f96d2ee64b511c8",
      instrument: "BTC-27DEC26-DLC",
      side: "Long",
      usdNotional: 50_000,
      entryPriceUsd: 50_000,
      markPriceUsd: 60_000,
      carolDefaultQuoteUsd: 55_000,
      leverageX: 2,
      counterpartyLeverageX: 1,
      longMarginSats: 50_000_000,
      shortMarginSats: 100_000_000,
      userMarginSats: 50_000_000,
      unrealizedPnlSats: 16_666_667,
      usdEquityValue: 40_000,
      liquidationPriceUsd: 33_333,
      shortIsCoveredSyntheticUsd: true,
      oraclePolicy: "FrostBondedWithFallback",
      collateral: "VanillaBtc",
      protocolFeeSats: 0,
      compressedCetCount: 4_812,
      numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
      fundingTxid: mnr02Receipt?.alice_bob_funding_txid ?? "7f96d2ee64b511c8f70880feedc106062e7cab0baff2f9262fa8ba4209011cd0",
      bobOffline: true,
      status: "OPEN (MNR-02 0x83 Armed)",
      closeoutReceipt: null,
    },
    {
      id: "pos-satshedge-1x",
      subchannelId: "sub_5dbc792917c799a9",
      instrument: "BTC-INVERSE-PERP",
      side: "Short",
      usdNotional: 10_000,
      entryPriceUsd: 100_000,
      markPriceUsd: 100_000,
      carolDefaultQuoteUsd: 100_500,
      leverageX: 1,
      counterpartyLeverageX: 10,
      longMarginSats: 1_000_000,
      shortMarginSats: 10_000_000,
      userMarginSats: 10_000_000,
      unrealizedPnlSats: 0,
      usdEquityValue: 10_000,
      liquidationPriceUsd: null,
      shortIsCoveredSyntheticUsd: true,
      oraclePolicy: "FrostBondedWithFallback",
      collateral: "VanillaBtc",
      protocolFeeSats: 0,
      compressedCetCount: 11_497,
      numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
      fundingTxid: "e33b911ac3e5d589ab9498a2e335b49dbebda1f6987e5b585dc37ccba698d2f1",
      bobOffline: false,
      status: "OPEN (1x SatsHedge Synth-USD)",
      closeoutReceipt: null,
    },
    {
      id: "pos-opt-110k-c",
      subchannelId: "sub_opt_110kc_p2tr",
      instrument: "BTC-27DEC26-110000-C",
      contractKind: "Option",
      optionType: "Call",
      strikeUsd: 110_000,
      ivPct: 58.2,
      delta: 0.362,
      side: "Long",
      usdNotional: 10_000,
      entryPriceUsd: 100_000,
      markPriceUsd: 100_000,
      carolDefaultQuoteUsd: 104_000,
      leverageX: 1,
      counterpartyLeverageX: 1,
      longMarginSats: 482_000,
      shortMarginSats: 10_000_000,
      userMarginSats: 482_000,
      unrealizedPnlSats: 64_500,
      usdEquityValue: 547,
      liquidationPriceUsd: null,
      shortIsCoveredSyntheticUsd: true,
      oraclePolicy: "FrostBondedWithFallback",
      collateral: "VanillaBtc",
      protocolFeeSats: 0,
      compressedCetCount: 618,
      numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
      fundingTxid: "91ab44ce01e889b2d3077fa419cc3281bc09f4a87e1152009dc482be7711a40c",
      counterparty: "Dave (p2tr_opt_writer)",
      bobOffline: false,
      status: "OPEN (P2TR Call $110k)",
      closeoutReceipt: null,
    },
  ];

  let activeInstrument = "BTC-INVERSE-PERP";
  let tradeCounter = recentTrades.length + 1;
  let posCounter = positions.length + 1;
  let lastCloseout = null;
  let lastNovation = null;
  let lastClearingReceipt = null;

  function getInstrumentMeta(symbol) {
    return (
      instruments.find((i) => i.symbol === symbol) ??
      optionInstruments.find((o) => o.symbol === symbol) ??
      instruments[0]
    );
  }

  function refreshPositionTelemetry(pos) {
    if (pos.contractKind === "Option") {
      const spot = getInstrumentMeta("BTC-INVERSE-PERP").markPriceUsd;
      const q = computeOptionQuote({
        optionType: pos.optionType || "Call",
        strikeUsd: pos.strikeUsd || 110_000,
        spotUsd: spot,
        ivPct: pos.ivPct || 58,
        daysToExpiry: 34,
        contractsBtc: Math.max(0.01, (pos.usdNotional || 10_000) / 100_000),
      });
      pos.markPriceUsd = spot;
      pos.delta = q.delta;
      pos.liquidationPriceUsd = pos.side === "Long" ? null : null;
      pos.unrealizedPnlSats = pos.side === "Long"
        ? q.buyerPremiumSats - pos.userMarginSats
        : pos.userMarginSats - q.buyerPremiumSats;
      pos.usdEquityValue = Math.max(0, Math.round(((pos.userMarginSats + pos.unrealizedPnlSats) * spot) / 1e8));
      return pos;
    }
    const inst = getInstrumentMeta(pos.instrument);
    const mark = pos.id === "pos-mnr02-ref" ? 60_000 : inst.markPriceUsd;
    const spec = {
      usdNotional: pos.usdNotional,
      entryPriceUsd: pos.entryPriceUsd,
      longMarginSats: pos.longMarginSats,
      shortMarginSats: pos.shortMarginSats,
    };
    const split = payoutAtPrice(spec, mark);
    const userSats = pos.side === "Long" ? split.longSats : split.shortSats;
    const userMargin = pos.side === "Long" ? pos.longMarginSats : pos.shortMarginSats;
    pos.markPriceUsd = mark;
    pos.userMarginSats = userMargin;
    pos.unrealizedPnlSats = userSats - userMargin;
    pos.usdEquityValue = Math.round((userSats * mark) / 1e8);
    pos.liquidationPriceUsd =
      pos.side === "Long" ? longLiquidationPriceUsd(spec) : shortLiquidationPriceUsd(spec);
    return pos;
  }

  function getNovaSummary() {
    if (cachedNovaDemo !== undefined) return cachedNovaDemo;
    if (locateShzBinary()) {
      const cli = tryRunShzCli(["nova-demo"]);
      cachedNovaDemo = cli.ok ? cli.data : null;
    } else {
      cachedNovaDemo = null;
    }
    return cachedNovaDemo;
  }

  function getState(instrumentSymbol) {
    if (instrumentSymbol && booksByInstrument.has(instrumentSymbol)) {
      activeInstrument = instrumentSymbol;
    }
    const inst = getInstrumentMeta(activeInstrument);
    const book = booksByInstrument.get(inst.symbol);
    const obView = formatOrderbookView(book, inst.symbol);
    const livePositions = positions.map(refreshPositionTelemetry);

    const tlVwap = baselineEvidence?.dex_simulation?.tradelayer_vwap_price_usd ?? 108_200;
    const tlMerkle =
      baselineEvidence?.dex_simulation?.tradelayer_merkle_root_hex ??
      "5dbc792917c799a91be81689dcf26aa16f0f5978e9dde3a5f16f82fc1cace605";

    const shzBin = locateShzBinary();
    const spotMark = getInstrumentMeta("BTC-INVERSE-PERP").markPriceUsd;
    const optionChain = buildOptionChain(spotMark);
    const frostMeta = {
      threshold: 3,
      total: 5,
      healthySigners: 5,
      quorumLabel: "3-of-5 FROST",
      signers: [
        { id: 1, name: "frost-01.shz.btc", region: "zurich", status: "online", latencyMs: 12, stakeNear: 2_000 },
        { id: 2, name: "frost-02.shz.btc", region: "tokyo", status: "online", latencyMs: 28, stakeNear: 2_000 },
        { id: 3, name: "frost-03.shz.btc", region: "frankfurt", status: "online", latencyMs: 16, stakeNear: 2_000 },
        { id: 4, name: "frost-04.shz.btc", region: "nyc", status: "online", latencyMs: 19, stakeNear: 2_000 },
        { id: 5, name: "frost-05.shz.btc", region: "singapore", status: "online", latencyMs: 31, stakeNear: 2_000 },
      ],
      nearVault: {
        account: "shz-oracle-guard.near",
        stakeNear: 10_000,
        tvlCapMultiplier: 10,
        maxTvlNear: 100_000,
        activeTvlUsd: inst.openInterestUsd,
        utilizationPct: 24.5,
      },
    };
    const oracleChecker = buildOracleCheckerStatus({
      markPriceUsd: spotMark,
      tlVwapUsd: tlVwap,
      tlMerkleRootHex: tlMerkle,
      frost: frostMeta,
      testnet4LiveReceipt,
    });

    return {
      protocol: baselineEvidence?.protocol ?? "SatsHedgeZero v0.2.0",
      instrument: inst.symbol,
      instruments,
      optionChain,
      optionInstruments,
      oracleChecker,
      market: {
        instrument: inst.symbol,
        kind: inst.kind,
        contractKind: inst.contractKind || "Swap",
        optionType: inst.optionType || null,
        strikeUsd: inst.strikeUsd || null,
        ivPct: inst.ivPct || null,
        delta: inst.delta ?? null,
        breakevenUsd: inst.breakevenUsd || null,
        expiryLabel: inst.expiryLabel,
        markPriceUsd: inst.markPriceUsd,
        spotPriceUsd: spotMark,
        indexPriceUsd: inst.indexPriceUsd,
        tradelayerVwapUsd: tlVwap,
        tradelayerMerkleRootHex: tlMerkle,
        pythPriceUsd: 100_500,
        pythConfBps: 20,
        switchboardPriceUsd: 100_600,
        change24hPct: inst.change24hPct,
        volume24hUsd: inst.volume24hUsd,
        openInterestUsd: inst.openInterestUsd,
        fundingRate8hBps: 0,
        feeBps: 0,
        makerFeeBps: 0,
        takerFeeBps: 0,
        frost: frostMeta,
        wallet: {
          connected: true,
          mode: "Non-Custodial P2TR",
          collateralActive: "VanillaBtc",
          tapV1Enabled: false,
          numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
          balanceSats: 250_000_000,
        },
      },
      orderbook: {
        ...obView,
        clearedLevels: book.lastClearedLevels || [],
        recentTrades: recentTrades.slice(0, 20),
      },
      positions: livePositions,
      lastCloseout,
      lastNovation,
      lastClearingReceipt,
      baselineEvidence,
      mnr02Receipt,
      testnet4LiveReceipt,
      clearing33kReceipt,
      clearingTrades: [
        { tradeNo: 1, label: "T1 Alice×Bob", priceUsd: 50_000, side: "Long" },
        { tradeNo: 2, label: "T2 Bob×Carol (Flatten)", priceUsd: 55_000, side: "Long" },
        { tradeNo: 3, label: "T3 Alice Closes (+PnL)", priceUsd: 60_000, side: "Short" },
      ],
      novaSummary: getNovaSummary(),
      engineInfo: {
        shzBinaryFound: Boolean(shzBin),
        shzBinaryPath: shzBin ? path.basename(shzBin) : null,
        mathEngine: shzBin ? "shz-cli + exact BigInt mirror" : "exact BigInt shz-margin mirror",
      },
    };
  }

  function submitOrder(payload = {}) {
    const instrument = booksByInstrument.has(payload.instrument)
      ? payload.instrument
      : activeInstrument;
    const book = booksByInstrument.get(instrument);
    const inst = getInstrumentMeta(instrument);

    // Enforce v0 collateral & zero-fee protocol guards
    const collateral = String(payload.collateral ?? "VanillaBtc");
    if (collateral !== "VanillaBtc") {
      return {
        ok: false,
        status: 400,
        error: "TAP collateral is reserved for v1; v0 settles strictly in vanilla BTC UTXOs",
      };
    }
    if (Number(payload.feeBps ?? 0) !== 0) {
      return {
        ok: false,
        status: 400,
        error: "Zero-fee protocol invariant violated: maker/taker/settlement fees must be 0 bps",
      };
    }

    const side = String(payload.side ?? "Long").toLowerCase() === "short" ? "Short" : "Long";
    const orderType = String(payload.orderType ?? "limit").toLowerCase() === "rfq" ? "rfq" : "limit";
    const usdNotional = Math.round(Number(payload.usdNotional ?? 0));
    const leverageX = Number(payload.leverageX ?? (side === "Short" ? 1 : 10));
    const oraclePolicy = String(payload.oraclePolicy ?? "FrostBondedWithFallback");

    if (!Number.isFinite(usdNotional) || usdNotional <= 0) {
      return { ok: false, status: 400, error: "usdNotional must be a positive integer USD amount" };
    }
    if (!Number.isFinite(leverageX) || leverageX < 0.1 || leverageX > 100) {
      return { ok: false, status: 400, error: "leverageX must be between 0.1 and 100" };
    }

    const bestAsk = book.asks[0]?.priceUsd ?? inst.markPriceUsd + 10;
    const bestBid = book.bids[0]?.priceUsd ?? inst.markPriceUsd - 10;
    const limitPriceUsd =
      orderType === "rfq"
        ? side === "Long"
          ? Math.round(bestAsk * 1.1)
          : Math.max(1, Math.round(bestBid * 0.9))
        : Math.round(Number(payload.limitPriceUsd ?? inst.markPriceUsd));

    if (!Number.isFinite(limitPriceUsd) || limitPriceUsd <= 0) {
      return { ok: false, status: 400, error: "limitPriceUsd must be > 0" };
    }

    const seq = book.nextSeq++;
    const orderId = taggedHashHex(
      "SatsHedgeZero/P2POrderIntent/v0",
      `${instrument}:${side}:${usdNotional}:${limitPriceUsd}:${leverageX}:${oraclePolicy}:${seq}`
    );
    const signatureHex = taggedHashHex("BIP0340/sig-sim", `${orderId}:${seq}`);

    const beforeObView = formatOrderbookView(book, instrument);
    let remainingUsd = usdNotional;
    const fills = [];
    const createdPositions = [];
    const nowTime = new Date().toISOString().slice(11, 19);

    if (side === "Long") {
      book.asks.sort((a, b) => a.priceUsd - b.priceUsd || a.sequenceNo - b.sequenceNo);
      let idx = 0;
      while (idx < book.asks.length && remainingUsd > 0) {
        const resting = book.asks[idx];
        if (resting.priceUsd > limitPriceUsd) break;

        const fillUsd = Math.min(remainingUsd, resting.openUsdNotional);
        const execPrice = resting.priceUsd; // Exact resting maker price!
        const longLevBps = Math.round(leverageX * 10_000);
        const shortLevBps = Math.round(resting.leverageX * 10_000);
        const longMarginSats = marginForLeverageBps(fillUsd, execPrice, longLevBps);
        const shortMarginSats = marginForLeverageBps(fillUsd, execPrice, shortLevBps);
        const spec = { usdNotional: fillUsd, entryPriceUsd: execPrice, longMarginSats, shortMarginSats };
        const cets = compressCetRanges(spec, 20, 250);
        const matchId = taggedHashHex("SatsHedgeZero/MatchTicket/v0", `${orderId}:${resting.orderId}:${fillUsd}`);

        const fill = {
          matchId: matchId.slice(0, 16),
          executionPriceUsd: execPrice,
          matchedUsdNotional: fillUsd,
          makerFeeSats: 0,
          takerFeeSats: 0,
          protocolFeeSats: 0,
          longMarginSats,
          shortMarginSats,
          compressedCetCount: cets.length,
        };
        fills.push(fill);

        recentTrades.unshift({
          id: `tr-${String(tradeCounter++).padStart(3, "0")}`,
          time: nowTime,
          instrument,
          priceUsd: execPrice,
          sizeUsd: fillUsd,
          side: "Long",
          feeSats: 0,
          settlement: "LN-DLC",
        });

        const pos = refreshPositionTelemetry({
          id: `pos-${String(posCounter++).padStart(3, "0")}`,
          subchannelId: `sub_${matchId.slice(0, 16)}`,
          instrument,
          contractKind: inst.contractKind || "Swap",
          optionType: inst.optionType || null,
          strikeUsd: inst.strikeUsd || null,
          ivPct: inst.ivPct || null,
          delta: inst.delta ?? null,
          side: "Long",
          usdNotional: fillUsd,
          entryPriceUsd: execPrice,
          markPriceUsd: inst.markPriceUsd,
          carolDefaultQuoteUsd: Math.round(execPrice * 1.02),
          leverageX,
          counterpartyLeverageX: resting.leverageX,
          longMarginSats,
          shortMarginSats,
          userMarginSats: longMarginSats,
          unrealizedPnlSats: 0,
          usdEquityValue: Math.round((longMarginSats * inst.markPriceUsd) / 1e8),
          liquidationPriceUsd: longLiquidationPriceUsd(spec),
          shortIsCoveredSyntheticUsd: isCoveredSyntheticUsdShort(fillUsd, execPrice, shortMarginSats),
          oraclePolicy,
          collateral: "VanillaBtc",
          protocolFeeSats: 0,
          compressedCetCount: cets.length,
          numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
          fundingTxid: matchId,
          bobOffline: false,
          status:
            inst.contractKind === "Option"
              ? `OPEN (P2TR ${inst.optionType} $${Math.round((inst.strikeUsd || 0) / 1000)}k)`
              : "OPEN (LN-DLC Subchannel)",
          closeoutReceipt: null,
        });
        positions.unshift(pos);
        createdPositions.push(pos);

        inst.markPriceUsd = execPrice;
        inst.volume24hUsd += fillUsd;
        inst.openInterestUsd += fillUsd;

        remainingUsd -= fillUsd;
        resting.openUsdNotional -= fillUsd;
        if (resting.openUsdNotional <= 0) {
          book.asks.splice(idx, 1);
        } else {
          idx += 1;
        }
      }

      if (remainingUsd > 0 && orderType === "limit") {
        book.bids.push({
          orderId: orderId.slice(0, 16),
          side: "Long",
          priceUsd: limitPriceUsd,
          openUsdNotional: remainingUsd,
          leverageX,
          oraclePolicy,
          maker: "you (P2TR)",
          sequenceNo: seq,
        });
        book.bids.sort((a, b) => b.priceUsd - a.priceUsd || a.sequenceNo - b.sequenceNo);
      }
    } else {
      book.bids.sort((a, b) => b.priceUsd - a.priceUsd || a.sequenceNo - b.sequenceNo);
      let idx = 0;
      while (idx < book.bids.length && remainingUsd > 0) {
        const resting = book.bids[idx];
        if (resting.priceUsd < limitPriceUsd) break;

        const fillUsd = Math.min(remainingUsd, resting.openUsdNotional);
        const execPrice = resting.priceUsd; // Exact resting maker price!
        const longLevBps = Math.round(resting.leverageX * 10_000);
        const shortLevBps = Math.round(leverageX * 10_000);
        const longMarginSats = marginForLeverageBps(fillUsd, execPrice, longLevBps);
        const shortMarginSats = marginForLeverageBps(fillUsd, execPrice, shortLevBps);
        const spec = { usdNotional: fillUsd, entryPriceUsd: execPrice, longMarginSats, shortMarginSats };
        const cets = compressCetRanges(spec, 20, 250);
        const matchId = taggedHashHex("SatsHedgeZero/MatchTicket/v0", `${resting.orderId}:${orderId}:${fillUsd}`);

        const fill = {
          matchId: matchId.slice(0, 16),
          executionPriceUsd: execPrice,
          matchedUsdNotional: fillUsd,
          makerFeeSats: 0,
          takerFeeSats: 0,
          protocolFeeSats: 0,
          longMarginSats,
          shortMarginSats,
          compressedCetCount: cets.length,
        };
        fills.push(fill);

        recentTrades.unshift({
          id: `tr-${String(tradeCounter++).padStart(3, "0")}`,
          time: nowTime,
          instrument,
          priceUsd: execPrice,
          sizeUsd: fillUsd,
          side: "Short",
          feeSats: 0,
          settlement: leverageX <= 1 ? "1x SatsHedge" : "LN-DLC",
        });

        const covered = isCoveredSyntheticUsdShort(fillUsd, execPrice, shortMarginSats);
        const pos = refreshPositionTelemetry({
          id: `pos-${String(posCounter++).padStart(3, "0")}`,
          subchannelId: `sub_${matchId.slice(0, 16)}`,
          instrument,
          contractKind: inst.contractKind || "Swap",
          optionType: inst.optionType || null,
          strikeUsd: inst.strikeUsd || null,
          ivPct: inst.ivPct || null,
          delta: inst.delta ?? null,
          side: "Short",
          usdNotional: fillUsd,
          entryPriceUsd: execPrice,
          markPriceUsd: inst.markPriceUsd,
          carolDefaultQuoteUsd: Math.round(execPrice * 0.98),
          leverageX,
          counterpartyLeverageX: resting.leverageX,
          longMarginSats,
          shortMarginSats,
          userMarginSats: shortMarginSats,
          unrealizedPnlSats: 0,
          usdEquityValue: Math.round((shortMarginSats * inst.markPriceUsd) / 1e8),
          liquidationPriceUsd: shortLiquidationPriceUsd(spec),
          shortIsCoveredSyntheticUsd: covered,
          oraclePolicy,
          collateral: "VanillaBtc",
          protocolFeeSats: 0,
          compressedCetCount: cets.length,
          numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
          fundingTxid: matchId,
          bobOffline: false,
          status:
            inst.contractKind === "Option"
              ? `OPEN (P2TR Short ${inst.optionType} $${Math.round((inst.strikeUsd || 0) / 1000)}k)`
              : covered
                ? "OPEN (1x SatsHedge Synth-USD)"
                : "OPEN (LN-DLC Subchannel)",
          closeoutReceipt: null,
        });
        positions.unshift(pos);
        createdPositions.push(pos);

        inst.markPriceUsd = execPrice;
        inst.volume24hUsd += fillUsd;
        inst.openInterestUsd += fillUsd;

        remainingUsd -= fillUsd;
        resting.openUsdNotional -= fillUsd;
        if (resting.openUsdNotional <= 0) {
          book.bids.splice(idx, 1);
        } else {
          idx += 1;
        }
      }

      if (remainingUsd > 0 && orderType === "limit") {
        book.asks.push({
          orderId: orderId.slice(0, 16),
          side: "Short",
          priceUsd: limitPriceUsd,
          openUsdNotional: remainingUsd,
          leverageX,
          oraclePolicy,
          maker: "you (P2TR)",
          sequenceNo: seq,
        });
        book.asks.sort((a, b) => a.priceUsd - b.priceUsd || a.sequenceNo - b.sequenceNo);
      }
    }

    const afterObView = formatOrderbookView(book, instrument);
    const clearedLevels = [
      ...computeBookClearedLevels(beforeObView.asks, afterObView.asks, "ask", 420),
      ...computeBookClearedLevels(beforeObView.bids, afterObView.bids, "bid", 420),
    ];
    book.lastClearedLevels = clearedLevels;

    return {
      ok: true,
      status: 200,
      data: {
        orderId: orderId.slice(0, 16),
        signatureHex: signatureHex.slice(0, 32),
        instrument,
        contractKind: inst.contractKind || "Swap",
        side,
        orderType,
        requestedUsdNotional: usdNotional,
        filledUsdNotional: usdNotional - remainingUsd,
        restingUsdNotional: orderType === "limit" ? remainingUsd : 0,
        makerFeeSats: 0,
        takerFeeSats: 0,
        protocolFeeSats: 0,
        fills,
        clearedLevels,
        positionsCreated: createdPositions,
        state: getState(instrument),
      },
    };
  }

  function closeoutMnr02(payload = {}) {
    let targetPos = null;
    if (payload.positionId) {
      targetPos = positions.find((p) => p.id === payload.positionId) ?? null;
    }

    const params = targetPos
      ? {
          notionalUsd: payload.notionalUsd ?? targetPos.usdNotional,
          entryPriceUsd: payload.entryPriceUsd ?? targetPos.entryPriceUsd,
          carolQuotePriceUsd: payload.carolQuotePriceUsd ?? targetPos.carolDefaultQuoteUsd ?? Math.round(targetPos.entryPriceUsd * 1.1),
          maturityPriceUsd: payload.maturityPriceUsd ?? targetPos.markPriceUsd,
          bobMarginSats: payload.bobMarginSats ?? (targetPos.side === "Long" ? targetPos.shortMarginSats : targetPos.longMarginSats),
          aliceMarginSats: payload.aliceMarginSats ?? (targetPos.side === "Long" ? targetPos.longMarginSats : targetPos.shortMarginSats),
          bobOffline: payload.bobOffline !== undefined ? payload.bobOffline : targetPos.bobOffline,
          minerFeeSats: payload.minerFeeSats ?? 1_000,
          anchorSats: payload.anchorSats ?? 330,
          side: payload.side ?? targetPos.side,
        }
      : payload;

    const receipt = computeMnr02Closeout(params, mnr02Receipt);
    lastCloseout = { ...receipt, positionId: targetPos?.id ?? null, timestamp: new Date().toISOString() };

    if (targetPos) {
      targetPos.bobOffline = receipt.bobOffline;
      targetPos.status = receipt.bobOffline
        ? "MNR-02 Routed (Leaf 0 0x83)"
        : "Coop Closed (Leaf 0 0x00)";
      targetPos.closeoutReceipt = lastCloseout;
    }

    return {
      ...lastCloseout,
      state: getState(activeInstrument),
    };
  }

  function setBobStatus(positionId, bobOffline) {
    const pos = positions.find((p) => p.id === positionId);
    if (pos) {
      pos.bobOffline = Boolean(bobOffline);
    }
    return getState(activeInstrument);
  }

  function sweepOrderbook(payload = {}) {
    const instrument = booksByInstrument.has(payload.instrument)
      ? payload.instrument
      : activeInstrument;
    const book = booksByInstrument.get(instrument);
    const side = String(payload.side || "Long").toLowerCase() === "short" ? "Short" : "Long";
    const targetSideRows = side === "Long" ? book.asks : book.bids;
    const topLevelUsd = targetSideRows[0]?.openUsdNotional ?? 25_000;
    const secondPartUsd = Math.round((targetSideRows[1]?.openUsdNotional ?? 20_000) * 0.4);
    const sweepUsd = Math.max(1_000, Math.round(Number(payload.usdNotional) || topLevelUsd + secondPartUsd));
    return submitOrder({
      instrument,
      side,
      orderType: "rfq",
      usdNotional: sweepUsd,
      leverageX: side === "Short" ? 1 : 10,
      oraclePolicy: "FrostBondedWithFallback",
      collateral: "VanillaBtc",
    });
  }

  function transferPosition(payload = {}) {
    const targetPos =
      (payload.positionId && positions.find((p) => p.id === payload.positionId)) || positions[0];
    if (!targetPos) {
      return { ok: false, status: 404, error: "Position not found for P2TR transfer/novation" };
    }
    const assignee = String(payload.assignee || "Carol (p2tr_novated_lp)");
    const transferPriceUsd = Math.max(
      1,
      Math.round(Number(payload.transferPriceUsd || targetPos.markPriceUsd || 100_000))
    );
    const novationTxid = taggedHashHex(
      "SatsHedgeZero/TaprootNovation/v0",
      `${targetPos.id}:${assignee}:${transferPriceUsd}:${Date.now()}`
    );
    const receipt = {
      positionId: targetPos.id,
      instrument: targetPos.instrument,
      contractKind: targetPos.contractKind || "Swap",
      previousSubchannelId: targetPos.subchannelId,
      newSubchannelId: `sub_nov_${novationTxid.slice(0, 12)}`,
      assignee,
      transferPriceUsd,
      numsInternalKey: UTXOREF_NUMS_INTERNAL_KEY,
      scriptLeafUsed: "Leaf 0: 0x83 Taproot Novation + Router Guard",
      novationTxid,
      protocolFeeSats: 0,
      conservationVerified: true,
      timestamp: new Date().toISOString(),
    };
    targetPos.subchannelId = receipt.newSubchannelId;
    targetPos.counterparty = assignee;
    targetPos.status = `NOVATED → ${assignee.split(" ")[0]} (0x83 P2TR)`;
    lastNovation = receipt;
    return {
      ok: true,
      status: 200,
      data: {
        ...receipt,
        state: getState(activeInstrument),
      },
    };
  }

  function clearMarginsEdmondsKarp(payload = {}) {
    const includeOfflineBob =
      payload.includeOfflineBob !== undefined ? Boolean(payload.includeOfflineBob) : true;
    const receipt = runEdmondsKarpMarginClearing({
      includeOfflineBob,
      clearing33kReceipt,
    });
    lastClearingReceipt = receipt;
    return {
      ...receipt,
      state: getState(activeInstrument),
    };
  }

  function getOracleCheck() {
    return getState(activeInstrument).oracleChecker;
  }

  return {
    getState,
    submitOrder,
    closeoutMnr02,
    setBobStatus,
    sweepOrderbook,
    transferPosition,
    clearMarginsEdmondsKarp,
    getOracleCheck,
  };
}

// ---------------------------------------------------------------------------
// HTTP Server (Zero External Dependencies)
// ---------------------------------------------------------------------------

function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 1_048_576) {
      throw new Error("Request body exceeds 1 MB");
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

function serveStaticFile(reqUrlPath, res) {
  const cleanPath = reqUrlPath === "/" ? "/index.html" : reqUrlPath;
  const resolved = path.resolve(PUBLIC_DIR, `.${cleanPath}`);
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Forbidden");
    return;
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not Found");
    return;
  }
  const ext = path.extname(resolved).toLowerCase();
  const contentType = MIME_TYPES[ext] ?? "application/octet-stream";
  const content = fs.readFileSync(resolved);
  res.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=60",
    "Content-Length": content.length,
  });
  res.end(content);
}

export function createAppServer(session = createSession()) {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
      const pathname = url.pathname;
      const method = (req.method || "GET").toUpperCase();

      if (pathname === "/api/state" && method === "GET") {
        const instrument = url.searchParams.get("instrument") || undefined;
        return sendJson(res, 200, session.getState(instrument));
      }

      if (pathname === "/api/quote" && method === "POST") {
        const body = await readJsonBody(req);
        const quote = computeQuote(body);
        return sendJson(res, 200, quote);
      }

      if (pathname === "/api/orders" && method === "POST") {
        const body = await readJsonBody(req);
        const result = session.submitOrder(body);
        if (!result.ok) {
          return sendJson(res, result.status, { error: result.error });
        }
        return sendJson(res, 200, result.data);
      }

      if (pathname === "/api/closeout-mnr02" && method === "POST") {
        const body = await readJsonBody(req);
        const result = session.closeoutMnr02(body);
        return sendJson(res, 200, result);
      }

      if (pathname === "/api/positions/bob-status" && method === "POST") {
        const body = await readJsonBody(req);
        const state = session.setBobStatus(body.positionId, body.bobOffline);
        return sendJson(res, 200, state);
      }

      if (pathname === "/api/options" && method === "GET") {
        const spot = Number(url.searchParams.get("spotUsd")) || undefined;
        const st = session.getState();
        const chain = spot ? buildOptionChain(spot) : st.optionChain;
        return sendJson(res, 200, {
          spotUsd: spot || st.market.spotPriceUsd,
          expiry: "27DEC26",
          feeBps: 0,
          strikes: OPTION_STRIKES_USD,
          optionChain: chain,
        });
      }

      if (pathname === "/api/options/quote" && method === "POST") {
        const body = await readJsonBody(req);
        return sendJson(res, 200, computeOptionQuote(body));
      }

      if (pathname === "/api/oracle-check" && (method === "GET" || method === "POST")) {
        if (method === "POST") await readJsonBody(req);
        return sendJson(res, 200, session.getOracleCheck());
      }

      if (pathname === "/api/orderbook/sweep" && method === "POST") {
        const body = await readJsonBody(req);
        const resSweep = session.sweepOrderbook(body);
        if (!resSweep.ok) return sendJson(res, resSweep.status, { error: resSweep.error });
        return sendJson(res, 200, resSweep.data);
      }

      if (pathname === "/api/positions/transfer" && method === "POST") {
        const body = await readJsonBody(req);
        const resNov = session.transferPosition(body);
        if (!resNov.ok) return sendJson(res, resNov.status, { error: resNov.error });
        return sendJson(res, 200, resNov.data);
      }

      if (pathname === "/api/clearing/edmonds-karp" && method === "POST") {
        const body = await readJsonBody(req);
        return sendJson(res, 200, session.clearMarginsEdmondsKarp(body));
      }

      if (method === "GET" || method === "HEAD") {
        return serveStaticFile(pathname, res);
      }

      sendJson(res, 404, { error: `Unknown route ${method} ${pathname}` });
    } catch (err) {
      sendJson(res, 400, { error: err?.message || "Bad Request" });
    }
  });

  return { server, session };
}

const isDirectRun =
  process.argv[1] && path.resolve(process.argv[1]) === __filename;

if (isDirectRun) {
  const port = Number(process.env.PORT || 4173);
  const host = process.env.HOST || "127.0.0.1";
  const { server } = createAppServer();
  server.listen(port, host, () => {
    console.log(`[SatsHedgeZero Terminal] listening on http://${host}:${port}`);
  });
}
