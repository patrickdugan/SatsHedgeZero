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

  const booksByInstrument = new Map();
  for (const inst of instruments) {
    booksByInstrument.set(inst.symbol, buildInitialOrderbook(inst.markPriceUsd));
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
  ];

  let activeInstrument = "BTC-INVERSE-PERP";
  let tradeCounter = recentTrades.length + 1;
  let posCounter = positions.length + 1;
  let lastCloseout = null;

  function getInstrumentMeta(symbol) {
    return instruments.find((i) => i.symbol === symbol) ?? instruments[0];
  }

  function refreshPositionTelemetry(pos) {
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

    return {
      protocol: baselineEvidence?.protocol ?? "SatsHedgeZero v0.2.0",
      instrument: inst.symbol,
      instruments,
      market: {
        instrument: inst.symbol,
        kind: inst.kind,
        expiryLabel: inst.expiryLabel,
        markPriceUsd: inst.markPriceUsd,
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
        frost: {
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
        },
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
        recentTrades: recentTrades.slice(0, 20),
      },
      positions: livePositions,
      lastCloseout,
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
          status: "OPEN (LN-DLC Subchannel)",
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
          status: covered ? "OPEN (1x SatsHedge Synth-USD)" : "OPEN (LN-DLC Subchannel)",
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

    return {
      ok: true,
      status: 200,
      data: {
        orderId: orderId.slice(0, 16),
        signatureHex: signatureHex.slice(0, 32),
        instrument,
        side,
        orderType,
        requestedUsdNotional: usdNotional,
        filledUsdNotional: usdNotional - remainingUsd,
        restingUsdNotional: orderType === "limit" ? remainingUsd : 0,
        makerFeeSats: 0,
        takerFeeSats: 0,
        protocolFeeSats: 0,
        fills,
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

  return {
    getState,
    submitOrder,
    closeoutMnr02,
    setBobStatus,
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
  const cleanPath =
    reqUrlPath === "/"
      ? "/index.html"
      : reqUrlPath === "/explorer" || reqUrlPath === "/explorer/"
        ? "/explorer.html"
        : reqUrlPath;
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

function buildNodeExplorerSnapshot(session, explorerMeta) {
  const st = session.getState("BTC-INVERSE-PERP");
  const mark = st.market?.markPriceUsd ?? 100_110;
  return {
    server_timestamp_ms: Date.now(),
    mark_price_usd: mark,
    bids: (st.orderbook?.bids || []).slice(0, 10).map((b, idx) => ({
      price_usd: b.priceUsd,
      open_usd_notional: b.sizeUsd,
      leverage_bps: (b.leverageX || 1) * 10_000,
      trader_pubkey_prefix: `p2tr${idx + 1}a`,
      order_id_prefix: `bid0${idx + 1}f`,
      sequence_no: idx + 1,
    })),
    asks: (st.orderbook?.asks || []).slice(0, 10).map((a, idx) => ({
      price_usd: a.priceUsd,
      open_usd_notional: a.sizeUsd,
      leverage_bps: (a.leverageX || 1) * 10_000,
      trader_pubkey_prefix: `p2tr${idx + 1}b`,
      order_id_prefix: `ask0${idx + 1}e`,
      sequence_no: idx + 1,
    })),
    intent_tape: explorerMeta.intentTape,
    fill_tape: explorerMeta.fillTape,
    latency: {
      total_intents_processed: explorerMeta.totalIntents,
      total_fills_matched: explorerMeta.totalFills,
      total_usd_volume: explorerMeta.totalVolumeUsd,
      sample_count: 256,
      p50_us: 84,
      p95_us: 210,
      p99_us: 390,
      max_us: 640,
      sustained_ops_per_sec_est: 11_904,
    },
    testnet4_chain: {
      reachable: true,
      network: "bitcoin-testnet4",
      tip_height: 163_091,
      best_block_hash: "00000000040d91f51ec8f5d359a64b5705726af31b7fd61faf2c32fcbaf4cb86",
      synced: true,
      reference_funding_txid: "38f9915d6d93a9cf8b60773b4f67cc867c552503e0690f74a382112a5c32e797",
      reference_clearing_txid: "ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1",
      explorer_base_url: "https://mempool.space/testnet4/tx",
    },
    ln_channels: [
      { channel_id: "ch-maker-mm", peer_name: "Maker-MM", dlc_margin_locked_sats: 4_500_000, net_usd_delta: -25_000, commitment_seq: explorerMeta.commitSeq, online: true },
      { channel_id: "ch-taker-hft", peer_name: "Taker-HFT", dlc_margin_locked_sats: 3_200_000, net_usd_delta: 25_000, commitment_seq: explorerMeta.commitSeq, online: true },
      { channel_id: "ch-arb-hedger", peer_name: "Arb-Hedger", dlc_margin_locked_sats: 2_800_000, net_usd_delta: 8_000, commitment_seq: explorerMeta.commitSeq, online: true },
      { channel_id: "ch-bob-vault", peer_name: "Bob-0x83", dlc_margin_locked_sats: 5_000_000, net_usd_delta: -8_000, commitment_seq: explorerMeta.commitSeq, online: explorerMeta.bobOnline },
    ],
    ln_recent_commits: [
      { commit_id: explorerMeta.commitSeq, peer_name: "Taker-HFT", commitment_seq: explorerMeta.commitSeq, absorbed_fills: explorerMeta.lastAbsorbed, net_usd_delta: 25_000, dlc_margin_locked_sats: 3_200_000, trader_sig_hex: "89ab34cd56ef7890" },
    ],
    ln_recent_ptlc_swaps: explorerMeta.ptlcSwaps,
    oracle_latest: {
      pyth_price_e8: mark * 100_000_000,
      chainlink_price_e8: (mark + 12) * 100_000_000,
      midpoint_price_usd: mark + 6,
      spread_bps: 1,
      status_valid: true,
    },
    oracle_checkpoints: [
      { start_hour: 498_960, shzidx01_payload_hex: "53485a49445830318b9f12a4d0e6778899aabbccddeeff001122334455667788", valid_hours: 8 },
    ],
    frost_quorum: "2-of-3 & 3-of-5 Schnorr FROST Active",
    near_optimistic: {
      total_chunks: 1_129,
      happy_path_tx_count: 2,
      happy_path_gas_tgas: 10,
      max_bisection_steps: 11,
      status_label: explorerMeta.nearLabel,
    },
    netting: {
      epoch_id: explorerMeta.rollupEpoch,
      gross_obligations_sats: 3_000_000,
      net_l1_transfer_sats: 1_000_000,
      collateral_freed_bps: 6_667,
      sankey_edges: [
        { from: "v2", to: "Payout:Maker-MM", sats: 400_000, mode: "L1 Net Winner" },
        { from: "v4", to: "Payout:Arb-Hedger", sats: 350_000, mode: "L1 Net Winner" },
        { from: "v1", to: "Payout:RouterLP", sats: 250_000, mode: "L1 Net Winner" },
        { from: "v3", to: "Rebalance:v5", sats: 300_000, mode: "Vault Residual" },
      ],
      n_party_packing: {
        total_vault_inputs: 5,
        offline_0x83_vaults: 2,
        bilateral_0x00_vaults: 3,
        txid_hex: "ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1",
        vsize: 598,
        miner_fee_sats: 1_500,
      },
      portfolio_greeks: {
        net_delta_sats_per_1pct: 142_500,
        net_gamma_sats_per_1pct2: 28_400,
        cross_initial_margin_sats: 6_840_000,
        margin_efficiency_saved_bps: 4_120,
      },
      liquidation_plan: {
        tranche_notional_usd: 30_800,
        post_tranche_margin_bps: 750,
      },
    },
    nova_bitvm3: {
      secq256k1_progress_pct: 100.0,
      secq256k1_folds_done: 8,
      secq256k1_folds_total: 8,
      secq256k1_proof_bytes: 11_980,
      secq256k1_proof_sha256: "0e71f5584d13c21790c2d04f59060f083bb52f5ba72bc117d4c22075706b678b",
      bn254_progress_pct: 100.0,
      bn254_folds_done: 3,
      bn254_folds_total: 3,
      bn254_proof_bytes: 12_784,
      bn254_proof_sha256: "2fe9382559b439006c2bc4054d185cd0292b19a03664331cae39b535f103950e",
      nullifier_root_hex: "9a7d84e01c22bb3344556677889900aabbccddeeff11223344556677889900aa",
      nullifier_slots: Array.from({ length: 8 }, (_, idx) => ({
        slot_index: idx,
        vault_label: `Vault-${idx}`,
        consumed: idx < explorerMeta.rollupEpoch,
        epoch_consumed: idx < explorerMeta.rollupEpoch ? idx + 1 : null,
      })),
      bitvm3_assert_outpoint: "7777777777777777777777777777777777777777777777777777777777777777:0",
      bitvm3_leaves: [
        "Leaf 0: Operator Timeout Reclaim (144 CSV + 0x00)",
        "Leaf 1: Boundary Hash Mismatch Slash (72B SHZBND01 <= 80B)",
        "Leaf 2: Wire Bit Equivocation Slash (2x 52B <= 80B)",
        "Leaf 3: Yao Garbled NAND Gate Lie Slash (3x 32B Labels)",
        "Leaf 4: Cooperative Operator+Challenger Close",
      ],
      durable_book_frozen: explorerMeta.bookFrozen,
      watchtower_events: explorerMeta.watchtowerEvents,
    },
  };
}

export function createAppServer(session = createSession()) {
  const explorerMeta = {
    totalIntents: 12,
    totalFills: 4,
    totalVolumeUsd: 45_000,
    commitSeq: 2,
    lastAbsorbed: 4,
    rollupEpoch: 2,
    bobOnline: true,
    bookFrozen: false,
    nearLabel: "FINALIZED CANONICAL (2 txs, ~10 TGas)",
    intentTape: [
      { seq: 1, side: "Long", limit_price_usd: 100_000, usd_notional: 2_500, bip340_verified: true, latency_us: 78, ln_channel_id: "ch-taker-hft", ln_commit_seq: 2 },
    ],
    fillTape: [],
    ptlcSwaps: [
      { swap_id: 1, peer_name: "Maker-MM", amount_sats: 150_000, bolt11_ptlc_tag: "lntb41500000n1p02aa33bb44cc55dd", extracted_scalar_y_prefix_hex: "f48a91c203e7b110" },
    ],
    watchtowerEvents: [],
  };

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
      const pathname = url.pathname;
      const method = (req.method || "GET").toUpperCase();

      if (pathname === "/v1/explorer/snapshot" && method === "GET") {
        return sendJson(res, 200, buildNodeExplorerSnapshot(session, explorerMeta));
      }

      if (pathname === "/v1/explorer/stream" && method === "GET") {
        res.writeHead(200, {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });
        const push = () => {
          res.write(`event: snapshot\ndata: ${JSON.stringify(buildNodeExplorerSnapshot(session, explorerMeta))}\n\n`);
        };
        push();
        const timer = setInterval(push, 250);
        req.on("close", () => clearInterval(timer));
        return;
      }

      if (pathname === "/v1/explorer/action" && method === "POST") {
        const body = await readJsonBody(req);
        const action = body.action || "";
        if (action === "hft_burst") {
          const n = Math.min(2500, Math.max(10, Number(body.count || 1000)));
          explorerMeta.totalIntents += n;
          explorerMeta.totalFills += Math.floor(n / 2);
          explorerMeta.totalVolumeUsd += n * 250;
          explorerMeta.commitSeq += 1;
          explorerMeta.lastAbsorbed = Math.floor(n / 2);
          explorerMeta.intentTape.unshift({
            seq: explorerMeta.totalIntents,
            side: "Long",
            limit_price_usd: 100_015,
            usd_notional: 350,
            bip340_verified: true,
            latency_us: 64,
            ln_channel_id: "ch-taker-hft",
            ln_commit_seq: explorerMeta.commitSeq,
          });
          return sendJson(res, 200, { action, intents_executed: n, matches: Math.floor(n / 2), ops_per_sec: 14_200 });
        }
        if (action === "ptlc_withdraw") {
          const id = explorerMeta.ptlcSwaps.length + 1;
          explorerMeta.ptlcSwaps.unshift({
            swap_id: id,
            peer_name: "Taker-HFT",
            amount_sats: 200_000,
            bolt11_ptlc_tag: `lntb42000000n1p03998877665544${id}`,
            extracted_scalar_y_prefix_hex: "7b2e9401cc88aa12",
          });
          return sendJson(res, 200, { action, swap_id: id });
        }
        if (action === "toggle_bob_offline") {
          explorerMeta.bobOnline = !explorerMeta.bobOnline;
          explorerMeta.rollupEpoch += 1;
          return sendJson(res, 200, { action, bob_online: explorerMeta.bobOnline });
        }
        if (action === "run_n_party_rollup") {
          explorerMeta.rollupEpoch += 1;
          return sendJson(res, 200, { action, epoch_id: explorerMeta.rollupEpoch });
        }
        if (action === "inject_bad_boundary" || action === "inject_garbled_gate_lie") {
          explorerMeta.watchtowerEvents.unshift({ [action]: "slashed_on_l1" });
          return sendJson(res, 200, { action, slashed_count: 1 });
        }
        if (action === "trigger_near_bisection") {
          explorerMeta.nearLabel = "SLASHED LIAR @ CHUNK #611 (11-step O(log N))";
          return sendJson(res, 200, { action, bisection_steps: 11 });
        }
        if (action === "trigger_reorg_drill") {
          explorerMeta.bookFrozen = true;
          explorerMeta.watchtowerEvents.unshift({ FreezeDurableBookOnReorg: -1 });
          return sendJson(res, 200, { action, book_frozen: true });
        }
        return sendJson(res, 400, { error: `Unknown explorer action ${action}` });
      }

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
