// SatsHedgeZero OG BitcoinWisdom + Deribit Pro Derivatives Terminal — Shell Controller & State Bus
import { OrderBookLevelTracker, annotateOrderBookLadder } from "./bitcorn/orderbook.js";

const fmtUsd = (n) =>
  typeof n === "number" && Number.isFinite(n)
    ? "$" + Math.round(n).toLocaleString("en-US")
    : "—";

const fmtCompactUsd = (n) => {
  if (!Number.isFinite(n)) return "—";
  if (n >= 1e9) return `$${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(1)}k`;
  return fmtUsd(n);
};

const fmtSats = (n) =>
  typeof n === "number" && Number.isFinite(n)
    ? Math.round(n).toLocaleString("en-US")
    : "—";

const fmtBtc = (sats) => (Number(sats || 0) / 1e8).toFixed(4);

const obLevelTracker = new OrderBookLevelTracker({ ttlMs: 420 });
let obDecayTimer = null;

// Ticket local form state
const ticket = {
  side: "Short",
  orderType: "limit",
  usdNotional: 10_000,
  limitPriceUsd: 100_000,
  leverageX: 1,
  oraclePolicy: "FrostBondedWithFallback",
  collateral: "VanillaBtc",
  limitPriceTouched: false,
};

let optionsChainOpen = false;
let oracleDrawerOpen = false;

// Shared state contract read by /charts.js and /workbench.js
window.SHZ_STATE = {
  instrument: "BTC-INVERSE-PERP",
  instruments: [],
  optionChain: [],
  optionInstruments: [],
  oracleChecker: null,
  activeOption: null,
  market: null,
  quote: null,
  optionQuote: null,
  positions: [],
  orderbook: null,
  lastCloseout: null,
  lastNovation: null,
  lastClearingReceipt: null,
  baselineEvidence: null,
  mnr02Receipt: null,
  novaSummary: null,
  chartMode: "candles",
  engineInfo: null,
};

function emitState() {
  window.dispatchEvent(
    new CustomEvent("shz:state", {
      detail: window.SHZ_STATE,
    })
  );
}

// ---------------------------------------------------------------------------
// API Methods (exposed on window.SHZ_API)
// ---------------------------------------------------------------------------

async function requestQuote(overrides = {}) {
  const mkt = window.SHZ_STATE.market;
  const side = overrides.side ?? ticket.side;
  const usdNotional = Math.max(1, Math.round(Number(overrides.usdNotional ?? ticket.usdNotional)));

  if (mkt?.contractKind === "Option") {
    const spotUsd = mkt.spotPriceUsd ?? 100_000;
    const contractsBtc = Math.max(0.01, usdNotional / spotUsd);
    const optRes = await fetch("/api/options/quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        optionType: mkt.optionType || "Call",
        strikeUsd: mkt.strikeUsd || 110_000,
        spotUsd,
        ivPct: mkt.ivPct || 58,
        daysToExpiry: 34,
        contractsBtc,
      }),
    });
    if (optRes.ok) {
      const oq = await optRes.json();
      window.SHZ_STATE.optionQuote = oq;
      window.SHZ_STATE.activeOption = oq;
    }
  } else {
    window.SHZ_STATE.optionQuote = null;
    window.SHZ_STATE.activeOption = null;
  }

  const entryPriceUsd = Math.max(
    1,
    Math.round(
      Number(
        overrides.entryPriceUsd ??
          (mkt?.contractKind === "Option"
            ? mkt.spotPriceUsd ?? 100_000
            : ticket.orderType === "rfq"
              ? mkt?.markPriceUsd ?? ticket.limitPriceUsd
              : ticket.limitPriceUsd)
      )
    )
  );
  const lev = Number(overrides.leverageX ?? ticket.leverageX);
  const longLevX = overrides.longLevX ?? (side === "Long" ? lev : 10);
  const shortLevX = overrides.shortLevX ?? (side === "Short" ? lev : 1);

  const res = await fetch("/api/quote", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      side,
      usdNotional,
      entryPriceUsd,
      longLevX,
      shortLevX,
    }),
  });
  if (!res.ok) {
    throw new Error(`Quote request failed (${res.status})`);
  }
  const quote = await res.json();
  window.SHZ_STATE.quote = quote;
  renderQuoteSummary();
  emitState();
  return quote;
}

async function refreshState(instrument) {
  const sym = instrument ?? window.SHZ_STATE.instrument ?? "BTC-INVERSE-PERP";
  if (sym !== window.SHZ_STATE.instrument) {
    obLevelTracker.reset();
    ticket.limitPriceTouched = false;
  }
  const res = await fetch(`/api/state?instrument=${encodeURIComponent(sym)}`);
  if (!res.ok) {
    throw new Error(`State fetch failed (${res.status})`);
  }
  const data = await res.json();
  Object.assign(window.SHZ_STATE, data);

  if (!ticket.limitPriceTouched && data.market?.markPriceUsd) {
    ticket.limitPriceUsd = data.market.markPriceUsd;
    const priceInput = document.getElementById("input-limit-price");
    if (priceInput) priceInput.value = String(ticket.limitPriceUsd);
  }

  renderHeader();
  renderOracleChecker();
  renderOptionChain();
  renderOrderbook();
  renderFallbackWorkbenchIfNeeded();

  await requestQuote();
  return window.SHZ_STATE;
}

async function triggerMnr02Closeout(payload = {}) {
  const res = await fetch("/api/closeout-mnr02", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Closeout failed (${res.status})`);
  }
  if (data.state) {
    Object.assign(window.SHZ_STATE, data.state);
  }
  window.SHZ_STATE.lastCloseout = data;
  renderHeader();
  renderOrderbook();
  renderFallbackWorkbenchIfNeeded();
  emitState();
  return data;
}

async function transferPosition(payload = {}) {
  const res = await fetch("/api/positions/transfer", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Position transfer failed (${res.status})`);
  }
  if (data.state) {
    Object.assign(window.SHZ_STATE, data.state);
  }
  window.SHZ_STATE.lastNovation = data;
  renderHeader();
  renderFallbackWorkbenchIfNeeded();
  emitState();
  return data;
}

async function runEdmondsKarpClearing(payload = {}) {
  const res = await fetch("/api/clearing/edmonds-karp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Clearing failed (${res.status})`);
  }
  if (data.state) {
    Object.assign(window.SHZ_STATE, data.state);
  }
  window.SHZ_STATE.lastClearingReceipt = data;
  renderHeader();
  renderFallbackWorkbenchIfNeeded();
  emitState();
  return data;
}

async function sweepOrderbook(payload = {}) {
  const res = await fetch("/api/orderbook/sweep", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      instrument: window.SHZ_STATE.instrument,
      side: ticket.side,
      ...payload,
    }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Sweep failed (${res.status})`);
  }
  if (data.state) {
    Object.assign(window.SHZ_STATE, data.state);
  }
  if (Array.isArray(data.clearedLevels) && data.clearedLevels.length) {
    obLevelTracker.injectCleared(data.clearedLevels, Date.now());
    window.SHZ_CHARTS?.ingestClearedLevels?.(data.clearedLevels);
  }
  renderHeader();
  renderOrderbook();
  renderFallbackWorkbenchIfNeeded();
  await requestQuote();
  return data;
}

async function verifyOracles() {
  const res = await fetch("/api/oracle-check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ verifyAll: true }),
  });
  if (!res.ok) throw new Error(`Oracle check failed (${res.status})`);
  const check = await res.json();
  window.SHZ_STATE.oracleChecker = check;
  oracleDrawerOpen = true;
  renderOracleChecker();
  emitState();
  return check;
}

async function toggleBobStatus(positionId, bobOffline) {
  const res = await fetch("/api/positions/bob-status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ positionId, bobOffline }),
  });
  if (!res.ok) throw new Error(`Failed updating Bob status (${res.status})`);
  const data = await res.json();
  Object.assign(window.SHZ_STATE, data);
  renderFallbackWorkbenchIfNeeded();
  emitState();
  return window.SHZ_STATE;
}

function syncViewTabs() {
  document.querySelectorAll("[data-chart-mode]").forEach((btn) => {
    const active = !optionsChainOpen && btn.getAttribute("data-chart-mode") === window.SHZ_STATE.chartMode;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  const optTab = document.getElementById("btn-chart-options");
  if (optTab) {
    optTab.classList.toggle("is-active", optionsChainOpen);
    optTab.setAttribute("aria-selected", optionsChainOpen ? "true" : "false");
  }
  const optPanel = document.getElementById("shz-options-chain-panel");
  if (optPanel) optPanel.hidden = !optionsChainOpen;

  document.getElementById("btn-desk-swaps")?.classList.toggle("is-active", !optionsChainOpen && !oracleDrawerOpen);
  document.getElementById("btn-desk-options")?.classList.toggle("is-active", optionsChainOpen);
  document.getElementById("btn-desk-oracle")?.classList.toggle("is-active", oracleDrawerOpen);
}

function setChartMode(mode) {
  optionsChainOpen = false;
  const normalized = mode === "payoff" ? "payoff" : "candles";
  window.SHZ_STATE.chartMode = normalized;
  syncViewTabs();
  emitState();
}

function toggleOptionsChain(open) {
  optionsChainOpen = open !== undefined ? Boolean(open) : !optionsChainOpen;
  syncViewTabs();
  renderOptionChain();
}

function toggleOracleDrawer(open) {
  oracleDrawerOpen = open !== undefined ? Boolean(open) : !oracleDrawerOpen;
  syncViewTabs();
  renderOracleChecker();
}

async function submitOrder(payload) {
  const res = await fetch("/api/orders", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Order rejected (${res.status})`);
  }
  if (data.state) {
    Object.assign(window.SHZ_STATE, data.state);
  }
  if (Array.isArray(data.clearedLevels) && data.clearedLevels.length) {
    obLevelTracker.injectCleared(data.clearedLevels, Date.now());
    window.SHZ_CHARTS?.ingestClearedLevels?.(data.clearedLevels);
  }
  renderHeader();
  renderOrderbook();
  renderFallbackWorkbenchIfNeeded();
  await requestQuote();
  return data;
}

window.SHZ_API = {
  refreshState,
  triggerMnr02Closeout,
  transferPosition,
  runEdmondsKarpClearing,
  sweepOrderbook,
  verifyOracles,
  setChartMode,
  toggleOptionsChain,
  toggleOracleDrawer,
  toggleBobStatus,
  requestQuote,
  submitOrder,
};

// ---------------------------------------------------------------------------
// Renderers (Header, Oracle Checker, Options Chain, Orderbook, Ticket)
// ---------------------------------------------------------------------------

function renderHeader() {
  const { market, instrument } = window.SHZ_STATE;
  if (!market) return;

  const sel = document.getElementById("shz-instrument-select");
  if (sel && sel.value !== instrument) sel.value = instrument;

  const badgeInst = document.getElementById("ticket-instrument-badge");
  if (badgeInst) badgeInst.textContent = instrument;

  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };

  setText(
    "stat-mark-price",
    market.contractKind === "Option"
      ? `${fmtUsd(market.markPriceUsd)} (Spot ${fmtUsd(market.spotPriceUsd)})`
      : fmtUsd(market.markPriceUsd)
  );
  setText("stat-tl-vwap", fmtUsd(market.tradelayerVwapUsd));

  const pythEl = document.getElementById("stat-pyth-relay");
  if (pythEl) {
    pythEl.innerHTML = `${fmtUsd(market.pythPriceUsd)} <small class="muted">±${market.pythConfBps}bps</small>`;
  }

  setText("stat-vol-24h", fmtCompactUsd(market.volume24hUsd));
  setText("stat-oi", fmtCompactUsd(market.openInterestUsd));

  const frostEl = document.getElementById("badge-frost");
  if (frostEl && market.frost) {
    frostEl.innerHTML = `<span class="dot dot-green"></span>${market.frost.threshold}-of-${market.frost.total} FROST (${market.frost.healthySigners}/${market.frost.total})`;
  }

  if (market.wallet) {
    setText("wallet-balance", `${fmtBtc(market.wallet.balanceSats)} BTC`);
  }
}

function renderOracleChecker() {
  const oc = window.SHZ_STATE.oracleChecker;
  if (!oc) return;
  const setEl = (id, txt) => {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
  };
  setEl(
    "oc-pyth",
    `● PYTH-LAZER Ed25519 #${oc.pythPro.feedId}: ${fmtUsd(oc.pythPro.priceUsd)} ±${oc.pythPro.confBps}bps (${oc.pythPro.publishLatencyMs}ms)`
  );
  setEl(
    "oc-tl",
    `● TL ${oc.tradelayerVwap.txType} VWAP ${fmtUsd(oc.tradelayerVwap.vwapPriceUsd)} · MERKLE ${oc.tradelayerVwap.merkleRootHex.slice(0, 8)}…${oc.tradelayerVwap.merkleRootHex.slice(-4)}`
  );
  setEl(
    "oc-frost",
    `● ${oc.frostQuorum.quorumLabel}: ${oc.frostQuorum.healthySigners}/${oc.frostQuorum.total} SCHNORR READY`
  );
  setEl(
    "oc-near",
    `● NEAR ${oc.nearGateways.fraudGuard.bondedStakeNear.toLocaleString("en-US")} BOND · IPA ${oc.nearGateways.transparentIpa.gasUsedTGas} TGas · GROTH16 ${oc.nearGateways.groth16Gateway.statementBytes}B`
  );

  const drawer = document.getElementById("shz-oracle-drawer");
  if (!drawer) return;
  drawer.hidden = !oracleDrawerOpen;
  if (!oracleDrawerOpen) return;

  drawer.innerHTML = `
    <div class="shz-oc-card">
      <div class="shz-oc-card-hd"><span>1. PYTH PRO (${oc.pythPro.channel})</span><span class="is-long">Ed25519 OK</span></div>
      <div class="shz-oc-kv"><span>Feed / Price</span><strong>#${oc.pythPro.feedId} · ${fmtUsd(oc.pythPro.priceUsd)} ±${oc.pythPro.confBps}bps</strong></div>
      <div class="shz-oc-kv"><span>Latency / Digest</span><strong>${oc.pythPro.publishLatencyMs}ms · ${oc.pythPro.payloadSha256Hex.slice(0, 12)}…</strong></div>
    </div>
    <div class="shz-oc-card">
      <div class="shz-oc-card-hd"><span>2. TRADELAYER L1 VWAP</span><span class="is-long">MERKLE OK</span></div>
      <div class="shz-oc-kv"><span>Block / VWAP</span><strong>#${oc.tradelayerVwap.anchorBlockHeight} · ${fmtUsd(oc.tradelayerVwap.vwapPriceUsd)}</strong></div>
      <div class="shz-oc-kv"><span>tx14 Root</span><strong>${oc.tradelayerVwap.merkleRootHex.slice(0, 14)}…</strong></div>
    </div>
    <div class="shz-oc-card">
      <div class="shz-oc-card-hd"><span>3. FROST 3-OF-5 QUORUM</span><span class="is-long">${oc.frostQuorum.healthySigners}/${oc.frostQuorum.total} ONLINE</span></div>
      <div class="shz-oc-kv"><span>NUMS P2TR Key</span><strong>${oc.frostQuorum.numsInternalKeyHex.slice(0, 14)}…</strong></div>
      <div class="shz-oc-kv"><span>Adaptor Nonces</span><strong>READY (0 bps fee)</strong></div>
    </div>
    <div class="shz-oc-card">
      <div class="shz-oc-card-hd"><span>4. NEAR IPA &amp; GROTH16 GATEWAY</span><span class="is-long">21.69 TGas</span></div>
      <div class="shz-oc-kv"><span>Transparent IPA</span><strong>${oc.nearGateways.transparentIpa.gasUsedTGas} TGas · 0 Trusted Setup</strong></div>
      <div class="shz-oc-kv"><span>Groth16 / Guard</span><strong>${oc.nearGateways.groth16Gateway.statementBytes}B · ${oc.nearGateways.fraudGuard.contractId}</strong></div>
    </div>
  `;
}

function renderOptionChain() {
  const panel = document.getElementById("shz-options-chain-panel");
  if (!panel) return;
  const chain = window.SHZ_STATE.optionChain || [];
  const activeSym = window.SHZ_STATE.instrument;
  const spot = window.SHZ_STATE.market?.spotPriceUsd ?? 100_000;

  if (!chain.length) {
    panel.innerHTML = `<div class="shz-opt-banner">Loading 27DEC26 European Vanilla Options Chain…</div>`;
    return;
  }

  const rowsHtml = chain
    .map((row) => {
      const c = row.call;
      const p = row.put;
      const cSel = activeSym === c.symbol ? "is-selected" : "";
      const pSel = activeSym === p.symbol ? "is-selected" : "";
      return `
        <tr>
          <td class="shz-opt-leg ${cSel} align-right muted" data-opt-symbol="${c.symbol}">${c.openInterestBtc.toFixed(1)}</td>
          <td class="shz-opt-leg ${cSel} align-right" data-opt-symbol="${c.symbol}">${c.ivPct.toFixed(1)}%</td>
          <td class="shz-opt-leg ${cSel} align-right is-long" data-opt-symbol="${c.symbol}">+${c.delta.toFixed(2)}</td>
          <td class="shz-opt-leg ${cSel} align-right is-long" data-opt-symbol="${c.symbol}">${c.bidBtc.toFixed(4)}</td>
          <td class="shz-opt-leg ${cSel} align-right" data-opt-symbol="${c.symbol}"><strong>${c.markBtc.toFixed(4)}</strong> <small class="muted">(${fmtUsd(c.markUsd)})</small></td>
          <td class="shz-opt-leg ${cSel} align-right is-short" data-opt-symbol="${c.symbol}">${c.askBtc.toFixed(4)}</td>
          <td class="shz-opt-strike-cell">$${row.strikeUsd.toLocaleString("en-US")}</td>
          <td class="shz-opt-leg ${pSel} align-right is-long" data-opt-symbol="${p.symbol}">${p.bidBtc.toFixed(4)}</td>
          <td class="shz-opt-leg ${pSel} align-right" data-opt-symbol="${p.symbol}"><strong>${p.markBtc.toFixed(4)}</strong> <small class="muted">(${fmtUsd(p.markUsd)})</small></td>
          <td class="shz-opt-leg ${pSel} align-right is-short" data-opt-symbol="${p.symbol}">${p.askBtc.toFixed(4)}</td>
          <td class="shz-opt-leg ${pSel} align-right is-short" data-opt-symbol="${p.symbol}">${p.delta.toFixed(2)}</td>
          <td class="shz-opt-leg ${pSel} align-right" data-opt-symbol="${p.symbol}">${p.ivPct.toFixed(1)}%</td>
          <td class="shz-opt-leg ${pSel} align-right muted" data-opt-symbol="${p.symbol}">${p.openInterestBtc.toFixed(1)}</td>
        </tr>
      `;
    })
    .join("");

  panel.innerHTML = `
    <div class="shz-opt-banner">
      <span><strong class="is-amber">BTC-27DEC26 EUROPEAN VANILLA OPTIONS</strong> · Underlying Spot ${fmtUsd(spot)} · P2TR NUMS Covered Settlement · 0.00% Fee</span>
      <span>Click any Call / Put strike to load P2TR Orderbook &amp; Ticket</span>
    </div>
    <table class="shz-opt-table">
      <thead>
        <tr>
          <th colspan="6" style="text-align:center; color:#66cc66;">CALLS (BTC-SETTLED P2TR)</th>
          <th style="text-align:center; color:#ff9900;">STRIKE</th>
          <th colspan="6" style="text-align:center; color:#dd4444;">PUTS (BTC-SETTLED P2TR)</th>
        </tr>
        <tr>
          <th class="align-right">OI (BTC)</th>
          <th class="align-right">IV</th>
          <th class="align-right">Delta</th>
          <th class="align-right">Bid (BTC)</th>
          <th class="align-right">Mark</th>
          <th class="align-right">Ask (BTC)</th>
          <th style="text-align:center;">USD</th>
          <th class="align-right">Bid (BTC)</th>
          <th class="align-right">Mark</th>
          <th class="align-right">Ask (BTC)</th>
          <th class="align-right">Delta</th>
          <th class="align-right">IV</th>
          <th class="align-right">OI (BTC)</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    </table>
  `;
}

function renderOrderbook() {
  const { orderbook, market } = window.SHZ_STATE;
  if (!orderbook) return;

  const asksEl = document.getElementById("ob-asks");
  const bidsEl = document.getElementById("ob-bids");
  const midEl = document.getElementById("ob-mid-price");
  const spreadEl = document.getElementById("ob-spread-info");
  const tradesEl = document.getElementById("recent-trades-list");

  const now = Date.now();
  const normalizedBook = {
    bids: orderbook.bids.map((r) => [r.priceUsd, r.sizeUsd]),
    asks: orderbook.asks.map((r) => [r.priceUsd, r.sizeUsd]),
    clearedLevels: orderbook.clearedLevels || [],
  };
  const { activeCleared, activeWalls } = obLevelTracker.observe(normalizedBook, now);

  const asksDecorated = annotateOrderBookLadder(normalizedBook.asks.slice(0, 8), "ask", activeCleared, activeWalls, 8).reverse();
  const bidsDecorated = annotateOrderBookLadder(normalizedBook.bids.slice(0, 8), "bid", activeCleared, activeWalls, 8);

  const renderSideHtml = (rows, sideCls) =>
    rows
      .map((item) => {
        const btcVal = item.price > 0 ? item.size / item.price : 0;
        const modCls = item.status !== "normal" ? ` shz-ob-row--${item.status}` : "";
        const ghostStyle = item.ghostPct > 0 ? `--ghost-width:${item.ghostPct.toFixed(1)}%;` : "--ghost-width:0%;";
        return `
      <div class="shz-ob-row ${sideCls}${modCls}" data-ob-price="${item.price}" data-level-status="${item.status}" style="${ghostStyle}" title="Click to populate Limit Price $${item.price.toLocaleString("en-US")}">
        <span class="depth-bar" style="width:${Math.min(100, item.depthPct).toFixed(1)}%"></span>
        <span class="ob-price">${item.price.toLocaleString("en-US")}</span>
        <span class="ob-size align-right">${item.status === "wiped" ? "0" : Math.round(item.size).toLocaleString("en-US")}</span>
        <span class="ob-btc align-right">${btcVal.toFixed(4)}</span>
        <span class="ob-total align-right">${fmtCompactUsd(item.cumulative)}</span>
      </div>`;
      })
      .join("");

  if (asksEl) asksEl.innerHTML = renderSideHtml(asksDecorated, "is-ask");
  if (bidsEl) bidsEl.innerHTML = renderSideHtml(bidsDecorated, "is-bid");

  if ((activeCleared.length || activeWalls.length) && obDecayTimer === null) {
    obDecayTimer = setTimeout(() => {
      obDecayTimer = null;
      renderOrderbook();
    }, 435);
  }

  if (midEl) midEl.textContent = fmtUsd(market?.markPriceUsd ?? orderbook.bestBidUsd);
  if (spreadEl) {
    spreadEl.textContent = `Spread $${orderbook.spreadUsd.toLocaleString("en-US")} (${orderbook.spreadBps} bps) · 0 fee`;
  }

  if (tradesEl && Array.isArray(orderbook.recentTrades)) {
    tradesEl.innerHTML = orderbook.recentTrades
      .slice(0, 12)
      .map(
        (t) => `
      <div class="shz-trade-row">
        <span class="${t.side === "Long" ? "is-long" : "is-short"}">${t.priceUsd.toLocaleString("en-US")}</span>
        <span class="align-right">${t.sizeUsd.toLocaleString("en-US")}</span>
        <span class="align-right muted">${t.settlement}</span>
        <span class="align-right muted">${t.time}</span>
      </div>`
      )
      .join("");
  }
}

function renderQuoteSummary() {
  const q = window.SHZ_STATE.quote;
  const oq = window.SHZ_STATE.optionQuote;
  const mkt = window.SHZ_STATE.market;
  if (!q) return;

  const isOption = mkt?.contractKind === "Option" && Boolean(oq);
  const optBanner = document.getElementById("ticket-option-banner");
  if (optBanner) {
    optBanner.hidden = !isOption;
    if (isOption) {
      optBanner.innerHTML = `<strong>${oq.optionType.toUpperCase()} $${oq.strikeUsd.toLocaleString("en-US")}</strong> · IV ${oq.ivPct}% · Δ ${oq.delta} · Mark ${oq.markBtc} BTC (${fmtUsd(oq.markUsd)}) · BE ${fmtUsd(oq.breakevenUsd)}`;
    }
  }

  const isShort = ticket.side === "Short";
  const isSatsHedge = !isOption && isShort && ticket.leverageX <= 1;

  const badge = document.getElementById("satshedge-badge");
  if (badge) badge.hidden = !isSatsHedge;

  const sumMargin = document.getElementById("sum-margin");
  if (sumMargin) {
    if (isOption) {
      const reqSats = isShort ? oq.writerCollateralSats : oq.buyerPremiumSats;
      sumMargin.textContent = `${fmtSats(reqSats)} sats (${fmtBtc(reqSats)} BTC)`;
    } else {
      sumMargin.textContent = `${fmtSats(q.userMarginSats)} sats (${fmtBtc(q.userMarginSats)} BTC)`;
    }
  }

  const sumLiq = document.getElementById("sum-liq");
  if (sumLiq) {
    if (isOption) {
      sumLiq.textContent = isShort ? "COVERED 1.0x BTC CALL/PUT" : "MAX LOSS = PREMIUM";
      sumLiq.className = "is-long";
    } else if (q.userLiquidationPriceUsd === null) {
      sumLiq.textContent = "∞ UNLIQUIDATABLE (1x SatsHedge)";
      sumLiq.className = "is-long";
    } else {
      sumLiq.textContent = fmtUsd(q.userLiquidationPriceUsd);
      sumLiq.className = isShort ? "is-short" : "is-amber";
    }
  }

  const sumCets = document.getElementById("sum-cets");
  if (sumCets) {
    const cetCnt = isOption ? oq.compressed20BitCetCount : q.compressed20BitCetCount;
    sumCets.textContent = `${cetCnt.toLocaleString("en-US")} CETs`;
  }

  const sumFunding = document.getElementById("sum-funding");
  if (sumFunding) {
    const totSats = isOption ? oq.totalP2trFundingSats : q.totalCollateralSats;
    sumFunding.textContent = `${fmtSats(totSats)} sats`;
  }

  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };
  setText("chart-meta-entry", isOption ? `Strike ${fmtUsd(oq.strikeUsd)}` : fmtUsd(q.entryPriceUsd));
  setText("chart-meta-long-liq", isOption ? `BE ${fmtUsd(oq.breakevenUsd)}` : fmtUsd(q.longLiquidationPriceUsd));
  setText(
    "chart-meta-short-liq",
    isOption ? `IV ${oq.ivPct}%` : q.shortLiquidationPriceUsd === null ? "∞ UNLIQ (1x)" : fmtUsd(q.shortLiquidationPriceUsd)
  );
  setText("chart-meta-cets", (isOption ? oq.compressed20BitCetCount : q.compressed20BitCetCount).toLocaleString("en-US"));

  const submitBtn = document.getElementById("btn-submit-order");
  if (submitBtn) {
    submitBtn.className = `shz-submit-btn ${isShort ? "is-short" : "is-long"}`;
    if (isOption) {
      submitBtn.textContent = `${isShort ? "Write / Short" : "Buy / Long"} ${oq.optionType} $${Math.round(oq.strikeUsd / 1000)}k (0 Fee)`;
    } else if (isSatsHedge) {
      submitBtn.textContent = "Open 1x SatsHedge Short (0 Fee)";
    } else if (isShort) {
      submitBtn.textContent = `Sell / Short ${ticket.leverageX}x (0 Fee)`;
    } else {
      submitBtn.textContent = `Buy / Long ${ticket.leverageX}x (0 Fee)`;
    }
  }
}

function renderFallbackWorkbenchIfNeeded() {
  const dock = document.getElementById("shz-workbench-root");
  if (!dock) return;
  if (dock.children.length > 0 && !dock.querySelector("[data-shz-fallback='true']")) {
    return;
  }
  const rows = (window.SHZ_STATE.positions || [])
    .map(
      (p) => `
    <tr>
      <td class="mono">${p.instrument}</td>
      <td class="${p.side === "Long" ? "is-long" : "is-short"} mono">${p.side} ${p.leverageX}x</td>
      <td class="mono">${fmtUsd(p.usdNotional)}</td>
      <td class="mono">${fmtUsd(p.entryPriceUsd)}</td>
      <td class="mono">${fmtUsd(p.markPriceUsd)}</td>
      <td class="mono">${fmtSats(p.userMarginSats)} sats</td>
      <td class="mono">${p.liquidationPriceUsd === null ? "∞ UNLIQ" : fmtUsd(p.liquidationPriceUsd)}</td>
      <td class="mono">${p.status}</td>
    </tr>`
    )
    .join("");

  dock.innerHTML = `
    <div class="shz-fallback-dock" data-shz-fallback="true">
      <div class="shz-panel-head" style="padding:4px 0 6px;background:transparent">
        <span class="shz-panel-title">Active Positions (Fallback Dock)</span>
        <span class="shz-micro-muted mono">${(window.SHZ_STATE.positions || []).length} open P2TR subchannels · 0 bps fee</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Instrument</th><th>Side</th><th>Notional</th><th>Entry</th>
            <th>Mark</th><th>Margin</th><th>Liq Price</th><th>Status</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function checkChartFallback() {
  const canvas = document.getElementById("shz-main-canvas");
  const fb = document.getElementById("shz-chart-fallback");
  if (!canvas || !fb) return;
  const untouched = canvas.width === 300 && canvas.height === 150;
  fb.hidden = !untouched;
}

// ---------------------------------------------------------------------------
// Event Wiring
// ---------------------------------------------------------------------------

function showFeedback(message, isError = false) {
  const box = document.getElementById("ticket-feedback");
  if (!box) return;
  box.hidden = false;
  box.textContent = message;
  box.className = `shz-feedback mono ${isError ? "is-err" : "is-ok"}`;
}

function syncTicketControls() {
  document.getElementById("tab-side-long")?.classList.toggle("is-long-active", ticket.side === "Long");
  document.getElementById("tab-side-short")?.classList.toggle("is-short-active", ticket.side === "Short");

  document.querySelectorAll("[data-order-type]").forEach((btn) => {
    btn.classList.toggle("is-active", btn.getAttribute("data-order-type") === ticket.orderType);
  });

  const priceInput = document.getElementById("input-limit-price");
  if (priceInput) {
    priceInput.disabled = ticket.orderType === "rfq";
    if (ticket.orderType === "rfq" && window.SHZ_STATE.market?.markPriceUsd) {
      priceInput.value = String(window.SHZ_STATE.market.markPriceUsd);
    }
  }

  const levDisplay = document.getElementById("display-leverage");
  if (levDisplay) levDisplay.textContent = `${ticket.leverageX}x`;

  const levSlider = document.getElementById("input-leverage");
  if (levSlider) levSlider.value = String(ticket.leverageX);

  document.querySelectorAll("[data-lev]").forEach((btn) => {
    btn.classList.toggle("is-selected", Number(btn.getAttribute("data-lev")) === ticket.leverageX);
  });

  const tapWarn = document.getElementById("tap-guard-warning");
  if (tapWarn) tapWarn.hidden = ticket.collateral === "VanillaBtc";
}

let quoteTimer = null;
function scheduleQuote() {
  if (quoteTimer) clearTimeout(quoteTimer);
  quoteTimer = setTimeout(() => {
    requestQuote().catch((err) => showFeedback(err.message, true));
  }, 45);
}

function bindEvents() {
  document.getElementById("shz-instrument-select")?.addEventListener("change", (e) => {
    ticket.limitPriceTouched = false;
    refreshState(e.target.value).catch((err) => showFeedback(err.message, true));
  });

  // Top desk view buttons
  document.querySelectorAll("[data-desk-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.getAttribute("data-desk-view");
      if (mode === "options") {
        toggleOptionsChain(true);
      } else if (mode === "oracle") {
        toggleOracleDrawer();
      } else {
        oracleDrawerOpen = false;
        setChartMode("candles");
        renderOracleChecker();
      }
    });
  });

  document.getElementById("btn-verify-oracles")?.addEventListener("click", () => {
    verifyOracles().catch((err) => showFeedback(err.message, true));
  });

  document.getElementById("btn-chart-options")?.addEventListener("click", () => {
    toggleOptionsChain();
  });

  document.getElementById("shz-options-chain-panel")?.addEventListener("click", (e) => {
    const cell = e.target.closest("[data-opt-symbol]");
    if (!cell) return;
    const sym = cell.getAttribute("data-opt-symbol");
    if (!sym) return;
    optionsChainOpen = false;
    syncViewTabs();
    refreshState(sym).catch((err) => showFeedback(err.message, true));
  });

  document.getElementById("btn-sweep-book")?.addEventListener("click", () => {
    sweepOrderbook()
      .then((res) => {
        showFeedback(
          `Swept ${res.clearedLevels?.length || 1} L2 level(s) (${fmtUsd(res.filledUsdNotional)}) · 0 sats fee`,
          false
        );
      })
      .catch((err) => showFeedback(err.message, true));
  });

  document.querySelectorAll("[data-chart-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      setChartMode(btn.getAttribute("data-chart-mode"));
    });
  });

  const handleBookClick = (e) => {
    const row = e.target.closest("[data-ob-price]");
    if (!row) return;
    const price = Number(row.getAttribute("data-ob-price"));
    if (!Number.isFinite(price) || price <= 0) return;
    ticket.orderType = "limit";
    ticket.limitPriceUsd = price;
    ticket.limitPriceTouched = true;
    const priceInput = document.getElementById("input-limit-price");
    if (priceInput) {
      priceInput.value = String(price);
      priceInput.classList.remove("shz-price-flash");
      void priceInput.offsetWidth;
      priceInput.classList.add("shz-price-flash");
    }
    syncTicketControls();
    scheduleQuote();
  };
  document.getElementById("ob-asks")?.addEventListener("click", handleBookClick);
  document.getElementById("ob-bids")?.addEventListener("click", handleBookClick);

  document.querySelectorAll("[data-side]").forEach((btn) => {
    btn.addEventListener("click", () => {
      ticket.side = btn.getAttribute("data-side") === "Long" ? "Long" : "Short";
      syncTicketControls();
      scheduleQuote();
    });
  });

  document.querySelectorAll("[data-order-type]").forEach((btn) => {
    btn.addEventListener("click", () => {
      ticket.orderType = btn.getAttribute("data-order-type") === "rfq" ? "rfq" : "limit";
      syncTicketControls();
      scheduleQuote();
    });
  });

  document.getElementById("input-usd-notional")?.addEventListener("input", (e) => {
    const v = Number(e.target.value);
    if (Number.isFinite(v) && v >= 1) {
      ticket.usdNotional = Math.round(v);
      scheduleQuote();
    }
  });

  document.querySelectorAll("[data-notional]").forEach((btn) => {
    btn.addEventListener("click", () => {
      ticket.usdNotional = Number(btn.getAttribute("data-notional"));
      const inp = document.getElementById("input-usd-notional");
      if (inp) inp.value = String(ticket.usdNotional);
      scheduleQuote();
    });
  });

  document.getElementById("input-limit-price")?.addEventListener("input", (e) => {
    const v = Number(e.target.value);
    if (Number.isFinite(v) && v >= 1) {
      ticket.limitPriceUsd = Math.round(v);
      ticket.limitPriceTouched = true;
      scheduleQuote();
    }
  });

  document.getElementById("btn-use-mark")?.addEventListener("click", () => {
    const mark = window.SHZ_STATE.market?.markPriceUsd ?? 100_000;
    ticket.limitPriceUsd = mark;
    ticket.limitPriceTouched = false;
    const inp = document.getElementById("input-limit-price");
    if (inp) inp.value = String(mark);
    scheduleQuote();
  });

  document.getElementById("input-leverage")?.addEventListener("input", (e) => {
    ticket.leverageX = Number(e.target.value);
    syncTicketControls();
    scheduleQuote();
  });

  document.querySelectorAll("[data-lev]").forEach((btn) => {
    btn.addEventListener("click", () => {
      ticket.leverageX = Number(btn.getAttribute("data-lev"));
      syncTicketControls();
      scheduleQuote();
    });
  });

  document.getElementById("select-oracle")?.addEventListener("change", (e) => {
    ticket.oraclePolicy = e.target.value;
  });

  document.getElementById("select-collateral")?.addEventListener("change", (e) => {
    ticket.collateral = e.target.value;
    syncTicketControls();
  });

  document.getElementById("shz-order-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await submitOrder({
        instrument: window.SHZ_STATE.instrument,
        side: ticket.side,
        orderType: ticket.orderType,
        usdNotional: ticket.usdNotional,
        limitPriceUsd: ticket.limitPriceUsd,
        leverageX: ticket.leverageX,
        oraclePolicy: ticket.oraclePolicy,
        collateral: ticket.collateral,
      });

      if (res.filledUsdNotional > 0) {
        const firstFill = res.fills[0];
        const pos = res.positionsCreated[0];
        showFeedback(
          `Filled ${fmtUsd(res.filledUsdNotional)} @ ${fmtUsd(firstFill.executionPriceUsd)} · Fee: 0 sats · Subchannel ${pos?.subchannelId ?? res.orderId}`,
          false
        );
      } else {
        showFeedback(
          `Resting Limit ${res.side} ${fmtUsd(res.restingUsdNotional)} @ ${fmtUsd(ticket.limitPriceUsd)} · Order ${res.orderId} · 0 bps fee`,
          false
        );
      }
    } catch (err) {
      showFeedback(err.message, true);
    }
  });
}

async function init() {
  bindEvents();
  syncTicketControls();
  syncViewTabs();
  try {
    await refreshState("BTC-INVERSE-PERP");
  } catch (err) {
    showFeedback(err.message, true);
  }
  setTimeout(checkChartFallback, 400);
}

window.addEventListener("DOMContentLoaded", init);
window.addEventListener("load", () => {
  if (window.SHZ_STATE.market) emitState();
  setTimeout(checkChartFallback, 250);
});
