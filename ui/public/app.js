// SatsHedgeZero Pro Trading Terminal — Shell Controller & Shared State Bus

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

// Shared state contract read by /charts.js and /workbench.js
window.SHZ_STATE = {
  instrument: "BTC-INVERSE-PERP",
  instruments: [],
  market: null,
  quote: null,
  positions: [],
  orderbook: null,
  lastCloseout: null,
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
// API Methods (exposed on window.SHZ_API for @ui-workbench)
// ---------------------------------------------------------------------------

async function requestQuote(overrides = {}) {
  const side = overrides.side ?? ticket.side;
  const usdNotional = Math.max(1, Math.round(Number(overrides.usdNotional ?? ticket.usdNotional)));
  const entryPriceUsd = Math.max(
    1,
    Math.round(
      Number(
        overrides.entryPriceUsd ??
          (ticket.orderType === "rfq"
            ? window.SHZ_STATE.market?.markPriceUsd ?? ticket.limitPriceUsd
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

function setChartMode(mode) {
  const normalized = mode === "payoff" ? "payoff" : "candles";
  window.SHZ_STATE.chartMode = normalized;
  document.querySelectorAll("[data-chart-mode]").forEach((btn) => {
    const active = btn.getAttribute("data-chart-mode") === normalized;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  emitState();
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
  renderHeader();
  renderOrderbook();
  renderFallbackWorkbenchIfNeeded();
  await requestQuote();
  return data;
}

window.SHZ_API = {
  refreshState,
  triggerMnr02Closeout,
  setChartMode,
  toggleBobStatus,
  requestQuote,
  submitOrder,
};

// ---------------------------------------------------------------------------
// Renderers (Header, Orderbook, Recent Fills, Order Ticket, Graceful Fallback)
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

  setText("stat-mark-price", fmtUsd(market.markPriceUsd));
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

function renderOrderbook() {
  const { orderbook, market } = window.SHZ_STATE;
  if (!orderbook) return;

  const asksEl = document.getElementById("ob-asks");
  const bidsEl = document.getElementById("ob-bids");
  const midEl = document.getElementById("ob-mid-price");
  const spreadEl = document.getElementById("ob-spread-info");
  const tradesEl = document.getElementById("recent-trades-list");

  // Display top 8 asks descending so lowest ask sits right above spread
  const asksToShow = orderbook.asks.slice(0, 8).reverse();
  const bidsToShow = orderbook.bids.slice(0, 8);

  if (asksEl) {
    asksEl.innerHTML = asksToShow
      .map(
        (r) => `
      <div class="shz-ob-row is-ask" data-ob-price="${r.priceUsd}" title="Click to populate Limit Price $${r.priceUsd.toLocaleString("en-US")}">
        <span class="depth-bar" style="width:${Math.min(100, r.depthPct)}%"></span>
        <span class="ob-price">${r.priceUsd.toLocaleString("en-US")}</span>
        <span class="ob-size align-right">${r.sizeUsd.toLocaleString("en-US")}</span>
        <span class="ob-btc align-right">${r.valueBtc.toFixed(4)}</span>
        <span class="ob-total align-right">${fmtCompactUsd(r.totalUsd)}</span>
      </div>`
      )
      .join("");
  }

  if (bidsEl) {
    bidsEl.innerHTML = bidsToShow
      .map(
        (r) => `
      <div class="shz-ob-row is-bid" data-ob-price="${r.priceUsd}" title="Click to populate Limit Price $${r.priceUsd.toLocaleString("en-US")}">
        <span class="depth-bar" style="width:${Math.min(100, r.depthPct)}%"></span>
        <span class="ob-price">${r.priceUsd.toLocaleString("en-US")}</span>
        <span class="ob-size align-right">${r.sizeUsd.toLocaleString("en-US")}</span>
        <span class="ob-btc align-right">${r.valueBtc.toFixed(4)}</span>
        <span class="ob-total align-right">${fmtCompactUsd(r.totalUsd)}</span>
      </div>`
      )
      .join("");
  }

  if (midEl) midEl.textContent = fmtUsd(market?.markPriceUsd ?? orderbook.bestBidUsd);
  if (spreadEl) {
    spreadEl.textContent = `Spread $${orderbook.spreadUsd.toLocaleString("en-US")} (${orderbook.spreadBps} bps) · 0 bps fee`;
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
  if (!q) return;

  const isShort = ticket.side === "Short";
  const isSatsHedge = isShort && ticket.leverageX <= 1;

  const badge = document.getElementById("satshedge-badge");
  if (badge) badge.hidden = !isSatsHedge;

  const sumMargin = document.getElementById("sum-margin");
  if (sumMargin) {
    sumMargin.textContent = `${fmtSats(q.userMarginSats)} sats (${fmtBtc(q.userMarginSats)} BTC)`;
  }

  const sumLiq = document.getElementById("sum-liq");
  if (sumLiq) {
    if (q.userLiquidationPriceUsd === null) {
      sumLiq.textContent = "∞ UNLIQUIDATABLE (1x SatsHedge)";
      sumLiq.className = "is-long";
    } else {
      sumLiq.textContent = fmtUsd(q.userLiquidationPriceUsd);
      sumLiq.className = isShort ? "is-short" : "is-amber";
    }
  }

  const sumCets = document.getElementById("sum-cets");
  if (sumCets) {
    sumCets.textContent = `${q.compressed20BitCetCount.toLocaleString("en-US")} CETs (${q.cetCompressionRatioPct}%)`;
  }

  const sumFunding = document.getElementById("sum-funding");
  if (sumFunding) {
    sumFunding.textContent = `${fmtSats(q.totalCollateralSats)} sats`;
  }

  // Update chart header telemetry strip
  const setText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };
  setText("chart-meta-entry", fmtUsd(q.entryPriceUsd));
  setText("chart-meta-long-liq", fmtUsd(q.longLiquidationPriceUsd));
  setText(
    "chart-meta-short-liq",
    q.shortLiquidationPriceUsd === null ? "∞ UNLIQ (1x)" : fmtUsd(q.shortLiquidationPriceUsd)
  );
  setText("chart-meta-cets", q.compressed20BitCetCount.toLocaleString("en-US"));

  const submitBtn = document.getElementById("btn-submit-order");
  if (submitBtn) {
    submitBtn.className = `shz-submit-btn ${isShort ? "is-short" : "is-long"}`;
    if (isSatsHedge) {
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
  // Only render graceful fallback if /workbench.js hasn't mounted its own DOM
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
        <span class="shz-panel-title">Active Positions (Fallback Dock — awaiting /workbench.js)</span>
        <span class="shz-micro-muted mono">${(window.SHZ_STATE.positions || []).length} open LN-DLC subchannels · 0 bps fee</span>
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
  // Show fallback hint only if canvas has not been sized/drawn by /charts.js
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
  // Instrument selector
  document.getElementById("shz-instrument-select")?.addEventListener("change", (e) => {
    ticket.limitPriceTouched = false;
    refreshState(e.target.value).catch((err) => showFeedback(err.message, true));
  });

  // Chart mode buttons
  document.querySelectorAll("[data-chart-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      setChartMode(btn.getAttribute("data-chart-mode"));
    });
  });

  // Orderbook click -> populate limit price
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

  // Side tabs
  document.querySelectorAll("[data-side]").forEach((btn) => {
    btn.addEventListener("click", () => {
      ticket.side = btn.getAttribute("data-side") === "Long" ? "Long" : "Short";
      syncTicketControls();
      scheduleQuote();
    });
  });

  // Order type toggle
  document.querySelectorAll("[data-order-type]").forEach((btn) => {
    btn.addEventListener("click", () => {
      ticket.orderType = btn.getAttribute("data-order-type") === "rfq" ? "rfq" : "limit";
      syncTicketControls();
      scheduleQuote();
    });
  });

  // Notional input + chips
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

  // Limit price + Mark button
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

  // Leverage slider + chips
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

  // Oracle & Collateral selects
  document.getElementById("select-oracle")?.addEventListener("change", (e) => {
    ticket.oraclePolicy = e.target.value;
  });

  document.getElementById("select-collateral")?.addEventListener("change", (e) => {
    ticket.collateral = e.target.value;
    syncTicketControls();
  });

  // Order submission
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
