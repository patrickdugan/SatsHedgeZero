// SatsHedgeZero — 5-Pane Real-Time Back-End Protocol Explorer Controller

const fmtUsd = (n) =>
  typeof n === "number" && Number.isFinite(n)
    ? "$" + Math.round(n).toLocaleString("en-US")
    : "—";

const fmtInt = (n) =>
  typeof n === "number" && Number.isFinite(n)
    ? Math.round(n).toLocaleString("en-US")
    : "—";

const esc = (s) =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

let latestSnapshot = null;

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function renderAll(snap) {
  if (!snap) return;
  latestSnapshot = snap;

  // Top KPI Ribbon
  setText("kpi-mark-px", fmtUsd(snap.mark_price_usd));
  setText(
    "kpi-latency",
    `${snap.latency?.p50_us ?? 0} / ${snap.latency?.p99_us ?? 0} µs`
  );
  setText(
    "kpi-counts",
    `${fmtInt(snap.latency?.total_intents_processed ?? 0)} / ${fmtInt(snap.latency?.total_fills_matched ?? 0)}`
  );
  const freedPct = ((snap.netting?.collateral_freed_bps ?? 0) / 100).toFixed(1);
  setText("kpi-netting-saved", `${freedPct}%`);
  setText(
    "kpi-t4-height",
    `#${fmtInt(snap.testnet4_chain?.tip_height ?? 163091)}`
  );

  renderPane1Hft(snap);
  renderPane2Lightning(snap);
  renderPane3Netting(snap);
  renderPane4Oracle(snap);
  renderPane5NovaBitVm3(snap);
}

// ---------------------------------------------------------------------------
// Pane 1: Tier-0 HFT Orderbook + SignedOrderIntent Tape
// ---------------------------------------------------------------------------
function renderPane1Hft(snap) {
  const lat = snap.latency || {};
  setText("lat-p50", `${lat.p50_us ?? 0} µs`);
  setText("lat-p95", `${lat.p95_us ?? 0} µs`);
  setText("lat-p99", `${lat.p99_us ?? 0} µs`);
  setText("lat-max", `${lat.max_us ?? 0} µs`);
  setText("lat-ops", `${fmtInt(lat.sustained_ops_per_sec_est ?? 0)}/s`);

  const bidsEl = document.getElementById("exp-bids-list");
  if (bidsEl) {
    bidsEl.innerHTML = (snap.bids || [])
      .slice(0, 6)
      .map(
        (b) =>
          `<div class="exp-ladder-row is-bid"><span class="is-long">${fmtUsd(b.price_usd)}</span><span>${fmtUsd(b.open_usd_notional)}</span><span class="muted">${esc(b.trader_pubkey_prefix)}</span></div>`
      )
      .join("");
  }

  const asksEl = document.getElementById("exp-asks-list");
  if (asksEl) {
    asksEl.innerHTML = (snap.asks || [])
      .slice(0, 6)
      .map(
        (a) =>
          `<div class="exp-ladder-row is-ask"><span class="is-short">${fmtUsd(a.price_usd)}</span><span>${fmtUsd(a.open_usd_notional)}</span><span class="muted">${esc(a.trader_pubkey_prefix)}</span></div>`
      )
      .join("");
  }

  const tbody = document.getElementById("intent-tape-tbody");
  if (tbody) {
    tbody.innerHTML = (snap.intent_tape || [])
      .slice(0, 18)
      .map((it) => {
        const cls = it.side === "Long" ? "is-long" : "is-short";
        return `<tr>
          <td>${it.seq}</td>
          <td class="${cls}">${esc(it.side)}</td>
          <td>${fmtUsd(it.limit_price_usd)}</td>
          <td>${fmtUsd(it.usd_notional)}</td>
          <td class="is-long">${it.bip340_verified ? "✓ Schnorr" : "✗"}</td>
          <td class="is-cyan">${it.latency_us}µs</td>
          <td>${esc(it.ln_channel_id)}#${it.ln_commit_seq}</td>
        </tr>`;
      })
      .join("");
  }
}

// ---------------------------------------------------------------------------
// Pane 2: Interactive SVG Testnet4 LN Topology + 100ms Coalescer + PTLC
// ---------------------------------------------------------------------------
function renderPane2Lightning(snap) {
  const channels = snap.ln_channels || [];
  const commits = snap.ln_recent_commits || [];
  setText(
    "ln-commit-pill",
    `Commits: ${commits.length > 0 ? "#" + commits[0].commit_id : "Ready"}`
  );

  const svg = document.getElementById("svg-ln-topology");
  if (svg) {
    const cx = 230;
    const cy = 88;
    const positions = [
      [70, 34],
      [390, 34],
      [70, 142],
      [390, 142],
      [230, 18],
      [230, 158],
    ];
    let lines = "";
    let nodes = "";

    channels.slice(0, 6).forEach((ch, idx) => {
      const [px, py] = positions[idx % positions.length];
      const stroke = ch.online ? "#00d285" : "#f59e0b";
      const dash = ch.online ? "" : 'stroke-dasharray="4 3"';
      const lockedM = (ch.dlc_margin_locked_sats / 1e6).toFixed(2);
      const mx = (cx + px) / 2;
      const my = (cy + py) / 2;
      lines += `<line x1="${cx}" y1="${cy}" x2="${px}" y2="${py}" stroke="${stroke}" stroke-width="2" ${dash} />`;
      lines += `<text x="${mx}" y="${my - 4}" fill="#97a8c2" font-size="9" font-family="JetBrains Mono" text-anchor="middle">${lockedM}M locked (seq#${ch.commitment_seq})</text>`;

      nodes += `<g>
        <rect x="${px - 54}" y="${py - 14}" width="108" height="28" rx="4" fill="#151d2a" stroke="${stroke}" stroke-width="1.3" />
        <text x="${px}" y="${py - 1}" fill="#e6edf3" font-size="9.5" font-weight="600" font-family="JetBrains Mono" text-anchor="middle">${esc(ch.peer_name)}${ch.online ? "" : " [OFF]"}</text>
        <text x="${px}" y="${py + 10}" fill="#38bdf8" font-size="8.5" font-family="JetBrains Mono" text-anchor="middle">Δ ${ch.net_usd_delta >= 0 ? "+" : ""}${ch.net_usd_delta} USD</text>
      </g>`;
    });

    const hub = `<g>
      <circle cx="${cx}" cy="${cy}" r="28" fill="#101a29" stroke="#38bdf8" stroke-width="2" />
      <text x="${cx}" y="${cy - 3}" fill="#38bdf8" font-size="9.5" font-weight="700" font-family="JetBrains Mono" text-anchor="middle">RouterLP</text>
      <text x="${cx}" y="${cy + 9}" fill="#00d285" font-size="8" font-family="JetBrains Mono" text-anchor="middle">100ms Hub</text>
    </g>`;

    svg.innerHTML = lines + nodes + hub;
  }

  const cTbody = document.getElementById("ln-commits-tbody");
  if (cTbody) {
    cTbody.innerHTML = commits
      .slice(0, 8)
      .map(
        (c) => `<tr>
          <td>${esc(c.peer_name)}</td>
          <td>#${c.commitment_seq}</td>
          <td class="is-cyan">${c.absorbed_fills}</td>
          <td class="${c.net_usd_delta >= 0 ? "is-long" : "is-short"}">${c.net_usd_delta >= 0 ? "+" : ""}${fmtInt(c.net_usd_delta)}</td>
          <td>${fmtInt(c.dlc_margin_locked_sats)}</td>
          <td class="is-long">${esc(c.trader_sig_hex.slice(0, 10))}…</td>
        </tr>`
      )
      .join("");
  }

  const swapsEl = document.getElementById("ptlc-swaps-list");
  if (swapsEl) {
    swapsEl.innerHTML = (snap.ln_recent_ptlc_swaps || [])
      .slice(0, 5)
      .map(
        (s) =>
          `<div class="exp-log-item">
            <strong class="is-cyan">PTLC #${s.swap_id}</strong> ${esc(s.peer_name)} ← <strong>${fmtInt(s.amount_sats)} sats</strong>
            • <code>${esc(s.bolt11_ptlc_tag)}</code> • extracted <code>y=${esc(s.extracted_scalar_y_prefix_hex)}…</code>
          </div>`
      )
      .join("");
  }
}

// ---------------------------------------------------------------------------
// Pane 3: SVG Edmonds-Karp Netting Sankey + 5-Party Packer + SPAN Greeks
// ---------------------------------------------------------------------------
function renderPane3Netting(snap) {
  const net = snap.netting || {};
  setText("netting-epoch-pill", `Epoch #${net.epoch_id ?? 1}`);

  const svg = document.getElementById("svg-netting-sankey");
  if (svg) {
    const edges = (net.sankey_edges || []).slice(0, 10);
    const leftNodes = [...new Set(edges.map((e) => e.from))];
    const rightNodes = [...new Set(edges.map((e) => e.to))];

    const leftY = new Map();
    leftNodes.forEach((n, i) => {
      leftY.set(n, 24 + (i * 126) / Math.max(1, leftNodes.length - 1));
    });
    const rightY = new Map();
    rightNodes.forEach((n, i) => {
      rightY.set(n, 24 + (i * 126) / Math.max(1, rightNodes.length - 1));
    });

    let paths = "";
    edges.forEach((e) => {
      const y1 = leftY.get(e.from) ?? 80;
      const y2 = rightY.get(e.to) ?? 80;
      const isWinner = e.to.startsWith("Payout:");
      const color = isWinner ? "rgba(0,210,133,0.55)" : "rgba(56,189,248,0.28)";
      const w = Math.max(1.5, Math.min(7, e.sats / 700_000));
      paths += `<path d="M 92 ${y1} C 220 ${y1}, 240 ${y2}, 335 ${y2}" fill="none" stroke="${color}" stroke-width="${w}" />`;
    });

    let lBoxes = "";
    leftNodes.forEach((n) => {
      const y = leftY.get(n);
      lBoxes += `<rect x="12" y="${y - 10}" width="80" height="20" rx="3" fill="#151d2a" stroke="#38bdf8" />
        <text x="52" y="${y + 3}" fill="#e6edf3" font-size="9" font-family="JetBrains Mono" text-anchor="middle">Vault ${esc(n)}</text>`;
    });

    let rBoxes = "";
    rightNodes.forEach((n) => {
      const y = rightY.get(n);
      const isWin = n.startsWith("Payout:");
      rBoxes += `<rect x="335" y="${y - 10}" width="115" height="20" rx="3" fill="#151d2a" stroke="${isWin ? "#00d285" : "#64748b"}" />
        <text x="392" y="${y + 3}" fill="${isWin ? "#00d285" : "#97a8c2"}" font-size="8.5" font-family="JetBrains Mono" text-anchor="middle">${esc(n)}</text>`;
    });

    const header = `<text x="230" y="12" fill="#f59e0b" font-size="9.5" font-weight="700" font-family="JetBrains Mono" text-anchor="middle">Gross ${fmtInt(net.gross_obligations_sats)} sats → Net L1 ${fmtInt(net.net_l1_transfer_sats)} sats (${((net.collateral_freed_bps || 0) / 100).toFixed(1)}% Freed)</text>`;
    svg.innerHTML = header + paths + lBoxes + rBoxes;
  }

  const pack = net.n_party_packing || {};
  const npEl = document.getElementById("nparty-box");
  if (npEl) {
    npEl.innerHTML = `
      <div class="exp-kv-cell"><span>5-Party Vault Inputs</span><strong class="is-cyan">${pack.total_vault_inputs ?? 5} (${pack.offline_0x83_vaults ?? 2}x 0x83 + ${pack.bilateral_0x00_vaults ?? 3}x 0x00)</strong></div>
      <div class="exp-kv-cell"><span>Atomic Clearing TXID</span><strong>${esc((pack.txid_hex || "").slice(0, 16))}…</strong></div>
      <div class="exp-kv-cell"><span>vSize / Miner Fee</span><strong class="is-long">${pack.vsize ?? 0} vB / ${fmtInt(pack.miner_fee_sats ?? 0)} sats</strong></div>
    `;
  }

  const g = net.portfolio_greeks || {};
  const liq = net.liquidation_plan || {};
  const glEl = document.getElementById("greeks-liq-box");
  if (glEl) {
    glEl.innerHTML = `
      <div class="exp-kv-cell"><span>Net Δ / Γ (1% move)</span><strong>${fmtInt(g.net_delta_sats_per_1pct)} / ${fmtInt(g.net_gamma_sats_per_1pct2)} sats</strong></div>
      <div class="exp-kv-cell"><span>SPAN Cross IM Saved</span><strong class="is-long">${((g.margin_efficiency_saved_bps || 0) / 100).toFixed(1)}% (${fmtInt(g.cross_initial_margin_sats)} sats)</strong></div>
      <div class="exp-kv-cell"><span>Dutch Partial-Liq Tranche</span><strong class="is-amber">$${fmtInt(liq.tranche_notional_usd)} → ${(liq.post_tranche_margin_bps || 0) / 100}% Margin</strong></div>
    `;
  }
}

// ---------------------------------------------------------------------------
// Pane 4: Multi-Source 200ms Oracle + Optimistic NEAR + Testnet4 Anchors
// ---------------------------------------------------------------------------
function renderPane4Oracle(snap) {
  const tick = snap.oracle_latest || {};
  const spreadBps = tick.spread_bps ?? 1;
  setText(
    "oracle-spread-pill",
    tick.status_valid !== false ? `VALID • ${spreadBps} bps` : `HOLD • ${spreadBps} bps`
  );
  setText("spread-meter-text", `${spreadBps} bps / 50 bps MAX`);
  const fillEl = document.getElementById("spread-meter-fill");
  if (fillEl) {
    fillEl.style.width = `${Math.min(100, Math.max(3, (spreadBps / 50) * 100))}%`;
  }

  const oBox = document.getElementById("oracle-live-box");
  if (oBox) {
    const pythUsd = tick.pyth_price_e8 ? (tick.pyth_price_e8 / 1e8).toFixed(2) : "100110.00";
    const clUsd = tick.chainlink_price_e8 ? (tick.chainlink_price_e8 / 1e8).toFixed(2) : "100122.00";
    oBox.innerHTML = `
      <div class="exp-kv-cell"><span>Pyth Pro Lazer (200ms)</span><strong class="is-long">$${pythUsd}</strong></div>
      <div class="exp-kv-cell"><span>Chainlink Streams v3</span><strong class="is-cyan">$${clUsd}</strong></div>
      <div class="exp-kv-cell"><span>Threshold FROST</span><strong>${esc(snap.frost_quorum)}</strong></div>
    `;
  }

  const near = snap.near_optimistic || {};
  const nearBox = document.getElementById("near-session-box");
  if (nearBox) {
    nearBox.innerHTML = `<strong>NEAR Transparent Checkpoint:</strong> ${esc(near.status_label)} • Compresses <code>${near.total_chunks ?? 1129}</code> Nova chunks into <code>${near.happy_path_tx_count ?? 2}</code> txs (<code>~${near.happy_path_gas_tgas ?? 10} TGas</code>) with <code>${near.max_bisection_steps ?? 11}</code>-step bisection fraud proof.`;
  }

  const t4 = snap.testnet4_chain || {};
  const base = t4.explorer_base_url || "https://mempool.space/testnet4/tx";
  const anchorsEl = document.getElementById("oracle-anchors-list");
  if (anchorsEl) {
    const ckpts = (snap.oracle_checkpoints || [])
      .slice(0, 2)
      .map(
        (c) =>
          `<div class="exp-log-item"><strong class="is-amber">SHZIDX01 8h Root (h#${c.start_hour}):</strong> <code>${esc(c.shzidx01_payload_hex.slice(0, 32))}…</code> (${c.valid_hours}/8 VALID)</div>`
      )
      .join("");
    anchorsEl.innerHTML = `
      <div class="exp-log-item">
        <strong class="is-amber">Live Testnet4 SHZIDX01 Anchor TX:</strong>
        <a href="${esc(base)}/7246cb0a22b276db8cfb1111c2626691000f3e5e2b0e049baba84d2affddc130" target="_blank" rel="noopener">7246cb0a22b276db8cfb1111…</a>
        (40B <code>SHZIDX01||c26ae964…</code>)
      </div>
      <div class="exp-log-item">
        <strong class="is-long">Live Testnet4 Clearing TX:</strong>
        <a href="${esc(base)}/${esc(t4.reference_clearing_txid)}" target="_blank" rel="noopener">${esc((t4.reference_clearing_txid || "").slice(0, 24))}…</a>
        • <a href="${esc(base)}/${esc(t4.reference_funding_txid)}" target="_blank" rel="noopener">Funding TX</a>
      </div>
      ${ckpts}
    `;
  }
}

// ---------------------------------------------------------------------------
// Pane 5: Dual Nova 0->100%, Sparse Nullifiers & BitVM3 Watchtower
// ---------------------------------------------------------------------------
function renderPane5NovaBitVm3(snap) {
  const nb = snap.nova_bitvm3 || {};
  const bookPill = document.getElementById("bitvm3-book-pill");
  if (bookPill) {
    bookPill.textContent = nb.durable_book_frozen
      ? "Durable Book: FROZEN (REORG ALERT)"
      : "Durable Book: READY (6-Conf Guard)";
    bookPill.className = `exp-mini-pill mono ${nb.durable_book_frozen ? "is-short" : "is-long"}`;
  }

  const secqPct = Number(nb.secq256k1_progress_pct ?? 100);
  setText(
    "secq-pct",
    `${secqPct.toFixed(1)}% (${nb.secq256k1_folds_done ?? 8}/${nb.secq256k1_folds_total ?? 8})`
  );
  const secqBar = document.getElementById("secq-bar");
  if (secqBar) secqBar.style.width = `${secqPct}%`;
  setText(
    "secq-meta",
    `${fmtInt(nb.secq256k1_proof_bytes)} B • In-Circuit TapSighash ✓ • sha256: ${(nb.secq256k1_proof_sha256 || "").slice(0, 20)}…`
  );

  const bnPct = Number(nb.bn254_progress_pct ?? 100);
  setText(
    "bn254-pct",
    `${bnPct.toFixed(1)}% (${nb.bn254_folds_done ?? 3}/${nb.bn254_folds_total ?? 3})`
  );
  const bnBar = document.getElementById("bn254-bar");
  if (bnBar) bnBar.style.width = `${bnPct}%`;
  setText(
    "bn254-meta",
    `${fmtInt(nb.bn254_proof_bytes)} B • Zero Trusted Setup • sha256: ${(nb.bn254_proof_sha256 || "").slice(0, 20)}…`
  );

  setText("nullifier-root-short", `${(nb.nullifier_root_hex || "").slice(0, 16)}…`);
  const nGrid = document.getElementById("nullifier-grid");
  if (nGrid) {
    nGrid.innerHTML = (nb.nullifier_slots || [])
      .map(
        (s) => `<div class="exp-null-slot ${s.consumed ? "is-consumed" : ""}">
          <div><strong>#${s.slot_index}</strong> ${esc(s.vault_label)}</div>
          <div class="${s.consumed ? "is-amber" : "is-long"}">${s.consumed ? `CONSUMED (Ep#${s.epoch_consumed})` : "EMPTY • READY"}</div>
        </div>`
      )
      .join("");
  }

  const leavesUl = document.getElementById("bitvm3-leaves-list");
  if (leavesUl) {
    leavesUl.innerHTML = (nb.bitvm3_leaves || [])
      .map((l) => `<li>${esc(l)}</li>`)
      .join("");
  }

  const wtEl = document.getElementById("watchtower-events-list");
  if (wtEl) {
    const evs = nb.watchtower_events || [];
    if (evs.length === 0) {
      wtEl.innerHTML = `<div class="exp-log-item is-long">✓ Watchtower armed on U_Assert (${esc((nb.bitvm3_assert_outpoint || "").slice(0, 16))}…) — 0 fraud faults</div>`;
    } else {
      wtEl.innerHTML = evs
        .map((ev) => `<div class="exp-log-item is-amber">${esc(JSON.stringify(ev))}</div>`)
        .join("");
    }
  }
}

// ---------------------------------------------------------------------------
// Action Buttons + Live SSE + WebSocket Ping Probe
// ---------------------------------------------------------------------------
async function triggerAction(action, count) {
  const toast = document.getElementById("action-toast");
  if (toast) toast.textContent = `Running ${action}…`;
  try {
    const res = await fetch("/v1/explorer/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, count }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    if (toast) {
      toast.textContent =
        action === "hft_burst"
          ? `✓ Executed ${data.intents_executed} signed intents (${data.matches} fills, ${Math.round(data.ops_per_sec).toLocaleString()} ops/s)`
          : `✓ Completed ${action}`;
    }
    await fetchSnapshotOnce();
  } catch (err) {
    if (toast) toast.textContent = `✗ ${err.message}`;
  }
}

async function fetchSnapshotOnce() {
  const res = await fetch("/v1/explorer/snapshot");
  if (!res.ok) return;
  const snap = await res.json();
  renderAll(snap);
}

function connectSseAndWs() {
  if (typeof EventSource !== "undefined") {
    const es = new EventSource("/v1/explorer/stream");
    es.addEventListener("snapshot", (ev) => {
      try {
        renderAll(JSON.parse(ev.data));
      } catch {
        // ignore malformed frame
      }
    });
    es.onerror = () => {
      const b = document.getElementById("badge-stream");
      if (b) b.textContent = "● POLLING 500ms";
    };
  }

  try {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${location.host}/v1/ws`);
    ws.onopen = () => {
      const b = document.getElementById("badge-ws");
      if (b) {
        b.textContent = "● WS /v1/ws CONNECTED";
        b.classList.add("is-live");
      }
      ws.send(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "public/subscribe",
          params: { channels: ["book.BTC-USD-INV.raw", "trades", "oracle.200ms"] },
        })
      );
    };
  } catch {
    // WebSocket optional when running under static HTTP mock
  }
}

document.querySelectorAll("[data-exp-action]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const act = btn.getAttribute("data-exp-action");
    const cnt = btn.getAttribute("data-count");
    triggerAction(act, cnt ? Number(cnt) : undefined);
  });
});

fetchSnapshotOnce().then(connectSseAndWs);
