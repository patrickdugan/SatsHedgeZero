# HFT-02A: latency economics and liquidity fragmentation

Registered on HFT-01 commit d19dfcf49fc36c911f23d3913d7f01c88733b0fa, stacked PR #22. The signed router, tariff, and signature checks remain unchanged.

## Frozen experimental contract

Seeds 107, 109, 113. Four seconds of synthetic arrivals; one versus four private books; 0%, 20%, 100% priority assignment using fixed tickets independent of the mark path. Equal aggregate collateral. Separate random tickets assign routers, with no smart routing or cross-book preview. Makers and takers have disjoint identities. Quotes on both sides every 40 ms, $300 quantity, $15 half-spread, cancel request after 300 ms. $100 FOK takes every 23 ms from t=150 ms, limit at arrival mark plus/minus $250. All arms share inputs except tier and router selection. Expiry 900 ms from arrival. Each quote's cancel inherits its tier. Both synthetic relays sign a mark every 50 ms. Quiet increments bounded by $6; shock increments by $55 with a $450 jump each second at half-second offset. BTC/USD bounded by $98k-$102k. At each timestamp: mark first, arrivals in insertion order, then eligible FIFO. Exact due times assume zero CPU backlog. Synthetic path extends beyond last execution for 500 ms markout. No advance price access for traders, real funds, provider data, network transport or settlement.

## Estimands and gates

Record every outcome including cancellation and failed takes. Arrival cost = signed (execution price minus arrival mark)/arrival mark in bps; execution cost substitutes current mark. Positive cost is worse for takers. Forward markout = signed (mark 500 ms after execution minus execution price)/execution price in bps; positive favors the taker. Each arm reports paired common-fill cost changes alongside baseline-only/treatment-only fills; priority cohort compared with identical logical intents in the free arm. Compare four books with one at equal adoption. All quantities on take side equal. Timing is modeled, not measured network latency.

Exact 20/200 ppm maker/taker rates and 70/30 oracle/router allocation remain as HFT-01. Convert provisional sats to USD at fill price. Normalize oracle revenue per $1m matched, and compute implied daily matched volume covering $100/$1k/$5k daily oracle costs. Zero revenue means no finite break-even; omit that field. Actual provider contracts, adoption, collection risk, operating costs and subscription income unknown.

All 36 arms (568 rows each, including 168 takes) must complete with matched exogenous inputs, exact eligible delays, conserved balances, zero fee DLCs, and reconciled receipts. Re-run one arm byte-for-byte. Free arms owe zero fees. Require fills and some all-priority oracle obligations as smoke gates, with economic outcomes reported in either direction. Three synthetic seeds cannot establish market performance.

HFT-02B: differential indexed matching and parallel signature verification preserving arrival order. HFT-02C: measured CPU backlog/transport, cancel/replace, provider skew, smart routing and real trace replay. HFT-03: authenticated durable channel coalescer.

Run: cargo run --locked --release -p shz-dex --example hft_event_replay -- 107 shock 4 20. Native CI pending.