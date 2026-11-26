# SHZ-RGB-01A: two-node native benchmark and recovery spike

Upstream WDK source 608937d849412a4c25e9b9a66a7571b561396ae0; native graph RLN ecc69f20308231400561f6f060fea88acfa40cc4. Upstream [production register](https://github.com/UTEXO-Protocol/wdk-rgb-lightning/blob/608937d849412a4c25e9b9a66a7571b561396ae0/PRODUCTION-GATES.md) and [regtest guide](https://github.com/UTEXO-Protocol/wdk-rgb-lightning/blob/608937d849412a4c25e9b9a66a7571b561396ae0/tests/regtest/README.md) inspected. These are exact source pins, not a claim that tarballs have been installed or verified.

## Critical admission gates

P02 interrupted BTC send reservation; P03 stale settled RGB balance after reorg; P04 double-counted pending witness balance; P06 valid-after-wrong-lock BFA receipt rejection. S01 leaves strict outbound settlement, mature BTC sweep, RGB commitment acceptance and channel recovery unqualified. S04 rejects mainnet IFA; BFA needs exact bridge/token identity. D01 native security review is unresolved. Historical P01 signer database lock has narrower follow-up passes; arbitrary recovery remains outside those receipts. Use strict signing. A diagnostic permissive pass cannot clear these gates.

The application must independently reconcile both legs and halt on a chain conflict. Do not derive collateral from getAssetBalance().pending/future or settled alone, and do not alter existing SHZ signed BTC clearing commitments. A post-reorg freeze flags any already recorded payout for investigation; it does not pretend to claw funds back.

## Execute on disposable Linux/regtest only

Use a **dedicated** upstream Compose stand with loopback ports, test credentials, no public funds and private evidence. Upstream setup requires Docker Compose, Git, Node 22+, audited exact native candidate package and ORG_READ_TOKEN for the three private BFA source dependencies. Do not publish or commit that token or wallet files. Use upstream instructions for native/package verification and startup; an npm install alone does not qualify the runtime. Run serially and use fresh wallets each time:

    git clone https://github.com/UTEXO-Protocol/wdk-rgb-lightning.git /tmp/shz-wdk
    git -C /tmp/shz-wdk checkout 608937d849412a4c25e9b9a66a7571b561396ae0
    # Follow pinned upstream setup / native provenance checks.
    # In the upstream checkout: npm ci, approved native install, npm run regtest:up -- --onchain-only
    # In SatsHedgeZero:
    export UTEXO_WDK_CHECKOUT=/tmp/shz-wdk
    export SHZ_DISPOSABLE_REGTEST=YES
    node integrations/utexo-rgb/benchmark.mjs btc-ln 100
    node integrations/utexo-rgb/benchmark.mjs rgb-ln 100 25
    node integrations/utexo-rgb/benchmark.mjs rgb-chain 100 25

The on-chain-only service profile still supplies the daemon, Bitcoin and indexers; no LSP is exercised. Benchmark uses upstream WalletProcess, strict signer, isolated wallets, and local RPC chain guard. Each invocation runs a single rail so one BTC failure does not prevent investigation of the other rails. Limit 100 payments and aggregate 10,000 fixture units per run. Report success-only percentiles with all failure/unexecuted counts. Polling granularity and explicit regtest mining mean these are local end-to-end observations, not public network latency. RGB on-chain requires both histories, six active-chain confirmations and receiver balance delta. LN requires matching invoice and two-sided terminal history. Routing/miner fee fields are deliberately null until independently validated; no claim of measured fees or exact channel balance deltas. No retries after an ambiguous send. No real USDT.

Run the upstream adverse scenarios separately, on the disposable stand:

    node tests/regtest/recovery.mjs --scenario=interrupted
    node tests/regtest/recovery.mjs --scenario=rgb-reorg
    node tests/regtest/recovery.mjs --scenario=force-close --rgb
    node tests/regtest/recovery.mjs --scenario=hodl-crash

The recovery transition model is a pure replay specification, not a durable journal or cryptographic verifier. It requires distinct externally verified BTC and RGB evidence IDs, prevents reuse of withdrawal/payment/leg IDs, freezes on conflict, disallows automatic retry and allows reconciliation of a payment initiated before expiry even after expiry. Evidence IDs alone are not verification; implement authenticated receipts, append/fsync and single-writer durable journal before connecting it to SHZ. No release/credit side effect exists.

Run:

    node integrations/utexo-rgb/mock.test.mjs
    node integrations/utexo-rgb/recovery.test.mjs

Recovery model isolate result: 124 assertions, 29 valid and 3877 rejected event sequences among 3,906 enumerated (ordered length 0–5 over five event types). Native benchmark and upstream adverse scenarios unexecuted in this environment: no Docker, bitcoind or external DNS. No actual timing, balances, transaction receipts or fees are claimed. The benchmark itself is source-reviewed against upstream calls, not yet native-validated. The corrected adapter now awaits the asynchronous read-only SDK facade and verifies account network/capabilities before constructing invoices.
