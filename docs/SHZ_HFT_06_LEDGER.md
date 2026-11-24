# HFT-06 continuation ledger

Branch `research/shz-hft06-oracle-relay-20261124`, stacked on HFT-05 `research/shz-hft05-durable-ln-20261124` (#31, `adc01e1`).

## Inspected heads (2026-11-24)

| PR | Branch | Head | Role |
| --- | --- | --- | --- |
| #23 | research/shz-hft02-indexed-20261124 | 504845d | HFT-02 indexed engine (stack base) |
| #25 | research/shz-event-parity-20261124 | 1e43ce4 | event replay parity (preserved, not merged) |
| #26 | research/shz-hft03-coalescer-20261124 | 2503b55 | 100 ms exact-leg coalescer (in stack) |
| #27 | research/shz-smart-routing-20261124 | df75cfb | negative smart-routing result (preserved) |
| #29 | research/shz-hft04-oracle-federation-20261124 | 0aeb0f0 | 4-of-5 packet federation (in stack) |
| #30 | research/l2-day-calibration-20261124 | 328a46c | 48 h public L2 calibration; `research/public_l2` copied onto this branch |
| #31 | research/shz-hft05-durable-ln-20261124 | adc01e1 | durable acknowledgement state machine (direct parent) |

## Status flags

`production_ready = false`, `live_feed_authenticated = false`, `onchain_config_verified = false`, `live_lightning_fee_collection = false`, `measured_network_lead = false` (loopback only), `independent_security_review = false`.

## Gates

| ID | Gate | State | Exact command / next action |
| --- | --- | --- | --- |
| G-SRC-1 | Pyth Pro access token + redistribution terms for tiered downstream delivery | BLOCKED: no subscription or rights | Obtain terms; set `PYTH_LAZER_ACCESS_TOKEN`; `cargo run --release -p shz-relay --features live --bin shz-relay -- serve --config <live.json>` |
| G-SRC-2 | Chainlink Data Streams client ID/secret, BTC/USD feed ID, DON config from the Verifier's `ConfigSet` events | BLOCKED: no credentials | Set `CHAINLINK_DS_CLIENT_ID/SECRET`; fill `source.chainlink_don` from chain; re-run `cargo test -p shz-oracle chainlink` plus a recorded live sample as a parity fixture |
| G-SRC-3 | Chainlink v3 second-granular timestamps vs HFT-04 500 ms skew / 1 s age | OPEN finding: 244/600 synthetic slots HOLD on skew | Decide: sub-second schema or per-source bounds in a new policy version (new `Policy::id` domain), then re-run `shz-collator replay` and pin a new receipt |
| G-SRC-4 | Live wire-format parity for Pyth JSON `solana.data` and Chainlink WS `report.fullReport` | OPEN: written from documentation, never exercised | Record 10 min of each with credentials; replay through `shz-collator replay` |
| G-FED-1 | Federated member vote transport between independent hosts | OPEN: `FederatedCollector` exists; in-process signers are dev-only (`SHZ_DEV_FEDERATION=1`) | Implement member vote RPC with fenced signer identity; 3–5 hosts |
| G-FED-2 | Audited threshold packet signer | OPEN: `ThresholdPacketSigner` trait only | Packet-specific DKG, durable nonce state, disjoint from FROST maturity nonces |
| G-NET-1 | Measured multi-site delivery, clock uncertainty and realized lead | OPEN: loopback only (premium-vs-standard p50 197.7 ms trusted, 181.7 ms federated) | Deploy relay + 3 subscriber sites; `shz-relay subscribe ... --count 18000` per site with PTP/NTP offset logs |
| G-LN-1 | Real Lightning commitment updates and fee receipt verification (LDK) | OPEN: `LightningAdapter` trait + `MockAdapter` | See `SHZ_HFT_06_ROUTER_LN.md` LDK notes; regtest loop before Testnet4 |
| G-LN-2 | Tiered router journal (durable WAL) | OPEN: tiered engine is in-memory; HFT-05 `DurableRouter` path is durable | Port HFT-05 journal framing to `TieredRouter` events |
| G-CAL-1 | 48 h public immediacy calibration | PENDING CI | Push triggers `shz-hft06-immediacy-calibration`; or `workflow_dispatch` |
| G-CAL-2 | TradingMoneyball private L2 caches and Core execution tapes | BLOCKED: not present on this machine | Run `immediacy.py hour --book <cache parquet>` on the cache host with an adapter to `pilot.Book` |
| G-CAL-3 | Client request congestion | BLOCKED: not observable in public L2 | Requires relay/router request traces |
| G-SEC-1 | Independent security review (relay auth, envelopes, ledger) | OPEN | External reviewer |
| G-LEGAL-1 | Market data licensing, derivatives and fee arrangements | OPEN | Counsel review before any paid tier |

## Reproduce

```
cargo test --locked -p shz-oracle -p shz-relay -p shz-dex -p shz-dlc -p shz-margin
cargo run --release -p shz-relay --bin shz-relay -- bench --clients 4 --seconds 60 --out relay_bench.json
cargo run --release -p shz-relay --bin shz-relay -- bench --clients 4 --seconds 30 --mode federated --out relay_bench_fed.json
cargo run --release -p shz-dex --example hft06_router_bench -- --orders 20000 --out router_bench.json
cargo run --release -p shz-relay --bin shz-collator -- gen-fixture --origin-us 1800000000000000 --seconds 120 --out rec.jsonl
cargo run --release -p shz-relay --bin shz-collator -- replay --recording rec.jsonl --origin-us 1800000000000000
python -m unittest research/public_l2/test_immediacy.py
```

Windows: add `+stable-x86_64-pc-windows-msvc` to cargo (the GNU toolchain lacks `dlltool` for tokio).
