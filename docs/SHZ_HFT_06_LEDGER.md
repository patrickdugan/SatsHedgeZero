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
| G-FED-1 | Federated member vote transport between independent hosts | PARTIAL: transport DONE and tested over loopback (`remote.rs`, `member.rs`, `shz-relay member`): five member tasks with own key, own durable lock and own collator vote on relay proposals only when their independently built digest matches; 4-of-5 certificates, linked-skip chaining after quorum timeouts, equivocation evidence, key-registry auth, trusted mode refuses members; bench `evidence/hft06/relay_bench_federated_remote_windows.json` (30 s, 0 timeouts, boundary-to-certificate p50 12.3 ms). OPEN: deployment on 3–5 separate hosts with independent source credentials, cross-host clock bounds, WebSocket keepalive/heartbeat for dead-peer detection, TLS between relay and members | `cargo test --locked -p shz-relay`; `shz-relay bench --mode federated-remote --clients 2 --seconds 30`; per host `SHZ_MEMBER_SIGNING_KEY_FILE=… shz-relay member --config member.json` |
| G-FED-2 | Audited threshold packet signer | OPEN: `ThresholdPacketSigner` trait only | Packet-specific DKG, durable nonce state, disjoint from FROST maturity nonces |
| G-NET-1 | Measured multi-site delivery, clock uncertainty and realized lead | OPEN: loopback only (premium-vs-standard p50 197.7 ms trusted, 181.7 ms federated) | Deploy relay + 3 subscriber sites; `shz-relay subscribe ... --count 18000` per site with PTP/NTP offset logs |
| G-LN-1 | Real Lightning commitment updates and fee receipt verification (LDK) | OPEN, design chosen: commitment evidence from a wrapping LDK `Persist` (no commitment-number event exists), BOLT12 fee collection, DLC legs outside channel commitments; `MockAdapter` only | Sub-gates G-LN-1a..d with exit criteria in `SHZ_HFT_06_LDK.md`; regtest before Testnet4 |
| G-DEP-0 | Deployed trusted relayer on delayed public data | LIVE since 2026-11-25 at http://170.75.168.145:8090 (witness VPS, unit `shz-public-relay`), key `9d0d3aa90b879c0e91cff2cb9ef0828d6d07bb74f5ec1767f72bccb52ba1a4b1`, 5 s signed hash-chained packets from Coinbase/Kraken/Bitstamp/Gemini with on-chain Chainlink audit | `python3 ops/public-relay/verify_client.py http://170.75.168.145:8090 --pubkey 9d0d3aa9...a4b1 --follow 10`; see `ops/public-relay/README.md` |
| G-E2E-1 | Reports → collator → relay certification → tiered release → client receiver → durable tiered router → batch Commit → fee ledger | DONE (single process, synthetic keys and funds) | `cargo test --locked -p shz-dex --test hft06_e2e_relay` |
| G-LN-2 | Tiered router journal (durable WAL) | DONE: `DurableTieredRouter` journals every tiered command, enforces the signed acknowledgement state machine, and feeds `FeeLedger` | `cargo test --locked -p shz-dex --test hft06_tiered_durable` |
| G-CAL-1 | 48 h public immediacy calibration | DONE: run 45422703126, 48/48 clean hours; achievable causal policy selects free; paid round trips −1.50 / −4.49 bps | Results in `research/public_l2/IMMEDIACY.md`; next: fresh dates after design freeze |
| G-CAL-2 | TradingMoneyball private L2 caches and Core execution tapes | BLOCKED: not present on this machine | Run `immediacy.py hour --book <cache parquet>` on the cache host with an adapter to `pilot.Book` |
| G-CAL-3 | Client request congestion | BLOCKED: not observable in public L2 | Requires relay/router request traces |
| G-SEC-1 | Independent security review (relay auth, envelopes, ledger) | OPEN | External reviewer |
| G-LEGAL-1 | Market data licensing, derivatives and fee arrangements | OPEN | Counsel review before any paid tier |

## CI evidence

| Run | Workflow | Result |
| --- | --- | --- |
| 45422703072 | shz-hft06-oracle-relay (tests, Linux relay and router benches) | success |
| 45422703126 | shz-hft06-immediacy-calibration | success |
| 45424124125 | shz-hft06-evidence-annotations (aggregates as public notices) | success |
| 45422702655 | shz-mnr05-bitvm3-ln-dlc | failure, also failing on the HFT-05 base adc01e1 (runs 45384479068, 45384468149); green on main 9ae87d1 |

## Reproduce

```
cargo test --locked -p shz-oracle -p shz-relay -p shz-dex -p shz-dlc -p shz-margin
cargo run --release -p shz-relay --bin shz-relay -- bench --clients 2 --seconds 30 --mode federated-remote --out relay_bench_fed_remote.json
cargo run --release -p shz-relay --bin shz-relay -- bench --clients 4 --seconds 60 --out relay_bench.json
cargo run --release -p shz-relay --bin shz-relay -- bench --clients 4 --seconds 30 --mode federated --out relay_bench_fed.json
cargo run --release -p shz-dex --example hft06_router_bench -- --orders 20000 --out router_bench.json
cargo run --release -p shz-relay --bin shz-collator -- gen-fixture --origin-us 1800000000000000 --seconds 120 --out rec.jsonl
cargo run --release -p shz-relay --bin shz-collator -- replay --recording rec.jsonl --origin-us 1800000000000000
python -m unittest research/public_l2/test_immediacy.py
```

Windows: add `+stable-x86_64-pc-windows-msvc` to cargo (the GNU toolchain lacks `dlltool` for tokio).
