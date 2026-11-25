# SHZ public trusted relayer

A deployed, deliberately simple oracle relayer: every 5 s it reads free public BTC/USD sources and publishes one BIP340-signed packet, hash-chained to the previous one. The data is late (public REST tickers and an on-chain feed, not a low-latency stream), and trust rests on one relay key and its operator. It is the trusted-relay starting point of HFT-06; the federated 4-of-5 mode in `crates/shz-relay` is the upgrade path.

## Live endpoint

Deployed 2026-11-25 on the witness VPS as systemd unit `shz-public-relay`:

```
http://170.75.168.145:8090/healthz
http://170.75.168.145:8090/v1/latest
http://170.75.168.145:8090/v1/packet/<seq>
http://170.75.168.145:8090/v1/stream          (Server-Sent Events)
http://170.75.168.145:8090/v1/archive/<YYYY-MM-DD>.jsonl
http://170.75.168.145:8090/v1/pubkey
```

Relay key (BIP340, x-only), pin it rather than fetching it:

```
9d0d3aa90b879c0e91cff2cb9ef0828d6d07bb74f5ec1767f72bccb52ba1a4b1
```

Plain HTTP; integrity comes from the signature and chain, not the transport.

## Packet

`body` fields: `schema` (`shz-public-relay/v1`), `market`, `data_class` (`public_delayed`), `seq`, `previous` (digest of packet `seq-1`), `interval_ms`, `slot_us`, `assembled_us`, `status` (`VALID` or `HOLD` with `hold_reason`), `median_e8`, `dispersion_bps`, `audit_deviation_bps`, `fast_sources_used`, and per-source `{id, role, ok, fetched_us, source_ts_us, ts_from_fetch, age_us, response_sha256, error}`.

Signed message: `tagged_hash("SHZ/PUBLIC-RELAY-PACKET/V1", canonical_json(body))` (BIP340 tagged hash, JSON with sorted keys and no spaces). `digest` is that message; `signature` is BIP340 over it.

Per-exchange prices are not published. They are kept with the raw responses in the relay's private archive (2-day retention) and committed to by `response_sha256`, so the operator can prove what each source returned.

## Rules

| Role | Sources | Use |
| --- | --- | --- |
| fast | Coinbase, Kraken, Bitstamp, Gemini public tickers | median; fresh if source time (or fetch time when the ticker has none) is within 30 s |
| audit | Chainlink BTC/USD aggregator on Ethereum (`0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c`, `latestRoundData` via a public RPC) | slow reference (0.5% deviation / 1 h heartbeat); fresh within 65 min |

VALID needs at least 3 fresh fast sources, fast-source dispersion of at most 50 bps, and the median within 150 bps of the audit value when the audit is available. Otherwise HOLD with `insufficient_fresh_sources`, `dispersion` or `audit_divergence`. Source signatures are not verified (these sources publish none). The Pyth Hermes public endpoint returned HTTP 401 on 2026-11-25, so Pyth is not used.

## Operation

```
python3 -m unittest test_public_relay            # offline: BIP340 vector, rules, chain, restart, tamper
python3 public_relay.py --state ./state --once   # one live packet
python3 verify_client.py http://170.75.168.145:8090 --pubkey 9d0d3aa9...a4b1 --follow 10
cargo test -p shz-relay --test public_relay_signature   # Rust verifies a Python-signed packet
```

Deploy (as on the VPS): system user `shzrelay`, code in `/opt/shz-public-relay`, `shz-public-relay.service` (MemoryMax 150M, CPUQuota 30%, ProtectSystem=strict). The signing key is generated on first start in `/var/lib/shz-public-relay/relay.key` (0600) and never leaves the box. Each packet is fsync'd to the archive before it is served; on restart the relay verifies the archive tail and continues the chain at `seq + 1`, refusing to start if the tail does not verify. Missed slots (fetch stall, suspend) show up as gaps in `slot_us` with consecutive `seq`.

Not provided: provider authentication, sub-second latency, redundancy, TLS, independent signers. Exchange market-data terms apply to any commercial redistribution of the median.
