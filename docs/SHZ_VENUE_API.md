# SHZ venue API (testnet)

`shz-venue` runs one HFT-06 tiered router (`DurableTieredRouter`) for the market `SHZ-BTCUSD-INV` (inverse BTC/USD contracts, integer USD prices, USD notional, BTC collateral in sats). Marks come from the live FROST relay (`http://170.75.168.145:8091/v1/stream`); every packet's group signature is checked before it reaches the router. Default listen `127.0.0.1:8095`; the trading page is served at `/`, the explorer at `/explorer.html`.

All keys, digests and signatures are lowercase hex. Prices are integer USD. Quantities are USD notional. Times are Unix microseconds (`_us`) unless a field says `_ms`.

## Accounts and collateral

An account is one router allocation: an owner key (BIP340 x-only) plus a Bitcoin outpoint whose sats are the collateral cap.

- `demo` accounts: the venue authority signs an allocation over a synthetic outpoint (`txid = tagged_hash("SHZ/VENUE/DEMO-OUTPOINT/V1", owner)`, `vout = 0`) with a cap of 200,000 sats, labelled `TESTNET DEMO CREDIT` everywhere. No coins back it.
- `utxo` accounts: the outpoint must be an unspent testnet4 output paying P2TR to the owner's key (key-path, no script tree); the funding transaction must have at least 1 confirmation; the venue checks it through the mempool.space testnet4 API before signing, and the cap is its value.

Registration is two steps because the allocation needs the owner's signature too:

1. `POST /api/register/draft` `{"owner": hex32, "kind": "demo" | "utxo", "outpoint": {"txid": hex32, "vout": n} | null}` -> `{"allocation_digest": hex32, "draft_id": str, "cap_sats": n, "outpoint": {...}, "label": str}`
2. Sign `allocation_digest` with BIP340 (raw 32-byte message), then `POST /api/register` `{"draft_id": str, "owner_signature": hex64}` -> `{"account": AccountView}`.

Registration is journaled; the account exists across restarts.

## Orders

Orders are signed `IntentV6` values. The client computes the intent id exactly as `crates/shz-dex/src/routing/tiered.rs` `IntentV6::id`:

```
tagged_hash("SHZ/HFT06/INTENT/V1",
  network[32] || epoch u64le || policy[32]            (scope)
  || router u32le || channel.txid[32] || channel.vout u32le || owner[32]
  || sequence u64le || expires_us u64le
  || action u8 (Post 1, Take 2, Cancel 3) || side u8 (Long 1, Short 2) || tier u8 (Standard 0, Intermediate 1, Premium 2)
  || tariff_version u32le || entitlement_digest[32] || execution_policy[32]
  || quantity u64le || limit_usd u64le || leverage_bps u32le
  || max_fee_ppm u32le || max_fee_sats u64le || max_mark_age_us u64le
  || early_window_opt_in u8 || cancel_target[32])
```

`tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)`. The signature is BIP340 over the id.

- `GET /api/template` -> everything constant a client needs: `{"scope": {"network","epoch","policy"}, "router": n, "tariff_version": n, "execution_policy": hex32, "tariff": {"maker_ppm":[s,i,p],"taker_ppm":[s,i,p]}, "max_mark_age_us": n, "leverage_bps": {"min","max"}, "collar_bps": 200, "market": "SHZ-BTCUSD-INV"}`.
- `POST /api/intent-id` `{"intent": IntentJson}` -> `{"id": hex32}`. Debug and test-vector aid only; clients must compute the id themselves before signing.
- `POST /api/intents` `{"intent": IntentJson}` -> `{"id": hex32, "due_us": n}` or HTTP 409 `{"error": "<TierReject>"}`.

`IntentJson` fields: `owner, channel {txid, vout}, sequence, expires_us, action ("post"|"take"|"cancel"), side ("long"|"short"), tier ("standard"|"intermediate"|"premium"), quantity, limit_usd, leverage_bps, max_fee_ppm, max_fee_sats, max_mark_age_us, early_window_opt_in, cancel_target, signature`. The server fills `scope`, `router`, `tariff_version`, `execution_policy` and `entitlement_digest` (zero for standard) from the template and rejects a signature that does not match. Non-standard tiers need an entitlement: `POST /api/entitlement` `{"owner": hex32, "tier": "intermediate"|"premium"}` returns a venue-signed testnet entitlement valid for 24 h; its digest goes into the intent (the server attaches the entitlement).

Sequences must strictly increase per account (use a millisecond clock). A `post` rests on the book; a `take` is fill-or-kill against one resting quote at a price no worse than `limit_usd`; `cancel` names the maker intent id in `cancel_target`.

## Market data

- `GET /api/status` -> `{"market", "mark": {"seq","status","price_usd","slot_us","packet_digest","age_s","verified": true}, "group_key", "router": {"clock_us","resting","batch_sequence"}, "accounts": n, "journal": {"records","digest"}}`
- `GET /api/book?depth=25` -> `{"bids": [[price_usd, qty_usd, n_orders]], "asks": [...], "mark": {...}}` (bids descending, asks ascending)
- `GET /api/trades?limit=100` -> newest first `[{"id","ts_us","price_usd","qty_usd","taker_side","maker_tier","taker_tier","packet_seq","packet_digest","batch_seq"|null}]`
- `GET /api/account/{owner}` -> `AccountView` `{"owner","label","outpoint","balance": {"cap","free","resting","pending","committed","paid_fees"}, "position": {"net_usd","avg_entry_usd","unrealized_sats"}, "open_orders": [...], "fills": [...], "pending_signatures": [{"id","kind","message","context"}]}`
- `POST /api/signatures` `{"owner": hex32, "items": [{"id", "signature": hex64}]}` completes batch approvals and channel acknowledgements (see Settlement).
- `GET /v1/candles?instrument=SHZ-BTCUSD-INV&interval=1m&limit=900` and `WS /v1/stream?instrument=SHZ-BTCUSD-INV&interval=1m`: the BitcornWisdom relay protocol (`docs/EMBED.md` in BitcornWisdom), candles built from venue trades; minutes with no trade carry the oracle mark as a zero-volume candle.
- `WS /api/stream`: JSON frames `{"type": "book"|"trade"|"mark"|"batch"|"account", ...}` pushed on change.

## Settlement plumbing

Fills are sealed into 100 ms batches (HFT-03 `Batch`). Each batch then needs:

1. an approval signature from every participating channel owner (`kind: "batch_approval"`, message = `Batch::approval_message`);
2. a channel acknowledgement per lane signed by owner, peer and monitor (`kind: "channel_ack"`, message = `DurableTieredRouter::ack_message`). On testnet the venue runs a **simulated channel adapter** holding the peer and monitor keys; no Lightning channel exists yet (see `docs/SHZ_HFT_06_LDK.md`).

Owners fetch these from `pending_signatures` and post them to `/api/signatures`. The demo clients sign automatically for their own channel. A batch moves `sealed -> prepared -> committed`; the fee ledger then shows accrued and committed fees per recipient.

## Explorer

- `GET /api/explorer/packets?limit=50` -> oracle packets the venue ingested: seq, slot, status, median, digest, signers, `verified`.
- `GET /api/explorer/fill/{id}` -> one fill end to end: taker and maker intents, the oracle packet it bound (digest, seq, slot, median, verified), the fill binding hash (`Fill.mark_id`) and its preimage fields, tariff and execution policy ids, fees and the oracle/router split, the batch (seq, digest, phase), approvals and acknowledgement status, fee-ledger state.
- `GET /api/explorer/batches?limit=50`, `GET /api/explorer/batch/{seq}`
- `GET /api/explorer/accounts` -> every allocation: owner, outpoint, kind, cap, label, mempool.space link for `utxo` accounts.
- `GET /api/explorer/journal` -> journal tip (records, digest) and config hash.
- `GET /api/explorer/dlc` -> the FROST relay's `/v1/dlc/events`, proxied.

Every explorer object links to the objects it binds (fill -> packet, batch, intents, account; batch -> fills, approvals, acks).

## Running it

```
cargo run -p shz-venue -- --listen 127.0.0.1:8095 --state ./venue-state --ui ui/venue
python ops/venue-mm/mm.py run --server http://127.0.0.1:8095
```

Open `http://127.0.0.1:8095/` for trading and `/explorer.html` for the plumbing. State lives in `--state`: `router.wal` (the HFT-06 journal), `fees.wal` (fee ledger), `venue.jsonl` (account labels), `venue.seed` (venue key seed). On restart the venue rebuilds its views from the router journal: resting quotes, every sealed batch with its fills and phase, and the signatures each unresolved batch still needs (acknowledgements for a prepared batch are regenerated). Oracle packets and rejected intents are not journaled, so a fill sealed before a restart shows its binding hash but not the packet body.

### Public testnet deployment

https://shz-venue.170-75-168-145.sslip.io/ (explorer at `/explorer.html`) runs on the witness host next to the FROST relay. Kit: `ops/venue-deploy/`.

- `shz-venue.service`: user `shzvenue`, binary `/opt/shz-venue/bin/shz-venue`, listens on 127.0.0.1:8096, reads marks from the local FROST relay (`http://127.0.0.1:8091`, group key pinned), state in `/var/lib/shz-venue`, MemoryMax 200M.
- `shz-venue-mm.service`: resident market maker on a demo-credit account whose key is generated on the host (`/var/lib/shz-venue-mm/mm.key`), quotes expire after 300 s.
- Caddy terminates TLS for the sslip.io name and proxies HTTP and WebSocket to the venue (`Caddyfile.snippet`).
- Install from a Linux checkout: `cargo build --release -p shz-venue` (with `CARGO_BUILD_JOBS=1` on a 1-vCPU host), then `sudo ops/venue-deploy/install.sh`.

The market maker reposts only when the mark moves `--requote-bps` (default 5), its inventory changes, or its quotes reach 2/3 of their expiry. Reposting on every 5 s mark grew `router.wal` by about 3.4 KB/s with two makers; with the threshold and 300 s expiry it grows by about 0.34 KB/s.
