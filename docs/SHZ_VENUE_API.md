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
- `GET /api/account/{owner}` -> `AccountView` `{"owner","label","outpoint","balance": {"cap","free","resting","pending","committed","paid_fees","realized_pnl","equity"}, "position": {"net_usd","committed_net_usd","unsettled_usd","avg_entry_usd","unrealized_sats","margin_sats","lots": [{"side","qty_usd","entry_usd","margin_sats","counterparty_margin_sats"}],"realized_pnl_sats","gross_traded_usd"}, "open_orders": [...], "fills": [...], "pending_signatures": [{"id","kind","message","context"}]}`. `balance` conserves `free + resting + pending + committed + paid_fees = cap + realized_pnl`; `equity = cap + realized_pnl`. `position.net_usd` is the committed lots plus fills whose batch has not committed (`unsettled_usd`).
- `POST /api/signatures` `{"owner": hex32, "items": [{"id", "signature": hex64}]}` completes batch approvals and channel acknowledgements (see Settlement).
- `GET /v1/candles?instrument=SHZ-BTCUSD-INV&interval=1m&limit=900` and `WS /v1/stream?instrument=SHZ-BTCUSD-INV&interval=1m`: the BitcornWisdom relay protocol (`docs/EMBED.md` in BitcornWisdom), candles built from venue trades; minutes with no trade carry the oracle mark as a zero-volume candle.
- `WS /api/stream`: JSON frames `{"type": "book"|"trade"|"mark"|"batch"|"account", ...}` pushed on change.

## Settlement plumbing

Fills are sealed into 100 ms batches (HFT-03 `Batch`). Each batch then needs:

1. an approval signature from every participating channel owner (`kind: "batch_approval"`, message = `Batch::approval_message`);
2. a channel acknowledgement per lane signed by owner, peer and monitor (`kind: "channel_ack"`, message = `DurableTieredRouter::ack_message`). On testnet the venue runs a **simulated channel adapter** holding the peer and monitor keys; no Lightning channel exists yet (see `docs/SHZ_HFT_06_LDK.md`).

Owners fetch these from `pending_signatures` and post them to `/api/signatures`. The demo clients sign automatically for their own channel. A batch moves `sealed -> prepared -> committed`; the fee ledger then shows accrued and committed fees per recipient.

### Margin release

Each account holds one position: FIFO lots, all on one side (`shz_dex::routing::positions`). When a
batch commits, each account's legs net against its open lots, oldest first:

- a leg on the same side as the lots (or a flat account) opens a lot; its margin moves pending -> committed;
- a leg on the opposite side closes lots. Each closed lot's margin leaves `committed`, and the lot pays
  out to `free` exactly as its opening DLC leg would settle at the closing fill's price
  (`InverseContractSpec::payout_at_price`, with the lot's margin and its opening counterparty's margin).
  `realized_pnl` moves by payout minus released margin. The closing leg's own margin for the closed
  quantity returns to `free`; any excess quantity (a flip) opens a lot on the new side.

The venue nets at the account, as a central counterparty: a lot opened against one account can be closed
against another. The payout clamp is the DLC rule, so a loss never exceeds the lot's margin and a gain
never exceeds the opening counterparty's margin for that quantity. Gains are funded by the margin still
committed in open lots on the other side. Reducing orders still need free margin when they match; it
comes back when their batch commits.

The settlement is computed from the account's position after the previous resolution and the batch's
legs, and it is bound into every lane's channel acknowledgement: once margin release is on, acks use
the tag `SHZ/HFT06/CHANNEL-ACK/V2` and append the lane's opened, closed-leg and released margin, payout,
closed quantity, net position before and after, and margin after. Owner, peer and monitor sign it; an
ack without it does not resolve. A fenced abort moves no position.

Margin release is switched on by one journaled `EnableMarginRelease` event, which the venue records on
startup if the journal lacks it. On a journal that predates it, replay runs the old events unchanged,
then the event rebuilds every position from the committed batches in sequence order and releases their
offset margin. `GET /api/status` reports `"margin_release": true`.

### Liquidation

Every lot is a fully collateralized DLC leg, so the backstop is the contract: a lot's payout to its owner is clamped at 0 past its bankruptcy price, and nobody can owe more than they posted. On top of that the venue runs a perps-style risk layer (`crates/shz-venue/src/risk.rs`), recomputed on every FROST mark:

- `position.risk` in `GET /api/account/{owner}`: `state` (`flat | ok | warning | maintenance | bankrupt`), `margin_bps` (exact clamped DLC value of the open lots at the mark over their notional in sats), `equity_sats`, `notional_usd`, `liquidation_price_usd` (where `margin_bps` falls below maintenance), `bankruptcy_price_usd` (where the position is worth 0), per-lot `bankruptcy_price_usd` (`InverseContractSpec::{long,short}_liquidation_price_usd`; `null` for a short covered at 1x or more), and `params`.
- Thresholds: maintenance 500 bps, warning 750 bps. `bankrupt` means at least one lot is at or past its bankruptcy price.
- Below maintenance (`reduce_only: true`) `POST /api/intents` accepts only posts and takes on the side opposite the position with `quantity` no larger than the committed lots (`account is maintenance (margin below 500 bps): only orders that reduce the position ...`). Cancels are always accepted.
- Below maintenance `position.risk.liquidation` carries the partial-liquidation plan from `shz_margin::liquidation_auction::compute_partial_liquidation_tranche`: `reduce_side`, `tranche_usd` (the least notional whose close restores 800 bps), `limit_usd` (mark moved against the account by the auction discount), `auction_discount_bps` (grows linearly from 0 to 200 bps over 60 s from the first mark that saw the breach), `penalty_sats`, `post_margin_bps`, `elapsed_ms`.
- WebSocket `{"type":"risk","owner","state","margin_bps","mark_usd"}` when an account's state changes.

The venue never signs for an account. The page (`ui/venue/liquidate.js`) executes the plan with the account's own key: reduce-only fill-or-kill takes against bids (closing a long) or asks (closing a short) at or inside `limit_usd`, one resting quote per take, on the Standard tier (0 taker fee), at most every 5 s, until the account is back above maintenance. It is on by default and can be switched off per browser. With clearing active, a take that reduces the position borrows its leg margin from the lots it closes (`TieredRouter::closing_loan`, `docs/SHZ_VENUE_CLEARING.md`), so an account with no free margin can still close; only a flip's excess and the taker fee come from free. An account whose page is closed keeps the contract backstop only: its lots run to their bankruptcy price and stop there. The closes are ordinary fills and clear through the central-counterparty netting above; multilateral clearing and the default waterfall for losses past a lot's bankruptcy price are in `docs/SHZ_VENUE_CLEARING.md`.

## Wallet connect

The page offers "Connect wallet" with a Nostr browser extension, a Lightning wallet (LNURL-auth QR) or a local key. No private key is pasted anywhere.

**What a wallet signs, and what it does not.** The router checks raw BIP340 signatures by the account owner over venue-chosen 32-byte messages (allocation digest, intent id, batch approvals, channel acks). NIP-07 can only sign Nostr events and LNURL-auth can only sign `k1`, so a wallet cannot produce those. A wallet therefore authorizes a **trading key** once, with an expiry, and the trading key signs everything as before. The account owner is the trading key; the wallet key is recorded next to it (`wallet_link` in `AccountView`, `GET /api/wallet/link/{trading_key}`) and journaled in `venue.jsonl`.

Both sides consent to a link. The wallet proves control of its key (Nostr event or LNURL ECDSA signature) and the trading key BIP340-signs the same link hash, so nobody can attach someone else's key to their wallet:

```
link_hash = tagged_hash("SHZ/VENUE/WALLET-LINK/V1",
  network[32] || len u8 || kind ("nostr"|"lnurl") || len u8 || wallet key (32 B x-only, or 33 B compressed for lnurl)
  || trading_key[32] || nonce[32] (Nostr challenge MAC, or lnurl k1) || expires_us u64le)
```

Rules: a link lasts 24 h (`expires_us`). Once a link has expired, the venue rejects `/api/intents` and `/api/signatures` for that trading key (HTTP 409 `wallet authorization expired; reconnect the wallet`); reconnecting with the same wallet renews it. A trading key stays bound to the first wallet that authorized it (`trading key is bound to another wallet`). Accounts with no link (local key, market makers) are unaffected. The trading key lives in the browser's localStorage, per wallet, so clearing site data loses the account like it does for a local key.

### Nostr (NIP-07, `window.nostr`)

1. `POST /api/wallet/nostr/challenge` `{"wallet": hex32, "trade_key": hex32}` (wallet = `getPublicKey()`) -> `{"challenge" (hex of trade_key[32] || link_expires_us u64be || expires_us u64be || mac[32]), "hash" (= link_hash), "venue" (network hex), "req": "wallet-link", "kind": 27810, "expires_us" (challenge, 5 min), "link_expires_us"}`.
2. The page asks the extension to `signEvent` an event of kind **27810** with tags `["shz-venue", venue]`, `["shz-req", "wallet-link"]`, `["shz-hash", hash]`, `["shz-challenge", challenge]` and a human-readable `content` naming the trading key. The trading key signs `hash` with BIP340.
3. `POST /api/wallet/nostr/link` `{"event": <signed event>, "session_signature": hex64}` -> `{"trade_key", "link": {"kind","wallet","issued_us","expires_us"}}`.

The venue's envelope check (`verify_nostr_envelope` in `crates/shz-venue/src/wallet.rs`) recomputes the NIP-01 event id (`sha256` of `[0,pubkey,created_at,kind,tags,content]`), verifies the BIP340 signature over it, requires `created_at` within 5 min, kind 27810, exactly one each of the `shz-venue`, `shz-req` and `shz-hash` tags equal to what the venue expects (so an event is not replayable for another venue, request or hash), and the signer to be the wallet the challenge was issued to. Challenges are single-use. Control characters in content and tags are refused so every serializer produces the same id. `ui/venue/test/nostr_vector.json` is a signed event shared by the Rust and JS tests.

### LNURL-auth (LUD-04)

1. `POST /api/wallet/lnurl/start` `{"trade_key": hex32, "origin": "https://host"}` -> `{"k1", "callback", "lnurl" (uppercase bech32, for the QR), "expires_us" (5 min)}`. The k1 is bound to `trade_key`; `origin` must be https (http only for localhost).
2. The wallet scans the QR and calls `GET /api/wallet/lnurl/callback?tag=login&action=login&k1=..&t=<trade_key>&e=<expires_us>&sig=<DER ECDSA over the 32 k1 bytes, no extra hash>&key=<33-byte compressed linking key>` -> `{"status":"OK"}` or `{"status":"ERROR","reason":".."}` (HTTP 200, as LUD-04 requires). High-S signatures are accepted. A k1 works once and expires after 5 min.
3. The page polls `GET /api/wallet/lnurl/status?k1=..` -> `pending | expired | authed {wallet, hash, link_expires_us} | linked`. A k1 no wallet has signed is always `pending`; the page stops at the `expires_us` it got in step 1. On `authed` it signs `hash` with the trading key and sends `POST /api/wallet/lnurl/confirm` `{"k1", "session_signature"}`, which installs the link.

Because the trading key is fixed when the k1 is issued and must sign the final hash, a different key cannot be swapped in between scan and confirm.

### Server state

Starting a login stores nothing. The Nostr challenge MAC and the LNURL k1 are keyed hashes, under a secret drawn at venue start, over the network, the trading key, the expiries and (Nostr) the wallet key; the later step recomputes and compares them. State is created only after a wallet signature verifies: used Nostr challenges (until they expire) and signed k1s, each in a table of at most 4,096 entries that drops expired entries and then the oldest when full. Unauthenticated requests therefore cannot fill a table and lock other users out. A venue restart invalidates outstanding challenges and QR codes (5 min each); installed links are journaled and survive it.

### Wallets

Named in the connect modal. None has been exercised against this venue with a real wallet yet.

| Wallet | Path | Platform |
|---|---|---|
| Alby (browser extension) | Nostr NIP-07 | Chrome, Firefox |
| nos2x | Nostr NIP-07 | Chrome |
| Phoenix | LNURL-auth QR | Android, iOS |
| Zeus | LNURL-auth QR | Android, iOS |
| Breez | LNURL-auth QR | Android, iOS |
| BlueWallet | LNURL-auth QR | Android, iOS |
| Blixt | LNURL-auth QR | Android, iOS |
| Alby Go (mobile) | LNURL-auth QR | Android, iOS |
| any WebLN provider | alias display only | browser |

Any other NIP-07 extension or LUD-04 wallet uses the same paths. The QR path needs the venue on https.

### WebLN

If `window.webln` exists the modal offers to show its `getInfo()` alias. This is display only: the venue has no Lightning backend (the channel adapter is simulated, see Settlement plumbing), so `sendPayment` and `makeInvoice` are never called, and a WebLN node key is not used for authentication.

## Explorer

- `GET /api/explorer/packets?limit=50` -> oracle packets the venue ingested: seq, slot, status, median, digest, signers, `verified`.
- `GET /api/explorer/fill/{id}` -> one fill end to end: taker and maker intents, the oracle packet it bound (digest, seq, slot, median, verified), the fill binding hash (`Fill.mark_id`) and its preimage fields, tariff and execution policy ids, fees and the oracle/router split, the batch (seq, digest, phase), approvals and acknowledgement status, fee-ledger state.
- `GET /api/explorer/batches?limit=50`, `GET /api/explorer/batch/{seq}`. A committed batch carries `settlements`: per lane, `opened_margin_sats`, `closed_leg_margin_sats`, `released_margin_sats`, `payout_sats`, `realized_pnl_sats`, `closed_usd`, `net_before_usd`, `net_after_usd`, `margin_after_sats` (the values its acks signed; batches committed before margin release was on show the values rebuilt when it was switched on).
- `GET /api/explorer/accounts` -> every allocation: owner, outpoint, kind, cap, label, balance (with `realized_pnl`), position, mempool.space link for `utxo` accounts.
- `GET /api/explorer/journal` -> journal tip (records, digest) and config hash.
- `GET /api/explorer/dlc` -> the FROST relay's `/v1/dlc/events`, proxied.

Every explorer object links to the objects it binds (fill -> packet, batch, intents, account; batch -> fills, approvals, acks).

## Running it

```
cargo run -p shz-venue -- --listen 127.0.0.1:8095 --state ./venue-state --ui ui/venue
python ops/venue-mm/mm.py run --server http://127.0.0.1:8095
```

Open `http://127.0.0.1:8095/` for trading and `/explorer.html` for the plumbing. State lives in `--state`: `router.wal` (the HFT-06 journal), `fees.wal` (fee ledger), `venue.jsonl` (account labels), `venue.seed` (venue key seed). On restart the venue rebuilds its views from the router journal: resting quotes, every sealed batch with its fills and phase, and the signatures each unresolved batch still needs (acknowledgements for a prepared batch are regenerated). Oracle packets and rejected intents are not journaled, so a fill sealed before a restart shows its binding hash but not the packet body.

### Deadline abort

Batches resolve strictly in order. If the batch at the head of the queue still lacks approvals or
channel acks 10 s (`ABORT_AFTER_US`) after its window ended, the venue fences and aborts it with the
adapter's peer and monitor signatures (owner signature all-zero), via `DurableTieredRouter::expire`.
Nothing moves on any channel. Every debit returns to free, the maker quotes behind its fills are
cancelled, and the fills no longer count in positions. Pending signature requests for that batch are
withdrawn, and its stream event is `{"type":"batch","phase":"aborted"}`. Sign within 10 s of a fill
to keep it.

### Public testnet deployment

https://shz-venue.170-75-168-145.sslip.io/ (explorer at `/explorer.html`) runs on the witness host next to the FROST relay. Kit: `ops/venue-deploy/`.

- `shz-venue.service`: user `shzvenue`, binary `/opt/shz-venue/bin/shz-venue`, listens on 127.0.0.1:8096, reads marks from the local FROST relay (`http://127.0.0.1:8091`, group key pinned), state in `/var/lib/shz-venue`, MemoryMax 200M.
- `shz-venue-mm.service`: resident market maker on a demo-credit account whose key is generated on the host (`/var/lib/shz-venue-mm/mm.key`), quotes expire after 300 s.
- `shz-venue-mm-utxo.service`: market maker on the operator's funded testnet4 output (user `shzvmmu`). It starts only when the operator has placed the key at `/var/lib/shz-venue-mm-utxo/mm.key` (0600) and `UTXO=<txid>:<vout>` in `/etc/shz-venue/mm-utxo.env`.
- Caddy terminates TLS for the sslip.io name and proxies HTTP and WebSocket to the venue (`Caddyfile.snippet`).
- Install from a Linux checkout: `cargo build --release -p shz-venue` (with `CARGO_BUILD_JOBS=1` on a 1-vCPU host), then `sudo ops/venue-deploy/install.sh`.

The market maker reposts only when the mark moves `--requote-bps` (default 5), its inventory changes, or its quotes reach 2/3 of their expiry. Reposting on every 5 s mark grew `router.wal` by about 3.4 KB/s with two makers; with the threshold and 300 s expiry it grows by about 0.34 KB/s.
