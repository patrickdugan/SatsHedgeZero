# venue-mm: tiny testnet market maker for shz-venue

Testnet only. Stdlib Python; reuses `../public-relay/bip340.py`. API contract: `docs/SHZ_VENUE_API.md`.

## Run against a local venue

```
python mm.py --selftest                 # offline quote-planning checks
python -m unittest test_intent          # BIP340, BIP86 address, intent id vector
python intent.py --verify-server http://127.0.0.1:8095   # authoritative id check (POST /api/intent-id)
python mm.py run                        # demo account, 2 levels/side, 5 USD, 15 bps spread
python mm.py run --dry-run              # build and sign intents, print them, send nothing
```

Flags: `--server --state-dir --levels --size-usd --spread-bps --step-bps --max-net-usd --leverage-bps
--max-mark-age-s --expires-s --requote-bps --poll-s --utxo txid:vout --wallet --fund-btc --dry-run`.

The key is `state/mm.key` (hex, mode 0600, never printed). `state/mm_state.json` holds the account outpoint
and open quote ids; on restart the bot cancels leftovers first. Output is one JSON line per action.

## Behaviour

- Polls `/api/status` every 2 s (no websocket client; stdlib has none). A new mark `seq` that moved at least
  `--requote-bps` (default 5) from the last quoted mark, an inventory change, or quotes at 2/3 of their expiry
  cancels the old quotes and posts the ladder at mark -/+ (spread + k*step) bps, rounded away from the mark, inside the 200 bps collar.
- No quotes when the mark is HOLD, unverified, missing or older than 20 s; existing quotes are cancelled.
- Inventory: net position skews both sides against it by up to one spread at the cap; a side stops when
  net +/- the ladder size would pass `--max-net-usd`.
- Pending `batch_approval` / `channel_ack` items for its own account are signed and posted each cycle.
- Standard tier (maker fee 0), 2x leverage, mark age limit 15 s, quotes expire after 60 s.

## Funding with tBTC (operator's decision)

Default is the `demo` account (TESTNET DEMO CREDIT, 200,000 sats, no coins behind it). For a real outpoint:

```
python mm.py init --wallet <wallet> --fund-btc 0.0005
```

prints the key's P2TR key-path address (`tb1p...`, BIP86 tweak, empty tree) and the exact
`bitcoin-cli -testnet4 -rpcwallet=<wallet> send '{"<addr>": <btc>}'` command. The bot never broadcasts.
After the transaction confirms: `python mm.py run --utxo <txid>:<vout>` (vout paying that address; the txid hex is
passed to the venue as-is).

## Risks

Testnet coins and a testnet venue: no value, but the venue can reject, restart, or lose state. Collateral in a
`utxo` account is only checked at registration. The key file controls the account; keep it out of git
(`state/` is ignored). Quotes can fill against a stale view between polls; sizes are deliberately tiny.

## Options market maker (`options_mm.py`)

For a venue started with `--options` (docs/SHZ_VENUE_OPTIONS.md). Testnet only, stdlib only, same
`bip340.py` and HTTP helpers as `mm.py`.

```
python options_mm.py --selftest                                   # Black-76, units, shared IntentV7 vector
python -m unittest test_options_mm
python options_mm.py run --server http://127.0.0.1:18295          # demo account, fund, quote, sign acks
```

- Quotes a bid and an ask on every BTC call and every USDT put of the nearest listed expiry at least
  30 s away: Black-76 from the oracle mark (r = 0, `--vol` 0.6), `--spread-bps` 800 of the premium each
  side, floor one sat or 0.01 USDT per quote. BTC series are inverse (`C / (K * F)` BTC per USD
  notional), USDT series linear (`P * 1e-8` USD per 1e-8 BTC). Sizes `--call-qty` 100 USD,
  `--put-qty` 1,000,000 (0.01 BTC).
- Requotes (cancel all, post the ladder) when the mark moves `--requote-bps` (10) from the last
  quoted mark, when the listed expiries change, or every `--refresh-s` (120). While an option batch
  is settling the venue refuses cancels; the bot retries on the next poll.
- Signs every pending signature of its account each poll (`--poll-s` 1): V4 option acks of the
  batches its quotes fill in.
- Collateral: funds `--fund-sats` (150,000) from its perpetual demo allocation and deposits
  `--deposit-usdt` (5,000) through the venue's simulated stablecoin adapter when below target.
- Key: `<state-dir>/options_mm.key` (hex, never printed). Output: one JSON line per action.

Run against the local drill venue: `node ops/venue-bench/options_drill/drill.mjs --mm` starts a
scripted relay and venue, runs this bot, trades against its quotes and moves the mark.

## Spot maker (`spot_mm.py`)

For a venue started with `--spot` (docs/SHZ_SPOT.md): quotes BTC/USDT bids and asks around the oracle
mark from its own demo account (BTC funded from the perpetual allocation, USDT through the simulated
adapter), signs its SpotIntent orders and its spot-batch acknowledgements.

```
python spot_mm.py --selftest            # ladder on tick and lot, shared SpotIntent vector
python -m unittest test_spot_mm
python spot_mm.py run --server http://127.0.0.1:8095
```

Flags: `--server --state-dir --levels --spread-bps --step-bps --size-sats --requote-bps --refresh-s
--fund-sats --deposit-usdt --expires-s --poll-s`. Key: `<state-dir>/spot_mm.key` (hex, never printed).
Local drill: `node ops/venue-bench/spot_drill/drill.mjs` (runs this bot against a local venue).
