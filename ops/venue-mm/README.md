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
--max-mark-age-s --expires-s --poll-s --utxo txid:vout --wallet --fund-btc --dry-run`.

The key is `state/mm.key` (hex, mode 0600, never printed). `state/mm_state.json` holds the account outpoint
and open quote ids; on restart the bot cancels leftovers first. Output is one JSON line per action.

## Behaviour

- Polls `/api/status` every 2 s (no websocket client; stdlib has none). A new mark `seq` cancels the old quotes
  and posts the ladder at mark -/+ (spread + k*step) bps, rounded away from the mark, inside the 200 bps collar.
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
