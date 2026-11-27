# Lightninger agent API v1 and delegated agent keys

Algorithmic traders and AI agents trade the Lightninger testnet venue through one versioned API,
with **delegated agent keys**: the account owner signs a grant that lets a separate agent key trade
the account inside hard limits, sign the account's batch acknowledgements for the agent's own trades
only, and never withdraw. The owner revokes it at any time; the revocation pulls the agent's resting
orders in the same journal record.

Testnet4 only. USDT on this venue is a labelled demo asset (simulated RGB adapter).

| Piece | Where |
|---|---|
| Router authority (grants, revocation, agent-signed intents, delegated acks) | `crates/shz-dex/src/routing/agents.rs`, events in `tiered_durable.rs`; tests `crates/shz-dex/tests/hft06_agents.rs` |
| Venue limits, grant views, delegated ack round | `crates/shz-venue/src/core/agents.rs` |
| API (REST + JSON-RPC over WebSocket) | `crates/shz-venue/src/agent_api.rs` |
| OpenAPI 3.1 spec (checked against the method table in a test) | `docs/agent-api/openapi.json`, served at `/agent/v1/openapi.json` |
| SDKs | `sdk/python/lightninger`, `sdk/ts` (shared vectors `sdk/vectors/agent_vectors.json`) |
| Owner panel in the browser | Settings → Agents (`ui/venue/agents.js`) |
| IronClaw / MCP | `integrations/ironclaw/` |
| End-to-end drill | `ops/venue-bench/agent_drill/drill.mjs` |

## Switching it on

`shz-venue ... --agents` journals `EnableAgents` once in the router journal and opens the write
methods. Without the flag every agent write answers `agents.off` (404) and nothing is journaled for
it; the read methods of `/agent/v1/*` are served either way. A journal without `EnableAgents`
replays byte for byte as before (router test `g1_off_by_default_and_old_journal_replays_unchanged`).
Reopening a journal that has `EnableAgents` without `--agents` keeps the agent writes off.

## Auth model

There are no API keys or sessions. Every write carries its own BIP340 signature:

| Write | Signed by | Message |
|---|---|---|
| grant | account owner (trading key) | `AgentGrant::id`, tag `SHZ/HFT06/AGENT-GRANT/V1` |
| revocation | account owner | `AgentRevocation::id`, tag `SHZ/HFT06/AGENT-REVOKE/V1` |
| order (perp, option, spot) | agent key | the intent id (IntentV6 / IntentV7 / SpotIntent v8) with `owner` = the account owner |
| batch acknowledgement | agent key | the same message the owner would sign (batch approval, V3 lane ack, V4 option/spot ack) |

The router checks the signer: an intent signed by the agent is accepted only on the agent path
under a live grant for that account and instrument; the agent's signature in the owner slot of an
approval or ack is accepted only when every leg of the batch on that account came from an intent
the same agent signed. An order the owner placed by hand is therefore never the agent's to
acknowledge.

Withdrawals and transfers (`fund`, `defund`, `deposit`, `withdraw`) verify the owner key only and
have no agent route; a grant with `may_withdraw = true` is refused by the router.

## Grants

```
AgentGrant {
  version: 1, scope, router, channel (the account's outpoint), owner, agent,
  nonce            strictly increasing per account (an old signed grant cannot be replayed)
  issued_us, expires_us   lifetime at most 30 days; judged on the router clock
  instruments      bits: perps 1, options 2, spot 4
  may_withdraw     must be false
  limits {
    max_order_notional_usd, max_daily_notional_usd (rolling 24 h),
    max_open_orders, max_orders_per_minute, collar_bps
  }
}
```

Encoding (little-endian): `u32 version | network[32] u64 epoch policy[32] | u32 router | txid[32]
u32 vout | owner[32] | agent[32] | u64 nonce | u64 issued_us | u64 expires_us | u8 instruments |
u8 may_withdraw | u64 max_order | u64 max_daily | u32 max_open | u32 per_minute | u32 collar_bps`.
Revocation: `u32 version | scope | u32 router | grant[32] | owner[32] | u64 issued_us`.

At most 4 live grants per account; the venue refuses limits above its ceiling (`server.info`
→ `grant_ceiling`). Flow: `grant.draft` returns the unsigned grant with the next nonce, its id and
a consent text; the owner's client **recomputes the id locally and compares every field with what
it asked for** (SDK `check_draft` / `checkDraft`, browser panel) before signing; `grant.create`
admits it.

### Limits and where they are enforced

| Limit | Enforced by | Error |
|---|---|---|
| grant signature, account, agent ≠ owner, no withdrawal, nonce, lifetime | router (journaled) | `grant.rejected`, `grant.signature` |
| expiry | router clock (and venue intake) | `grant.expired` |
| revocation (instant; resting and queued orders pulled) | router | `grant.revoked` |
| instrument class | router and venue | `grant.instrument` |
| cancels only of the agent's own orders | router | `venue.rejected` |
| acks only for the agent's own legs | router; venue offers only those | `ack.outside_grant` |
| notional per order | venue intake | `limit.order_notional` |
| notional per rolling 24 h (counted at acceptance) | venue intake, persisted as `agent_use` log lines | `limit.daily_notional` |
| open orders (perp queued/resting, option and spot resting) | venue intake | `limit.open_orders` |
| orders per minute (cancels count) | venue intake | `limit.rate` |
| price collar vs the mark (perp limit, spot price) | venue intake | `limit.collar` |

Notional is whole USD at the mark: perpetual `quantity`; option BTC series `qty`; stable series and
spot size × mark. Option premiums are bounded by the per-order notional, not the collar. Venue-side
checks run before anything reaches the router journal, so a refused order journals nothing. The
per-minute window is in memory (it restarts empty).

If a grant lapses between the agent's signature and the batch's prepare or resolve, the router
refuses the delegated event, the venue clears the agent's signatures and re-posts the owner's
pending signatures (the batch then commits on the owner or aborts at the deadline as before).

## API

Base path `/agent/v1`. The same methods over REST and JSON-RPC 2.0 (`/agent/v1/ws`):

| JSON-RPC method | REST | Writes |
|---|---|---|
| `server.info` | `GET /info` | |
| `server.time` | `GET /time` | |
| `market.list` | `GET /markets` (signing template, spot pair) | |
| `market.book` | `GET /book?instrument=perp\|spot\|option:<series>&depth=` | |
| `market.trades` | `GET /trades?instrument=perp\|spot\|option&limit=` | |
| `market.mark` | `GET /mark` | |
| `options.chain` | `GET /options/chain` | |
| `account.get` | `GET /account?owner=` (balances, positions, risk, clearing claim, orders, pending signatures, options, spot, grants) | |
| `grant.list` | `GET /grants?owner=&agent=` | |
| `grant.get` | `GET /grant?id=` (grant, status, consent, usage) | |
| `grant.draft` | `POST /grants/draft` | |
| `grant.create` | `POST /grants` | yes |
| `grant.revoke` | `POST /grants/revoke` | yes |
| `order.place` | `POST /orders` `{grant, instrument, intent}` | yes |
| `order.cancel` | `POST /orders/cancel` | yes |
| `order.replace` | `POST /orders/replace` `{grant, instrument, cancel, place}` (place is not sent if the cancel is refused) | yes |
| `order.list` | `GET /orders?grant=` | |
| `ack.pending` | `GET /acks?grant=` | |
| `ack.submit` | `POST /acks` `{grant, items:[{id, signature}]}` | yes |
| `intent.id` | `POST /intent-id` (client self-check) | |

WebSocket only: `subscribe {channels}`, `unsubscribe`, `resync {channel, since}`. Channels:
`book`, `trades`, `mark`, `spot.book`, `options.book`, `batches`, `account`, `grants`.

* **Sequence numbers and resync.** Every notification is `{"method":"subscription","params":{"channel","seq","data"}}`
  with `seq` +1 per event on that channel. A client that sees a jump calls `resync {channel, since}`
  and gets the missed events (`replay`) while the server holds them (last 1,000 per channel), else
  a `snapshot` and the current `seq`. A connection that falls behind gets `gap` with the channels to
  resync. Heartbeat every 15 s carries each subscribed channel's `seq`.
* **Idempotency.** Writes accept `Idempotency-Key` (REST header) or `idempotency_key` (RPC param):
  a retry with the same key and body returns the first response (`idempotent_replay: true`, 24 h);
  the same key with a different body is `idempotency.mismatch` (409). Intents also carry
  per-account sequence numbers; the router refuses a replayed sequence.
* **Rate limits.** Token bucket per grant when the call names one, else per client address:
  20/s sustained, burst 60. Every REST response carries `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Reset`; a 429 carries `Retry-After`.
* **Errors.** `{"error":{"code","message","details","retryable"}}` with the HTTP status from
  `x-error-status` in the spec; over JSON-RPC the same object is `error.data` (`error.code` is
  -32602 for invalid params, -32601 unknown method, otherwise -32000 − HTTP status).

### Example: Python

```python
from lightninger import Client, Agent, create_grant, new_key, pubkey_hex
c = Client("http://127.0.0.1:8095")
agent_sk = new_key()
# owner side, on the owner's machine (or Settings -> Agents in the browser):
g = create_grant(c, owner_sk, pubkey_hex(agent_sk), ["perps", "spot"],
                 {"max_order_notional_usd": 100, "max_daily_notional_usd": 1000, "max_open_orders": 10,
                  "max_orders_per_minute": 30, "collar_bps": 200}, expires_in_s=86_400,
                 confirm=lambda text: input(text + "\nSign? [y/N] ") == "y")
# agent side, holding only agent_sk:
a = Agent(c, agent_sk, g["id"])
a.start_autosigner()                     # signs acks for the agent's own trades
a.perp_post("long", 50, 99_500)          # quantity USD, limit USD
a.spot_take(True, 20_000, 100_100_000_000)   # 20,000 sats at 100,100.0 demo USDT
```

### Example: raw JSON-RPC

```json
{"jsonrpc":"2.0","id":1,"method":"subscribe","params":{"channels":["trades","batches"]}}
{"jsonrpc":"2.0","id":2,"method":"order.place","params":{"grant":"<id>","instrument":"perp","intent":{...signed...},"idempotency_key":"k-1"}}
{"jsonrpc":"2.0","id":3,"method":"resync","params":{"channel":"trades","since":41}}
```

## Threat model

**Prompt-injected agents.** An LLM agent reads market data and other text it does not control; an
injected instruction can make it try anything its tools allow. The grant is the boundary, enforced
by the venue and the router, not by the agent: it cannot trade outside its instruments, size,
24 h budget, open-order count, rate or collar, cannot cancel the owner's orders, cannot
acknowledge the owner's trades, and has no withdrawal or transfer path at all. The worst case is
the grant's daily notional traded badly inside the collar. Keep grants small and short. The MCP
server marks tool results as data in its instructions, offers `halt_trading`, halts itself after 5
refused trading calls in a row or on `grant.revoked`/`grant.expired`, and caps trading calls per
minute locally (default 20).

**Key leakage.** The agent key is a separate key: leaking it exposes only the grant, and the owner
revokes it in one signed message (resting and queued agent orders are pulled in the same journal
record). The owner's trading key never leaves the owner's client: the SDKs, the browser panel and
the MCP server only ever need the agent key. The MCP trading endpoint additionally requires a bearer
token that IronClaw injects at its egress boundary (the model never sees it); it listens on loopback
only and rejects non-loopback `Origin` headers. A malicious venue cannot widen a grant: owner clients
recompute the grant id and compare every field before signing.

**Runaway loops.** Per-minute order cap and open-order cap per grant, 24 h notional, per-client and
per-grant API rate limits (429 with `Retry-After`), idempotency keys so retries never double-place,
and the MCP server's local breaker. Expiry is mandatory (≤ 30 days).

**What it does not cover.** Grant limits bound size, not strategy quality; a capped agent can still
lose up to its budget. The venue is a trusted operator on testnet: the limits are checked by the
venue process and the router journal it writes (the journal is replayable and auditable, not
enforced by a third party). Settlement uses the simulated channel adapter of the testnet venue.

## Live switch-on

1. Deploy a build with this change and add `--agents` to the venue unit's command line. That
   journals one `EnableAgents` record; nothing else changes until an owner signs a grant.
2. Expose `/agent/v1/` and `/agent/v1/ws` through the existing reverse proxy (same origin as `/api/`).
3. Owners delegate from Settings → Agents in the browser or with `python -m lightninger grant`.
