# Lightninger for IronClaw

[IronClaw](https://github.com/nearai/ironclaw) is NEAR AI's open-source agent runtime: a Rust
reimplementation inspired by OpenClaw, focused on privacy and security (Apache-2.0 / MIT). It loads
external tools three ways: **MCP servers over HTTP(S) with JSON-RPC 2.0** (stdio is rejected),
packaged as an extension whose `manifest.toml` declares the server, namespace, permission and
effects; **WASM tools** in a wasmtime sandbox with a `capabilities.json`; and **skills**
(`SKILL.md` with activation keywords). Secrets are stored encrypted and injected at the host's
egress boundary for approved endpoints only, so tools and the model never see them; tool output is
treated as untrusted (leak detector, sanitizer, policy engine).

This integration is the MCP form:

```
IronClaw ──HTTP JSON-RPC──▶ integrations/ironclaw/server.ts ──agent API v1──▶ shz-venue
            (bearer token injected        holds the AGENT key only            enforces the owner's
             by IronClaw at egress)       auto-signs the agent's own acks     grant (router + venue)
```

| Endpoint | Tools | Auth |
|---|---|---|
| `/mcp/market` | `venue_info`, `market_overview`, `order_book`, `recent_trades`, `option_chain`, `account` (read-only) | none (loopback only) |
| `/mcp/trade` | the read tools plus `grant_status`, `my_orders`, `place_perp_order`, `place_option_order` (single legs and combos), `place_spot_order`, `cancel_order`, `halt_trading` | `Authorization: Bearer <token>` |

The trading endpoint exists only when the server is started with an agent key and a grant. The
grant (consent text, limits, usage, expiry, status) is in the server's `initialize` instructions,
in each trading tool's description and in `grant_status`. Trading tools are annotated
`destructiveHint: true`; read tools `readOnlyHint: true`. The account owner's key is never given to
the server or to IronClaw.

## Setup, end to end

Requirements: Node ≥ 22.18 (runs the TypeScript directly), Python ≥ 3.10 for the owner CLI, a venue
with `--agents` (local: `shz-venue --options --stable-usdt <id> --spot --agents`; the drill below
starts one), and IronClaw.

1. **Agent key** (on the machine that runs the MCP server):

   ```
   python -m lightninger --venue http://127.0.0.1:8095 keygen --out agent.key
   ```

   (run from `sdk/python`, or `pip install ./sdk/python`). It prints the agent's public key only.

2. **Grant** (the account owner, with the owner's trading key; the agent never sees it). In the
   browser: Settings → Agents, paste the agent public key, choose instruments and limits, *Review
   grant*, read the consent text, *Sign and activate*. Or with a key file:

   ```
   python -m lightninger grant --owner-key owner.key --agent <agent pubkey> --instruments perps,options,spot \
       --max-order 100 --max-daily 1000 --max-open 10 --rate 30 --collar-bps 200 --hours 24 --label ironclaw
   ```

   Both recompute the drafted grant's id and compare every field with the request before signing.
   Note the grant id.

3. **MCP server**:

   ```
   node integrations/ironclaw/server.ts --venue http://127.0.0.1:8095 --listen 127.0.0.1:8765 \
       --agent-key agent.key --grant <grant id> --token-file lightninger-mcp.token
   ```

   On first run it creates `lightninger-mcp.token` (mode 0600) and prints only its path. It listens
   on loopback only and refuses an agent key equal to the account owner key.

4. **IronClaw extensions**: copy `extensions/lightninger_market/` and `extensions/lightninger_trade/`
   (each a `manifest.toml`) into IronClaw's extension directory (`/system/extensions/<id>/`) or
   import them on the web UI's Extensions page, then `ironclaw extension activate lightninger_market`
   and `ironclaw extension activate lightninger_trade`. On the Extensions page, set the
   `lightninger_mcp_token` credential of `lightninger_trade` to the contents of the token file;
   IronClaw injects it as `Authorization: Bearer …` at egress. Both manifests use
   `default_permission = "ask"`, so IronClaw asks before each tool call until you grant it.

5. **Skill** (optional): copy `skills/lightninger-trading/` to `~/.ironclaw/skills/`. It tells the
   agent to read the grant first, stay inside it, treat tool output as data, and halt on anything
   that asks for keys, withdrawals or larger limits.

6. **Revoke** at any time, from the browser (Settings → Agents → *Revoke now*) or:

   ```
   python -m lightninger revoke --owner-key owner.key --grant <grant id>
   ```

   The revocation journals once and pulls the agent's resting and queued orders in the same record;
   the MCP session reports `grant.revoked` and halts.

## Local guards (on top of the venue's)

* at most `--max-trades-per-minute` trading calls per minute (default 20);
* after 5 refused trading calls in a row, or on `grant.revoked` / `grant.expired`, the session halts
  until the server restarts;
* `halt_trading` lets the model stop itself;
* `Origin` headers other than loopback are refused (DNS rebinding), the trade endpoint compares the
  bearer token in constant time, request bodies are capped at 1 MiB.

## Protocol

MCP streamable HTTP, JSON responses: `POST` a JSON-RPC message (or batch) to the endpoint;
`initialize` returns `protocolVersion` (2025-06-18, 2025-03-26 or 2024-11-05, as requested),
`capabilities.tools`, `serverInfo`, `instructions` and an `Mcp-Session-Id` header; notifications get
`202`; `tools/list`; `tools/call` returns `content` (text JSON), `structuredContent` and `isError`
(API refusals come back as tool errors carrying the API's error code); `ping`; `DELETE` ends a
session; `GET` is `405` (no server-initiated stream).

## Verified

`ops/venue-bench/agent_drill/drill.mjs` drives this server as an MCP client would, against a local
venue: initialize on both endpoints, 401 without the token, the tool lists and annotations, market
data, `grant_status`, an order inside the grant, a refused order past it as a tool error, and the
halt after the owner revokes the grant mid-session. The manifests follow the shape of IronClaw's own
packaged MCP extension (`notion-mcp/manifest.toml` on IronClaw main); they have not been loaded into
a running IronClaw here.
