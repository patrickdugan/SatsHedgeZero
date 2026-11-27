"""Canonical byte encodings and ids (stdlib only).

Each function mirrors the Rust `id()` of the same structure, byte for byte:

* `perp_intent_id`   IntentV6     crates/shz-dex/src/routing/tiered.rs      SHZ/HFT06/INTENT/V1
* `option_intent_id` IntentV7     crates/shz-dex/src/routing/options.rs     SHZ/HFT06/INTENT/V7
* `spot_intent_id`   SpotIntent   crates/shz-dex/src/routing/options/spot.rs SHZ/HFT06/SPOT-INTENT/V8
* `grant_id`         AgentGrant   crates/shz-dex/src/routing/agents.rs      SHZ/HFT06/AGENT-GRANT/V1
* `revocation_id`    AgentRevocation (same file)                            SHZ/HFT06/AGENT-REVOKE/V1

`sdk/vectors/agent_vectors.json` (written by the Rust test `shared_agent_vectors`) pins
every id; tests/test_vectors.py checks this module against it.

`template` is the venue's signing context: GET /agent/v1/markets -> `perp` (scope, router,
tariff_version, execution_policy) plus `spot_pair` for spot intents.
"""
import struct

from . import bip340

ZERO32 = "00" * 32
ACTIONS = {"post": 1, "take": 2, "cancel": 3}
SIDES = {"long": 1, "short": 2}
TIERS = {"standard": 0, "intermediate": 1, "premium": 2}
INSTRUMENT_BITS = {"perps": 1, "options": 2, "spot": 4}
TAG_PERP = b"SHZ/HFT06/INTENT/V1"
TAG_OPTION = b"SHZ/HFT06/INTENT/V7"
TAG_SPOT = b"SHZ/HFT06/SPOT-INTENT/V8"
TAG_GRANT = b"SHZ/HFT06/AGENT-GRANT/V1"
TAG_REVOKE = b"SHZ/HFT06/AGENT-REVOKE/V1"


def tagged_hash(tag, msg: bytes) -> bytes:
    return bip340.tagged_hash(tag, msg)


def _u8(n):
    return struct.pack("<B", n)


def _u32(n):
    return struct.pack("<I", n)


def _u64(n):
    return struct.pack("<Q", n)


def _i64(n):
    return struct.pack("<q", n)


def _h(s, n=32):
    b = bytes.fromhex(s)
    if len(b) != n:
        raise ValueError(f"expected {n}-byte hex")
    return b


def _scope(tpl):
    sc = tpl["scope"]
    return _h(sc["network"]) + _u64(sc["epoch"]) + _h(sc["policy"])


def _op(c):
    return _h(c["txid"]) + _u32(c["vout"])


def asset_bytes(a):
    if not a or a.get("kind") == "btc":
        return _u8(1)
    proto = {"rgb": 0, "tap": 1}[a["protocol"]]
    return _u8(2) + _u8(proto) + _h(a["id"]) + _u8(a["decimals"])


def perp_intent_id(i, tpl) -> bytes:
    tier = i.get("tier", "standard")
    ent = ZERO32 if tier == "standard" else (i.get("entitlement_digest") or ZERO32)
    b = _scope(tpl) + _u32(tpl["router"]) + _op(i["channel"]) + _h(i["owner"])
    b += _u64(i["sequence"]) + _u64(i["expires_us"])
    b += _u8(ACTIONS[i["action"]]) + _u8(SIDES[i["side"]]) + _u8(TIERS[tier])
    b += _u32(tpl["tariff_version"]) + _h(ent) + _h(tpl["execution_policy"])
    b += _u64(i["quantity"]) + _u64(i["limit_usd"]) + _u32(i["leverage_bps"])
    b += _u32(i["max_fee_ppm"]) + _u64(i["max_fee_sats"]) + _u64(i["max_mark_age_us"])
    b += _u8(1 if i.get("early_window_opt_in") else 0) + _h(i.get("cancel_target") or ZERO32)
    return tagged_hash(TAG_PERP, b)


def option_intent_id(i, tpl) -> bytes:
    b = _u32(i.get("version", 7)) + _scope(tpl) + _u32(tpl["router"]) + _op(i["channel"]) + _h(i["owner"])
    b += _u64(i["sequence"]) + _u64(i["expires_us"]) + _u8(ACTIONS[i["action"]])
    legs = i.get("legs", [])
    b += _u64(len(legs))
    for leg in legs:
        b += _h(leg["series"]) + _u8(1 if leg["long"] else 0) + _u64(leg["qty"])
    b += _i64(i.get("premium_milli", 0)) + _h(i.get("cancel_target") or ZERO32)
    ol = i.get("other_limits") or []
    if ol:
        b += _u64(len(ol))
        for x in ol:
            b += asset_bytes(x["asset"]) + _i64(x["premium_milli"])
    return tagged_hash(TAG_OPTION, b)


def spot_intent_id(i, tpl) -> bytes:
    b = _u32(i.get("version", 8)) + _scope(tpl) + _u32(tpl["router"]) + _op(i["channel"]) + _h(i["owner"])
    b += _u64(i["sequence"]) + _u64(i["expires_us"]) + _u8(ACTIONS[i["action"]])
    b += _h(i.get("pair") or tpl["spot_pair"]) + _u8(1 if i.get("buy") else 0)
    b += _u64(i.get("qty_sats", 0)) + _u64(i.get("price", 0)) + _h(i.get("cancel_target") or ZERO32)
    return tagged_hash(TAG_SPOT, b)


def intent_id(instrument, i, tpl) -> bytes:
    return {"perp": perp_intent_id, "option": option_intent_id, "spot": spot_intent_id}[instrument](i, tpl)


def instrument_bits(names):
    bits = 0
    for n in names:
        bits |= INSTRUMENT_BITS[n]
    return bits


def grant_id(g) -> bytes:
    lim = g["limits"]
    sc = g["scope"]
    b = _u32(g["version"]) + _h(sc["network"]) + _u64(sc["epoch"]) + _h(sc["policy"]) + _u32(g["router"]) + _op(g["channel"])
    b += _h(g["owner"]) + _h(g["agent"]) + _u64(g["nonce"]) + _u64(g["issued_us"]) + _u64(g["expires_us"])
    b += _u8(instrument_bits(g["instruments"])) + _u8(1 if g.get("may_withdraw") else 0)
    b += _u64(lim["max_order_notional_usd"]) + _u64(lim["max_daily_notional_usd"]) + _u32(lim["max_open_orders"])
    b += _u32(lim["max_orders_per_minute"]) + _u32(lim["collar_bps"])
    return tagged_hash(TAG_GRANT, b)


def revocation_id(r, scope) -> bytes:
    b = _u32(r.get("version", 1)) + _h(scope["network"]) + _u64(scope["epoch"]) + _h(scope["policy"]) + _u32(r.get("router", 1))
    b += _h(r["grant"]) + _h(r["owner"]) + _u64(r["issued_us"])
    return tagged_hash(TAG_REVOKE, b)
