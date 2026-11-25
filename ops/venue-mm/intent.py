"""IntentV6 id, BIP340 signing, JSON builder and P2TR testnet4 address (stdlib only).

The id encoding mirrors `IntentV6::id` in crates/shz-dex/src/routing/tiered.rs.
Authoritative check: `python intent.py --verify-server http://127.0.0.1:8095`
posts a sample intent to `POST /api/intent-id` and compares the server's id.
"""
import json
import os
import struct
import sys
from hashlib import sha256

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public-relay"))
import bip340  # noqa: E402

DOMAIN_INTENT = b"SHZ/HFT06/INTENT/V1"
ACTIONS = {"post": 1, "take": 2, "cancel": 3}
SIDES = {"long": 1, "short": 2}
TIERS = {"standard": 0, "intermediate": 1, "premium": 2}
ZERO32 = "00" * 32


def tagged_hash(tag, msg):
    return bip340.tagged_hash(tag, msg)


def intent_id(i, tpl):
    """`i`: IntentJson-like dict; `tpl`: GET /api/template (scope, router, tariff_version, execution_policy)."""
    sc = tpl["scope"]
    b = bytes.fromhex(sc["network"]) + struct.pack("<Q", sc["epoch"]) + bytes.fromhex(sc["policy"])
    b += struct.pack("<I", tpl["router"])
    b += bytes.fromhex(i["channel"]["txid"]) + struct.pack("<I", i["channel"]["vout"])
    b += bytes.fromhex(i["owner"])
    b += struct.pack("<QQ", i["sequence"], i["expires_us"])
    b += bytes([ACTIONS[i["action"]], SIDES[i["side"]], TIERS[i["tier"]]])
    b += struct.pack("<I", tpl["tariff_version"])
    b += bytes.fromhex(i.get("entitlement_digest") or ZERO32)
    b += bytes.fromhex(tpl["execution_policy"])
    b += struct.pack("<QQI", i["quantity"], i["limit_usd"], i["leverage_bps"])
    b += struct.pack("<IQQ", i["max_fee_ppm"], i["max_fee_sats"], i["max_mark_age_us"])
    b += bytes([1 if i["early_window_opt_in"] else 0])
    b += bytes.fromhex(i["cancel_target"])
    return tagged_hash(DOMAIN_INTENT, b)


def build_intent(sk, tpl, channel, *, sequence, expires_us, action, side, quantity=0, limit_usd=0,
                 leverage_bps=0, max_mark_age_us=0, tier="standard", max_fee_ppm=0, max_fee_sats=0,
                 cancel_target=ZERO32, entitlement_digest=None, early_window_opt_in=False):
    i = {
        "owner": bip340.pubkey(sk).hex(),
        "channel": {"txid": channel["txid"], "vout": channel["vout"]},
        "sequence": sequence, "expires_us": expires_us, "action": action, "side": side, "tier": tier,
        "quantity": quantity, "limit_usd": limit_usd, "leverage_bps": leverage_bps,
        "max_fee_ppm": max_fee_ppm, "max_fee_sats": max_fee_sats, "max_mark_age_us": max_mark_age_us,
        "early_window_opt_in": early_window_opt_in, "cancel_target": cancel_target,
    }
    if entitlement_digest:
        i["entitlement_digest"] = entitlement_digest
    iid = intent_id(i, tpl)
    i["signature"] = sign(sk, iid).hex()
    return iid.hex(), i


def sign(sk, msg32):
    return bip340.sign(msg32, sk, os.urandom(32))


# ---- P2TR (BIP86 key path) address ----
_CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for k in range(5):
            chk ^= gen[k] if (top >> k) & 1 else 0
    return chk


def _hrp_expand(h):
    return [ord(c) >> 5 for c in h] + [0] + [ord(c) & 31 for c in h]


def bech32m_encode(hrp, witver, prog):
    acc, bits, data = 0, 0, [witver]
    for byte in prog:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 0x2BC830A3
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CH[d] for d in data + chk)


def taproot_output_key(internal_x32):
    """BIP86: Q = P + H_TapTweak(P)·G with an empty script tree."""
    pt = bip340._lift_x(bip340._int(internal_x32))
    t = bip340._int(tagged_hash("TapTweak", internal_x32))
    q = bip340._add(pt, bip340._mul(bip340.G, t))
    return bip340._bytes(q[0])


def p2tr_address(internal_x32, hrp="tb"):
    return bech32m_encode(hrp, 1, taproot_output_key(internal_x32))


def address_for_secret(sk, hrp="tb"):
    """Key-path address whose *internal key* is the owner's x-only key (what the venue checks)."""
    return bech32m_encode(hrp, 1, taproot_output_key(bip340.pubkey(sk)))


# ---- HTTP helpers ----
def http(method, url, body=None, timeout=10):
    import urllib.request, urllib.error
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw.decode(errors="replace")}


def verify_server(url):
    url = url.rstrip("/")
    st, tpl = http("GET", url + "/api/template")
    assert st == 200, tpl
    sk = bytes.fromhex("00" * 31 + "07")
    iid, intent = build_intent(sk, tpl, {"txid": "11" * 32, "vout": 0}, sequence=1, expires_us=2_000_000_000_000_000,
                               action="post", side="long", quantity=5, limit_usd=90000, leverage_bps=20000,
                               max_mark_age_us=15_000_000)
    st, r = http("POST", url + "/api/intent-id", {"intent": intent})
    ok = st == 200 and r.get("id") == iid
    print(json.dumps({"local": iid, "server": r, "match": ok}))
    return ok


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-server":
        sys.exit(0 if verify_server(sys.argv[2]) else 1)
    print("usage: intent.py --verify-server URL")
    sys.exit(2)
