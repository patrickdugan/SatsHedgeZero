#!/usr/bin/env python3
"""Generate byte-level compatibility vectors for shz-frost-member from the Python member.

Runs the real `frost_signer` HTTP handler (`make_handler(...).do_POST/do_GET`, no socket) for
five members with a deterministic nonce stream and a fixed clock, and records every request,
status code and response body, plus each member's final nonces.json and dlc.json bytes.
`tests/vectors.rs` replays the same requests against the Rust member and requires identical
bytes.

    python crates/shz-frost-member/tests/gen_vectors.py   (writes tests/vectors.json)
"""
import hashlib
import io
import json
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "ops" / "public-relay"))
import coord_auth  # noqa: E402
import dlc_oracle  # noqa: E402
import frost  # noqa: E402
import frost_signer as fs  # noqa: E402
import public_relay as pr  # noqa: E402

N = frost.N
SCALAR_TAG = b"shz-frost-member/vector/scalar/"
AUX_TAG = b"shz-frost-member/vector/aux/"


class Stream:
    """Deterministic replacement for `secrets.randbelow(N - 1) + 1` and `os.urandom(32)`."""

    def __init__(self):
        self.k = 0
        self.a = 0

    def scalar(self) -> int:
        self.k += 1
        return int.from_bytes(hashlib.sha256(SCALAR_TAG + self.k.to_bytes(4, "big")).digest(), "big") % (N - 1) + 1

    def aux(self, n: int) -> bytes:
        self.a += 1
        return hashlib.sha256(AUX_TAG + self.a.to_bytes(4, "big")).digest()[:n]


rng = Stream()
frost.rand_scalar = rng.scalar
dlc_oracle.os = types.SimpleNamespace(**{k: getattr(dlc_oracle.os, k) for k in dir(dlc_oracle.os) if not k.startswith("__")})
dlc_oracle.os.urandom = rng.aux

S = 1_800_000_000_000_000  # first slot (a whole second)
T = S + 20_000_000  # the members' clock
pr.now_us = lambda: T


def fake(prices: dict, slot: int) -> dict:
    out = {}
    for sid, (role, _, _) in pr.SOURCES.items():
        raw = json.dumps({"sid": sid, "p": prices[sid]}).encode()
        ts = slot - 1_000_000
        out[sid] = (role, slot + 50_000, raw, (prices[sid], None if sid in ("kraken", "gemini") else ts))
    return out


BASE = {"coinbase": 10_000_000_000_000, "kraken": 10_001_000_000_000, "bitstamp": 9_999_000_000_000,
        "gemini": 10_000_500_000_000, "chainlink_eth": 10_010_000_000_000}

group, shares = frost.keygen(3, 5)
rng_start = rng.k
tmp = Path(tempfile.mkdtemp())
view = fs.StaticView()
members = {s["index"]: fs.Member(s, tmp / f"m{s['index']}", view=view) for s in shares}
steps = []


def handler(m):
    H = fs.make_handler(m, coord_auth.UNAUTHENTICATED)
    h = H.__new__(H)
    codes = []
    h.send_response = lambda c, msg=None: codes.append(c)
    h.send_header = lambda k, v: None
    h.end_headers = lambda: None
    h.wfile = io.BytesIO()
    return h, codes


def post(i: int, path: str, req=None, raw: bytes | None = None):
    raw = json.dumps(req).encode() if raw is None else raw
    h, codes = handler(members[i])
    h.rfile, h.path, h.headers = io.BytesIO(raw), path, {"Content-Length": str(len(raw))}
    h.do_POST()
    out = h.wfile.getvalue().decode()
    steps.append({"member": i, "method": "POST", "path": path, "request": raw.decode(), "status": codes[0], "response": out})
    return codes[0], json.loads(out)


def get(i: int, path: str):
    h, codes = handler(members[i])
    h.path = path
    h.do_GET()
    out = h.wfile.getvalue().decode()
    steps.append({"member": i, "method": "GET", "path": path, "request": "", "status": codes[0], "response": out})


def frost_round(idx, seq, body, parent):
    commits = [post(i, "/commit", {"seq": seq})[1] for i in idx]
    msg = pr.packet_message(body)
    zs = {}
    for i in idx:
        code, r = post(i, "/sign", {"seq": seq, "body": body, "parent": parent, "commitments": commits})
        assert code == 200, r
        zs[i] = int(r["z"], 16)
    sig = frost.aggregate(group, msg, commits, zs)
    return {"body": body, "digest": msg.hex(), "signature": sig.hex()}


# ---- FROST packets
results1 = fake(BASE, S)
view.set_from_results(results1, S)
body1, _ = pr.assemble(1, "00" * 32, S, 5000, results1)
p1 = frost_round([1, 2, 3], 1, body1, None)
body2, _ = pr.assemble(2, p1["digest"], S + 5_000_000, 5000, fake(BASE, S + 5_000_000))
p2 = frost_round([2, 3, 4], 2, body2, p1)

# ---- refusals (each must produce Python's exact error text)
off = {k: v * 10_100 // 10_000 for k, v in BASE.items()}
body3, _ = pr.assemble(3, p2["digest"], S + 10_000_000, 5000, fake(off, S + 10_000_000))
post(1, "/sign", {"seq": 3, "body": body3, "parent": p2, "commitments": []})
post(2, "/sign", {"seq": 2, "body": body2, "parent": p1, "commitments": []})
post(2, "/sign", {"seq": 1, "body": body1, "parent": None, "commitments": []})
post(5, "/sign", {"seq": 3, "body": dict(body3, previous="ab" * 32), "parent": p2, "commitments": []})
post(1, "/commit", {"seq": 0})
post(1, "/commit", {"seq": "abc"})
post(1, "/commit", {"seq": 2**70})
post(1, "/commit", {})
post(1, "/commit", raw=b"{bad")
post(1, "/commit", raw=b"")
post(1, "/nope", {"seq": 1})
post(5, "/commit", {"seq": 7.9})

# ---- DLC event attested from p2 (maturity = p2's slot)
E1, M1, NB1 = "SHZ-BTCUSD-VEC1", (S + 5_000_000) // 1_000_000, 6
deals = {str(i): post(i, "/dlc/deal", {"event_id": E1, "maturity_unix": M1, "num_bits": NB1, "members": [1, 2, 3, 4, 5]})[1] for i in members}
post(1, "/dlc/deal", {"event_id": E1, "maturity_unix": M1 + 1, "num_bits": NB1, "members": [1, 2, 3, 4, 5]})
r1 = [post(i, "/dlc/receive", {"event_id": E1, "deals": deals})[1]["R"] for i in members][0]
core = dlc_oracle.canonical_core(group, E1, M1, NB1, r1)
post(4, "/dlc/sign-announcement", {"event_id": E1, "core": dict(core, outcome="other rule"), "signers": [1, 2, 4]})
for i in (1, 2, 3):
    post(i, "/dlc/sign-announcement", {"event_id": E1, "core": core, "signers": [1, 2, 3]})
post(5, "/dlc/lock-outcome", {"event_id": E1, "packet": p1})
locks = {str(i): post(i, "/dlc/lock-outcome", {"event_id": E1, "packet": p2})[1]["lock"] for i in (1, 2, 3, 4)}
post(4, "/dlc/sign-outcome", {"event_id": E1, "packet": p2, "signers": [2, 3, 4], "locks": dict(list(locks.items())[:3])})
for i in (1, 2, 3):
    post(i, "/dlc/sign-outcome", {"event_id": E1, "packet": p2, "signers": [1, 2, 3], "locks": locks})
post(1, "/dlc/lock-unattestable", {"event_id": E1})

# ---- DLC event declared unattestable (no VALID packet in its window)
E2, M2, NB2 = "SHZ-BTCUSD-VEC2", M1 - 600, 4
deals2 = {str(i): post(i, "/dlc/deal", {"event_id": E2, "maturity_unix": M2, "num_bits": NB2, "members": [1, 2, 3, 4, 5]})[1] for i in members}
for i in members:
    post(i, "/dlc/receive", {"event_id": E2, "deals": deals2})
ulocks = {str(i): post(i, "/dlc/lock-unattestable", {"event_id": E2})[1]["lock"] for i in (1, 2, 3, 4)}
for i in (2, 3, 4):
    post(i, "/dlc/sign-unattestable", {"event_id": E2, "signers": [2, 3, 4], "locks": ulocks})
post(5, "/dlc/sign-unattestable", {"event_id": E2, "signers": [2, 3, 5], "locks": ulocks})
post(2, "/dlc/lock-outcome", {"event_id": "SHZ-UNKNOWN", "packet": p2})

for i in members:
    get(i, "/healthz")
get(1, "/nothing")

key = coord_auth.member_key(bytes(range(32)), group["group_pubkey"], 1)
body = json.dumps({"seq": 3}).encode()
auth = {"master": bytes(range(32)).hex(), "key": key.hex(), "index": 1, "path": "/commit", "body": body.decode(), "now_us": T,
        "header": coord_auth.header(key, group["group_pubkey"], 1, "/commit", body, now_us=T)}

files = {str(i): {"nonces": (tmp / f"m{i}" / "nonces.json").read_text(), "dlc": (tmp / f"m{i}" / "dlc.json").read_text()} for i in members}
out = {"clock_us": T, "rng_start": rng_start, "static_median_e8": view.median_e8, "group": group, "shares": shares,
       "steps": steps, "files": files, "auth": auth}
(HERE / "vectors.json").write_text(json.dumps(out, indent=1) + "\n")
print(f"{len(steps)} steps, scalars drawn {rng.k}, aux drawn {rng.a}")
