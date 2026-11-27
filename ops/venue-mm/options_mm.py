"""Demo options market maker for a shz-venue started with --options. Testnet only. Stdlib only.

  python options_mm.py run --server http://127.0.0.1:18295     # register, fund, quote, sign acks
  python options_mm.py --selftest                              # pricing + shared IntentV7 vector

Quotes BTC calls and USDT puts (both sides) on the nearest listed DLC expiry around a Black-76
price from the oracle mark (r = 0, flat --vol), with --spread-bps each side and a floor of one
smallest unit per contract. BTC series are inverse: premium per USD notional ~ C / (K * F) BTC.
USDT series are linear: premium per 1e-8 BTC = P_usd * 1e-8 USD. Requotes when the mark moves
--requote-bps from the last quoted mark, when the listed expiries change, or every --refresh-s.
Signs its own IntentV7 orders and every pending signature of its account (V4 option acks).
Collateral: funds --fund-sats from the perpetual allocation and deposits --deposit-usdt through
the venue's simulated stablecoin adapter when below target. API: docs/SHZ_VENUE_OPTIONS.md.
The key is <state-dir>/options_mm.key (hex, never printed). One JSON line per action.
"""
import argparse
import json
import math
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import intent as I  # noqa: E402
import bip340  # noqa: E402

TAG_INTENT_V7 = b"SHZ/HFT06/INTENT/V7"
TAG_TRANSFER = b"SHZ/VENUE/OPTIONS-TRANSFER/V1"
ACTIONS = {"post": 1, "take": 2, "cancel": 3}
TRANSFER_OPS = {"fund": 1, "defund": 2, "deposit": 3, "withdraw": 4}
YEAR_S = 365.0 * 86400.0
ZERO32 = "00" * 32


def log(**kw):
    kw["t_ms"] = int(time.time() * 1000)
    print(json.dumps(kw, sort_keys=True), flush=True)


# ---------------------------------------------------------------- encodings (mirror crates/shz-dex IntentV7::id)
def asset_bytes(a):
    if a is None or a.get("kind") == "btc":
        return b"\x01"
    return b"\x02" + bytes([{"rgb": 0, "tap": 1}[a["protocol"]]]) + bytes.fromhex(a["id"]) + bytes([a["decimals"]])


def intent_v7_id(i, tpl):
    sc = tpl["scope"]
    b = struct.pack("<I", i.get("version", 7)) + bytes.fromhex(sc["network"]) + struct.pack("<Q", sc["epoch"]) + bytes.fromhex(sc["policy"])
    b += struct.pack("<I", tpl["router"]) + bytes.fromhex(i["channel"]["txid"]) + struct.pack("<I", i["channel"]["vout"])
    b += bytes.fromhex(i["owner"]) + struct.pack("<QQ", i["sequence"], i["expires_us"]) + bytes([ACTIONS[i["action"]]])
    b += struct.pack("<Q", len(i["legs"]))
    for leg in i["legs"]:
        b += bytes.fromhex(leg["series"]) + bytes([1 if leg["long"] else 0]) + struct.pack("<Q", leg["qty"])
    b += struct.pack("<q", i.get("premium_milli", 0)) + bytes.fromhex(i.get("cancel_target") or ZERO32)
    ol = i.get("other_limits") or []
    if ol:
        b += struct.pack("<Q", len(ol))
        for x in ol:
            b += asset_bytes(x["asset"]) + struct.pack("<q", x["premium_milli"])
    return bip340.tagged_hash(TAG_INTENT_V7, b)


def transfer_digest(op, owner, asset, amount, expires_us):
    a = None if op in ("fund", "defund") else asset
    return bip340.tagged_hash(TAG_TRANSFER, bytes([TRANSFER_OPS[op]]) + bytes.fromhex(owner) + asset_bytes(a) + struct.pack("<QQ", amount, expires_us))


# ---------------------------------------------------------------- pricing
def ncdf(x):
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def black76(kind, f, k, t_years, vol):
    """Undiscounted Black-76 price in USD per BTC (r = 0)."""
    intrinsic = max(0.0, f - k) if kind == "call" else max(0.0, k - f)
    if t_years <= 0 or vol <= 0:
        return intrinsic
    sd = vol * math.sqrt(t_years)
    d1 = (math.log(f / k) + 0.5 * sd * sd) / sd
    d2 = d1 - sd
    if kind == "call":
        return f * ncdf(d1) - k * ncdf(d2)
    return k * ncdf(-d2) - f * ncdf(-d1)


def fair_milli(series, mark, now_s, vol):
    """Fair premium_milli per unit: BTC series msat per USD notional, stable series thousandths
    of a base unit per 1e-8 BTC."""
    t = max(series["maturity_unix"] - now_s, 0) / YEAR_S
    v = black76(series["kind"], float(mark), float(series["strike_usd"]), t, vol)
    if series["asset"]["kind"] == "btc":
        return v / (series["strike_usd"] * mark) * 1e8 * 1000.0
    return v * 1e-8 * 10 ** series["asset"]["decimals"] * 1000.0


def plan_quotes(series_list, mark, now_s, *, vol=0.6, spread_bps=800, min_lead_s=30, call_qty=100, put_qty=1_000_000):
    """[(series_id, long, qty, premium_milli)] for the nearest expiry with maturity >= now + min_lead_s:
    BTC calls and stablecoin puts, a bid and an ask each."""
    live = [s for s in series_list if s.get("settled_price_usd") is None and s.get("maturity_unix") and s["maturity_unix"] >= now_s + min_lead_s]
    if not live or not mark:
        return []
    first = min(s["maturity_unix"] for s in live)
    out = []
    for s in sorted(live, key=lambda s: (s["kind"], s["asset_code"], s["strike_usd"])):
        if s["maturity_unix"] != first:
            continue
        btc = s["asset"]["kind"] == "btc"
        if not ((s["kind"] == "call" and btc) or (s["kind"] == "put" and not btc)):
            continue
        qty = call_qty if btc else put_qty
        # smallest quote: 1 sat (BTC) or 0.01 of the stablecoin per quote, in premium_milli per unit
        floor_milli = max(1, math.ceil((1 if btc else 10 ** max(s["asset"]["decimals"] - 2, 0)) * 1000 / qty))
        fair = fair_milli(s, mark, now_s, vol)
        ask = max(floor_milli * 2, math.ceil(fair * (1 + spread_bps / 1e4)))
        bid = math.floor(fair * (1 - spread_bps / 1e4))
        if bid >= floor_milli:
            out.append((s["id"], True, qty, bid))
        out.append((s["id"], False, qty, ask))
    return out


# ---------------------------------------------------------------- bot
class OptionsMM:
    def __init__(self, a):
        self.a = a
        self.server = a.server.rstrip("/")
        os.makedirs(a.state_dir, exist_ok=True)
        self.keyfile = os.path.join(a.state_dir, "options_mm.key")
        self.sk = self.load_key()
        self.owner = bip340.pubkey(self.sk).hex()
        self.seq = 0
        self.xfer = 0
        self.tpl = None
        self.acct = None
        self.quoted = None  # (mark, expiry set) of the live ladder
        self.quoted_at = 0.0
        self.signed = set()

    def load_key(self):
        if not os.path.exists(self.keyfile):
            fd = os.open(self.keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(os.urandom(32).hex())
            log(ev="key_created", file=self.keyfile)
        return bytes.fromhex(open(self.keyfile).read().strip())

    def get(self, path):
        return I.http("GET", self.server + path)

    def post(self, path, body):
        return I.http("POST", self.server + path, body)

    def next_seq(self):
        self.seq = max(self.seq + 1, int(time.time() * 1e6))
        return self.seq

    def register(self):
        st, acct = self.get("/api/account/" + self.owner)
        if st != 200:
            st, d = self.post("/api/register/draft", {"owner": self.owner, "kind": "demo", "outpoint": None})
            if st != 200:
                raise RuntimeError("register draft: %s %s" % (st, d))
            sig = I.sign(self.sk, bytes.fromhex(d["allocation_digest"])).hex()
            st, r = self.post("/api/register", {"draft_id": d["draft_id"], "owner_signature": sig})
            if st != 200:
                raise RuntimeError("register: %s %s" % (st, r))
            acct = r["account"]
            log(ev="registered", owner=self.owner, outpoint=acct["outpoint"])
        self.acct = acct

    def refresh(self):
        st, acct = self.get("/api/account/" + self.owner)
        if st == 200:
            self.acct = acct
        return self.acct

    def transfer(self, op, amount, asset=None):
        self.xfer = max(self.xfer + 1, int((time.time() + 60) * 1e6))
        d = transfer_digest(op, self.owner, asset, amount, self.xfer)
        body = {"owner": self.owner, "amount": amount, "expires_us": self.xfer, "signature": I.sign(self.sk, d).hex()}
        if asset is not None and op in ("deposit", "withdraw"):
            body["asset"] = {k: asset[k] for k in ("kind", "protocol", "id", "decimals")}
        st, r = self.post("/api/options/" + op, body)
        log(ev="transfer", op=op, amount=amount, status=st, error=(r or {}).get("error") if st != 200 else None)
        return st == 200

    def ensure_collateral(self, assets):
        bal = {b["asset"]: b for b in (self.refresh().get("options") or {}).get("balances", [])}
        btc = bal.get("BTC", {"free": 0, "locked": 0})
        if btc["free"] + btc["locked"] < self.a.fund_sats:
            free_perp = (self.acct.get("balance") or {}).get("free", 0)
            amt = min(self.a.fund_sats - btc["free"] - btc["locked"], free_perp)
            if amt > 0:
                self.transfer("fund", amt)
        usdt = next((a for a in assets if a.get("code") == "USDT"), None)
        if usdt and self.a.deposit_usdt > 0:
            want = int(self.a.deposit_usdt * 10 ** usdt["decimals"])
            have = bal.get("USDT", {"free": 0, "locked": 0})
            if have["free"] + have["locked"] < want:
                self.transfer("deposit", want - have["free"] - have["locked"], usdt)

    def send(self, fields):
        i = {"version": 7, "owner": self.owner, "channel": {"txid": self.acct["outpoint"]["txid"], "vout": self.acct["outpoint"]["vout"]},
             "sequence": self.next_seq(), "expires_us": int((time.time() + self.a.expires_s) * 1e6), "premium_milli": 0, "cancel_target": ZERO32, **fields}
        i["signature"] = I.sign(self.sk, intent_v7_id(i, self.tpl)).hex()
        return self.post("/api/options/intents", {"intent": i})

    def sign_pending(self):
        todo = [p for p in (self.acct or {}).get("pending_signatures", []) if p["id"] not in self.signed]
        if not todo:
            return
        items = [{"id": p["id"], "signature": I.sign(self.sk, bytes.fromhex(p["message"])).hex()} for p in todo]
        st, r = self.post("/api/signatures", {"owner": self.owner, "items": items})
        if st == 200:
            self.signed.update(p["id"] for p in todo)
        log(ev="signed", n=len(items), kinds=sorted({p["kind"] for p in todo}), status=st)

    def requote(self, view, mark, reason):
        mine = (self.refresh().get("options") or {}).get("open_orders", [])
        for q in mine:
            st, r = self.send({"action": "cancel", "legs": [], "cancel_target": q["id"]})
            if st != 200:
                log(ev="cancel_refused", id=q["id"][:12], status=st, error=(r or {}).get("error"))
                return False  # an option batch is settling: try again next cycle
        plan = plan_quotes(view["series"], mark, time.time(), vol=self.a.vol, spread_bps=self.a.spread_bps,
                           call_qty=self.a.call_qty, put_qty=self.a.put_qty)
        posted = 0
        for sid, long, qty, milli in plan:
            st, r = self.send({"action": "post", "legs": [{"series": sid, "long": long, "qty": qty}], "premium_milli": milli})
            if st == 200:
                posted += 1
            else:
                log(ev="post_refused", series=sid[:12], long=long, premium_milli=milli, status=st, error=(r or {}).get("error"))
        log(ev="requoted", reason=reason, mark=mark, cancelled=len(mine), posted=posted, planned=len(plan),
            ladder=[[sid[:8], "bid" if long else "ask", milli] for sid, long, qty, milli in plan[:6]])
        return posted == len(plan)

    def run(self):
        st, self.tpl = self.get("/api/template")
        st, view = self.get("/api/options/series")
        if st != 200 or not view.get("enabled"):
            raise RuntimeError("options are off on %s" % self.server)
        self.register()
        self.ensure_collateral(view.get("assets", []))
        while True:
            try:
                self.cycle()
            except Exception as e:  # keep quoting through venue restarts
                log(ev="error", error=repr(e))
            time.sleep(self.a.poll_s)

    def cycle(self):
        self.refresh()
        self.sign_pending()
        st, view = self.get("/api/options/series")
        if st != 200:
            return
        mark = view.get("mark_usd")
        expiries = tuple(sorted({s["event_id"] for s in view["series"] if s.get("settled_price_usd") is None}))
        if not mark:
            return
        reason = None
        if self.quoted is None:
            reason = "start"
        elif abs(mark - self.quoted[0]) / self.quoted[0] * 1e4 >= self.a.requote_bps:
            reason = "mark %s -> %s" % (self.quoted[0], mark)
        elif expiries != self.quoted[1]:
            reason = "expiries changed"
        elif time.time() - self.quoted_at > self.a.refresh_s:
            reason = "refresh"
        if reason and self.requote(view, mark, reason):
            self.quoted, self.quoted_at = (mark, expiries), time.time()


def selftest():
    # Black-76 parity and inverse/linear unit conversions
    f, k, t, v = 100_000.0, 100_000.0, 900 / YEAR_S, 0.6
    c, p = black76("call", f, k, t, v), black76("put", f, k, t, v)
    assert abs((c - p) - (f - k)) < 1e-6, (c, p)
    assert 120 < c < 135, c  # at the money ~0.4 * sigma * sqrt(T) * F = 0.4 * 0.6 * 0.00534 * 1e5 = 128 USD per BTC
    call = {"kind": "call", "strike_usd": 100_000, "maturity_unix": 900, "asset": {"kind": "btc"}, "asset_code": "BTC", "id": "aa" * 32, "settled_price_usd": None, "event_id": "E"}
    put = {"kind": "put", "strike_usd": 100_000, "maturity_unix": 900, "asset": {"kind": "stable", "decimals": 6}, "asset_code": "USDT", "id": "bb" * 32, "settled_price_usd": None, "event_id": "E"}
    m_call, m_put = fair_milli(call, 100_000, 0, v), fair_milli(put, 100_000, 0, v)
    assert abs(m_call - c / (k * f) * 1e11) < 1e-6 and 1_200 < m_call < 1_350, m_call  # ~128 sats per 100 USD contract
    assert abs(m_put - p * 10) < 1e-6, m_put  # 0.01 BTC contract: p/100 USDT
    plan = plan_quotes([call, put], 100_000, 0, vol=v, spread_bps=800)
    assert [(x[1]) for x in plan] == [True, False, True, False], plan
    for sid, long, qty, milli in plan:
        fair = m_call if sid == call["id"] else m_put
        assert (milli < fair) if long else (milli > fair), (sid, long, milli, fair)
    # shared Rust/JS vector
    vec = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ui", "venue", "test", "options_vector.json")))
    tpl = {"scope": vec["scope"], "router": vec["router"]}
    for c in vec["intents"]:
        assert intent_v7_id(c["intent"], tpl).hex() == c["id"], c["name"]
    for x in vec["transfers"]:
        assert transfer_digest(x["op"], x["owner"], x["asset"], x["amount"], x["expires_us"]).hex() == x["digest"], x["op"]
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="run", choices=["run"])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--server", default="http://127.0.0.1:8095")
    ap.add_argument("--state-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "state"))
    ap.add_argument("--vol", type=float, default=0.6, help="annualised volatility for Black-76")
    ap.add_argument("--spread-bps", type=float, default=800, help="each side of fair, in bps of the premium")
    ap.add_argument("--requote-bps", type=float, default=10, help="mark move that triggers a requote")
    ap.add_argument("--refresh-s", type=float, default=120, help="requote at least this often (time decay)")
    ap.add_argument("--call-qty", type=int, default=100, help="BTC call quote size, USD notional")
    ap.add_argument("--put-qty", type=int, default=1_000_000, help="USDT put quote size, 1e-8 BTC")
    ap.add_argument("--fund-sats", type=int, default=150_000)
    ap.add_argument("--deposit-usdt", type=float, default=5_000)
    ap.add_argument("--expires-s", type=int, default=3600)
    ap.add_argument("--poll-s", type=float, default=1.0)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    OptionsMM(a).run()


if __name__ == "__main__":
    main()
