"""Demo BTC/USDT spot market maker for a shz-venue started with --spot. Testnet only. Stdlib only.

  python spot_mm.py run --server http://127.0.0.1:18295     # register, fund, quote, sign acks
  python spot_mm.py --selftest                              # quote plan + shared SpotIntent vector

Quotes --levels bids and asks around the oracle mark (GET /api/spot/book mark_usd): level k sits
--spread-bps + k * --step-bps from the mark, --size-sats each, prices on the pair's tick (bids
round down, asks up) and sizes on its lot. Requotes when the mark moves --requote-bps from the
last quoted mark, when one of its orders filled or was pulled, or every --refresh-s. Signs its
own SpotIntent orders (version 8) and every pending signature of its account (the V4
acknowledgements of spot batches it is in). Funding: --fund-sats BTC from the perpetual
allocation and --deposit-usdt through the venue's simulated stablecoin adapter into the shared
asset wallet when below target. API: docs/SHZ_SPOT.md. The key is <state-dir>/spot_mm.key (hex,
never printed). One JSON line per action.
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
from options_mm import log, transfer_digest  # noqa: E402

TAG_SPOT_INTENT = b"SHZ/HFT06/SPOT-INTENT/V8"
ACTIONS = {"post": 1, "take": 2, "cancel": 3}
ZERO32 = "00" * 32


# ---------------------------------------------------------------- encodings (mirror crates/shz-dex SpotIntent::id)
def spot_intent_id(i, tpl):
    sc = tpl["scope"]
    b = struct.pack("<I", i.get("version", 8)) + bytes.fromhex(sc["network"]) + struct.pack("<Q", sc["epoch"]) + bytes.fromhex(sc["policy"])
    b += struct.pack("<I", tpl["router"]) + bytes.fromhex(i["channel"]["txid"]) + struct.pack("<I", i["channel"]["vout"])
    b += bytes.fromhex(i["owner"]) + struct.pack("<QQ", i["sequence"], i["expires_us"]) + bytes([ACTIONS[i["action"]]])
    b += bytes.fromhex(i["pair"]) + bytes([1 if i.get("buy") else 0]) + struct.pack("<QQ", i.get("qty_sats", 0), i.get("price", 0))
    b += bytes.fromhex(i.get("cancel_target") or ZERO32)
    return bip340.tagged_hash(TAG_SPOT_INTENT, b)


# ---------------------------------------------------------------- quoting
def plan_quotes(mark_usd, pair, *, levels=3, spread_bps=20, step_bps=10, size_sats=40_000):
    """[(buy, qty_sats, price)] around `mark_usd`; price in quote base units per BTC on the tick."""
    tick, lot, d = pair["tick"], pair["lot_sats"], pair["quote"]["decimals"]
    qty = max(lot, size_sats // lot * lot)
    mark = mark_usd * 10 ** d
    out = []
    for k in range(levels):
        off = (spread_bps + k * step_bps) / 1e4
        bid = math.floor(mark * (1 - off) / tick) * tick
        ask = math.ceil(mark * (1 + off) / tick) * tick
        if bid > 0:
            out.append((True, qty, int(bid)))
        out.append((False, qty, int(ask)))
    return out


def quote_units(sats, price):
    return sats * price // 100_000_000


class SpotMM:
    def __init__(self, a):
        self.a = a
        self.server = a.server.rstrip("/")
        os.makedirs(a.state_dir, exist_ok=True)
        self.keyfile = os.path.join(a.state_dir, "spot_mm.key")
        self.sk = self.load_key()
        self.owner = bip340.pubkey(self.sk).hex()
        self.seq = 0
        self.xfer = 0
        self.tpl = None
        self.acct = None
        self.pair = None
        self.quoted = None  # mark of the live ladder
        self.quoted_ids = set()
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

    def wallet(self):
        return {b["asset"]: b for b in ((self.refresh() or {}).get("spot") or {}).get("balances", [])}

    def ensure_funds(self):
        w = self.wallet()
        btc = w.get("BTC", {"free": 0, "spot_locked": 0})
        if btc["free"] + btc["spot_locked"] < self.a.fund_sats:
            free_perp = (self.acct.get("balance") or {}).get("free", 0)
            amt = min(self.a.fund_sats - btc["free"] - btc["spot_locked"], free_perp)
            if amt > 0:
                self.transfer("fund", amt)
        q = self.pair["quote"]
        if self.a.deposit_usdt > 0:
            want = int(self.a.deposit_usdt * 10 ** q["decimals"])
            have = w.get(q["code"], {"free": 0, "spot_locked": 0})
            if have["free"] + have["spot_locked"] < want:
                self.transfer("deposit", want - have["free"] - have["spot_locked"], q)

    def send(self, fields):
        i = {"version": 8, "owner": self.owner, "channel": {"txid": self.acct["outpoint"]["txid"], "vout": self.acct["outpoint"]["vout"]},
             "sequence": self.next_seq(), "expires_us": int((time.time() + self.a.expires_s) * 1e6), "pair": self.pair["pair"],
             "buy": False, "qty_sats": 0, "price": 0, "cancel_target": ZERO32, **fields}
        i["signature"] = I.sign(self.sk, spot_intent_id(i, self.tpl)).hex()
        return self.post("/api/spot/intents", {"intent": i})

    def sign_pending(self):
        todo = [p for p in (self.acct or {}).get("pending_signatures", []) if p["id"] not in self.signed]
        if not todo:
            return
        items = [{"id": p["id"], "signature": I.sign(self.sk, bytes.fromhex(p["message"])).hex()} for p in todo]
        st, r = self.post("/api/signatures", {"owner": self.owner, "items": items})
        if st == 200:
            self.signed.update(p["id"] for p in todo)
        log(ev="signed", n=len(items), kinds=sorted({p["kind"] for p in todo}), status=st)

    def open_orders(self):
        return ((self.acct or {}).get("spot") or {}).get("open_orders", [])

    def requote(self, mark, reason):
        mine = self.open_orders()
        for q in mine:
            st, r = self.send({"action": "cancel", "cancel_target": q["id"]})
            if st != 200:
                log(ev="cancel_refused", id=q["id"][:12], status=st, error=(r or {}).get("error"))
                return False  # a batch is settling: try again next cycle
        self.ensure_funds()
        w = self.wallet()
        free_btc = w.get("BTC", {}).get("free", 0)
        free_q = w.get(self.pair["quote"]["code"], {}).get("free", 0)
        plan = plan_quotes(mark, self.pair, levels=self.a.levels, spread_bps=self.a.spread_bps, step_bps=self.a.step_bps, size_sats=self.a.size_sats)
        posted, ids = 0, set()
        for buy, qty, price in plan:
            need = quote_units(qty, price) if buy else qty
            if need > (free_q if buy else free_btc):
                log(ev="skip_unfunded", buy=buy, price=price, qty_sats=qty)
                continue
            st, r = self.send({"action": "post", "buy": buy, "qty_sats": qty, "price": price})
            if st == 200:
                posted += 1
                ids.add(r["id"])
                if buy:
                    free_q -= need
                else:
                    free_btc -= need
            else:
                log(ev="post_refused", buy=buy, price=price, status=st, error=(r or {}).get("error"))
        self.quoted_ids = ids
        log(ev="requoted", reason=reason, mark=mark, cancelled=len(mine), posted=posted, planned=len(plan),
            ladder=[["bid" if b else "ask", p / 10 ** self.pair["quote"]["decimals"]] for b, q, p in plan])
        return posted > 0

    def run(self):
        st, self.tpl = self.get("/api/template")
        st, book = self.get("/api/spot/book")
        if st != 200:
            raise RuntimeError("spot is off on %s" % self.server)
        self.pair = book["pair"]
        self.register()
        self.ensure_funds()
        while True:
            try:
                self.cycle()
            except Exception as e:  # keep quoting through venue restarts
                log(ev="error", error=repr(e))
            time.sleep(self.a.poll_s)

    def cycle(self):
        self.refresh()
        self.sign_pending()
        st, book = self.get("/api/spot/book")
        if st != 200:
            return
        mark = book.get("mark_usd")
        if not mark:
            return
        live = {q["id"] for q in self.open_orders()}
        reason = None
        if self.quoted is None:
            reason = "start"
        elif abs(mark - self.quoted) / self.quoted * 1e4 >= self.a.requote_bps:
            reason = "mark %s -> %s" % (self.quoted, mark)
        elif self.quoted_ids and live != self.quoted_ids and book.get("staged") is None:
            reason = "filled or pulled"
        elif time.time() - self.quoted_at > self.a.refresh_s:
            reason = "refresh"
        if reason and self.requote(mark, reason):
            self.quoted, self.quoted_at = mark, time.time()


def selftest():
    pair = {"pair": "c4" * 32, "lot_sats": 1000, "tick": 100_000, "quote": {"decimals": 6, "code": "USDT"}}
    plan = plan_quotes(90_000, pair, levels=2, spread_bps=20, step_bps=10, size_sats=200_500)
    assert [b for b, _, _ in plan] == [True, False, True, False], plan
    assert all(q == 200_000 for _, q, _ in plan), plan  # down to the lot
    assert all(p % pair["tick"] == 0 for _, _, p in plan), plan
    assert plan[0][2] == 89_820_000_000 and plan[1][2] == 90_180_000_000, plan  # 20 bps each side
    assert plan[2][2] < plan[0][2] < 90_000_000_000 < plan[1][2] < plan[3][2], plan
    assert all(quote_units(q, p) * 100_000_000 == q * p for _, q, p in plan)  # exact fills
    vec = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "ui", "venue", "test", "spot_vector.json")))
    tpl = {"scope": vec["scope"], "router": vec["router"]}
    for c in vec["intents"]:
        assert spot_intent_id(c["intent"], tpl).hex() == c["id"], c["name"]
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="run", choices=["run"])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--server", default="http://127.0.0.1:8095")
    ap.add_argument("--state-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "state"))
    ap.add_argument("--levels", type=int, default=3, help="price levels each side")
    ap.add_argument("--spread-bps", type=float, default=20, help="first level's distance from the mark")
    ap.add_argument("--step-bps", type=float, default=10, help="distance between levels")
    ap.add_argument("--size-sats", type=int, default=40_000, help="size per level (rounded down to the lot)")
    ap.add_argument("--requote-bps", type=float, default=10, help="mark move that triggers a requote")
    ap.add_argument("--refresh-s", type=float, default=300)
    ap.add_argument("--fund-sats", type=int, default=150_000, help="BTC kept in the asset wallet (demo accounts hold 200,000)")
    ap.add_argument("--deposit-usdt", type=float, default=2_000)
    ap.add_argument("--expires-s", type=int, default=3600)
    ap.add_argument("--poll-s", type=float, default=1.0)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    SpotMM(a).run()


if __name__ == "__main__":
    main()
