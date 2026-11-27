"""Tiny-size market maker for the SHZ testnet venue. Testnet only. Stdlib only.

  python mm.py init      # create key, print P2TR testnet4 funding address + send command
  python mm.py register  # demo account (default) or --utxo txid:vout
  python mm.py run       # register if needed, then quote
  python mm.py --selftest
"""
import argparse
import json
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import intent as I  # noqa: E402
import bip340  # noqa: E402

COLLAR_BPS = 200
MAX_QUOTE_MARK_AGE_S = 20.0


def log(**kw):
    kw["t_ms"] = int(time.time() * 1000)
    print(json.dumps(kw, sort_keys=True), flush=True)


def plan_quotes(mark, net_usd, *, levels=2, size_usd=5, spread_bps=15, step_bps=10, max_net_usd=50,
                status="OK", age_s=0.0, verified=True):
    """Pure quote planner. Returns [(side, price_usd, qty_usd)], side in long (bid) / short (ask)."""
    if mark is None or not verified or str(status).upper() in ("HOLD", "NONE") or age_s is None \
            or age_s > MAX_QUOTE_MARK_AGE_S:
        return []
    mark = int(mark)
    if mark <= 0 or max_net_usd <= 0:
        return []
    # inventory skew: long inventory shifts both sides down (sell easier, buy harder)
    shift_bps = -(net_usd / max_net_usd) * spread_bps
    out = []
    for side in ("long", "short"):
        for k in range(levels):
            off = spread_bps + k * step_bps
            if off >= COLLAR_BPS - 5:
                break
            if side == "long":
                if net_usd + (k + 1) * size_usd > max_net_usd:
                    break
                px = math.floor(mark * (1 - (off - shift_bps) / 10000))
                if px >= mark:
                    px = mark - 1
            else:
                if net_usd - (k + 1) * size_usd < -max_net_usd:
                    break
                px = math.ceil(mark * (1 + (off + shift_bps) / 10000))
                if px <= mark:
                    px = mark + 1
            if px <= 0 or abs(px - mark) * 10000 > mark * COLLAR_BPS:
                continue
            out.append((side, px, size_usd))
    return out


class MM:
    def __init__(self, a):
        self.a = a
        self.server = a.server.rstrip("/")
        os.makedirs(a.state_dir, exist_ok=True)
        self.keyfile = os.path.join(a.state_dir, "mm.key")
        self.quoted_mark, self.quoted_net = None, None
        self.statefile = os.path.join(a.state_dir, "mm_state.json")
        self.sk = self.load_key()
        self.owner = bip340.pubkey(self.sk).hex()
        self.state = self.load_state()
        self.last_seq = 0
        self.tpl = None

    # --- key / state ---
    def load_key(self):
        if not os.path.exists(self.keyfile):
            sk = os.urandom(32)
            fd = os.open(self.keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(sk.hex())
            log(ev="key_created", file=self.keyfile)
        return bytes.fromhex(open(self.keyfile).read().strip())

    def load_state(self):
        try:
            return json.load(open(self.statefile))
        except Exception:
            return {"open_quotes": [], "channel": None}

    def save_state(self):
        tmp = self.statefile + ".tmp"
        json.dump(self.state, open(tmp, "w"))
        os.replace(tmp, self.statefile)

    # --- funding ---
    def funding(self):
        addr = I.address_for_secret(self.sk, "tb")
        cmd = "bitcoin-cli -testnet4 -rpcwallet=%s send '{\"%s\": %s}'" % (self.a.wallet, addr, self.a.fund_btc)
        print("owner key (x-only): %s" % self.owner)
        print("testnet4 P2TR funding address: %s" % addr)
        print("operator command (this tool never broadcasts):\n  %s" % cmd)
        print("then: python mm.py register --utxo <txid>:<vout>  (vout of the output paying that address)")
        return addr

    # --- http ---
    def get(self, path):
        return I.http("GET", self.server + path)

    def post(self, path, body):
        return I.http("POST", self.server + path, body)

    def template(self):
        if not self.tpl:
            st, t = self.get("/api/template")
            if st != 200:
                raise RuntimeError("template: %s %s" % (st, t))
            self.tpl = t
        return self.tpl

    # --- registration ---
    def channel(self):
        if self.state.get("channel"):
            return self.state["channel"]
        if self.a.utxo:
            txid, vout = self.a.utxo.split(":")
            return {"txid": txid, "vout": int(vout)}
        txid = I.tagged_hash("SHZ/VENUE/DEMO-OUTPOINT/V1", bytes.fromhex(self.owner)).hex()
        return {"txid": txid, "vout": 0}

    def register(self):
        st, acct = self.get("/api/account/" + self.owner)
        if st == 200:
            self.state["channel"] = acct["outpoint"]
            self.save_state()
            log(ev="already_registered", outpoint=acct["outpoint"], label=acct.get("label"))
            return
        kind = "utxo" if self.a.utxo else "demo"
        op = None
        if self.a.utxo:
            txid, vout = self.a.utxo.split(":")
            op = {"txid": txid, "vout": int(vout)}
        body = {"owner": self.owner, "kind": kind, "outpoint": op}
        if self.a.dry_run:
            log(ev="dry_run_register_draft", body=body)
            return
        st, d = self.post("/api/register/draft", body)
        if st != 200:
            raise RuntimeError("draft: %s %s" % (st, d))
        sig = I.sign(self.sk, bytes.fromhex(d["allocation_digest"])).hex()
        st, r = self.post("/api/register", {"draft_id": d["draft_id"], "owner_signature": sig})
        if st != 200:
            raise RuntimeError("register: %s %s" % (st, r))
        self.state["channel"] = r["account"]["outpoint"]
        self.save_state()
        log(ev="registered", kind=kind, cap_sats=d.get("cap_sats"), label=d.get("label"),
            outpoint=self.state["channel"])

    # --- intents ---
    def next_seq(self):
        # Microseconds, like every other client (docs/SHZ_AGENT_API.md, sequences).
        self.last_seq = max(int(time.time() * 1e6), self.last_seq + 1)
        return self.last_seq

    def send(self, iid, intent, what):
        if self.a.dry_run:
            log(ev="dry_run_intent", what=what, id=iid, intent=intent)
            return True, {"id": iid}
        st, r = self.post("/api/intents", {"intent": intent})
        log(ev="intent", what=what, id=iid, http=st, resp=r)
        return st == 200, r

    def cancel(self, qid):
        now_us = int(time.time() * 1e6)
        iid, it = I.build_intent(self.sk, self.template(), self.channel(), sequence=self.next_seq(),
                                 expires_us=now_us + 60_000_000, action="cancel", side="long", cancel_target=qid)
        self.send(iid, it, "cancel")

    def cancel_all(self):
        for qid in list(self.state["open_quotes"]):
            self.cancel(qid)
        self.state["open_quotes"] = []
        self.save_state()

    def post_quote(self, side, px, qty):
        now_us = int(time.time() * 1e6)
        iid, it = I.build_intent(self.sk, self.template(), self.channel(), sequence=self.next_seq(),
                                 expires_us=now_us + self.a.expires_s * 1_000_000, action="post", side=side,
                                 quantity=qty, limit_usd=px, leverage_bps=self.a.leverage_bps,
                                 max_mark_age_us=self.a.max_mark_age_s * 1_000_000)
        ok, r = self.send(iid, it, "post_%s_%d" % (side, px))
        if ok and not self.a.dry_run:
            self.state["open_quotes"].append(iid)
            self.save_state()

    # --- settlement ---
    def settle(self, acct):
        items = []
        for p in acct.get("pending_signatures", []):
            sig = I.sign(self.sk, bytes.fromhex(p["message"])).hex()
            items.append({"id": p["id"], "signature": sig})
            log(ev="sign", id=p["id"], kind=p["kind"], context=p.get("context"))
        if items and not self.a.dry_run:
            st, r = self.post("/api/signatures", {"owner": self.owner, "items": items})
            log(ev="signatures_posted", http=st, resp=r)

    # --- loop ---
    def step(self, last_seq_quoted, last_quote_t):
        st, status = self.get("/api/status")
        if st != 200:
            log(ev="status_error", http=st)
            return last_seq_quoted, last_quote_t
        m = status.get("mark") or {}
        st, acct = self.get("/api/account/" + self.owner)
        if st == 200:
            self.settle(acct)
            net = (acct.get("position") or {}).get("net_usd", 0) or 0
        else:
            net = 0
        plan = plan_quotes(m.get("price_usd"), net, levels=self.a.levels, size_usd=self.a.size_usd,
                           spread_bps=self.a.spread_bps, step_bps=self.a.step_bps, max_net_usd=self.a.max_net_usd,
                           status=m.get("status", "OK"), age_s=m.get("age_s"), verified=m.get("verified", False))
        now = time.time()
        px = m.get("price_usd")
        moved = px is None or self.quoted_mark is None or abs(px - self.quoted_mark) * 10000 >= self.a.requote_bps * self.quoted_mark
        due = (m.get("seq") != last_seq_quoted and (moved or net != self.quoted_net)) or now - last_quote_t > self.a.expires_s * 0.66
        if not plan:
            if self.state["open_quotes"]:
                log(ev="suppress", status=m.get("status"), age_s=m.get("age_s"))
                self.cancel_all()
            return last_seq_quoted, last_quote_t
        if due:
            self.cancel_all()
            log(ev="plan", seq=m.get("seq"), mark=m.get("price_usd"), net_usd=net, quotes=plan)
            for side, qpx, qty in plan:
                self.post_quote(side, qpx, qty)
            self.quoted_mark, self.quoted_net = px, net
            return m.get("seq"), now
        return last_seq_quoted, last_quote_t

    def run(self):
        self.register()
        self.cancel_all()  # leftovers from a previous run
        seq, t = None, 0.0
        try:
            while True:
                try:
                    seq, t = self.step(seq, t)
                except Exception as e:  # keep running on transient errors
                    log(ev="error", err=repr(e))
                time.sleep(self.a.poll_s)
        except KeyboardInterrupt:
            self.cancel_all()
            log(ev="stopped")


def selftest():
    k = dict(levels=2, size_usd=5, spread_bps=15, step_bps=10, max_net_usd=50)
    q = plan_quotes(90000, 0, **k)
    bids = [p for s, p, _ in q if s == "long"]
    asks = [p for s, p, _ in q if s == "short"]
    assert bids == [89865, 89775], bids  # 15 and 25 bps
    assert asks == [90135, 90225], asks
    assert all(abs(p - 90000) * 10000 <= 90000 * COLLAR_BPS for _, p, _ in q)
    # long inventory: both sides shift down
    qs = plan_quotes(90000, 25, **k)
    assert [p for s, p, _ in qs if s == "long"][0] < bids[0]
    assert [p for s, p, _ in qs if s == "short"][0] < asks[0]
    # cap: at +50 no bids; at -50 no asks; near cap fewer levels
    assert not [1 for s, _, _ in plan_quotes(90000, 50, **k) if s == "long"]
    assert not [1 for s, _, _ in plan_quotes(90000, -50, **k) if s == "short"]
    assert len([1 for s, _, _ in plan_quotes(90000, 40, **k) if s == "long"]) == 2
    assert len([1 for s, _, _ in plan_quotes(90000, 46, **k) if s == "long"]) == 0
    # HOLD, stale, unverified, missing
    assert plan_quotes(90000, 0, status="HOLD", **k) == []
    assert plan_quotes(90000, 0, age_s=20.5, **k) == []
    assert plan_quotes(90000, 0, age_s=19.0, **k)
    assert plan_quotes(90000, 0, verified=False, **k) == []
    assert plan_quotes(None, 0, **k) == []
    # wide ladder never leaves the collar
    wide = plan_quotes(90000, 0, levels=30, size_usd=1, spread_bps=15, step_bps=10, max_net_usd=1000)
    assert wide and all(abs(p - 90000) * 10000 <= 90000 * COLLAR_BPS for _, p, _ in wide)
    # tiny mark: still strictly outside the mark
    t = plan_quotes(100, 0, **k)
    assert all((s == "long" and p < 100) or (s == "short" and p > 100) for s, p, _ in t), t
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="run", choices=["init", "register", "run"])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--server", default="http://127.0.0.1:8095")
    ap.add_argument("--state-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "state"))
    ap.add_argument("--utxo", help="txid:vout of a funded testnet4 P2TR output (default: demo account)")
    ap.add_argument("--levels", type=int, default=2)
    ap.add_argument("--size-usd", type=int, default=5)
    ap.add_argument("--spread-bps", type=int, default=15)
    ap.add_argument("--step-bps", type=int, default=10)
    ap.add_argument("--max-net-usd", type=int, default=50)
    ap.add_argument("--leverage-bps", type=int, default=20000)
    ap.add_argument("--max-mark-age-s", type=int, default=15)
    ap.add_argument("--expires-s", type=int, default=60)
    ap.add_argument("--requote-bps", type=float, default=5.0,
                    help="repost only when the mark moved this far, inventory changed, or quotes near expiry")
    ap.add_argument("--poll-s", type=float, default=2.0)
    ap.add_argument("--wallet", default="<wallet>")
    ap.add_argument("--fund-btc", default="0.0005")
    ap.add_argument("--dry-run", action="store_true", help="build and sign intents, print them, send nothing")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    mm = MM(a)
    if a.cmd == "init":
        mm.funding()
    elif a.cmd == "register":
        mm.register()
    else:
        if a.utxo is None:
            log(ev="account_kind", kind="demo", note="TESTNET DEMO CREDIT, no coins back it")
        mm.run()


if __name__ == "__main__":
    main()
