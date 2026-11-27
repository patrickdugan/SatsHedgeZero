"""Trading as a delegated agent key, and the owner-side grant helpers.

An `Agent` holds only its own key. It signs intents whose `owner` field is the account
owner (the grant names both), places them through the agent API, and signs the pending
batch acknowledgements the venue offers it (those whose every leg on the account is the
agent's own). The owner's key is used only in `create_grant` / `revoke_grant`, on the
owner's machine, never by the agent.
"""
import os
import threading
import time

from . import bip340
from .client import Client, LightningerError
from .encoding import ZERO32, grant_id, intent_id, revocation_id


def new_key():
    """A fresh secp256k1 secret key (32 bytes)."""
    while True:
        k = os.urandom(32)
        if 0 < int.from_bytes(k, "big") < bip340.N:
            return k


def pubkey_hex(sk):
    return bip340.pubkey(sk).hex()


def sign(sk, msg32):
    return bip340.sign(msg32, sk, os.urandom(32)).hex()


class Agent:
    def __init__(self, client: Client, agent_sk: bytes, grant: str):
        self.c = client
        self.sk = agent_sk
        self.pk = pubkey_hex(agent_sk)
        self.grant_id = grant
        self.seq = {"perp": 0, "desk": 0}
        self.refresh()

    def refresh(self):
        """Grant, signing template, account and its last sequences from the venue."""
        self.view = self.c.grant(self.grant_id)
        self._seed(self.view.get("sequences"))
        g = self.view["grant"]
        if g["agent"] != self.pk:
            raise ValueError("this grant names another agent key")
        self.owner = g["owner"]
        self.channel = g["channel"]
        self.limits = g["limits"]
        m = self.c.markets()
        self.template = dict(m["perp"])
        if m.get("spot", {}).get("enabled"):
            self.template["spot_pair"] = m["spot"]["pair"]
        self.spot = m.get("spot")
        return self.view

    def status(self):
        return self.c.grant(self.grant_id)

    # -------------------------------------------------------------- signing
    # Sequences are per account and per book, shared with the owner's browser and bots: the
    # perpetual router has one counter, the options desk one for options and spot. Every client
    # uses the microsecond clock; the agent also starts above the venue's last admitted sequence.
    @staticmethod
    def book(instrument):
        return "perp" if instrument == "perp" else "desk"

    def _seed(self, seqs):
        if seqs:
            self.seq["perp"] = max(self.seq["perp"], seqs.get("perp", 0))
            self.seq["desk"] = max(self.seq["desk"], seqs.get("option", 0), seqs.get("spot", 0))

    def next_seq(self, instrument="perp"):
        b = self.book(instrument)
        self.seq[b] = max(int(time.time() * 1e6), self.seq[b] + 1)
        return self.seq[b]

    def _signed(self, instrument, fields, ttl_s):
        i = {"channel": self.channel, "owner": self.owner, "sequence": self.next_seq(instrument),
             "expires_us": int((time.time() + ttl_s) * 1e6), **fields}
        iid = intent_id(instrument, i, self.template)
        i["signature"] = sign(self.sk, iid)
        return iid.hex(), i

    def _send(self, instrument, fields, ttl_s, cancel=False):
        for attempt in range(2):
            iid, i = self._signed(instrument, fields, ttl_s)
            try:
                r = (self.c.cancel if cancel else self.c.place)(self.grant_id, instrument, i)
                r.setdefault("id", iid)
                return r
            except LightningerError as e:
                # The owner (or another client) used a higher sequence meanwhile: re-read the
                # account's sequences and sign once more above them.
                if attempt == 0 and e.code == "venue.rejected" and "Replay" in (e.message or ""):
                    self._seed(self.c.grant(self.grant_id).get("sequences"))
                    continue
                raise

    # ---------------------------------------------------------- perpetuals
    def _perp(self, action, side, qty_usd, limit_usd, leverage_bps, ttl_s):
        t = self.template
        rate = t["tariff"]["maker_ppm" if action == "post" else "taker_ppm"][0]
        return {"action": action, "side": side, "tier": "standard", "quantity": qty_usd, "limit_usd": limit_usd,
                "leverage_bps": leverage_bps, "max_fee_ppm": rate, "max_fee_sats": 100_000,
                "max_mark_age_us": t.get("max_mark_age_us", 15_000_000), "early_window_opt_in": False, "cancel_target": ZERO32}

    def perp_post(self, side, qty_usd, limit_usd, leverage_bps=20_000, ttl_s=120):
        return self._send("perp", self._perp("post", side, qty_usd, limit_usd, leverage_bps, ttl_s), ttl_s)

    def perp_take(self, side, qty_usd, limit_usd, leverage_bps=20_000, ttl_s=30):
        return self._send("perp", self._perp("take", side, qty_usd, limit_usd, leverage_bps, ttl_s), ttl_s)

    def perp_cancel(self, order_id, ttl_s=30):
        f = {"action": "cancel", "side": "long", "tier": "standard", "quantity": 0, "limit_usd": 0, "leverage_bps": 0,
             "max_fee_ppm": 0, "max_fee_sats": 0, "max_mark_age_us": 0, "early_window_opt_in": False, "cancel_target": order_id}
        return self._send("perp", f, ttl_s, cancel=True)

    # ------------------------------------------------------------- options
    def option_post(self, series, long, qty, premium_milli, ttl_s=300):
        return self._send("option", {"version": 7, "action": "post", "legs": [{"series": series, "long": long, "qty": qty}],
                                     "premium_milli": premium_milli, "cancel_target": ZERO32}, ttl_s)

    def option_take(self, legs, premium_milli, other_limits=None, ttl_s=60):
        """`legs`: [{"series", "long", "qty"}] (one leg, or a combo of up to 4)."""
        f = {"version": 7, "action": "take", "legs": legs, "premium_milli": premium_milli, "cancel_target": ZERO32}
        if other_limits:
            f["other_limits"] = other_limits
        return self._send("option", f, ttl_s)

    def option_cancel(self, order_id, ttl_s=60):
        return self._send("option", {"version": 7, "action": "cancel", "legs": [], "premium_milli": 0, "cancel_target": order_id}, ttl_s, cancel=True)

    # ---------------------------------------------------------------- spot
    def spot_post(self, buy, qty_sats, price, ttl_s=300):
        """`price`: quote-asset base units per BTC (USDT 6 decimals: 90,000.0 -> 90_000_000_000)."""
        return self._send("spot", {"version": 8, "action": "post", "pair": self.template["spot_pair"], "buy": buy,
                                   "qty_sats": qty_sats, "price": price, "cancel_target": ZERO32}, ttl_s)

    def spot_take(self, buy, qty_sats, price, ttl_s=60):
        return self._send("spot", {"version": 8, "action": "take", "pair": self.template["spot_pair"], "buy": buy,
                                   "qty_sats": qty_sats, "price": price, "cancel_target": ZERO32}, ttl_s)

    def spot_cancel(self, order_id, ttl_s=60):
        return self._send("spot", {"version": 8, "action": "cancel", "pair": self.template["spot_pair"], "buy": False,
                                   "qty_sats": 0, "price": 0, "cancel_target": order_id}, ttl_s, cancel=True)

    # ---------------------------------------------------------------- acks
    def sign_pending_acks(self):
        """Sign every acknowledgement the venue lets this agent sign; returns the venue's result."""
        items = [{"id": p["id"], "signature": sign(self.sk, bytes.fromhex(p["message"]))} for p in self.c.pending_acks(self.grant_id)]
        if not items:
            return {"accepted": 0, "refused": []}
        return self.c.submit_acks(self.grant_id, items)

    def start_autosigner(self, interval_s=0.25):
        """Background thread that signs pending acks; returns a stop() function."""
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    self.sign_pending_acks()
                except Exception:
                    pass
                stop.wait(interval_s)

        threading.Thread(target=loop, daemon=True, name="lightninger-acks").start()
        return stop.set


# ----------------------------------------------------------------- owner side
def check_draft(draft, owner, agent, instruments, limits):
    """Verify a server-drafted grant before the owner signs it: it must be exactly what was
    asked for, never allow withdrawals, and its id must be the local hash of its fields."""
    g = draft["grant"]
    problems = []
    if g["owner"] != owner:
        problems.append("owner differs")
    if g["agent"] != agent:
        problems.append("agent key differs")
    if sorted(g["instruments"]) != sorted(instruments):
        problems.append("instruments differ")
    if g["limits"] != limits:
        problems.append("limits differ")
    if g.get("may_withdraw"):
        problems.append("grant would allow withdrawals")
    if grant_id(g).hex() != draft["id"]:
        problems.append("server id is not the hash of the grant fields")
    if problems:
        raise ValueError("refusing to sign the drafted grant: " + ", ".join(problems))
    return bytes.fromhex(draft["id"])


def create_grant(client: Client, owner_sk: bytes, agent_pk: str, instruments, limits, expires_in_s=86_400, label="", confirm=None):
    """Draft, check, show and sign a grant with the owner's key. `confirm(consent_text)` must
    return True to sign (default: sign). Returns the venue's grant view."""
    owner = pubkey_hex(owner_sk)
    d = client.grant_draft(owner, agent_pk, instruments, limits, expires_in_s, label)
    gid = check_draft(d, owner, agent_pk, instruments, limits)
    if confirm is not None and not confirm(d["consent"]):
        raise RuntimeError("grant not confirmed")
    g = dict(d["grant"], signature=sign(owner_sk, gid))
    return client.grant_create(g, label)


def revoke_grant(client: Client, owner_sk: bytes, gid: str):
    """Owner-signed revocation; takes effect in the venue's next journal record."""
    view = client.grant(gid)
    g = view["grant"]
    r = {"version": 1, "router": g["router"], "grant": gid, "owner": pubkey_hex(owner_sk), "issued_us": int(time.time() * 1e6)}
    r["signature"] = sign(owner_sk, revocation_id(r, g["scope"]))
    return client.grant_revoke(r)
