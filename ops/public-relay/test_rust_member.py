"""The member test suites with Rust members (crates/shz-frost-member) in place of frost_signer.py.

    cargo build -p shz-frost-member --features test-hooks
    SHZ_RUST_MEMBER=<target>/debug/shz-frost-member python -m unittest -v test_rust_member

Without SHZ_RUST_MEMBER every test here is skipped. With it, `frost_signer.Member`, `serve`,
`StaticView` and `dlc_oracle.DlcMember` are replaced by proxies that run one Rust member process
each, and test_frost, test_dlc and test_review_hft06 run unchanged on top of them: the Python
coordinator (`frost_relay`, `dlc_coord`) talks HTTP to Rust members, and the member internals the
tests call directly (`Member.sign`, `._check_content`, `.dlc.sign_outcome`, `DlcMember._partial`,
`.state.s`, a monkeypatched `frost.partial_sign` or `Member.sign`) reach the Rust process through
its `/test/*` routes and harness callbacks (feature `test-hooks`). Tests of Python library code
(keygen, aggregation, SourceView over fake sources, the public relay) still exercise Python.

`MixedConfederation` runs the deployment-shaped case: Python coordinator, two Python members and
three Rust members (`--coord-auth-key`, no test hooks used) publish VALID packets and attest a DLC
event. `RustCli` checks the command line against frost_signer.py's.
"""
from __future__ import annotations

import atexit
import builtins
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bip340  # noqa: E402
import coord_auth  # noqa: E402
import dlc_coord  # noqa: E402
import dlc_oracle  # noqa: E402
import frost  # noqa: E402
import frost_relay  # noqa: E402
import frost_signer  # noqa: E402
import public_relay as pr  # noqa: E402

BIN = os.environ.get("SHZ_RUST_MEMBER")
ORIG_MEMBER, ORIG_SERVE, ORIG_STATIC_VIEW = frost_signer.Member, frost_signer.serve, frost_signer.StaticView
ORIG_DLC_MEMBER, ORIG_PARTIAL = dlc_oracle.DlcMember, frost.partial_sign
_procs: list["RustProc"] = []
_tokens: dict[str, object] = {}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _raise_from(text: str):
    kind, _, msg = text.partition(": ")
    cls = getattr(builtins, kind, None)
    if not (isinstance(cls, type) and issubclass(cls, Exception)) or cls is StopIteration:
        cls = ValueError
    raise cls(msg)


# ------------------------------------------------------------ callbacks ----

class _Callbacks(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        token, _, what = self.path.strip("/").partition("/")
        owner, req = _tokens.get(token), json.loads(raw)
        if what == "partial":
            fn = frost.partial_sign  # the tests monkeypatch this module attribute
            out = {"z": req["z"]}
            if fn is not ORIG_PARTIAL:
                z = fn(owner.share, int(req["d"], 16), int(req["e"], 16), bytes.fromhex(req["msg"]), req["commits"])
                out = {"z": z.to_bytes(32, "big").hex()}
        else:
            try:
                out = {"result": owner.__dict__["sign"](req["req"])}
            except Exception as e:  # noqa: BLE001 - reported to the Rust member as its refusal
                out = {"error": f"{type(e).__name__}: {e}"}
        b = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


_cb = None


def _callback_url() -> str:
    global _cb
    if _cb is None:
        _cb = ThreadingHTTPServer(("127.0.0.1", 0), _Callbacks)
        _cb.daemon_threads = True
        threading.Thread(target=_cb.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{_cb.server_address[1]}"


# -------------------------------------------------------------- process ----

class RustProc:
    """One shz-frost-member process."""

    def __init__(self, owner, share: dict, state_dir: Path, view_mode: str, key: bytes | None, port: int | None = None,
                 dlc_path: Path | None = None, max_dev: int = 50, max_age: float = 35.0, hooks: bool = True):
        self.share, self.key = share, key
        self.port = port or _free_port()
        scratch = Path(tempfile.mkdtemp())
        share_file = scratch / "share.json"
        share_file.write_text(json.dumps(share))
        args = [BIN, "--share", str(share_file), "--state", str(state_dir), "--listen", f"127.0.0.1:{self.port}",
                "--max-deviation-bps", str(max_dev), "--view-max-age-s", str(max_age)]
        if key is None:
            args.append("--no-coord-auth")
        else:
            (scratch / "coord_auth.key").write_text(key.hex() + "\n")
            args += ["--coord-auth-key", str(scratch / "coord_auth.key")]
        if view_mode == "nocheck":
            args.append("--no-price-check")
        else:
            args += ["--test-view", view_mode]
        if dlc_path is not None:
            args += ["--test-dlc-path", str(dlc_path)]
        if hooks:
            token = f"t{id(self)}"
            _tokens[token] = owner
            args += ["--test-hooks", f"{_callback_url()}/{token}"]
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.p.stdout.readline()
        if not line.startswith("frost member"):
            raise RuntimeError(f"rust member failed to start: {line}{self.p.stderr.read()}")
        _procs.append(self)
        if hooks:
            self.call("/test/hooks", {"partial": True})

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def alive(self) -> bool:
        return self.p.poll() is None

    def raw(self, path: str, obj) -> tuple[int, dict]:
        body = json.dumps(obj).encode()
        h = {"Content-Type": "application/json"}
        if self.key is not None:
            h[coord_auth.HEADER] = coord_auth.header(self.key, self.share["group"]["group_pubkey"], self.share["index"], path, body)
        try:
            with urllib.request.urlopen(urllib.request.Request(self.url + path, data=body, headers=h), timeout=60) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def call(self, path: str, obj):
        code, r = self.raw(path, obj)
        if code == 200:
            return r
        _raise_from(r.get("error", f"HTTP {code}"))

    def kill(self):
        if self.alive():
            self.p.kill()
            self.p.wait()
        for f in (self.p.stdout, self.p.stderr):
            f.close()


def _cleanup():
    for p in _procs:
        try:
            p.kill()
        except Exception:  # noqa: BLE001
            pass


atexit.register(_cleanup)


# --------------------------------------------------------------- proxies ----

class SyncedStaticView(ORIG_STATIC_VIEW):
    """StaticView whose reading is pushed to every Rust member that holds it."""

    def __init__(self, median_e8: int | None = None):
        self.members: list = []
        super().__init__(median_e8)

    def set(self, median_e8, at_us=None):
        super().set(median_e8, at_us)
        for m in getattr(self, "members", []):
            m._push_view()


class RustDlc:
    """`dlc_oracle.DlcMember` API over a Rust process."""

    def __init__(self, share: dict, proc_of):
        self.share, self.i, self.t = share, share["index"], share["group"]["threshold"]
        self._proc_of = proc_of

    def _c(self, what: str, obj):
        return self._proc_of().call(f"/test/dlc/{what}", obj)["result"]

    @property
    def s(self):
        return self._c("state", {})

    def _ev(self, event_id):
        ev = self.s["events"].get(event_id)
        if ev is None:
            raise ValueError("unknown event")
        return ev

    def deal(self, event_id, maturity_unix, num_bits, members):
        return self._c("deal", {"event_id": event_id, "maturity_unix": maturity_unix, "num_bits": num_bits, "members": members})

    def receive(self, event_id, deals):
        return self._c("receive", {"event_id": event_id, "deals": deals})

    def sign_announcement(self, event_id, core, signers):
        return self._c("sign-announcement", {"event_id": event_id, "core": core, "signers": signers})

    def lock_decision(self, event_id, decision, now_us=None):
        return self._c("lock-decision", {"event_id": event_id, "decision": decision, "now_us": now_us})

    def sign_unattestable(self, event_id, now_us, signers, locks=None):
        return self._c("sign-unattestable", {"event_id": event_id, "now_us": now_us, "signers": signers, "locks": locks})

    def sign_outcome(self, event_id, price_usd, signers, locks=None):
        return self._c("sign-outcome", {"event_id": event_id, "price_usd": price_usd, "signers": signers, "locks": locks})

    def _partial(self, ev, d, msg, signers):
        eid = next(k for k, v in self.s["events"].items() if v == ev)
        return int(self._c("partial", {"event_id": eid, "d": d, "msg": msg.hex(), "signers": signers}), 16)


class RustDlcMember(RustDlc):
    """Drop-in for `dlc_oracle.DlcMember(share, state_path)`: a Rust process on that dlc.json."""

    def __init__(self, share: dict, state_path: Path):
        self.path = Path(state_path)
        self.proc = RustProc(self, share, Path(tempfile.mkdtemp()), "nocheck", None, dlc_path=self.path)
        super().__init__(share, lambda: self.proc)


class _State:
    def __init__(self, m):
        self._m = m

    @property
    def s(self):
        return self._m._call("/test/state", {})["result"]


class RustMember:
    """Drop-in for `frost_signer.Member`: the Rust process starts on first use or in `serve`."""

    def __init__(self, share: dict, state_dir: Path, view=None, max_deviation_bps: int = 50, view_max_age_s: float = 35.0):
        self.share, self.index = share, share["index"]
        self.state_dir, self.view = Path(state_dir), view
        self.max_dev, self.max_age = max_deviation_bps, view_max_age_s
        self.proc: RustProc | None = None
        self.dlc = RustDlc(share, self._proc)
        self.state = _State(self)
        if isinstance(view, SyncedStaticView):
            view.members.append(self)

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)
        if name == "sign" and self.proc is not None and self.proc.alive():
            self.proc.call("/test/hooks", {"sign": True})

    def _view_mode(self) -> str:
        if self.view is frost_signer.NO_PRICE_CHECK:
            return "nocheck"
        return "none" if self.view is None else "static"

    def _start(self, key: bytes | None, port: int | None):
        if self.proc is not None:
            self.proc.kill()
        self.proc = RustProc(self, self.share, self.state_dir, self._view_mode(), key, port, max_dev=self.max_dev, max_age=self.max_age)
        self._push_view()
        if "sign" in self.__dict__:
            self.proc.call("/test/hooks", {"sign": True})

    def _proc(self) -> RustProc:
        if self.proc is None or not self.proc.alive():
            self._start(None, None)
        return self.proc

    def _push_view(self):
        if isinstance(self.view, ORIG_STATIC_VIEW) and self.proc is not None and self.proc.alive():
            self.proc.call("/test/view", {"median_e8": self.view.median_e8, "at_us": self.view.at_us})

    def _call(self, path, obj):
        return self._proc().call(path, obj)

    @property
    def content_refusals(self) -> int:
        return self._call("/test/stats", {})["result"]["content_refusals"]

    def commit(self, seq):
        return self._call("/commit", {"seq": seq})

    def sign(self, req):
        return self._call("/sign", req)

    def dlc_attest(self, req):
        return self._call("/dlc/sign-outcome", req)

    def dlc_lock_outcome(self, req):
        return self._call("/dlc/lock-outcome", req)

    def dlc_lock_unattestable(self, req):
        return self._call("/dlc/lock-unattestable", req)

    def dlc_unattestable(self, req):
        return self._call("/dlc/sign-unattestable", req)

    def _check_content(self, body):
        self._call("/test/check-content", {"body": body})

    def _observe(self, pkt):
        self._call("/test/observe", {"packet": pkt})


class _Server:
    def __init__(self, m: RustMember):
        self.m, self.server_address = m, ("127.0.0.1", m.proc.port)
        self._stop = threading.Event()

    def serve_forever(self):
        self._stop.wait()

    def shutdown(self):
        if self.m.proc is not None:
            self.m.proc.kill()
        self._stop.set()

    def server_close(self):
        pass


def rust_serve(m: RustMember, listen: str, verifier):
    """`frost_signer.serve` with the same verifier checks, then (re)starts the Rust process."""
    key = None
    if verifier is not coord_auth.UNAUTHENTICATED:
        if not isinstance(verifier, coord_auth.Verifier) or verifier.index != m.index \
                or verifier.group_pubkey != m.share["group"]["group_pubkey"]:
            raise ValueError("coordinator verifier does not match this member")
        key = verifier.key
    port = int(listen.rsplit(":", 1)[1]) or None
    m._start(key, port)
    return _Server(m)


def _install():
    """Swap the member classes the suites construct. `dlc_oracle` itself stays intact (the Python
    members of the mixed run use it); the suites see a copy whose DlcMember is the Rust proxy."""
    import types

    import test_dlc
    import test_review_hft06
    frost_signer.Member, frost_signer.serve, frost_signer.StaticView = RustMember, rust_serve, SyncedStaticView
    rust_dlc = types.ModuleType("dlc_oracle_rust")
    rust_dlc.__dict__.update(dlc_oracle.__dict__)
    rust_dlc.DlcMember = RustDlcMember
    test_dlc.dlc = test_review_hft06.dlc = rust_dlc


if BIN:
    _install()
    from test_frost import Confederation, NonceSafety, Threshold  # noqa: E402,F401
    from test_dlc import DlcOracle  # noqa: E402,F401
    from test_review_hft06 import *  # noqa: E402,F401,F403
    from test_public_relay import BASE, fake  # noqa: E402


@unittest.skipUnless(BIN, "set SHZ_RUST_MEMBER to a shz-frost-member binary built with --features test-hooks")
class MixedConfederation(unittest.TestCase):
    """Python coordinator, Python members 1-2, Rust members 3-5 started as deployed (auth key file)."""

    def test_mixed_members_publish_and_attest(self):
        tmp = Path(tempfile.mkdtemp())
        group, shares = frost.keygen(3, 5)
        master = bytes(range(32))
        pk = group["group_pubkey"]
        view = SyncedStaticView()
        servers, procs, urls = [], [], []
        for s in shares:
            i = s["index"]
            key = coord_auth.member_key(master, pk, i)
            if i <= 2:
                m = ORIG_MEMBER(s, tmp / f"m{i}", view=view)
                srv = ORIG_SERVE(m, "127.0.0.1:0", coord_auth.Verifier(key, pk, i))
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                servers.append(srv)
                urls.append(f"http://127.0.0.1:{srv.server_address[1]}")
            else:
                # Deployed shape: auth key file, no test hooks; the price check runs on a static
                # reading because the fast sources are faked here.
                p = RustProc(None, s, tmp / f"m{i}", "static", key, hooks=False)
                procs.append(p)
                urls.append(p.url)

        def push(results, slot):
            view.set_from_results(results, slot)
            for p in procs:
                p.call("/test/view", {"median_e8": view.median_e8, "at_us": None})

        try:
            relay = frost_relay.FrostRelay(tmp / "relay", 5000, group, urls, auth_master=master)
            coord = dlc_coord.DlcCoordinator(relay, tmp / "relay", num_bits=8)
            now_s = pr.now_us() // 1_000_000
            maturity = now_s - now_s % 60 + 60
            ev = coord.setup(maturity)
            core = ev["core"]
            gx = bytes.fromhex(pk)
            self.assertTrue(bip340.verify(dlc_oracle.announcement_message(core), gx, bytes.fromhex(ev["announcement_signature"])))

            push(fake(BASE), maturity * 1_000_000 - 10_000_000)
            p0 = relay.publish(maturity * 1_000_000 - 10_000_000, fake(BASE))
            self.assertEqual((p0["body"]["status"], p0["frost_signers"]), ("VALID", [1, 2, 3]))
            servers[0].shutdown()
            servers[0].server_close()
            push(fake(BASE), maturity * 1_000_000)
            p1 = relay.publish(maturity * 1_000_000, fake(BASE))
            self.assertEqual((p1["body"]["status"], p1["frost_signers"]), ("VALID", [2, 3, 4]))
            self.assertTrue(pr.verify_packet(p0, pk) and pr.verify_packet(p1, pk))
            self.assertEqual(p1["body"]["previous"], p0["digest"])

            ev = coord.attest(ev)
            self.assertEqual(ev["status"], "attested")
            att = ev["attestation"]
            self.assertEqual(att["price_usd"], p1["body"]["median_e8"] // 100_000_000)
            self.assertTrue(set(att["signers"]) & {3, 4, 5} and 2 in att["signers"], att["signers"])
            for d, (bit, sig) in enumerate(zip(att["digit_bits"], att["digit_signatures"])):
                self.assertTrue(bip340.verify(dlc_oracle.digit_message(core["event_id"], d, bit), gx, bytes.fromhex(sig)))
            # The Rust members checked the price themselves: one off by 100 bps is refused by all three.
            off = {k: v * 10_100 // 10_000 for k, v in BASE.items()}
            with self.assertRaises(RuntimeError):
                relay.publish(maturity * 1_000_000 + 5_000_000, fake(off))
        finally:
            for srv in servers[1:]:
                srv.shutdown()
                srv.server_close()
            for p in procs:
                p.kill()


@unittest.skipUnless(BIN, "set SHZ_RUST_MEMBER to a shz-frost-member binary")
class RustCli(unittest.TestCase):
    def test_cli_requires_an_explicit_auth_choice_like_frost_signer(self):
        r = subprocess.run([BIN, "--share", "x", "--state", "y"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--coord-auth-key", r.stderr)
        r = subprocess.run([BIN, "--state", "y", "--no-coord-auth"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("the following arguments are required: --share", r.stderr)

    def test_keygen_writes_shares_the_python_member_loads(self):
        out = Path(tempfile.mkdtemp()) / "k"
        r = subprocess.run([BIN, "keygen", "--t", "3", "--n", "5", "--out", str(out)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        group = json.loads((out / "group.json").read_text())
        self.assertEqual(r.stdout.strip(), group["group_pubkey"])
        shares = [json.loads((out / f"share{i}.json").read_text()) for i in range(1, 6)]
        msg = bip340.tagged_hash("t", b"m")
        states = {i: frost.SignerState(Path(tempfile.mkdtemp()) / "s.json") for i in (1, 3, 5)}
        nonces = {i: states[i].commit(1) for i in states}
        commits = [{"index": i, "D": frost.ser(frost._mul(frost.G, nonces[i][0])).hex(), "E": frost.ser(frost._mul(frost.G, nonces[i][1])).hex()} for i in states]
        partials = {i: ORIG_PARTIAL(shares[i - 1], *states[i].take(1, msg), msg, commits) for i in states}
        self.assertTrue(bip340.verify(msg, bytes.fromhex(group["group_pubkey"]), frost.aggregate(group, msg, commits, partials)))


if __name__ == "__main__":
    unittest.main()
