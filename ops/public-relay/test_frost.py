"""FROST confederation tests (offline: sources are faked, members run on loopback)."""
import itertools
import json
import sys
import tempfile
import time
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bip340  # noqa: E402
import frost  # noqa: E402
import frost_relay  # noqa: E402
import frost_signer  # noqa: E402
import coord_auth  # noqa: E402
import public_relay as pr  # noqa: E402
from test_public_relay import BASE, fake  # noqa: E402

MSG = bip340.tagged_hash("t", b"m")


def run_round(shares, idx, msg=MSG, states=None):
    states = states or {i: frost.SignerState(Path(tempfile.mkdtemp()) / "s.json") for i in idx}
    nonces = {i: states[i].commit(1) for i in idx}
    commits = [{"index": i, "D": frost.ser(frost._mul(frost.G, nonces[i][0])).hex(), "E": frost.ser(frost._mul(frost.G, nonces[i][1])).hex()} for i in idx]
    partials = {i: frost.partial_sign(shares[i - 1], *states[i].take(1, msg), msg, commits) for i in idx}
    return commits, partials


class Threshold(unittest.TestCase):
    def test_every_3_of_5_set_yields_a_bip340_signature(self):
        group, shares = frost.keygen(3, 5)
        for idx in itertools.combinations(range(1, 6), 3):
            commits, partials = run_round(shares, idx)
            sig = frost.aggregate(group, MSG, commits, partials)
            self.assertTrue(bip340.verify(MSG, bytes.fromhex(group["group_pubkey"]), sig))
        commits, partials = run_round(shares, (1, 2, 3, 4, 5))
        self.assertTrue(bip340.verify(MSG, bytes.fromhex(group["group_pubkey"]), frost.aggregate(group, MSG, commits, partials)))

    def test_parity_cases_across_keys_and_nonces(self):
        odd_r = 0
        for _ in range(12):
            group, shares = frost.keygen(2, 3)
            commits, partials = run_round(shares, (1, 3))
            r = frost.group_commitment(bytes.fromhex(group["group_pubkey"]), MSG, commits)
            odd_r += r[1] & 1
            self.assertTrue(bip340.verify(MSG, bytes.fromhex(group["group_pubkey"]), frost.aggregate(group, MSG, commits, partials)))
        self.assertTrue(0 < odd_r < 12, "both R parities exercised")

    def test_too_few_signers_and_cheating_partial(self):
        group, shares = frost.keygen(3, 5)
        with self.assertRaises(ValueError):  # members refuse to sign for a below-threshold set
            run_round(shares, (1, 2))
        commits, partials = run_round(shares, (2, 4, 5))
        partials[4] = (partials[4] + 1) % frost.N
        with self.assertRaises(frost.CheatingSigner) as cm:
            frost.aggregate(group, MSG, commits, partials)
        self.assertEqual(cm.exception.indices, [4])


class NonceSafety(unittest.TestCase):
    def test_nonce_used_once_even_across_restart(self):
        d = Path(tempfile.mkdtemp())
        st = frost.SignerState(d / "s.json")
        self.assertEqual(st.commit(7), st.commit(7))
        st.take(7, MSG)
        with self.assertRaises(ValueError):
            st.take(7, MSG)
        st2 = frost.SignerState(d / "s.json")
        for bad in (7, 6):
            with self.assertRaises(ValueError):
                st2.commit(bad)
        st2.commit(9)
        st2.take(9, MSG)
        with self.assertRaises(ValueError):
            frost.SignerState(d / "s.json").take(9, MSG)


MASTER = bytes(range(32))


def verifier_for(group, m):
    pk = group["group_pubkey"]
    return coord_auth.Verifier(coord_auth.member_key(MASTER, pk, m.index), pk, m.index)


class Confederation(unittest.TestCase):
    def test_live_members_two_down_then_quorum_loss_and_cheater(self):
        tmp = Path(tempfile.mkdtemp())
        group, shares = frost.keygen(3, 5)
        members, servers, urls = [], [], []
        for s in shares:
            m = frost_signer.Member(s, tmp / f"m{s['index']}", view=frost_signer.NO_PRICE_CHECK)
            srv = frost_signer.serve(m, "127.0.0.1:0", verifier_for(group, m))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            members.append(m)
            servers.append(srv)
            urls.append(f"http://127.0.0.1:{srv.server_address[1]}")
        relay = frost_relay.FrostRelay(tmp / "relay", 5000, group, urls, auth_master=MASTER)
        pk = group["group_pubkey"]
        now = pr.now_us()
        p1 = relay.publish(now, fake(BASE))
        self.assertTrue(pr.verify_packet(p1, pk))
        self.assertEqual(p1["frost_signers"], [1, 2, 3])
        servers[0].shutdown(); servers[0].server_close()
        servers[2].shutdown(); servers[2].server_close()
        p2 = relay.publish(now + 5_000_000, fake(BASE))
        self.assertTrue(pr.verify_packet(p2, pk))
        self.assertEqual((p2["frost_signers"], p2["body"]["previous"]), ([2, 4, 5], p1["digest"]))
        # Member 4 starts cheating: identified, slot cannot complete with the rest, then banned.
        real = frost.partial_sign
        def bad(share, *a, **k):
            z = real(share, *a, **k)
            return (z + 1) % frost.N if share["index"] == 4 else z
        frost_signer.frost.partial_sign = bad
        try:
            with self.assertRaises(RuntimeError):
                relay.publish(now + 10_000_000, fake(BASE))
            self.assertEqual(relay.fstats["cheaters"], {"4": 1})
            self.assertEqual(relay.seq, 2, "a failed slot does not advance the chain")
            with self.assertRaises(RuntimeError):  # only 2 honest members left: below threshold
                relay.publish(now + 15_000_000, fake(BASE))
        finally:
            frost_signer.frost.partial_sign = real
        # Restart the coordinator: reserved sequences are never reused, members 1 and 3
        # return, and the next packet jumps seq but still links to the last published one.
        for i in (0, 2):
            srv = frost_signer.serve(members[i], "127.0.0.1:0", verifier_for(group, members[i]))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            servers[i] = srv
            urls[i] = f"http://127.0.0.1:{srv.server_address[1]}"
        relay2 = frost_relay.FrostRelay(tmp / "relay", 5000, group, urls, auth_master=MASTER)
        self.assertEqual((relay2.seq, relay2.reserved), (2, 4))
        p5 = relay2.publish(now + 20_000_000, fake(BASE))
        self.assertTrue(pr.verify_packet(p5, pk))
        self.assertEqual((p5["body"]["seq"], p5["body"]["previous"]), (5, p2["digest"]))
        bad = dict(p5["body"], seq=6, previous="ab" * 32)
        with self.assertRaises(ValueError):  # does not extend a group-signed parent
            members[1].sign({"seq": 6, "body": bad, "parent": p5, "commitments": []})
        for srv in servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
