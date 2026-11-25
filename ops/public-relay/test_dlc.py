"""Threshold DLC oracle tests: nonce DKG, announcement, attestation, refusals.

Members run on loopback HTTP exactly as deployed; sources are faked.
Writes fixture_dlc_event.json (announcement + attestation in shz_dlc serde
form) for the Rust CET settlement test in crates/shz-dlc/tests.
"""
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bip340  # noqa: E402
import dlc_coord  # noqa: E402
import dlc_oracle as dlc  # noqa: E402
import frost  # noqa: E402
import frost_relay  # noqa: E402
import frost_signer  # noqa: E402
import public_relay as pr  # noqa: E402
from test_public_relay import BASE, fake  # noqa: E402

HERE = Path(__file__).resolve().parent


class Confed:
    def __init__(self, nbits=dlc.NUM_BITS):
        self.tmp = Path(tempfile.mkdtemp())
        self.group, shares = frost.keygen(3, 5)
        self.members, self.servers, urls = [], [], []
        for s in shares:
            m = frost_signer.Member(s, self.tmp / f"m{s['index']}")
            srv = frost_signer.serve(m, "127.0.0.1:0")
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.members.append(m)
            self.servers.append(srv)
            urls.append(f"http://127.0.0.1:{srv.server_address[1]}")
        self.relay = frost_relay.FrostRelay(self.tmp / "relay", 5000, self.group, urls)
        self.coord = dlc_coord.DlcCoordinator(self.relay, self.tmp / "relay", num_bits=nbits)

    def close(self):
        for s in self.servers:
            try:
                s.shutdown()
                s.server_close()
            except Exception:  # noqa: BLE001
                pass


class DlcOracle(unittest.TestCase):
    def test_announce_attest_and_refusals(self):
        c = Confed()
        try:
            now_s = pr.now_us() // 1_000_000
            maturity = now_s - now_s % 60 + 60
            ev = c.coord.setup(maturity)
            core = ev["core"]
            gx = bytes.fromhex(c.group["group_pubkey"])
            # Announcement: threshold signature with the reserved nonce, all nonces even-Y and distinct.
            self.assertTrue(bip340.verify(dlc.announcement_message(core), gx, bytes.fromhex(ev["announcement_signature"])))
            self.assertEqual(ev["announcement_signature"][:64], core["announcement_nonce_x"])
            self.assertEqual(len(set(core["digit_nonces_x"] + [core["announcement_nonce_x"]])), dlc.NUM_BITS + 1)
            self.assertEqual(c.coord.setup(maturity), ev, "setup is idempotent")

            # Two VALID relay packets after maturity: the outcome is the first.
            p1 = c.relay.publish(maturity * 1_000_000, fake(BASE))
            p2 = c.relay.publish(maturity * 1_000_000 + 5_000_000, fake(dict(BASE, coinbase=10_100_000_000_000, kraken=10_100_000_000_000, bitstamp=10_100_000_000_000, gemini=10_100_000_000_000)))
            ev = c.coord.attest(ev)
            self.assertEqual(ev["status"], "attested")
            price = p1["body"]["median_e8"] // 100_000_000
            att = ev["attestation"]
            self.assertEqual((att["price_usd"], att["outcome_packet"]["seq"]), (price, p1["body"]["seq"]))
            for d, (bit, sig) in enumerate(zip(att["digit_bits"], att["digit_signatures"])):
                self.assertEqual(sig[:64], core["digit_nonces_x"][d])
                self.assertTrue(bip340.verify(dlc.digit_message(core["event_id"], d, bit), gx, bytes.fromhex(sig)))

            # Equivocation refused: a member that attested will not sign a different price.
            signer = c.members[att["signers"][0] - 1]
            with self.assertRaises(ValueError):
                signer.dlc.sign_outcome(core["event_id"], price + 1, att["signers"])
            # The same outcome again is harmless (same message per nonce).
            signer.dlc.sign_outcome(core["event_id"], price, att["signers"])
            # Members refuse a later packet once they have seen an earlier VALID one (no outcome shopping).
            spare = next(m for m in c.members if m.index not in att["signers"])
            spare._observe(p1)
            with self.assertRaises(ValueError):
                spare.dlc_attest({"event_id": core["event_id"], "packet": p2, "signers": [spare.index] + att["signers"][:2]})
            # ... and a packet outside the maturity window or not group-signed.
            forged = json.loads(json.dumps(p1))
            forged["body"]["median_e8"] += 10**12
            with self.assertRaises(ValueError):
                spare.dlc_attest({"event_id": core["event_id"], "packet": forged, "signers": [spare.index] + att["signers"][:2]})

            fixture = {"oracle_pubkey_x": c.group["group_pubkey"], "announcement": ev["shz_dlc_announcement"],
                       "announcement_core": core, "announcement_signature": ev["announcement_signature"],
                       "attestation": ev["shz_dlc_attestation"]}
            (HERE / "fixture_dlc_event.json").write_text(json.dumps(fixture, indent=1))
        finally:
            c.close()

    def test_dkg_rejects_bad_share_and_tampered_commitments(self):
        group, shares = frost.keygen(3, 5)
        tmp = Path(tempfile.mkdtemp())
        ms = [dlc.DlcMember(s, tmp / f"d{s['index']}.json") for s in shares]
        deals = {str(m.i): m.deal("E1", 1_800_000_000, 4, [1, 2, 3, 4, 5]) for m in ms}
        bad = json.loads(json.dumps(deals))
        x = int(bad["2"]["enc"]["1"][3], 16) ^ 1
        bad["2"]["enc"]["1"][3] = x.to_bytes(32, "big").hex()
        with self.assertRaisesRegex(ValueError, "dealer 2"):
            ms[0].receive("E1", bad)
        bad = json.loads(json.dumps(deals))
        bad["1"]["commitments"][0][0] = bad["3"]["commitments"][0][0]
        with self.assertRaisesRegex(ValueError, "my own commitments"):
            ms[0].receive("E1", bad)
        rs = {m.i: m.receive("E1", deals) for m in ms}
        self.assertEqual(len({tuple(r) for r in rs.values()}), 1, "all members derive the same group nonces")
        # Any 3 members reconstruct the same nonce secret, consistent with R (checked via a signature).
        core_msg = dlc.digit_message("E1", 0, 1)
        for subset in ([1, 2, 3], [2, 4, 5]):
            parts = {j: ms[j - 1]._partial(ms[j - 1].s["events"]["E1"], 0, core_msg, subset) for j in subset}
            negate = [bool(dlc.group_nonce(deals, d)[1] & 1) for d in range(5)]
            sig = dlc.aggregate(group, deals, negate, 0, core_msg, rs[1][0], parts)
            self.assertTrue(bip340.verify(core_msg, bytes.fromhex(group["group_pubkey"]), sig))
        # A cheating partial is identified.
        parts = {j: ms[j - 1]._partial(ms[j - 1].s["events"]["E1"], 0, core_msg, [1, 3, 5]) for j in (1, 3, 5)}
        parts[3] = (parts[3] + 1) % frost.N
        with self.assertRaises(frost.CheatingSigner) as cm:
            dlc.aggregate(group, deals, [bool(dlc.group_nonce(deals, d)[1] & 1) for d in range(5)], 0, core_msg, rs[1][0], parts)
        self.assertEqual(cm.exception.indices, [3])
        # Nonce locks survive restart: a reloaded member still refuses a second message on nonce 0.
        ms[1].sign_outcome("E1", 9, [2, 3, 4])  # 1001: digit 0 matches the bit it already signed
        again = dlc.DlcMember(shares[1], tmp / "d2.json")
        with self.assertRaises(ValueError):
            again.sign_outcome("E1", 10, [2, 3, 4])
        again.sign_outcome("E1", 9, [2, 3, 4])  # same outcome again is allowed

    def test_digit_message_and_decomposition_match_shz(self):
        self.assertEqual(dlc.decompose(5, 4), [0, 1, 0, 1])
        self.assertEqual(dlc.decompose(99, 4), [1, 1, 1, 1])  # clamps like shz_margin
        m = dlc.digit_message("E", 2, 1)
        self.assertEqual(m, bip340.tagged_hash(b"SatsHedgeZero/DLC/DigitOutcome/v0", (1).to_bytes(4, "little") + b"E" + bytes([2, 1])))


if __name__ == "__main__":
    unittest.main()
