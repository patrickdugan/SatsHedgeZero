"""The Python encoders reproduce every id in sdk/vectors/agent_vectors.json (written by the
Rust test `shared_agent_vectors`), verify the Rust signatures, and refuse a tampered draft."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from lightninger import bip340, check_draft  # noqa: E402
from lightninger.encoding import grant_id, intent_id, revocation_id  # noqa: E402
from lightninger.ws import _Ws  # noqa: E402,F401

V = json.load(open(os.path.join(HERE, "..", "..", "vectors", "agent_vectors.json")))
AUX0_SIG = "68a0876694901ce65759974f33d1eb1818ffe12e84abc5a4e94656ea6da57553263d39374f1f4a46167d306a42d3630972c56a612e34ed7c3e73eed14cd73f9b"


class Vectors(unittest.TestCase):
    def test_keys(self):
        self.assertEqual(bip340.pubkey(bytes.fromhex(V["keys"]["owner_sk"])).hex(), V["keys"]["owner_pk"])
        self.assertEqual(bip340.pubkey(bytes.fromhex(V["keys"]["agent_sk"])).hex(), V["keys"]["agent_pk"])

    def test_grant_and_revocation_ids(self):
        g = V["grant"]["wire"]
        self.assertEqual(grant_id(g).hex(), V["grant"]["id"])
        self.assertTrue(bip340.verify(bytes.fromhex(V["grant"]["id"]), bytes.fromhex(g["owner"]), bytes.fromhex(g["signature"])))
        r = V["revocation"]["wire"]
        self.assertEqual(r["grant"], V["grant"]["id"])
        self.assertEqual(revocation_id(r, g["scope"]).hex(), V["revocation"]["id"])
        self.assertTrue(bip340.verify(bytes.fromhex(V["revocation"]["id"]), bytes.fromhex(r["owner"]), bytes.fromhex(r["signature"])))

    def test_intent_ids_and_agent_signatures(self):
        agent = bytes.fromhex(V["keys"]["agent_pk"])
        for inst in ("perp", "option", "spot"):
            i = V[inst]["intent"]
            iid = intent_id(inst, i, V["template"])
            self.assertEqual(iid.hex(), V[inst]["id"], inst)
            self.assertTrue(bip340.verify(iid, agent, bytes.fromhex(i["signature"])), inst)
            self.assertEqual(i["owner"], V["keys"]["owner_pk"], "agent signs with the owner field = account owner")

    def test_bip340_zero_aux_matches_the_wasm_signer(self):
        # Same constant in sdk/ts/test/vectors.test.ts (sign.wasm, the browser's signer).
        sig = bip340.sign(bytes.fromhex(V["grant"]["id"]), bytes.fromhex(V["keys"]["agent_sk"]), bytes(32))
        self.assertEqual(sig.hex(), AUX0_SIG)

    def test_draft_check_refuses_tampering(self):
        g = dict(V["grant"]["wire"])
        g.pop("signature")
        d = {"grant": g, "id": V["grant"]["id"], "consent": "..."}
        args = (g["owner"], g["agent"], g["instruments"], g["limits"])
        self.assertEqual(check_draft(d, *args).hex(), V["grant"]["id"])
        for k, v in [("agent", "00" * 32), ("may_withdraw", True), ("limits", dict(g["limits"], max_order_notional_usd=10**9))]:
            bad = dict(d, grant=dict(g, **{k: v}))
            with self.assertRaises(ValueError):
                check_draft(bad, *args)
        with self.assertRaises(ValueError):
            check_draft(dict(d, id="11" * 32), *args)


if __name__ == "__main__":
    unittest.main()
