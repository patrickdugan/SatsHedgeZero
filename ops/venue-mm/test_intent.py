import unittest
import intent
import bip340


class T(unittest.TestCase):
    def test_bip340_vector0(self):
        sk = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
        pk = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        msg = bytes(32)
        sig = bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        self.assertEqual(bip340.pubkey(sk), pk)
        self.assertTrue(bip340.verify(msg, pk, sig))
        s2 = bip340.sign(msg, sk, bytes(32))
        self.assertEqual(s2, sig)

    def test_bip86_address(self):
        # BIP86: m/86'/0'/0'/0/0 of the "abandon ... about" mnemonic
        x = bytes.fromhex("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
        self.assertEqual(intent.taproot_output_key(x).hex(),
                         "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
        self.assertEqual(intent.p2tr_address(x, "bc"), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
        self.assertTrue(intent.p2tr_address(x, "tb").startswith("tb1p"))

    def test_intent_id_vector(self):
        # Fixture computed by hand-concatenating the byte layout in tiered.rs IntentV6::id with
        # hashlib only (no shared code with intent.py). Authoritative check: POST /api/intent-id
        # on a running venue (`python intent.py --verify-server URL`).
        tpl = {"scope": {"network": "01" * 32, "epoch": 7, "policy": "02" * 32}, "router": 1,
               "tariff_version": 1, "execution_policy": "04" * 32}
        i = {"owner": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
             "channel": {"txid": "03" * 32, "vout": 2}, "sequence": 1700000000000,
             "expires_us": 1700000060000000, "action": "post", "side": "long", "tier": "standard",
             "quantity": 5, "limit_usd": 90000, "leverage_bps": 20000, "max_fee_ppm": 0,
             "max_fee_sats": 0, "max_mark_age_us": 15000000, "early_window_opt_in": False,
             "cancel_target": "00" * 32}
        self.assertEqual(intent.intent_id(i, tpl).hex(),
                         "7cb3335fa27c57e43c7f1c4034809db3bd40871f9e8caa0e70f809aea86b4a15")

    def test_build_signs(self):
        sk = bytes.fromhex("00" * 31 + "03")
        tpl = {"scope": {"network": "01" * 32, "epoch": 7, "policy": "02" * 32}, "router": 1,
               "tariff_version": 1, "execution_policy": "04" * 32}
        iid, j = intent.build_intent(sk, tpl, {"txid": "03" * 32, "vout": 0}, sequence=1, expires_us=9, action="cancel",
                                     side="long", cancel_target="aa" * 32)
        self.assertTrue(bip340.verify(bytes.fromhex(iid), bytes.fromhex(j["owner"]), bytes.fromhex(j["signature"])))


if __name__ == "__main__":
    unittest.main()
