"""Offline tests for the public trusted relayer (no network)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bip340  # noqa: E402
import public_relay as pr  # noqa: E402

SLOT = 1_800_000_000_000_000


def fake(prices: dict, ages_s: dict | None = None, errors: dict | None = None):
    """Build fetch results as fetch_all would return them."""
    ages_s = ages_s or {}
    errors = errors or {}
    out = {}
    for sid, (role, _, _) in pr.SOURCES.items():
        raw = json.dumps({"sid": sid, "p": prices.get(sid)}).encode()
        if sid in errors:
            out[sid] = (role, SLOT + 50_000, None, errors[sid])
            continue
        ts = SLOT - int(ages_s.get(sid, 1) * 1_000_000)
        out[sid] = (role, SLOT + 50_000, raw, (prices[sid], None if sid in ("kraken", "gemini") else ts))
    return out


BASE = {"coinbase": 10_000_000_000_000, "kraken": 10_001_000_000_000, "bitstamp": 9_999_000_000_000,
        "gemini": 10_000_500_000_000, "chainlink_eth": 10_010_000_000_000}


class Bip340Vectors(unittest.TestCase):
    def test_vector_0(self):
        sk = (3).to_bytes(32, "big")
        self.assertEqual(bip340.pubkey(sk).hex().upper(), "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        sig = bip340.sign(bytes(32), sk, bytes(32))
        self.assertEqual(sig.hex().upper(),
                         "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                         "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")

    def test_roundtrip_and_tamper(self):
        sk = bytes.fromhex("11" * 32)
        msg = bip340.tagged_hash("x", b"y")
        sig = bip340.sign(msg, sk, bytes(32))
        pk = bip340.pubkey(sk)
        self.assertTrue(bip340.verify(msg, pk, sig))
        self.assertFalse(bip340.verify(msg, pk, sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(bip340.verify(bytes(32), pk, sig))


class Assembly(unittest.TestCase):
    def test_valid_median_and_audit(self):
        body, private = pr.assemble(1, "00" * 32, SLOT, 5000, fake(BASE))
        self.assertEqual(body["status"], "VALID")
        self.assertEqual(body["fast_sources_used"], 4)
        self.assertEqual(body["median_e8"], (10_000_000_000_000 + 10_000_500_000_000) // 2)
        self.assertLessEqual(body["dispersion_bps"], 50)
        self.assertIsNotNone(body["audit_deviation_bps"])
        self.assertNotIn("price_e8", json.dumps(body["sources"]))  # per-source prices stay private
        self.assertEqual(private["coinbase"], BASE["coinbase"])
        self.assertTrue(next(s for s in body["sources"] if s["id"] == "kraken")["ts_from_fetch"])

    def test_hold_rules(self):
        b, _ = pr.assemble(1, "00" * 32, SLOT, 5000, fake(BASE, errors={"coinbase": "fetch: URLError", "kraken": "fetch: URLError"}))
        self.assertEqual((b["status"], b["hold_reason"]), ("HOLD", "insufficient_fresh_sources"))
        b, _ = pr.assemble(1, "00" * 32, SLOT, 5000, fake(BASE, ages_s={"bitstamp": 31, "coinbase": 40}))
        self.assertEqual(b["hold_reason"], "insufficient_fresh_sources")
        wide = dict(BASE, bitstamp=9_900_000_000_000)
        b, _ = pr.assemble(1, "00" * 32, SLOT, 5000, fake(wide))
        self.assertEqual(b["hold_reason"], "dispersion")
        far = dict(BASE, chainlink_eth=9_700_000_000_000)
        b, _ = pr.assemble(1, "00" * 32, SLOT, 5000, fake(far))
        self.assertEqual(b["hold_reason"], "audit_divergence")
        # Chainlink an hour old is still a usable audit reference; absent audit does not HOLD.
        b, _ = pr.assemble(1, "00" * 32, SLOT, 5000, fake(BASE, ages_s={"chainlink_eth": 3_500}))
        self.assertEqual(b["status"], "VALID")
        b, _ = pr.assemble(1, "00" * 32, SLOT, 5000, fake(BASE, errors={"chainlink_eth": "fetch: TimeoutError"}))
        self.assertEqual((b["status"], b["audit_deviation_bps"]), ("VALID", None))


class ChainAndRestart(unittest.TestCase):
    def test_signed_chain_survives_restart_and_detects_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            r = pr.Relay(Path(d), 5000)
            p1 = r.publish(SLOT, fake(BASE))
            p2 = r.publish(SLOT + 5_000_000, fake(BASE))
            self.assertTrue(pr.verify_packet(p1, r.pubkey) and pr.verify_packet(p2, r.pubkey))
            self.assertEqual(p2["body"]["previous"], p1["digest"])
            self.assertEqual(p2["body"]["seq"], 2)
            r2 = pr.Relay(Path(d), 5000)
            self.assertEqual((r2.seq, r2.previous, r2.pubkey), (2, p2["digest"], r.pubkey))
            p3 = r2.publish(SLOT + 10_000_000, fake(BASE))
            self.assertEqual((p3["body"]["seq"], p3["body"]["previous"]), (3, p2["digest"]))
            bad = json.loads(json.dumps(p3))
            bad["body"]["median_e8"] += 1
            self.assertFalse(pr.verify_packet(bad, r.pubkey))
            # Tampered archive tail: restart refuses to continue the chain.
            f = next((Path(d) / "archive").glob("*.jsonl"))
            lines = f.read_text().splitlines()
            lines[-1] = json.dumps(bad)
            f.write_text("\n".join(lines) + "\n")
            with self.assertRaises(SystemExit):
                pr.Relay(Path(d), 5000)
            self.assertTrue(any((Path(d) / "raw").iterdir()))


class SharedOpener(unittest.TestCase):
    """Fetches reuse one opener and one verifying TLS context (no per-request cycles)."""

    def test_get_reuses_the_module_opener(self):
        import io
        import ssl
        import urllib.request
        from unittest import mock

        https = [h for h in pr._OPENER.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertEqual(len(https), 1)
        self.assertIs(https[0]._context, pr._TLS)
        self.assertEqual((pr._TLS.verify_mode, pr._TLS.check_hostname), (ssl.CERT_REQUIRED, True))
        seen = []

        def fake_open(req, timeout):
            seen.append((req.full_url, req.get_header("Content-type"), timeout))
            return io.BytesIO(b'{"ok":1}')

        with mock.patch.object(pr._OPENER, "open", side_effect=fake_open), \
                mock.patch.object(urllib.request, "build_opener", side_effect=AssertionError("per-request opener")), \
                mock.patch.object(ssl, "create_default_context", side_effect=AssertionError("per-request context")):
            for _ in range(3):
                self.assertEqual(pr._get("https://example.invalid/t"), b'{"ok":1}')
            self.assertEqual(pr._get("https://example.invalid/rpc", data=b"{}", timeout=1.5), b'{"ok":1}')
        self.assertEqual(seen[-1], ("https://example.invalid/rpc", "application/json", 1.5))
        self.assertEqual(len(seen), 4)


if __name__ == "__main__":
    unittest.main()
