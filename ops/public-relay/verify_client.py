#!/usr/bin/env python3
"""Verify a running public relayer: pinned key, signature, digest, and chain links.

  python3 verify_client.py http://170.75.168.145:8090 [--pubkey HEX] [--follow N]

Without --pubkey the key is fetched from /v1/pubkey (trust on first use);
pin it for real use. --follow N reads N packets from /v1/stream and checks
that each links to the previous one by digest with seq + 1.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import public_relay as pr  # noqa: E402


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=pr.UA), timeout=10) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--pubkey")
    ap.add_argument("--follow", type=int, default=0)
    ap.add_argument("--dlc", help="verify a DLC event's announcement and attestation (FROST relay)")
    a = ap.parse_args()
    pk = a.pubkey or get(a.base + "/v1/pubkey")["pubkey_bip340"]
    if a.dlc:
        import bip340
        import dlc_oracle as dlc
        ev = get(f"{a.base}/v1/dlc/event/{a.dlc}")
        core = ev["core"]
        gx = bytes.fromhex(pk)
        assert core["oracle_pubkey_x"] == pk, "event not announced by the pinned key"
        assert bip340.verify(dlc.announcement_message(core), gx, bytes.fromhex(ev["announcement_signature"])), "bad announcement signature"
        out = {"event_id": core["event_id"], "maturity_unix": core["maturity_unix"], "announcement_ok": True, "status": ev["status"]}
        if ev["status"] == "attested":
            att = ev["attestation"]
            assert att["digit_bits"] == dlc.decompose(att["price_usd"], core["num_bits"]), "bits do not match price"
            for d, (bit, sig) in enumerate(zip(att["digit_bits"], att["digit_signatures"])):
                assert sig[:64] == core["digit_nonces_x"][d], "digit signed with a nonce other than the announced one"
                assert bip340.verify(dlc.digit_message(core["event_id"], d, bit), gx, bytes.fromhex(sig)), f"bad digit {d}"
            out.update(price_usd=att["price_usd"], digits_ok=len(att["digit_signatures"]), signers=att["signers"], outcome_packet=att["outcome_packet"]["seq"])
        if ev["status"] == "unattestable":
            sig = bytes.fromhex(ev["unattestable_signature"])
            assert sig[:32].hex() == core["unattestable_nonce_x"], "notice not signed with the announced nonce"
            assert bip340.verify(dlc.unattestable_message(core["event_id"]), gx, sig), "bad unattestable notice"
            out.update(unattestable_notice_ok=True, signers=ev["unattestable_signers"])
        print(json.dumps(out))
        return
    latest = get(a.base + "/v1/latest")
    ok = pr.verify_packet(latest, pk)
    b = latest["body"]
    print(json.dumps({"seq": b["seq"], "status": b["status"], "median_usd": b.get("median_e8", 0) / 1e8,
                      "fast_sources": b["fast_sources_used"], "signature_ok": ok}))
    if not ok:
        sys.exit(1)
    if b["seq"] > 1:
        try:
            prev = get(f"{a.base}/v1/packet/{b['seq'] - 1}")
            assert pr.verify_packet(prev, pk) and b["previous"] == prev["digest"], "chain link broken"
            print("chain link to seq", b["seq"] - 1, "ok")
        except urllib.error.HTTPError:
            print("seq", b["seq"] - 1, "not published (skipped slot); link checked on the stream")
    if a.follow:
        last = latest
        with urllib.request.urlopen(a.base + "/v1/stream", timeout=30) as r:
            n = 0
            for line in r:
                if not line.startswith(b"data: "):
                    continue
                p = json.loads(line[6:])
                assert pr.verify_packet(p, pk), "bad signature"
                assert p["body"]["seq"] > last["body"]["seq"], "sequence went backwards"
                assert p["body"]["previous"] == last["digest"], "chain link broken"
                last = p
                n += 1
                print(json.dumps({"seq": p["body"]["seq"], "status": p["body"]["status"], "median_usd": p["body"].get("median_e8", 0) / 1e8}))
                if n >= a.follow:
                    break


if __name__ == "__main__":
    main()
