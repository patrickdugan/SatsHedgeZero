"""HFT-06 security review reproductions (review of 20a8edc).

Each test asserts the SAFE property, so it FAILS on 20a8edc and passes once
the finding is fixed. Run:

  python3 -m unittest -v test_review_hft06
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bip340  # noqa: E402
import dlc_oracle as dlc  # noqa: E402
import frost  # noqa: E402
import public_relay as pr  # noqa: E402
from bip340 import N  # noqa: E402
from test_dlc import Confed  # noqa: E402
from test_public_relay import BASE, fake  # noqa: E402


def interpolate_at(points: dict[int, int], x: int) -> int:
    """Value at x of the lowest-degree polynomial through points {j: y_j} (mod N)."""
    acc = 0
    for j, y in points.items():
        num, den = 1, 1
        for m in points:
            if m != j:
                num = num * (x - m) % N
                den = den * (j - m) % N
        acc = (acc + y * num * pow(den, N - 2, N)) % N
    return acc


def unblind(z_hex: str, j: int, signers: list[int]) -> int:
    """A DLC partial is lambda_j(S) * (k_j + c s_j); lambda is public."""
    return int(z_hex, 16) * pow(frost.lagrange(j, signers), N - 2, N) % N


def split_recover(w_a: dict[int, int], c_a: int, w_b: dict[int, int], c_b: int) -> dict[int, int]:
    """w_a[j] = k_j + c_a s_j for t members, w_b[j] = k_j + c_b s_j for the others.

    k and s are degree t-1 polynomials in j, so t values of k + c_a s fix it
    everywhere; subtracting a w_b value isolates that member's key share.
    """
    inv = pow((c_a - c_b) % N, N - 2, N)
    return {j: (interpolate_at(w_a, j) - w) * inv % N for j, w in w_b.items()}


class F01_DlcSplitSigningLeaksKey(unittest.TestCase):
    """F-01: one group nonce, two messages, split across honest members."""

    def _dkg(self, shares, event_id, nbits=4):
        tmp = Path(tempfile.mkdtemp())
        ms = [dlc.DlcMember(s, tmp / f"d{s['index']}.json") for s in shares]
        deals = {str(m.i): m.deal(event_id, 1_800_000_000, nbits, [1, 2, 3, 4, 5]) for m in ms}
        r = [m.receive(event_id, deals) for m in ms][0]
        return ms, r

    def _core(self, group, event_id, r, nbits, note):
        return {"event_id": event_id, "maturity_unix": 1_800_000_000, "num_bits": nbits,
                "oracle_pubkey_x": group["group_pubkey"], "digit_nonces_x": r[:nbits],
                "announcement_nonce_x": r[nbits], "unattestable_nonce_x": r[nbits + 1],
                "outcome": note}

    def _announcement_split(self, group, shares, event_id, set_a, set_b):
        """Malicious coordinator only: every member is honest and runs unmodified code."""
        nbits = 4
        ms, r = self._dkg(shares, event_id, nbits)
        gx = bytes.fromhex(group["group_pubkey"])
        core_a = self._core(group, event_id, r, nbits, "rule text A")
        core_b = self._core(group, event_id, r, nbits, "rule text B")
        c_a = frost.challenge(bytes.fromhex(r[nbits]), gx, dlc.announcement_message(core_a))
        c_b = frost.challenge(bytes.fromhex(r[nbits]), gx, dlc.announcement_message(core_b))
        w_a = {j: unblind(ms[j - 1].sign_announcement(event_id, core_a, set_a), j, set_a) for j in set_a}
        claimed = sorted(set_b + set_a[: 3 - len(set_b)])  # members only see a list; nobody checks who answers
        w_b = {j: unblind(ms[j - 1].sign_announcement(event_id, core_b, claimed), j, claimed) for j in set_b}
        return split_recover(w_a, c_a, w_b, c_b)

    def test_coordinator_cannot_extract_group_key_via_announcement(self):
        group, shares = frost.keygen(3, 5)
        true = {s["index"]: int(s["secret_share"], 16) for s in shares}
        got = {}
        try:
            got.update(self._announcement_split(group, shares, "EV-A", [1, 2, 3], [4, 5]))
            got.update(self._announcement_split(group, shares, "EV-B", [3, 4, 5], [1, 2]))
        except ValueError:
            return  # fixed: an honest member refused one of the two announcement texts
        leaked = sorted(j for j, v in got.items() if v == true[j])
        idx = sorted(got)[:3]
        x = sum(frost.lagrange(j, idx) * got[j] for j in idx) % N
        forged = bip340.sign(bip340.tagged_hash("anything", b"forged by the coordinator"), x.to_bytes(32, "big"), bytes(32))
        forgery_ok = bip340.verify(bip340.tagged_hash("anything", b"forged by the coordinator"), bytes.fromhex(group["group_pubkey"]), forged)
        self.assertFalse(leaked or forgery_ok,
                         f"coordinator recovered key shares of members {leaked} from two announcements and forged a group signature: {forgery_ok}")

    def test_coordinator_cannot_extract_shares_via_two_outcome_packets(self):
        """Deployed HTTP path: two VALID group-signed packets in one maturity window."""
        c = Confed(nbits=dlc.NUM_BITS)
        try:
            true = {m.index: int(m.share["secret_share"], 16) for m in c.members}
            now_s = pr.now_us() // 1_000_000
            maturity = now_s - now_s % 5
            ev = c.coord.setup(maturity)
            core = ev["core"]
            eid, nb = core["event_id"], core["num_bits"]
            gx = bytes.fromhex(c.group["group_pubkey"])
            # Honest relay output: consecutive slots whose integer USD price differs.
            p1 = c.relay.publish(maturity * 1_000_000, fake(BASE))
            hi = {k: 10_100_000_000_000 for k in ("coinbase", "kraken", "bitstamp", "gemini")}
            p2 = c.relay.publish(maturity * 1_000_000 + 5_000_000, fake(dict(BASE, **hi)))
            self.assertEqual((p1["body"]["status"], p2["body"]["status"]), ("VALID", "VALID"))
            set_a = p1["frost_signers"]
            set_b = [m.index for m in c.members if m.index not in set_a]
            try:
                res_a = {j: c.members[j - 1].dlc_attest({"event_id": eid, "packet": p1, "signers": set_a}) for j in set_a}
                claimed = sorted(set_b + set_a[:1])
                res_b = {j: c.members[j - 1].dlc_attest({"event_id": eid, "packet": p2, "signers": claimed}) for j in set_b}
            except ValueError:
                return  # fixed: the members that did not sign the relay packets refused the second outcome
            bits_a = dlc.decompose(res_a[set_a[0]]["price_usd"], nb)
            bits_b = dlc.decompose(res_b[set_b[0]]["price_usd"], nb)
            d = next(i for i in range(nb) if bits_a[i] != bits_b[i])
            r_x = bytes.fromhex(core["digit_nonces_x"][d])
            c_a = frost.challenge(r_x, gx, dlc.digit_message(eid, d, bits_a[d]))
            c_b = frost.challenge(r_x, gx, dlc.digit_message(eid, d, bits_b[d]))
            w_a = {j: unblind(res_a[j]["z"][d], j, set_a) for j in set_a}
            w_b = {j: unblind(res_b[j]["z"][d], j, claimed) for j in set_b}
            got = split_recover(w_a, c_a, w_b, c_b)
            leaked = sorted(j for j, v in got.items() if v == true[j])
            self.assertFalse(leaked, f"coordinator recovered the long-term key shares of members {leaked} from one DLC event")
        finally:
            c.close()


class F05_MemberSignEndpoint(unittest.TestCase):
    def test_sign_with_huge_seq_does_not_wedge_member(self):
        """Any caller that can reach a member port can burn the whole sequence space."""
        c = Confed(nbits=4)
        try:
            slot = pr.now_us() // 5_000_000 * 5_000_000
            p1 = c.relay.publish(slot, fake(BASE))
            victim = c.members[p1["frost_signers"][0] - 1]
            huge = 2**70
            body = dict(p1["body"], seq=huge, previous=p1["digest"], slot_us=pr.now_us())
            try:
                commit = victim.commit(huge)
                others = [dict(index=i, D=commit["D"], E=commit["E"]) for i in (4, 5) if i != victim.index][:2]
                victim.sign({"seq": huge, "body": body, "parent": p1, "commitments": [commit] + others})
            except ValueError:
                pass
            self.assertLess(victim.state.s["last_seq"], 2**63, "member high-water mark jumped past u64 on one unauthenticated request")
        finally:
            c.close()

    def test_same_slot_is_signed_once(self):
        """Two VALID group-signed packets for one slot make the DLC outcome rule ambiguous."""
        c = Confed(nbits=4)
        try:
            slot = pr.now_us() // 5_000_000 * 5_000_000
            p1 = c.relay.publish(slot, fake(BASE))
            hi = {k: 10_100_000_000_000 for k in ("coinbase", "kraken", "bitstamp", "gemini")}
            try:
                p2 = c.relay.publish(slot, fake(dict(BASE, **hi)))
            except RuntimeError:
                return  # fixed: members refused a second packet for the slot
            both = pr.verify_packet(p1, c.group["group_pubkey"]) and pr.verify_packet(p2, c.group["group_pubkey"])
            self.assertFalse(both and p1["body"]["median_e8"] != p2["body"]["median_e8"],
                             "group signed two VALID packets with different medians for the same slot_us")
        finally:
            c.close()


class F04_OneSilentMemberStopsTheFeed(unittest.TestCase):
    def test_one_member_that_commits_but_never_signs_does_not_stop_publication(self):
        """4 of 5 members are honest and reachable; threshold is 3."""
        c = Confed(nbits=4)
        try:
            def refuse(req):
                raise ValueError("refusing to sign")
            slot = pr.now_us() // 5_000_000 * 5_000_000 - 20_000_000
            c.relay.publish(slot - 5_000_000, fake(BASE))  # the chain is past genesis
            c.members[0].sign = refuse  # still answers /commit
            published = 0
            for k in range(4):
                try:
                    c.relay.publish(slot + k * 5_000_000, fake(BASE))
                    published += 1
                except RuntimeError:
                    pass
            self.assertGreaterEqual(published, 2, f"{published} of 4 slots published with one silent member and four honest ones")
        finally:
            c.close()


class F10_RefusedNoticeFlag(unittest.TestCase):
    def test_refused_notice_does_not_block_attestation(self):
        group, shares = frost.keygen(3, 5)
        tmp = Path(tempfile.mkdtemp())
        ms = [dlc.DlcMember(s, tmp / f"d{s['index']}.json") for s in shares]
        deals = {str(m.i): m.deal("E1", 1_800_000_000, 4, [1, 2, 3, 4, 5]) for m in ms}
        for m in ms:
            m.receive("E1", deals)
        late = (1_800_000_000 + 3_600) * 1_000_000
        with self.assertRaises(ValueError):
            ms[0].sign_unattestable("E1", late, [])  # invalid signing set: no notice partial is produced
        try:
            if hasattr(ms[0], "lock_decision"):  # patched API: digits need a quorum of decision locks
                locks = {str(m.i): m.lock_decision("E1", "price:9") for m in ms[:4]}
                ms[0].sign_outcome("E1", 9, [1, 2, 3], locks)
            else:
                ms[0].sign_outcome("E1", 9, [1, 2, 3])
        except ValueError as e:
            self.fail(f"member refused to attest after a notice request that produced no signature: {e}")


class F01_Patched(unittest.TestCase):
    """Properties of the decision-lock quorum (skipped on code without it)."""

    def setUp(self):
        if not hasattr(dlc, "decision_quorum"):
            self.skipTest("decision locks not implemented")

    def _event(self):
        group, shares = frost.keygen(3, 5)
        tmp = Path(tempfile.mkdtemp())
        ms = [dlc.DlcMember(s, tmp / f"d{s['index']}.json") for s in shares]
        deals = {str(m.i): m.deal("E1", 1_800_000_000, 4, [1, 2, 3, 4, 5]) for m in ms}
        for m in ms:
            m.receive("E1", deals)
        return group, ms

    def test_split_locks_release_no_partial(self):
        group, ms = self._event()
        self.assertEqual(dlc.decision_quorum(3, 5), 4)
        a = {str(m.i): m.lock_decision("E1", "price:9") for m in ms[:3]}
        b = {str(m.i): m.lock_decision("E1", "price:6") for m in ms[3:]}
        for m, price, locks in [(ms[0], 9, a), (ms[3], 6, b), (ms[0], 9, {**a, **b}), (ms[3], 6, {**b, **a})]:
            with self.assertRaises(ValueError):
                m.sign_outcome("E1", price, [1, 2, 3] if m.i == 1 else [3, 4, 5], locks)
        with self.assertRaises(ValueError):  # a member holds one decision per event
            ms[0].lock_decision("E1", "price:6")
        late = (1_800_000_000 + 3_600) * 1_000_000
        with self.assertRaises(ValueError):
            ms[0].lock_decision("E1", dlc.UNATTESTABLE, late)
        self.assertEqual(sum(len(m.s["events"]["E1"]["signed"]) for m in ms), 0, "no nonce was used")

    def test_forged_or_foreign_locks_do_not_count(self):
        group, ms = self._event()
        locks = {str(m.i): m.lock_decision("E1", "price:9") for m in ms[:3]}
        forged = dict(locks, **{"4": locks["1"], "5": "00" * 64, "01": locks["1"], "9": locks["2"]})
        self.assertEqual(dlc.verified_lockers(group, "E1", "price:9", forged), {1, 2, 3})
        with self.assertRaises(ValueError):
            ms[0].sign_outcome("E1", 9, [1, 2, 3], forged)
        locks["4"] = ms[3].lock_decision("E1", "price:9")
        self.assertEqual(len(ms[0].sign_outcome("E1", 9, [1, 2, 3], locks)), 4)

    def test_notice_and_attestation_cannot_both_reach_quorum(self):
        group, ms = self._event()
        late = (1_800_000_000 + 3_600) * 1_000_000
        notice = {str(m.i): m.lock_decision("E1", dlc.UNATTESTABLE, late) for m in ms[:4]}
        ms[0].sign_unattestable("E1", late, [1, 2, 3], notice)
        price = {}
        for m in ms:
            try:
                price[str(m.i)] = m.lock_decision("E1", "price:9")
            except ValueError:
                pass
        self.assertEqual(sorted(price), ["5"], "only the member outside the notice quorum can still lock a price")
        with self.assertRaises(ValueError):
            ms[4].sign_outcome("E1", 9, [3, 4, 5], price)


class F02_NoticeAndAttestationWithOneFaultyMember(unittest.TestCase):
    def test_one_rolled_back_member_cannot_yield_both(self):
        """Members 1-4 are honest. Member 5 signs the notice, has its state file restored
        from a copy taken after the nonce setup, and then signs the outcome."""
        import shutil
        group, shares = frost.keygen(3, 5)
        tmp = Path(tempfile.mkdtemp())
        ms = [dlc.DlcMember(s, tmp / f"d{s['index']}.json") for s in shares]
        deals = {str(m.i): m.deal("E1", 1_800_000_000, 4, [1, 2, 3, 4, 5]) for m in ms}
        r = [m.receive("E1", deals) for m in ms][0]
        negate = [bool(dlc.group_nonce(deals, d)[1] & 1) for d in range(6)]
        gx = bytes.fromhex(group["group_pubkey"])
        shutil.copy(tmp / "d5.json", tmp / "d5.backup")
        late = (1_800_000_000 + 3_600) * 1_000_000
        quorum = hasattr(dlc, "decision_quorum")

        def notice(members, signers):
            if quorum:
                locks = {}
                for m in members:
                    locks[str(m.i)] = m.lock_decision("E1", dlc.UNATTESTABLE, late)
                return {m.i: int(m.sign_unattestable("E1", late, signers, locks), 16) for m in members}
            return {m.i: int(m.sign_unattestable("E1", late, signers), 16) for m in members}

        def outcome(members, signers):
            if quorum:
                locks = {}
                for m in members:
                    locks[str(m.i)] = m.lock_decision("E1", "price:9")
                return {m.i: [int(z, 16) for z in m.sign_outcome("E1", 9, signers, locks)] for m in members}
            return {m.i: [int(z, 16) for z in m.sign_outcome("E1", 9, signers)] for m in members}

        have_notice = have_attestation = False
        try:
            parts = notice([ms[0], ms[1], ms[4]], [1, 2, 5])
            sig = dlc.aggregate(group, deals, negate, 5, dlc.unattestable_message("E1"), r[5], parts)
            have_notice = bip340.verify(dlc.unattestable_message("E1"), gx, sig)
        except ValueError:
            pass
        shutil.copy(tmp / "d5.backup", tmp / "d5.json")
        rolled_back = dlc.DlcMember(shares[4], tmp / "d5.json")
        try:
            parts = outcome([ms[2], ms[3], rolled_back], [3, 4, 5])
            bits = dlc.decompose(9, 4)
            sigs = [dlc.aggregate(group, deals, negate, d, dlc.digit_message("E1", d, bits[d]), r[d], {j: z[d] for j, z in parts.items()}) for d in range(4)]
            have_attestation = all(bip340.verify(dlc.digit_message("E1", d, bits[d]), gx, sigs[d]) for d in range(4))
        except ValueError:
            pass
        self.assertFalse(have_notice and have_attestation,
                         "event E1 carries a valid unattestable notice AND a valid attestation with four honest members")


class F03_MembersSignUncheckedContent(unittest.TestCase):
    def test_group_does_not_sign_a_median_no_member_checked(self):
        """The coordinator alone fixes every field of the body, including median_e8."""
        c = Confed(nbits=dlc.NUM_BITS)
        try:
            now_s = pr.now_us() // 1_000_000
            maturity = now_s - now_s % 5
            ev = c.coord.setup(maturity)
            if hasattr(c, "view"):
                c.view.set_from_results(fake(BASE), maturity * 1_000_000)  # what every member observes
            invented = {k: 3 * v for k, v in BASE.items()}  # three times the market
            publish = getattr(c, "raw_publish", c.relay.publish)
            try:
                pkt = publish(maturity * 1_000_000, fake(invented))
            except RuntimeError:
                return  # members refused the body
            ev = c.coord.attest(ev)
            self.assertFalse(pkt["body"]["status"] == "VALID" and ev["status"] == "attested",
                             f"group signed and attested {ev.get('attestation', {}).get('price_usd')} USD supplied by the coordinator")
        finally:
            c.close()


class F03_Patched(unittest.TestCase):
    """Rules of the member-side price check (skipped on code without it)."""

    def setUp(self):
        import frost_signer
        if not hasattr(frost_signer, "StaticView"):
            self.skipTest("member price check not implemented")

    def test_member_price_check_rules(self):
        c = Confed(nbits=4)
        try:
            slot = pr.now_us() // 5_000_000 * 5_000_000 - 30_000_000
            market = fake(BASE)
            scaled = lambda num: fake({k: v * num // 10_000 for k, v in BASE.items()})
            high_water = lambda: [m.state.s["last_seq"] for m in c.members]

            c.view.set_from_results(market, slot)
            p1 = c.raw_publish(slot, scaled(10_030))  # 30 bps from the members' reading: signed
            self.assertEqual(p1["body"]["status"], "VALID")

            before = high_water()
            with self.assertRaises(RuntimeError):  # 70 bps away: every member asked refuses
                c.raw_publish(slot + 5_000_000, scaled(10_070))
            self.assertEqual(high_water(), before, "a refused body spends no sequence and no nonce")
            self.assertGreaterEqual(sum(m.content_refusals for m in c.members), 3)

            c.view.set(c.view.median_e8, at_us=pr.now_us() - 60_000_000)  # the reading is a minute old
            with self.assertRaises(RuntimeError):
                c.raw_publish(slot + 10_000_000, market)

            c.view.set(None)  # members have no usable reading
            with self.assertRaises(RuntimeError):
                c.raw_publish(slot + 15_000_000, market)
            hold = c.raw_publish(slot + 20_000_000, fake(BASE, errors={"coinbase": "fetch: URLError", "kraken": "fetch: URLError"}))
            self.assertEqual(hold["body"]["status"], "HOLD", "a HOLD body asserts no price and is signed without a reading")
            self.assertTrue(pr.verify_packet(hold, c.group["group_pubkey"]))
        finally:
            c.close()

    def test_member_without_a_view_refuses_valid_bodies(self):
        import frost_signer
        group, shares = frost.keygen(3, 5)
        m = frost_signer.Member(shares[0], Path(tempfile.mkdtemp()))  # no view given
        body, _ = pr.assemble(1, "00" * 32, pr.now_us(), 5000, fake(BASE))
        with self.assertRaisesRegex(ValueError, "no usable independent price reading"):
            m._check_content(body)
        with self.assertRaises(ValueError):
            m._check_content(dict(body, median_e8=float(body["median_e8"])))
        with self.assertRaises(ValueError):
            m._check_content(dict(body, market="ETH/USD"))
        m._check_content(dict(body, status="HOLD"))

    def test_source_view_applies_the_relay_rules(self):
        import frost_signer
        ok = {sid: (role, lambda sid=sid: b"x", lambda raw, sid=sid: (BASE[sid], None)) for sid, (role, _, _) in pr.SOURCES.items() if role == "fast"}
        v = frost_signer.SourceView(sources=ok)
        self.assertEqual(sorted(v.sources), ["bitstamp", "coinbase", "gemini", "kraken"])
        r = v.refresh()
        self.assertEqual((r["status"], r["fast_sources_used"], r["median_e8"]), ("VALID", 4, (BASE["coinbase"] + BASE["gemini"]) // 2))
        def boom():
            raise OSError("down")
        two_down = dict(ok, coinbase=("fast", boom, None), kraken=("fast", boom, None))
        r = frost_signer.SourceView(sources=two_down).refresh()
        self.assertEqual((r["status"], r["median_e8"]), ("HOLD", None), "fewer than three fresh sources is not a usable reading")



class F05_CoordinatorAuthentication(unittest.TestCase):
    """F-05 part 3: a member accepts POSTs only from the holder of its coordinator key."""

    def setUp(self):
        import threading
        import coord_auth
        import frost_signer
        self.ca, self.fs = coord_auth, frost_signer
        self.group, shares = frost.keygen(3, 5)
        self.pk = self.group["group_pubkey"]
        self.master = bytes(range(32))
        self.m = frost_signer.Member(shares[0], Path(tempfile.mkdtemp()), view=frost_signer.NO_PRICE_CHECK)
        self.v = coord_auth.Verifier(coord_auth.member_key(self.master, self.pk, 1), self.pk, 1)
        self.srv = frost_signer.serve(self.m, "127.0.0.1:0", self.v)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _raw(self, path, body: bytes, auth=None):
        import urllib.error
        import urllib.request
        h = {"Content-Type": "application/json"}
        if auth is not None:
            h[self.ca.HEADER] = auth
        try:
            with urllib.request.urlopen(urllib.request.Request(self.url + path, data=body, headers=h), timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _hdr(self, path, body, key=None, index=1, now_us=None):
        k = key or self.ca.member_key(self.master, self.pk, index)
        return self.ca.header(k, self.pk, index, path, body, now_us)

    def test_unauthenticated_local_caller_is_refused_and_changes_nothing(self):
        # The F-05 item 2 attack from any local process: a huge seq would move the member's high-water mark.
        before = self.m.state.s["last_seq"]
        for path, obj in (("/commit", {"seq": 7}), ("/sign", {"seq": 2**70}), ("/dlc/deal", {"event_id": "SHZ-BTCUSD-X"})):
            code, r = self._raw(path, json.dumps(obj).encode())
            self.assertEqual(code, 401, (path, r))
        self.assertEqual(self.m.state.s["last_seq"], before)
        self.assertEqual(self.m.state.s.get("nonces", {}), {}, "no nonce is stored for an unauthenticated /commit")
        with __import__("urllib.request").request.urlopen(self.url + "/healthz", timeout=5) as r:
            h = json.loads(r.read())
        self.assertEqual((h["coord_auth"], h["auth_refused"]), (True, 3))

    def test_authenticated_coordinator_is_served(self):
        c = self.ca.Client(self.master, self.pk)
        r = c.post(self.url, "/commit", {"seq": 1}, 5)
        self.assertEqual(r["index"], 1)

    def test_replay_stale_tamper_path_and_other_member_key_are_refused(self):
        body = json.dumps({"seq": 3}).encode()
        h = self._hdr("/commit", body)
        self.assertEqual(self._raw("/commit", body, h)[0], 200)
        self.assertEqual(self._raw("/commit", body, h)[0], 401, "replay of an accepted request")
        old = self._hdr("/commit", body, now_us=pr.now_us() - 31_000_000)
        self.assertEqual(self._raw("/commit", body, old)[0], 401, "timestamp outside the window")
        h2 = self._hdr("/commit", body)
        self.assertEqual(self._raw("/commit", json.dumps({"seq": 4}).encode(), h2)[0], 401, "body changed")
        h3 = self._hdr("/commit", body)
        self.assertEqual(self._raw("/sign", body, h3)[0], 401, "path changed")
        other = self.ca.header(self.ca.member_key(self.master, self.pk, 2), self.pk, 2, "/commit", body)
        self.assertEqual(self._raw("/commit", body, other)[0], 401, "member 2's request replayed to member 1")
        forged = self._hdr("/commit", body, key=self.ca.member_key(bytes(32), self.pk, 1))
        self.assertEqual(self._raw("/commit", body, forged)[0], 401, "key not derived from the coordinator master")
        for bad in ("", "v1", "v2 1 00 00", "v1 x y z", "v1 1 " + "00" * 15 + " " + "00" * 32):
            self.assertEqual(self._raw("/commit", body, bad or None)[0], 401, bad)

    def test_member_refuses_a_verifier_for_another_index_or_group(self):
        with self.assertRaises(ValueError):
            self.fs.serve(self.m, "127.0.0.1:0", self.ca.Verifier(bytes(32), self.pk, 2))
        with self.assertRaises(ValueError):
            self.fs.serve(self.m, "127.0.0.1:0", self.ca.Verifier(bytes(32), "02" * 32, 1))

    def test_member_cli_requires_an_explicit_auth_choice(self):
        import subprocess
        here = Path(__file__).resolve().parent
        r = subprocess.run([sys.executable, str(here / "frost_signer.py"), "--share", "x", "--state", "y"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--coord-auth-key", r.stderr)
        r = subprocess.run([sys.executable, str(here / "frost_relay.py"), "--group", "x", "--signers", "y", "--state", "z"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--coord-auth-master", r.stderr)


if __name__ == "__main__":
    unittest.main()
