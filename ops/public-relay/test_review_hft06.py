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
    @unittest.expectedFailure  # open on the patch branch: needs member-side source checks (see the findings report)
    def test_group_does_not_sign_a_median_no_member_checked(self):
        """The coordinator alone fixes every field of the body, including median_e8."""
        c = Confed(nbits=dlc.NUM_BITS)
        try:
            now_s = pr.now_us() // 1_000_000
            maturity = now_s - now_s % 5
            ev = c.coord.setup(maturity)
            invented = {k: 3 * v for k, v in BASE.items()}  # 300,000 USD while the market trades near 59,000
            try:
                pkt = c.relay.publish(maturity * 1_000_000, fake(invented))
            except RuntimeError:
                return  # members refused the body
            ev = c.coord.attest(ev)
            self.assertFalse(pkt["body"]["status"] == "VALID" and ev["status"] == "attested",
                             f"group signed and attested {ev.get('attestation', {}).get('price_usd')} USD supplied by the coordinator")
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
