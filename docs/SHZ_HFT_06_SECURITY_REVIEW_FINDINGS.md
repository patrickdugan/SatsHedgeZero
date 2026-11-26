# HFT-06 security review: findings

Reviewed commit: `20a8edc` on `research/shz-hft06-oracle-relay-20261124` (diff base `adc01e1`). Review date: 2026-11-25. All file and line references are to `20a8edc`.

This branch (`review/shz-hft06-security-20261125`) is cut from `20a8edc`. Its first commit adds failing reproductions only; the later commits add proposed fixes. Nothing was pushed to the review branch and the live deployment was not changed.

## Result

The threshold DLC oracle does not hold its main property. A coordinator acting alone, with all five members honest and running unmodified code, recovers members' long-term key shares and then the group secret key, and forges a group signature. The reproduction does this in two DLC announcements. The same key signs the relay packets and every DLC attestation, so this is a full break of the FROST confederation by its coordinator.

Two more findings break stated properties of the oracle with one faulty member or none. The Rust relay, router, journal and Bitcoin settlement code held up: the findings there are Low.

| ID | Severity | Status | Finding | Fixed on this branch |
| --- | --- | --- | --- | --- |
| F-01 | Critical | confirmed | DLC oracle: coordinator splits one group nonce across two messages and extracts the group key | yes |
| F-02 | High | confirmed | An event carries both a notice and an attestation with one faulty member | yes |
| F-03 | High | confirmed | Members sign packet contents chosen by the coordinator, including the median that becomes the DLC outcome | yes |
| F-04 | Medium | confirmed | One member that commits but never signs stops publication | yes |
| F-05 | Medium | confirmed | Member `/sign`: two VALID packets for one slot, unbounded sequence, no caller authentication | yes (part 3 not deployed) |
| F-06 | Low | confirmed | `RemoteFed::on_vote` overflows on a member-chosen sequence | yes |
| F-07 | Low | confirmed | A late certificate reaches Standard and Intermediate before their release time | yes |
| F-08 | Low | confirmed | Fee ledger accepts a journal rollback and re-emits instructions; `Instruct` double-counts a repeated sequence | yes |
| F-09 | Low | confirmed | MNR-02 refund height wraps or becomes a timestamp; refund amounts unchecked | yes |
| F-10 | Low | confirmed | A refused notice request blocks attestation | yes |
| F-11 | Low | suspected | Public HTTP surface: unbounded threads, subscribers and event-file work | no |
| F-12 | Low | suspected | Rust member: certified-parent ratchet is in memory only | no |
| F-13 | Low | suspected | Router accepts a `public_release_us` earlier than the Standard feed delay | no |
| F-14 | Low | confirmed (live) | An interrupted DLC setup wedges its event: the coordinator retries it every 5 s forever | yes |

## How to run the reproductions

```
git checkout 96eb1db        # first commit of this branch: 20a8edc plus failing tests
cd ops/public-relay && python3 -m unittest -v test_review_hft06
cargo test --locked -p shz-relay -p shz-dex -p shz-utxoref --test review_hft06 --no-fail-fast
```

At `96eb1db`: 6 of 6 Python tests fail and 7 of 7 Rust tests fail. At the branch head, with the F-02 and F-03 tests added: against the `20a8edc` code 7 Python tests fail, 3 are skipped (they test the fix) and 1 is an expected failure (F-03); against the patched code 25 of 25 Python tests pass with the F-03 expected failure, and the Rust suite passes (137 tests, including the 7 reproductions).

---

## F-01 Critical (confirmed): the coordinator extracts the group key from the DLC oracle

**Where.** `ops/public-relay/dlc_oracle.py:187-197` (`_partial`), `:199-210` (`sign_announcement`), `:229-237` (`sign_outcome`); `ops/public-relay/frost_signer.py:52-57` (`_observe`), `:68-85` (`dlc_attest`); `ops/public-relay/frost_relay.py:109-110`.

**Broken property.** "A nonce never signs two messages" and "the coordinator or a minority of members cannot learn a share or forge a group signature."

**Cause.** DLC nonces are committed before maturity, so they cannot carry FROST binding factors. Each per-event nonce is a plain degree-2 Shamir sharing: member `j` holds `k_j = K(j)` and its key share `s_j = f(j)`, and returns `z_j = lambda_j * (k_j + c * s_j)`. The Lagrange factor is public, so the coordinator sees `w_j = k_j + c * s_j`.

Each member locks its own share of a nonce to one message. Nothing makes all members lock the same message. If members 1, 2, 3 sign message A (challenge `c_A`) and members 4, 5 sign message B (challenge `c_B`):

- `H(j) = K(j) + c_A f(j)` is a degree-2 polynomial known at `j = 1, 2, 3`, so it is known everywhere.
- `H(4) - w_4 = (c_A - c_B) * f(4)`, which gives `s_4`. The same gives `s_5`.

One event yields two key shares. A second event with the partition reversed yields two more. Three shares give the group secret.

**Two ways to hand members different messages.**

1. *Announcement text.* `sign_announcement` checks seven fields of `core` and then signs the hash of the whole coordinator-supplied JSON. Any other key (`outcome`, `threshold`, an extra key) changes the message. No packet, timing or market condition is needed; it works at setup for every event.
2. *Two outcome packets.* `dlc_attest` accepts any group-signed VALID packet in the 30 s window unless the member has seen an earlier one. Members learn of packets only through `_observe(parent)` inside `/sign`. The coordinator always signs with the first three members that answer (`frost_relay.py:109-110`), so members 4 and 5 never see a packet. On the live relay `/healthz` reports `participation: {"1":153,"2":153,"3":153}`. The coordinator sends the first VALID packet to members 1-3 and the next one, whose integer USD price differs, to members 4-5. Ordinary consecutive packets suffice. F-05 also lets it obtain two VALID packets for the same slot, which passes the `earlier` check (strict `<` at `frost_signer.py:79`) even for members that saw the first.

**Reproduction (both fail at `20a8edc`).**

```
python3 -m unittest -v test_review_hft06.F01_DlcSplitSigningLeaksKey
```

- `test_coordinator_cannot_extract_group_key_via_announcement`: honest `DlcMember` objects, two events. Output: `coordinator recovered key shares of members [1, 2, 4, 5] from two announcements and forged a group signature: True`.
- `test_coordinator_cannot_extract_shares_via_two_outcome_packets`: five members on loopback HTTP as deployed, two honest relay packets, the member entry point `dlc_attest`. Output: `coordinator recovered the long-term key shares of members [4, 5] from one DLC event`.

**Impact.** Forgery of relay packets and of attestations for any event, past or future, under the group key. Every contract bound to the oracle can be settled at a price of the attacker's choice until its refund height. Trusted-dealer key generation and single-host deployment (known gaps 1 and 7) are not required: this holds with a real DKG and members on separate hosts.

**Fix (implemented).**

- The announcement is no longer coordinator text. `dlc_oracle.canonical_core` builds the only valid core from the member's own nonce setup and constants; a member signs that and refuses any `core` whose canonical JSON differs.
- Decision locks. A member durably locks an event to one decision (`price:<usd>` or `unattestable`) and signs the lock with its key share (BIP340, tag `SHZ/DLC/DECISION-LOCK/V1`). It releases digit or notice partials only when shown valid locks for its own decision from `q = ceil((n + t) / 2)` members, which is 4 of 5. Two quorums share at least `t` members, so with up to `t - 1` faulty members one honest member is in both and only one decision can reach quorum.
- `dlc_coord.py` runs lock collection as phase 1, publishes the locks with the attestation, and refuses to set up an event with fewer than `q` dealers.

**Cost of the fix.** Attestation needs 4 live members instead of 3. With fewer the event stays unattested and contracts take the refund path. A coordinator can still strand an event by splitting locks 3/2 (`test_split_locks_release_no_partial` shows no partial is released); it could already do that by not attesting. With `t` or more faulty members nothing holds, as before.

## F-02 High (confirmed): notice and attestation for the same event with one faulty member

**Where.** `ops/public-relay/dlc_oracle.py:212-237`; `ops/public-relay/frost_signer.py:59-66`.

**Broken property.** "An event never carries both an attestation and an unattestable notice."

**Cause.** Exclusivity is enforced per member. Two signing sets of 3 out of 5 share only one member, so the property has no fault tolerance: one member that signs both, or whose state file is restored from a backup, is enough. `seen_valid` is in memory only and is filled only for members in a signing set, so the "saw a VALID packet" guard on the notice is empty for members 4 and 5 and for any member after a restart.

**Scenario.** Members 1, 2, 5 sign the notice. Member 5's `dlc.json` is restored from a copy taken after nonce setup. Members 3, 4, 5 attest. Members 1-4 followed the protocol.

**Reproduction.** `python3 -m unittest -v test_review_hft06.F02_NoticeAndAttestationWithOneFaultyMember` fails at `20a8edc`: `event E1 carries a valid unattestable notice AND a valid attestation with four honest members`.

**Impact.** Counterparties told to stop waiting can later be settled by a CET. The notice is informational on chain, so the loss is bounded by what a party does on the strength of the notice.

**Fix (implemented).** The decision lock of F-01 covers `unattestable` as a decision, so both outcomes need 4 of 5 locks and cannot both reach quorum with fewer than 3 equivocating members (`test_notice_and_attestation_cannot_both_reach_quorum`).

## F-03 High (confirmed, fixed): members sign contents the coordinator chooses

**Where.** `ops/public-relay/frost_signer.py:92-115`. The member checks `schema`, `seq`, slot recency and the parent link. It checks no price field.

**Broken property.** Known gap 7 states the coordinator's freedom over a DLC outcome as "at most 6 VALID packets in the 30 s window". That mitigation is insufficient. The coordinator assembles the body, so it sets `median_e8` and `status` itself, and three honest members sign it. The choice is any price.

**Scenario.** A compromised coordinator publishes a VALID packet with an invented median at a maturity slot. The group signs it and then attests it.

**Reproduction.** `python3 -m unittest -v test_review_hft06.F03_MembersSignUncheckedContent`. Against the `20a8edc` member it fails with `group signed and attested 300000 USD supplied by the coordinator`; against the patched member it passes (no expected-failure marker remains), and `F03_Patched` checks the refusals.

**Impact.** The FROST group protects the key from the coordinator (after F-01 is fixed) but not the data. For price integrity the Python confederation is a single trusted relayer whatever the key ceremony. The Rust relay does not have this problem: `MemberCore::on_proposal` votes only on a digest rebuilt from the member's own collator (`crates/shz-relay/src/member.rs:165-172`).

**Fix (implemented, deployed).** Each member runs its own `SourceView` (`ops/public-relay/frost_signer.py`): a background read of the four fast sources every 15 s, staggered by member index, judged with the same `public_relay.assemble` rules. Before any nonce is taken, `Member._check_content` refuses a VALID body unless the member holds its own VALID reading no older than 35 s and the body's median lies within 50 bps of it. A HOLD body is signed without a reading. No reading means refusal. `NO_PRICE_CHECK` is an explicit opt-out for offline protocol tests, never the default. Flags: `--max-deviation-bps`, `--view-refresh-s`, `--view-max-age-s`, `--no-price-check`; `/healthz` reports `price_view` and `content_refusals`.

**Live check (2026-11-25 13:33 UTC).** Member 5 on the witness VPS was asked, exactly as a coordinator would, to sign a body whose median was three times the market (175,540 vs 58,513 USD). It answered HTTP 409 `median is 20000 bps from this member's own reading (limit 50)`; its `last_seq` (952) and `signed` (0) did not change, `content_refusals` became 1. The refusal precedes `take()`, so the probed sequence's nonce stays unused. The last 200 packets of both relays used all four fast sources with no source errors after the members started polling (seven processes polling each exchange from one IP).

**Residual.** The coordinator can still move a VALID median by up to 50 bps, pick among the VALID packets in the 30 s outcome window, and withhold or force HOLD to push contracts to the refund path. The sources are unauthenticated public tickers and all members share one host and network path, so they share one view of the sources: a source or network that lies to the host lies to every member.

## F-14 Low (confirmed on the live host, fixed): an interrupted DLC setup wedges its event

**Where.** `ops/public-relay/dlc_coord.py`, `setup` and `tick`.

**Observed.** After the F-03 member rollout (members restarted one at a time) the coordinator logged `dlc setup SHZ-BTCUSD-20261125T1415Z failed: only 3 dealers; the decision quorum is 4` every 5 s, 140 times, and announced nothing new. Members 1 and 2 answered `/dlc/deal` with `event already set up`: an earlier attempt had run `receive` on them (which consumes their dealing) and was then interrupted by a member restart. Their state is durable, so the event could never reach four dealers again.

**Fix (implemented, deployed 13:31 UTC).** A dealing refused with `event already set up` while dealers are below quorum raises `SetupWedged`; `tick` then records the event as `setup_abandoned` (with the reason) and never retries it. No announcement was ever published for such an event, so no contract can depend on it. Other failures still retry. Live result: 14:15Z abandoned with `2 member(s) already consumed their dealing; 3 dealers < quorum 4`, and 14:30Z was set up and announced immediately after. Test: `test_dlc.DlcOracle.test_interrupted_setup_is_abandoned_not_retried`.

## F-04 Medium (confirmed): one silent member stops publication

**Where.** `ops/public-relay/frost_relay.py:109-117`.

**Broken property.** Liveness with up to 2 of 5 faulty members.

**Cause.** A member that answers `/commit` and then refuses or times out on `/sign` fails the first set `{1,2,3}`. Members 2 and 3 have spent the sequence. Every other 3-subset contains 1, 2 or 3, so the slot is skipped. The next slot starts with `{1,2,3}` again. A bad partial gets a member banned; a refusal does not.

**Reproduction.** `python3 -m unittest -v test_review_hft06.F04_OneSilentMemberStopsTheFeed` fails at `20a8edc`: `0 of 4 slots published with one silent member and four honest ones`.

**Fix (implemented).** A member that fails `/sign` goes to the back of the signing order for 60 slots and is counted in `stats.frost.refusals`. Subsets that contain a member that has already spent the sequence are skipped. One slot is lost when a member starts failing; the next slot signs.

## F-05 Medium (confirmed): member `/sign` accepts too much

**Where.** `ops/public-relay/frost_signer.py:92-115`, `:137-160`; `ops/public-relay/frost.py:196-216`.

1. **Two VALID packets for one slot.** A member requires a newer sequence and a group-signed parent. It does not require a newer slot. The group signs two packets with the same `slot_us` and different medians, so "the first VALID packet with slot_us >= maturity" has no single answer. Reproduction: `test_same_slot_is_signed_once`.
2. **Unbounded sequence.** `take()` sets `last_seq` to whatever sequence the request carries. One request with `seq = 2**70`, built from any public packet as parent, moves a member's high-water mark past `u64`. The coordinator then follows it (`_member_high_water`), and Rust verifiers cannot parse the packets. The state is durable. Reproduction: `test_sign_with_huge_seq_does_not_wedge_member`.
3. **No caller authentication.** Any process that reaches a member port can call `/commit`, `/sign` and every `/dlc/*` endpoint. On the deployment the ports are loopback-only (a connection to 170.75.168.145:9101 from outside failed), so the callers are the five member users and anything else on the box, which also runs a Bitcoin node. Item 2 lets one member wedge the other four. `commit()` also keeps every nonce for a sequence above the last signed one, so its state file grows without bound when sequences are requested in descending order.

**Fix.** Implemented: a durable `last_slot` so a member signs a slot once and only after its parent's slot; `seq < 2**53` and at most `2**20` ahead of the group-signed parent; at most 64 stored nonces; negative `Content-Length` clamped. Part 3, implemented in `f52c3e9` (`ops/public-relay/coord_auth.py`): every coordinator POST carries `X-SHZ-Auth: v1 <ts_us> <nonce> <mac>`, an HMAC-SHA256 over the group key, the member index, the path, the timestamp, the nonce and the body hash. The key is per member, `K_i = HMAC(master, tag | group key | i)`: the coordinator holds the master and member `i` holds only `K_i`, so a member can forge requests only to itself. A member answers 401 to a missing or wrong MAC, a timestamp more than 30 s from its clock, or a nonce it already accepted inside that window, before parsing the body; `/healthz` stays open and reports `coord_auth` and `auth_refused`. `frost_signer.py` and `frost_relay.py` refuse to start without a key or an explicit `--no-coord-auth`. HMAC and not BIP340: the pure-Python BIP340 sign takes 16 ms on the 1-vCPU witness host and a slot makes eight member calls. Tests: `test_review_hft06.F05_CoordinatorAuthentication` (unauthenticated `/commit`, `/sign` with `seq = 2**70` and `/dlc/deal` refused with member state unchanged; replay, stale timestamp, changed body, changed path, another member's key and a key not derived from the master refused; malformed headers; mismatched verifier; CLI requires a choice), and `test_frost`/`test_dlc` now run every member with authentication on. Residual: the replay cache is in memory, so for 30 s after a member restart a request captured before it can be replayed once (capturing loopback traffic needs root on the host); root on the host reads every key.

## F-06 Low (confirmed): `RemoteFed::on_vote` overflows on a member-chosen sequence

**Where.** `crates/shz-relay/src/remote.rs:356-380`, the expression `s + SEEN_WINDOW` at `:375`.

The vote signature covers the digest only; `seq` is a free field. A federation member sends a vote with `seq = u64::MAX - 5`. The loop removes every older entry, which erases the equivocation window, and then evaluates `s + SEEN_WINDOW` on its own entry. With overflow checks (debug and test builds) this panics while holding `inner`, the mutex is poisoned, and every later vote panics. The release build in `deploy/hft06/Dockerfile` wraps instead and only loses the evidence. Needs one of the five member keys.

**Reproduction.** `cargo test -p shz-relay --test review_hft06 member_vote_with_huge_sequence` panics at `remote.rs:375`.

**Fix (implemented).** Votes above the proposed or certified sequence are counted as off-proposal and not recorded; the addition saturates.

## F-07 Low (confirmed): a late certificate is released before a tier's delay

**Where.** `crates/shz-relay/src/schedule.rs:80-82` (`validate`), `:94-97` (`release_at`).

A certificate later than `certification_deadline_us` is released to all tiers at the certification time. `validate` allows any deadline from 1 us to one cadence. With a 50 ms deadline, a certificate at T+60 ms reaches Standard 142 ms before T+202 ms and Intermediate 42 ms early. With the default 200 ms deadline, a certificate at T+200.001 ms reaches Standard inside the 2 ms clock-uncertainty margin that on-time releases keep. All tiers receive it together, so no tier gains on another; the property "no tier before its release time" is what fails.

**Reproduction.** `cargo test -p shz-relay --test review_hft06 late_certificate` (two tests): `Standard received the packet 142000 us before its release time`.

**Fix (implemented).** The late branch releases at `max(certified, boundary + standard_delay + clock_uncertainty)`. The existing unit test's expectation for T+200.001 ms changes from T+200.001 ms to T+202 ms.

## F-08 Low (confirmed): fee ledger rollback and repeated `Instruct` sequences

**Where.** `crates/shz-dex/src/routing/ln_fees.rs:371-385` (`open`), `:226-236`, `:291-300`.

1. The fee WAL is hash-chained, so a torn or edited tail fails closed. A file cut at a frame boundary is a valid prefix, and `open` has no pinned tip, unlike `DurableTieredRouter::open`. Cutting the last `Instruct` frame makes `poll` emit the same settlement instructions again; cutting `Collect` frames makes collected fees outstanding again. Needs a restored backup or a rolled-back volume.
2. `Instruct` does not reject a repeated sequence, and `instructions()` adds the outstanding amount once per list entry. `poll` never builds such a list; the public `record` does not prevent it.

**Reproduction.** `cargo test -p shz-dex --test review_hft06`: `re-emitted 4 settlement instructions totalling 10000 sats (first emission: 10000 sats)` and `left: 20000, right: 10000`.

**Fix (implemented).** `FeeLedger::tip()` and `FeeLedger::open_pinned(.., minimum)` return `LedgerError::Rollback` when the journal ends before the pinned tip. `Instruct` rejects a repeated sequence. The caller must store the tip off the journal's volume, as for the router journal.

## F-09 Low (confirmed for heights, by reading for amounts): MNR-02 refund parameters unchecked

**Where.** `crates/shz-utxoref/src/mnr02.rs:454-455`, `:619-620`; `bins/shz-cli/src/dlc_refund_plan.rs:76-81`, `:104`.

- `maturity_height + refund_delay_blocks` is an unchecked `u32` add. It panics in debug and wraps to a near-zero height in release.
- No check keeps the CLTV operand below 500,000,000. `build(.., 499_999_990, 6, 144)` produces operand 500,000,134, which Bitcoin reads as a 1985 timestamp, so the pre-signed refund is final as soon as the funding confirms.
- `refund_bob = distributable - refund_alice` underflows when Bob's margin is below his fee share, and Alice's share saturates to zero. Neither refund output is checked against dust.
- `dlc_refund_plan` has the same missing 500,000,000 check, and `gap < min_gap_secs as i64` disables the floor for `min_gap_secs > i64::MAX`.

All inputs come from the party building the contract, so this is self-harm today. It becomes a free option on the refund path if a counterparty ever proposes heights.

**Reproduction.** `cargo test -p shz-utxoref --test review_hft06`: `refund CLTV operand 500000134 is a timestamp in the past`, and a panic at `mnr02.rs:455`.

**Fix (implemented).** Checked addition, a `< 500_000_000` bound in both places, checked refund amounts with a 330-sat floor, and the gap comparison in `i128`.

## F-10 Low (confirmed): a refused notice request blocks attestation

**Where.** `ops/public-relay/dlc_oracle.py:224-225`.

`sign_unattestable` sets `ev["unattestable"] = True` and then calls `_partial`, which raises on an invalid signer list. No partial is produced, but the flag stays in memory and is written to disk by the next save of any event. The member then refuses to attest. After window plus grace, one request per member with `signers: []` strands an event with neither an attestation nor a notice.

**Reproduction.** `python3 -m unittest -v test_review_hft06.F10_RefusedNoticeFlag`: `member refused to attest after a notice request that produced no signature`.

**Fix (implemented).** The in-memory flag is gone. The durable decision lock is the only state, and it is set by an explicit lock request.

## F-11 Low (suspected, not run against the live host): public HTTP surface

**Where.** `ops/public-relay/public_relay.py:348-428`, `:444-446`; `ops/public-relay/dlc_coord.py:196-209`, `:227-243`.

- `ThreadingHTTPServer` with no connection cap and no socket timeout: each idle connection holds a thread and a descriptor until the peer closes. `/v1/stream` has no subscriber cap.
- `GET /v1/dlc/events` reads and parses up to 200 event files per request. Each file holds 330 nonce commitments.
- `tick()` parses every event file every 5 s and event files are never pruned (96 per day), so coordinator work grows without bound under a 30% CPU quota.
- `_restore` verifies only the last archive line. Earlier lines within the 2 h window are served unverified. A torn last line makes startup raise `JSONDecodeError`.

Not exercised on the live host, as instructed. To reproduce locally: start `frost_relay.py` with `test_dlc.Confed`, open 2,000 idle TCP connections to the listen port, and watch `/healthz` stop answering when descriptors run out.

**Fix.** Put a reverse proxy with connection and rate limits in front, or set `timeout` on the handler and cap threads and subscribers. Cache the event list. Move attested events out of the scan directory. Verify every restored line.

## F-12 Low (suspected, traced by reading): Rust member parent ratchet is not durable

**Where.** `crates/shz-relay/src/member.rs:99`, `:138-164`.

`MemberCore.parent` is in memory. After a restart it is `None`, so the member accepts any valid certificate as a parent provided the proposal's sequence is above its durable lock high-water mark. A coordinator can then have restarted members certify a child of an old certificate, skipping the packets between. Contents stay honest, because members vote only on their own rebuilt packet. This extends known gap 8: the claim "the chain cannot fork" in `remote.rs:22-32` holds for an honest coordinator only.

**Fix.** Persist the highest verified parent `(seq, digest)` beside the sign lock and load it at start.

## F-13 Low (suspected, traced by reading): `public_release_us` is not tied to the feed delay

**Where.** `crates/shz-dex/src/routing/tiered.rs:299`, `:310-313`, `:408`.

`ingest_mark` requires only `public_release_us >= boundary_us`. A take is "privileged" while `now < public_release_us`, but a Standard maker sees the mark at `boundary_us + feed_delay(Standard)`. A mark fed with `public_release_us = boundary + 50 ms` ends early-window protection 150 ms before Standard makers can see it, and a Premium taker can fill a maker that did not opt in. The mark feeder is operator code, and `hft06_e2e_relay.rs` passes the Standard release time.

**Fix.** Reject a mark whose `public_release_us` is below `boundary_us + feed_delay(Standard)`, or compute `privileged` from the execution policy.

## Informational

- **Collator live and replay can differ at a boundary** (`crates/shz-oracle/src/collator.rs:198-204`, `:281-290`). `ingest` treats a report arriving exactly at T_k as part of slot k; `close_through(T_k)` closes slot k first, and a report stamped earlier that is ingested after `close_through(now)` is dropped as `ClockRegression`. The doc comment tells live callers to drain the socket first. A member that does not will disagree with the others, which costs liveness, not safety.
- **Chainlink spread multiplication** (`crates/shz-oracle/src/chainlink_streams.rs:425`). `(ask - bid) as u128 * 10_000` can wrap in release for an ask near `i128::MAX`. It needs f+1 DON signatures on an absurd report.
- **Entitlements are not bound to a router or scope** (`crates/shz-dex/src/routing/tiered.rs:164-168`). The same client can present one entitlement to every router that trusts the relay key. This may be intended. Reported by a first-pass reader; I did not verify it.
- **`FeeLedger::record` is public** and accepts `Accrue` and `Commit` without the router checks that `observe_batch` and `observe_resolution` apply.
- **`decompose` on a negative price** yields all-one bits (`dlc_oracle.py:56-58`). Reachable only through F-03; the patched member requires a positive integer median.
- **Lock signatures use the key share** for an ordinary BIP340 signature under a separate tag (introduced by the F-01 fix). This is sound for Schnorr but worth a second opinion before production.
- **Sign-lock file has no inter-process lock** (`crates/shz-relay/src/authority.rs:92`). Reported by a first-pass reader; I did not verify it.

## Mitigations in the brief that I think are insufficient

- **Gap 7** (bounded choice among outcome packets): see F-03. The choice is unbounded, because members do not check contents.
- **Gap 1** (the confederation "adds no security until members run on independent machines with a DKG"): F-01 and F-03 would survive both changes. Both are fixed here; F-03 keeps a 50 bps residual and a shared view of the sources while members share one host.
- **Gap 8** (a coordinator can publish a withheld aggregate; clients reject it by `previous`): at `20a8edc` the coordinator can also have the group sign a second packet for the same slot (F-05). Fixed here by the durable `last_slot`.

## Examined and found sound

Coverage: I read all of `ops/public-relay` myself. The Rust files were each read in full by a first-pass reader (three Sonnet subagents, one per area). I then re-read the code behind every reported finding and behind the central negative results: mode separation in `envelope.rs`, catch-up and checkpoint gating in `hub.rs`, client continuity in `client.rs`, the signature loop and policy checks in `chainlink_streams.rs:375-430`, `collator.rs:196-330`, `tiered.rs:285-430`, `ln_fees.rs:215-430`, the journal open paths and domain tags. The remaining line references below come from the first-pass readers.

**BIP340 and FROST (`bip340.py`, `frost.py`).**
- The Jacobian doubling and addition formulas are correct for a = 0. `_jadd` handles equal and opposite points; `_mul` returns infinity for `k = 0 mod N`. Verification rejects `r >= p`, `s >= n`, `x >= p`, odd-Y and infinite `R`. BIP340 vector 0 passes.
- FROST binding factors cover the group key, the message, the full sorted commitment list and the signer index. Parity: the group key is even from keygen; nonces are negated when `R` is odd; `verify_partial` negates `R_i` the same way.
- Nonces are stored before commitments leave and removed, with `last_seq` advanced, before a partial leaves, so a FROST nonce pair signs once across restarts. A partial under a different commitment list or message is a one-time pad on the key share. The F-01 attack does not carry over to packet signing because of the binding factors.
- The scalar multiplication is not constant time. I did not assess timing leakage.

**DLC nonce DKG.**
- Shares are checked against Feldman commitments. A dealer cannot be impersonated without its ECDH pad. The pad input is unambiguous (32-byte prefix, fixed 4-byte suffix) and binds event, dealer, recipient and nonce index. A member's own contribution is always included, so the coordinator does not learn a nonce share. Duplicate dealer keys such as `"1"` and `"01"` only scale a polynomial.
- A member's partial on each nonce is durable before it leaves.

**Chainlink source authentication (`chainlink_streams.rs`).**
- Signatures are verified before the report blob is decoded (`:389-402`). The signed hash is `keccak(keccak(report) || context[0..3])`.
- Exactly f+1 signatures, distinct pinned signers, high-s rejected, recovery id 0 or 1, unused `rawVs` bytes zero.
- ABI decoding is canonical: fixed head offset, each offset equals the previous end, zero padding, no trailing bytes.
- `int192` is sign-extended and range-checked. Non-positive prices and inverted bid/ask are rejected. Feed id, config validity window, expiry and freshness use checked or saturating arithmetic.

**Collator (`collator.rs`).**
- Slots close before a later arrival is accepted (`:203`). No wall clock, no hash-map iteration, no floats. VALID needs both sources, age, skew and dispersion inside the HFT-04 bounds (`:302-312`). Duplicates and non-monotone source times are rejected.

**Relay modes and tier gating (`envelope.rs`, `authority.rs`, `hub.rs`, `client.rs`, `server.rs`).**
- A trusted-relay packet cannot pass as federated: the verifier is pinned to a mode at construction (`envelope.rs:121`), the trusted message has its own tag over policy, key and digest (`:49-56`), the relay key is refused if it is a member key (`:101`), and config requires an explicit `mode`.
- The sign lock is written and synced before a signature exists (`authority.rs:112-113`, `:155`); a torn or edited lock line fails closed.
- Catch-up and checkpoints are gated by release time (`hub.rs:309`, `:345`). The tier comes from server config, not the client.
- Clients require `previous` to equal the last accepted digest; the federated sequence jump is allowed only then (`hub.rs:213`, `client.rs:93-95`).
- Client auth uses a fresh 32-byte nonce per connection bound to relay id and client id. Members are authenticated against `policy.members`. Slow subscribers are dropped. The WebSocket accept path has no pre-auth connection cap or handshake timeout; I did not test it and list it with F-11 in spirit.

**Router and journals (`tiered.rs`, `tiered_durable.rs`, `durable.rs`, `coalescer.rs`).**
- Entitlement digest, relay signature, client, tier, tariff version and validity are enforced at submit (`tiered.rs:314-324`) and expiry again at execution (`:367`).
- Early-window protection skips makers that did not opt in (`:417`). HOLD and the stale-mark collar are enforced.
- Fee arithmetic: `fee_sats` is a bounded ceiling, the maker fee is a telescoping difference, the 70/30 split and the operator split conserve exactly, and the batch checks `maker + taker == oracle + router`.
- The tiered journal fsyncs before applying, fails closed on a torn tail, and detects a rollback with a pinned tip (`tiered_durable.rs:143-159`).
- HFT-05 and HFT-06 acknowledgements use different tags, WAL config hashes and magic bytes, and the HFT-05 `ack_message` field order is unchanged. No timeout releases matched collateral.

**DLC settlement and refund on Bitcoin.**
- The refund transaction has `nLockTime` equal to the refund height and input sequence `0xfffffffe`; the leaf contains `OP_CHECKLOCKTIMEVERIFY` with the same height; the sighash is `SIGHASH_DEFAULT` over all outputs.
- The anticipation point is `R_j + e_j * X` with even-Y lifts and the tagged hash and length-prefixed message the oracle signs, so only the matching attestation completes a CET.
- `dlc-refund-plan` computes the gap over the whole span from the tip to the refund height, so long-dated contracts are refused unless the refund delay grows with the horizon. `unilateral_cltv_height` cannot overflow because it is below the checked refund height. The default 2x speed factor is a mainnet assumption; I did not assess testnet4 or signet block rates against it.
- Regtest drill, run on the patched tree with Bitcoin Core 31.1: the unilateral CET is `non-final` at tip 117 and confirms at 119; the refund is `non-final` at tip 269 for CLTV 270 and confirms at 271 with its CPFP child; the foreign attestation is rejected. This matches `evidence/hft06/dlc_oracle_regtest_windows.json`.

## Live deployment (read-only)

About a dozen GET requests and one TCP connection attempt in total.

- `:8090/healthz` and `:8091/healthz` answered `ok`; the FROST relay reported signing set `{1,2,3}` for all 153 packets since its last start.
- `verify_client.py --dlc SHZ-BTCUSD-20261125T1000Z` verified the announcement and 20 digit signatures (58,992 USD, outcome packet 4572).
- `/v1/dlc/event/SHZ-BTCUSD-..%2f..%2frelay` returned 400, `/v1/archive/..%2f..%2frelay.key.jsonl` returned 404, and `/v1/packet/-1` and an oversized sequence returned 404.
- Port 9101 is not reachable from outside.

At the time of the review the live members ran the `20a8edc` code. F-01 needs the coordinator's position, and on this box the coordinator and the members have one operator, so the review did not change the deployment's exposure.

## Deployment of the fixes and new group key (2026-11-25 10:24 UTC)

After the review the FROST confederation on the witness VPS was redeployed from commit `46c4379` of this branch and re-keyed.

- New group key: `403c496669cba966c14d989711a2a16026c7c295305301e5c61b96eb718cfdb8` (3-of-5, trusted dealer in tmpfs, dealer files shredded). The first key `68b52a25...d312` is retired.
- Installed: `dlc_coord.py`, `dlc_oracle.py`, `frost.py`, `frost_relay.py`, `frost_signer.py`. `bip340.py`, `public_relay.py`, `verify_client.py`, the unit files and the single-key relayer on 8090 were not touched.
- The old relay archive, DLC event files, group file and code are in `/var/lib/shz-frost-archive-20261125T102416Z` (root, 0700).
- The five old members' `share.json`, `dlc.json` and `nonces.json` were overwritten and deleted with `shred -n 3 -z -u` later the same day. `dlc.json` went with the shares because it held the nonce shares of attested events: three of them and one published digit signature give the old group key. A search of the box found no other copy. `shred` overwrites in place and cannot reach a copy the hosting provider may hold in a volume snapshot.
- The chain restarted at `seq` 1. Events announced under the old key (10:15Z to 11:00Z) will not be attested by it.
- On the box before the switch: `python3 -m unittest test_frost test_dlc test_review_hft06` on Python 3.14, 20 tests pass with the F-03 expected failure.

Checks after the switch, from outside the box:

- `verify_client.py --follow 3` under the new key: signatures and chain links valid from `seq` 7.
- Event `SHZ-BTCUSD-20261125T1030Z`, the first one announced and attested by the new code: `verify_client.py --dlc` reports the announcement and 20 digit signatures valid, 58,835 USD, outcome packet 68. Its published `decision_locks` verify for all five members against the verification shares in `/v1/pubkey` (quorum 4), none verifies for a different price, and its announcement digest equals the digest of `canonical_core` rebuilt from public fields.
- All seven `shz-*` units and `rehearsal-bitcoind` active, no relay restarts, relay memory 86 MB of 220 MB.

F-03 member price check deployed 2026-11-25 (member `frost_signer.py` sha256 prefix `92b2b5a01cc48e4f`, members restarted 5 to 1; previous file kept in the archive directory as `code/frost_signer.46c4379.py`). F-14 fix deployed at 13:31 UTC (`dlc_coord.py` sha256 prefix `4572098f53377951`; previous file `code/dlc_coord.pre-wedge.py`). After both: event `SHZ-BTCUSD-20261125T1330Z` verifies from outside the box under the new key (announcement and 20 digit signatures, 58,766 USD, signers 1/2/3, outcome packet 2214).

Still true of the live deployment: the F-03 residual (50 bps band, outcome-window choice, withholding), no coordinator authentication on member ports (F-05 part 3: fixed in `f52c3e9`, deploy not run; kit staged at `~/shz-deploy-20261126/auth/auth-deploy.sh`), F-11, F-12, F-13, trusted-dealer keygen and a single host. The FROST coordinator was OOM-killed once at 13:15 UTC (anon RSS 216 MB of 220 MB) while retrying the wedged event. After the F-14 fix (13:31 to 13:36 UTC, three samples) its anonymous memory was 67, 48 and 45 MB, the single-key relay 65 to 74 MB, both of 220 MB, with no restarts.

## What was run

| Suite | Tree | Result |
| --- | --- | --- |
| `cargo test --locked -p shz-oracle -p shz-relay -p shz-dex -p shz-dlc -p shz-margin -p shz-cli` | `20a8edc` | pass |
| `python3 -m unittest test_public_relay test_frost test_dlc` | `20a8edc` | 14 pass |
| `test_review_hft06` (Python) | `20a8edc` code | 7 fail, 3 skipped, 1 expected failure |
| `--test review_hft06` (Rust, 3 crates) | `96eb1db` | 7 fail |
| All of the above plus `-p shz-utxoref` | branch head | Rust 137 pass; Python 29 pass, no expected failure (F-03 fixed, F-14 test added) |
| `shz dlc-oracle-regtest` (debug build, Core 31.1) | branch head | exit 0 |

Windows, toolchain `1.99.0-x86_64-pc-windows-msvc`. The regtest drill was run as a debug build because of disk space; the brief's command uses `--release`.
