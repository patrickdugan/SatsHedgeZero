# SHZ public trusted relayer

A deployed, deliberately simple oracle relayer: every 5 s it reads free public BTC/USD sources and publishes one BIP340-signed packet, hash-chained to the previous one. The data is late (public REST tickers and an on-chain feed, not a low-latency stream), and trust rests on one relay key and its operator. It is the trusted-relay starting point of HFT-06; the federated 4-of-5 mode in `crates/shz-relay` is the upgrade path.

## Live endpoint

Deployed 2026-11-25 on the witness VPS as systemd unit `shz-public-relay`:

```
http://170.75.168.145:8090/healthz
http://170.75.168.145:8090/v1/latest
http://170.75.168.145:8090/v1/packet/<seq>
http://170.75.168.145:8090/v1/stream          (Server-Sent Events)
http://170.75.168.145:8090/v1/archive/<YYYY-MM-DD>.jsonl
http://170.75.168.145:8090/v1/pubkey
```

Relay key (BIP340, x-only), pin it rather than fetching it:

```
9d0d3aa90b879c0e91cff2cb9ef0828d6d07bb74f5ec1767f72bccb52ba1a4b1
```

Plain HTTP; integrity comes from the signature and chain, not the transport.

## FROST 3-of-5 confederation (port 8091)

The same packets, signed by a FROST threshold group instead of one key:

```
http://170.75.168.145:8091/v1/latest    (same API as 8090)
group key (BIP340): 68b52a25233d8b87f5c09d44a71fb5e15bfd025c2dde56f9674468e1f1c3d312
```

- Five members run as separate systemd units (`shz-frost-signer@1..5`), each under its own system user with only its own share (`/var/lib/shz-frost-signer-N/share.json`, 0600) and durable nonce state, listening on 127.0.0.1:9101..9105. The coordinator `shz-frost-relay` assembles the packet, collects nonce commitments, takes the first three members that answer, checks every partial signature against that member's verification share, and publishes the aggregate. The result is one standard BIP340 signature under the group key; `frost_signers` in each packet lists the signing set.
- Two-round FROST (`frost.py`): binding factors over the full commitment list; even-Y group key fixed at keygen; signers negate nonces when the group commitment has odd Y. Nonces are persisted before commitments are released and erased before a partial is released, so no nonce signs two messages, across restarts too.
- Members sign a sequence at most once, a slot at most once (durable `last_slot`), and only a body that links to a group-signed parent packet with an earlier slot sent with the request; the sequence may run at most 2^20 ahead of that parent and stays below 2^53. A member that commits and then fails `/sign` is moved to the back of the signing order for 60 slots. The coordinator reserves each sequence durably before signing, so a crash after members signed but before publication costs one sequence number rather than wedging the chain: `seq` may jump, `previous` always links to the last published packet. A member caught sending a bad partial is named in `/healthz` (`stats.frost.cheaters`) and left out of later signing sets.
- Fault drill on the deployment (2026-11-25): members 1 and 3 stopped, packets kept flowing signed by {2, 4, 5}; a third member stopped, publication paused (skipped slots counted, no packet); all restarted, signing resumed with {1, 2, 3}.
- Keygen was a trusted dealer on the box; the dealer files were shredded after distribution, and all five members share one host and one operator. This demonstrates the protocol and its failure handling; it adds no security over the single-key relayer until members run on independent machines with a DKG.

## DLC oracle on the FROST group (port 8091)

The confederation also acts as a threshold DLC oracle for BTC/USD, compatible with `shz_dlc::OracleAnnouncement` / `OracleAttestation` and the existing CET adaptor-signature code.

```
GET http://170.75.168.145:8091/v1/dlc/events              announced events, status, stats
GET http://170.75.168.145:8091/v1/dlc/event/<event_id>    announcement (+ attestation)
python3 verify_client.py http://170.75.168.145:8091 --pubkey 68b52a25...d312 --dlc SHZ-BTCUSD-20261125T0915Z
```

- **Events.** A maturity every 15 min; the next four are kept announced. Event id `SHZ-BTCUSD-YYYYMMDDTHHMMZ`; 20 binary digits (integer USD, MSB first, clamped like `shz_margin::decompose_price_bits`). Outcome: `floor(median_e8 / 1e8)` of the first VALID FROST relay packet with `slot_us` in [maturity, maturity + 30 s); no such packet means the event stays unattested and the contract uses its refund path.
- **Pre-committed nonces without a dealer.** Per event, members run a Feldman-VSS DKG of 21 nonces (20 digits plus one that signs the announcement). Each member checks every received share against the dealer's public commitments. Shares travel through the coordinator encrypted under pads derived from pairwise ECDH of the members' verification shares, so the coordinator never learns a nonce. A group nonce with odd Y is negated in every share.
- **Announcement.** `core` (event id, maturity, digit nonces, announcement nonce, rule) is threshold-signed with the reserved nonce under `tagged_hash("SHZ/DLC/ANNOUNCEMENT/V1", canonical_json(core))`. Members sign only a core whose nonces equal their own DKG result.
- **Decision locks.** The per-event nonces are plain Shamir shares, so the group key is exposed if honest members sign two different messages with shares of the same nonce, even when each member signs only one. Every member therefore durably locks an event to one decision (`price:<usd>` or `unattestable`) and signs that lock with its key share (`/dlc/lock-outcome`, `/dlc/lock-unattestable`). A member releases digit or notice partials only when shown locks for its own decision from `decision_quorum = ceil((n + t) / 2)` members (4 of 5): two quorums share at least `t` members, so with up to `t - 1` faulty members only one decision per event can reach quorum. Attestation therefore needs 4 live members; with fewer, the event stays unattested and contracts use the refund path. The locks are published with the attestation (`decision_locks`). The announcement is the member's own canonical core (`dlc_oracle.canonical_core`); any other text is refused.
- **Attestation.** Members verify the outcome packet themselves: group-signed, VALID, inside the maturity window, and no earlier VALID packet at or after maturity among those they have seen. Each nonce is durably locked to one digit message before a partial leaves the member. The coordinator checks every partial against the member's nonce-share and key-share commitments (identifiable abort) and publishes the aggregate digit signatures.
- **Unattestable events.** If no VALID packet exists in the outcome window, after a further 60 s grace the group signs a notice with a third reserved nonce (`unattestable_nonce_x`, committed in the announcement): BIP340 over `tagged_hash("SHZ/DLC/UNATTESTABLE/V1", event_id)`, published as `status: unattestable` with `unattestable_signature`. Members refuse it once any digit nonce has signed or if they saw a VALID packet in the window, and after signing it they refuse to attest, so an event can never carry both. The notice is informational: contracts recover funds through the pre-signed CLTV refund (`docs/SHZ_HFT_06_DLC_REFUND.md`, `shz dlc-refund-plan`, `shz dlc-oracle-regtest`), which needs no oracle signature.
- **Settlement.** `cargo test -p shz-dlc --test frost_oracle_settlement` deserializes a threshold announcement and attestation, checks them with `OracleAttestation::verify_against`, builds the compressed CETs of a 1,000 USD inverse contract, and shows the attestation completes the adaptor signature of exactly the CET covering the attested price; a CET for another range cannot be completed.

## Packet

`body` fields: `schema` (`shz-public-relay/v1`), `market`, `data_class` (`public_delayed`), `seq`, `previous` (digest of packet `seq-1`), `interval_ms`, `slot_us`, `assembled_us`, `status` (`VALID` or `HOLD` with `hold_reason`), `median_e8`, `dispersion_bps`, `audit_deviation_bps`, `fast_sources_used`, and per-source `{id, role, ok, fetched_us, source_ts_us, ts_from_fetch, age_us, response_sha256, error}`.

Signed message: `tagged_hash("SHZ/PUBLIC-RELAY-PACKET/V1", canonical_json(body))` (BIP340 tagged hash, JSON with sorted keys and no spaces). `digest` is that message; `signature` is BIP340 over it.

Per-exchange prices are not published. They are kept with the raw responses in the relay's private archive (2-day retention) and committed to by `response_sha256`, so the operator can prove what each source returned.

## Rules

| Role | Sources | Use |
| --- | --- | --- |
| fast | Coinbase, Kraken, Bitstamp, Gemini public tickers | median; fresh if source time (or fetch time when the ticker has none) is within 30 s |
| audit | Chainlink BTC/USD aggregator on Ethereum (`0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c`, `latestRoundData` via a public RPC) | slow reference (0.5% deviation / 1 h heartbeat); fresh within 65 min |

VALID needs at least 3 fresh fast sources, fast-source dispersion of at most 50 bps, and the median within 150 bps of the audit value when the audit is available. Otherwise HOLD with `insufficient_fresh_sources`, `dispersion` or `audit_divergence`. Source signatures are not verified (these sources publish none). The Pyth Hermes public endpoint returned HTTP 401 on 2026-11-25, so Pyth is not used.

## Operation

```
python3 -m unittest test_public_relay test_frost test_dlc  # offline: BIP340 vector, relay rules, FROST signing, DLC DKG/announce/attest/refusals
python3 public_relay.py --state ./state --once   # one live packet
python3 verify_client.py http://170.75.168.145:8090 --pubkey 9d0d3aa9...a4b1 --follow 10
cargo test -p shz-relay --test public_relay_signature   # Rust verifies single-key and FROST-aggregate packets
cargo test -p shz-dlc --test frost_oracle_settlement    # CET adaptor settlement against a threshold attestation
```

Deploy (as on the VPS): system user `shzrelay`, code in `/opt/shz-public-relay`, `shz-public-relay.service` (MemoryMax 220M, CPUQuota 30%, ProtectSystem=strict). Memory holds the last 2 h of packets (older ones: `/v1/archive/<day>.jsonl`). The signing key is generated on first start in `/var/lib/shz-public-relay/relay.key` (0600) and never leaves the box. Each packet is fsync'd to the archive before it is served; on restart the relay verifies the archive tail and continues the chain at `seq + 1`, refusing to start if the tail does not verify. Missed slots (fetch stall, suspend) show up as gaps in `slot_us` with consecutive `seq`.

Not provided: provider authentication, sub-second latency, redundancy, TLS, independent signers. Exchange market-data terms apply to any commercial redistribution of the median.
