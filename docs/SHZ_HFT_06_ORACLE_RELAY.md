# SHZ-HFT-06: trusted oracle collator, tiered feed access and Lightning fee integration

Stacked on HFT-05 (#31, `adc01e1`), which stacks on HFT-04 (#29) → HFT-03 (#26) → HFT-02 (#23). The research branches #25 (event parity), #27 (smart routing) and #30 (public L2 calibration) are preserved; #30's `research/public_l2` pipeline is carried onto this branch for the immediacy study. `production_ready` remains false everywhere.

Router integration and the Lightning fee ledger are specified in [SHZ_HFT_06_ROUTER_LN.md](SHZ_HFT_06_ROUTER_LN.md); the tariff study in [research/public_l2/IMMEDIACY.md](../research/public_l2/IMMEDIACY.md); outstanding gates and exact commands in [SHZ_HFT_06_LEDGER.md](SHZ_HFT_06_LEDGER.md).

## 1. Source authentication inventory

| Source | Before HFT-06 | HFT-06 |
| --- | --- | --- |
| Pyth Pro / Lazer | Native Ed25519 Solana-envelope verifier, strict LE payload parser, pinned/governed signer registry (`pyth_lazer.rs`) | Reused unchanged by the collator |
| Chainlink Data Streams | No verifier. HFT-04 packets carried an unverified Chainlink report digest | `chainlink_streams.rs`: strict canonical ABI decode of `fullReport`, DON rule `h = keccak256(keccak256(reportBlob) ‖ reportContext)`, exactly `f+1` distinct ECDSA secp256k1 signers recovered and checked against a pinned `configDigest → (f, signers, validity window)` registry, high-`s` rejected, v3 schema decode with sign-extension/upper-bit checks, expiry, bid ≤ benchmark ≤ ask, spread bound, 18-decimal → `price_e8` integer normalization; API HMAC header helper |
| TradeLayer VWAP | Witness-quorum VWAP proofs (`tradelayer.rs`) | Slow independent audit reference only (`audit_against_tradelayer`), never a slot input |

Not done: the pinned DON registry must be loaded from the deployed Verifier contract's `ConfigSet` history by the operator (receipts say `onchain_config_verified: false`); no real Chainlink report is in the repository, so wire parity is tested against reports built with our own DON keys. Live Pyth and Chainlink sockets (`--features live`) compile in CI but have not been run against the services: no credentials or redistribution terms are available to this project.

## 2. Collator (`shz-oracle::collator`)

Input: raw signed frames with an arrival timestamp (socket receive time live; recorded value in replay). Each frame is authenticated by its native verifier before any field is read, then retained with SHA256 of the raw bytes, a domain-separated report digest, normalized `price_e8`, source timestamp, arrival timestamp and signer identity.

Slot `k` closes at `T_k = origin + (k−1)·200 ms` and sees exactly the reports that arrived at or before `T_k`. A report arriving after `T_k` first closes slot `k`, so it can only affect later slots; replay of an arrival-ordered recording is bit-identical. Every slot is an explicit HFT-04 `Packet`: VALID (both sources present, age ≤ 1 s, cross-source skew ≤ 500 ms, dispersion ≤ 50 bps) or HOLD(1 missing/stale, 2 skew/dispersion, 3 operator emergency). Per-source monotonicity: an exact replay is a duplicate, a non-increasing source timestamp is retained but not used, a source timestamp more than 100 ms after arrival is rejected as future-dated. The collator's packets pass the unchanged HFT-04 `Signer::vote` validation (tested).

**Calibration finding.** Chainlink v3 crypto reports carry whole-second `observationsTimestamp`. Under the HFT-04 constants (500 ms skew, 1 s age), healthy feeds HOLD a large share of slots: in the 120 s synthetic replay 244 of 600 slots HOLD on skew and 88 on staleness (268 VALID). Any live policy needs either a Chainlink schema with sub-second timestamps or a recalibrated skew/age bound for that source; this is recorded as gate G-SRC-3, not silently widened.

Replay receipt (`evidence/hft06/collator_replay_120s.json`, pinned in CI): chain receipt `effb98474d262f7335d89df8226a299e5a726b2798f70fdcc18b625faf3ed723`.

## 3. Relay (`crates/shz-relay`)

**Security modes, never mixed.** `trusted_relay`: one pinned relay key signs `tagged_hash("SHZ/HFT06/TRUSTED-RELAY-PACKET/V1", 0x01 ‖ policy ‖ relay_key ‖ packet_digest)`. `federated`: the HFT-04 4-of-5 BIP340 certificate over the raw packet digest. A verifier is pinned to one mode and rejects the other variant (`ModeMismatch`); the trusted signature is over a different message; configuration rejects a relay key equal to any federation member. A test relabels a trusted signature as four member votes and shows both verifiers reject it.

**Key lifecycles.** Packet keys sign at 5 Hz with durable one-signature-per-sequence locks (append-only, hash-chained, fsync before release; restart refuses equivocation and regression; torn or edited lock files fail closed). `ensure_key_separation` rejects a packet key equal to the FROST maturity group key. `ThresholdPacketSigner` is the seam for an audited threshold implementation (one BIP340 signature under a packet-specific group key, same lock semantics, nonces disjoint from DLC events); none is implemented. The in-process five-signer federation runs only with `SHZ_DEV_FEDERATION=1`; production federated mode uses the member vote transport below.

**Member vote transport (federated mode, G-FED-1).** Five independent processes (`shz-relay member --config member.json`, key from `SHZ_MEMBER_SIGNING_KEY[_FILE]`) each hold ONE member key, their own `DurableSignLock` and their own collator over their own source feed, so each authenticates the raw provider reports itself and rebuilds every slot packet. A member connects to the relay's vote endpoint (`member_listen`, WebSocket) and authenticates with a BIP340 challenge over `tagged_hash("SHZ/HFT06/MEMBER-AUTH/V1", relay_id ‖ nonce ‖ member)` against the registry `policy.members` (a key outside the policy, a real key claiming another slot, an index outside 0..4 and a signature replayed from another connection are all refused and counted). Per slot the relay sends a proposal (`seq`, packet, parent certificate, absolute deadline). A member signs only when the proposal digest equals the digest of its own packet for that `seq`; otherwise it sends `disagree{seq, own_digest}` and signs nothing. The durable lock is written and synced before the signature exists. The relay verifies every vote, feeds `FederatedCollector`, publishes the certificate at the fourth valid vote and broadcasts it to the members; one disagreeing or absent member does not stop a quorum of four. Conflicting valid signatures by one member over different digests for one `seq` are stored as equivocation evidence (`/healthz` `federation.member_equivocation_evidence`, `shz_relay_member_equivocations_total`). A trusted-relay relay never admits members: a listener bound there answers every connection with an error and closes.

*Chaining rule.* `previous` is always the digest of the last **certified** packet, never of the last proposed one. A proposal carries that parent certificate; a member verifies it once (4-of-5), requires `parent.seq < seq`, `previous == digest(parent)` and a parent no older than any it has accepted, then rebuilds its own packet with that `previous` before comparing digests. A slot with no quorum by `boundary + certification_deadline` is abandoned (`quorum_timeouts`, no certificate); the next proposal links to the last certified packet and its `seq` jumps over the abandoned slots (`skipped_slots`). In federated mode the hub and `TieredReceiver` accept a jump only when `previous` equals the last accepted digest (a trusted-relay hub still treats any gap as an error), so the chain stays a single line and a receiver sees the outage as a missing mark that fails closed. Before the first certificate only `seq = 1` with `previous = 0` is admissible: the relay re-proposes its slot-1 packet until four members have built the same packet, and that genesis certificate is released late (flagged `late`, no tier lead). Members re-vote the same digest for a re-proposed slot (the lock is idempotent) and refuse a different digest for any slot already signed, including after a restart.

*Measured* (`evidence/hft06/relay_bench_federated_remote_windows.json`, `shz-relay bench --mode federated-remote --clients 2 --seconds 30`, relay and five member tasks in one process over loopback WebSockets, Windows x86_64, release): 155 slots, 155 certified, 0 quorum timeouts, 0 lost, 0 verification failures; proposal to quorum p50 6.7 ms (p99 12.3 ms); boundary to certificate p50 12.3 ms (p99 22.5 ms); realized premium-vs-standard lead p50 194.2 ms (p99 198.7 ms), premium-vs-intermediate p50 99.4 ms. Member-side lock fsyncs and signatures are part of the quorum latency and run concurrently in five tasks on one machine; geographic round-trip times are not included. Tests (`crates/shz-relay/tests/remote_federation.rs`): certificates form and clients receive federated packets; one member on a different feed still yields quorum with four; two members down gives `quorum_timeouts` and no certificate, then recovery with a linked jump; genesis waits for quorum; unknown member keys refused; trusted mode refuses members; conflicting votes become evidence.

**Schedule.** For boundary `T`, certification time `C`, clock bound `e`: Premium `C`; Intermediate `max(C, T+d_i+e)` with `d_i = 100 ms` configurable in (0, 200 ms); Standard `max(C, T+200 ms+e)`. A certificate later than `T + deadline` (default 200 ms) goes to every tier at once and is flagged `late` (no lead, chain stays continuous). Each tier is scheduled independently, so premium transport failure cannot delay the public release; public release is bounded by `T + max(deadline, 200 ms + e)`.

**Hub.** Verifies every packet, enforces `seq = last+1` and `previous = last digest`, idempotent exact duplicates, equivocation and gap rejection with counters. Bounded per-subscriber queues; a full queue disconnects that subscriber (never blocks, never silently skips). Catch-up from `from_seq` and checkpoint retrieval return only packets already released to the requester's tier. An append-only checkpoint log (fsync per packet) is replayed and re-verified on restart; corruption fails closed. The client `TieredReceiver` advances the chain on in-sequence late packets without exposing a mark, re-anchors at a certified checkpoint, and fails closed on HOLD, stale source, clock regression or uncertainty above 5 ms.

**Access.** BIP340 challenge-response: the server sends a fresh 32-byte nonce per connection, the client signs `tagged_hash("SHZ/HFT06/RELAY-AUTH/V1", relay_id ‖ nonce ‖ client_id)`; only public keys are configured; per-client connection limits. HTTP: `/healthz`, `/metrics` (Prometheus), `/v1/checkpoint/{latest|seq}` (public = standard tier).

## 4. Measured delivery (synthetic loopback, single process)

`shz-relay bench --clients 4 --seconds 60 --slow-client 1` on Windows x86_64 (`evidence/hft06/relay_bench_trusted_windows.json`); federated: 30 s (`relay_bench_federated_windows.json`). One monotonic clock, so clock uncertainty is 0 by construction; cross-host uncertainty and real network paths are unmeasured. The fourth client per tier sleeps 900 ms per message; TCP buffering absorbed its backlog (no lag disconnect at 824 B/message) and its record did not drain inside the collection timeout, so three clients per tier are reported. Lag disconnection is covered by unit tests.

| Stage (trusted relay) | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| Native verify + normalize per report | 127 µs | 895 µs | 1.15 ms |
| Durable lock (fsync) + BIP340 sign per slot | 2.82 ms | 3.84 ms | 4.61 ms |
| Client receive − boundary, premium | 10.4 ms | 17.9 ms | 19.8 ms |
| Client receive − boundary, intermediate | 109.0 ms | 115.6 ms | 116.3 ms |
| Client receive − boundary, standard | 206.4 ms | 213.4 ms | 214.6 ms |
| Client signature verification | 0.21 ms | 0.30 ms | 0.52 ms |
| **Realized lead premium vs standard** | **197.7 ms** | 201.7 ms | 202.9 ms |
| Realized lead premium vs intermediate | 103.1 ms | 106.3 ms | 106.9 ms |

305 slots, 2,745 deliveries, 0 lost, 0 verification failures, 61 deliveries/s, 824 B per delivery, 668 B checkpoint log and 134 B signer lock per slot. Federated (dev): certification p50 15.4 ms / p99 53.2 ms (four fsyncs + four signatures), realized premium-vs-standard lead p50 181.7 ms, p99 199.8 ms, 0 lost. The configured 200 ms gap is not the realized advantage: certification latency, scheduler slip (Windows timer, 1.7–6.7 ms server send after release) and the clock-bound margin all move it, and network paths are absent here. CI repeats both runs on Linux (run 45422703072, ubuntu-24.04): trusted mode certification p50 0.48 ms, premium receive 0.91 ms after the boundary (p99 1.23 ms), intermediate 102.1 ms, standard 202.1 ms, realized premium-vs-standard lead p50 201.2 ms (p99 201.3 ms); federated certification p50 2.05 ms, lead p50 199.8 ms; 0 lost, 0 verification failures in both. Router on Linux: admission p50 155 µs, matching 1.6 µs, seal 1.3 µs, 6,857 orders/s and 3,122 fills/s, fee conservation exact. The Linux lead exceeds 200 ms because the lower tiers wait the extra 2 ms clock-bound margin while premium waits only for certification.

### End-to-end stage budget (synthetic, Windows x86_64)

Router and fee path from `cargo run --release -p shz-dex --example hft06_router_bench -- --orders 20000` (`evidence/hft06/router_bench_windows.json`, FeedOnly arm):

| Stage | p50 | p99 |
| --- | ---: | ---: |
| Source ingest: native verify + normalize per report | 127 µs | 1.15 ms |
| Certification: durable lock + trusted signature per slot | 2.82 ms | 4.61 ms |
| Relay delivery: premium receive − boundary | 10.4 ms | 19.8 ms |
| Router admission (signature + entitlement), admitted | 290 µs | 555 µs |
| Matching per fill | 7.8 µs | 32.0 µs |
| 100 ms batch seal (HFT-03 `seal_legs`) | 5.0 µs | 13.9 µs |
| Fee commitment per batch, in-memory ledger | 0.81 ms | 1.36 ms |
| Fee commitment per batch, fsync'd WAL | 10.3 ms | 12.1 ms |

Sustained router throughput in that loop: 3,603 orders/s and 1,641 fills/s single-threaded. The WAL appends about 3.86 kB per batch. Fee conservation holds exactly (18,215 sat = maker + taker fees = oracle + router dues = batch dues), and the ledger reconciles clean against the HFT-05 `DurableRouter`. All three execution arms produce 9,107 fills from 20,000 intents. Premium takers fill 3,036 times under FeedOnly and 3,392 under SchedulerOnly/Combined. The configured leads are reported per mechanism, and the Combined sum is flagged `double_counted`, never as a measured advantage. Admission p50 varied between 300 and 630 µs across runs on this laptop. Not measured: real Lightning transport, cross-router contention, WAL cost on the tiered matching path (the WAL on the tiered path is in `DurableTieredRouter`, gate G-LN-2; its throughput is not yet measured).

## 5. Operating

```
cargo build --release -p shz-relay --bins
target/release/shz-relay dev-config --dir deploy/hft06          # writes relay.local.json + client keys (gitignored)
target/release/shz-relay keygen --out deploy/hft06/secrets/relay.key
SHZ_RELAY_SIGNING_KEY_FILE=deploy/hft06/secrets/relay.key target/release/shz-relay serve --config deploy/hft06/relay.local.json
target/release/shz-relay subscribe --url ws://127.0.0.1:9440 --client-id premium-dev --key-file deploy/hft06/clients/premium-dev.key --count 5
target/release/shz-relay checkpoint --http 127.0.0.1:9441
target/release/shz-collator gen-fixture --origin-us 1800000000000000 --seconds 120 --out rec.jsonl
target/release/shz-collator replay --recording rec.jsonl --origin-us 1800000000000000 --archive obs.jsonl
docker compose -f deploy/hft06/docker-compose.yml up --build
```

Configuration schema: `deploy/hft06/relay.schema.json`. Secrets: `deploy/hft06/.env.example` (environment or mounted secret files only). Windows builds need the MSVC toolchain (`+stable-x86_64-pc-windows-msvc`); the GNU toolchain lacks `dlltool` for tokio's `windows-sys`.
