# HFT-06 security review brief

Review target: branch `research/shz-hft06-oracle-relay-20261124` at `20a8edc` (stacked on HFT-05 `adc01e1`). About 9.5k lines in scope; the rest of the branch diff is fixtures, evidence JSON, docs and CI. Deployed instances are live on the witness VPS: 170.75.168.145:8090 (single key) and :8091 (FROST 3-of-5).

## In scope, by priority

| # | Area | Files | What must hold |
| --- | --- | --- | --- |
| 1 | Source authentication | `crates/shz-oracle/src/chainlink_streams.rs`, `pyth_lazer.rs` (pre-existing) | No field trusted before signature checks; canonical ABI only; exactly f+1 distinct pinned DON signers; high-s rejected; integer overflow/sign-extension; expiry and freshness |
| 2 | Collator determinism | `crates/shz-oracle/src/collator.rs` | A report arriving after T_k cannot affect slot k; replay is bit-identical; VALID only under the HFT-04 bounds; monotonicity and duplicate handling |
| 3 | Relay envelopes and modes | `crates/shz-relay/src/envelope.rs`, `authority.rs` | A trusted-relay signature can never pass as a federated certificate; durable one-signature-per-seq locks (torn/edited files fail closed); FROST maturity key separation |
| 4 | Hub, schedule, client | `hub.rs`, `schedule.rs`, `client.rs` | No tier receives a packet before its release time, including via catch-up or checkpoint; continuity, equivocation and gap rules; federated seq-jump accepted only when `previous` = last accepted digest; bounded queues |
| 5 | Network surface | `server.rs`, `remote.rs`, `member.rs`, `config.rs`, bins | Challenge-response auth (nonce reuse, client-id binding), member auth against `policy.members`, parsing limits, connection limits, DoS on WS/HTTP, the proposal-carries-parent chaining rule, members vote only on their own independently built digest |
| 6 | Router admission and matching | `crates/shz-dex/src/routing/tiered.rs` | Entitlement and tariff enforcement; public-only makers never fill against a privileged mark; stale-quote collar; emergency HOLD; fee arithmetic and the 70/30 split conserve exactly; fills bind packet digest, entitlements, tariff and policy |
| 7 | Durability and acknowledgements | `tiered_durable.rs`, `durable.rs` (refactored), `coalescer.rs` (`seal_legs`) | Fsync before apply; crash cuts; rollback detection with pinned tip; HFT-05 ack digest byte-identical; HFT-05 and HFT-06 acks cannot cross; no timeout releases collateral |
| 8 | Fee ledger | `crates/shz-dex/src/routing/ln_fees.rs` | Accrued vs committed vs collected vs outstanding never conflated; duplicate/overpaying receipts; reversal on fenced abort; WAL replay |
| 9 | Deployed Python relayers | `ops/public-relay/{bip340,public_relay,frost,frost_signer,frost_relay}.py` | BIP340 correctness (Jacobian rewrite); FROST binding factors, parity handling, nonce single use across restarts, partial verification; HTTP handler path handling; archive restore refusing a bad tail |
| 10 | Threshold DLC oracle | `ops/public-relay/{dlc_oracle,dlc_coord}.py`, DLC paths in `frost_signer.py`; `crates/shz-dlc/tests/frost_oracle_settlement.rs` | Nonce DKG: shares checked against commitments, ECDH pads keep nonces from the coordinator, parity handling; a nonce never signs two messages (locks durable before partials leave, across restarts); members attest only the first VALID group-signed packet in the maturity window; announcement binds the nonces; attestations interoperate with `shz_dlc` CET adaptor settlement |
| 11 | Unattestable notice and refund tooling | `dlc_oracle.py` (`sign_unattestable`), `dlc_coord.py` (`declare_unattestable`), `bins/shz-cli/src/{dlc_refund_plan,dlc_oracle_regtest}.rs`, `crates/shz-utxoref/src/mnr02.rs` refund leaf | An event never carries both an attestation and an unattestable notice; the notice uses its own announced nonce; refund heights cannot arrive before the attestation deadline under faster blocks; the pre-signed CLTV refund is non-final before its height and spends only to the agreed outputs |

## Threat model

- **Adversaries:** a malicious subscriber (tries to receive early, replay, exhaust resources); a malicious or compromised relay coordinator (forks the chain, equivocates, leaks early data, reorders); a minority of malicious federation members (up to 1 of 5 for HFT-04 certificates; up to 2 of 5 for FROST liveness); a malicious trader (forged intents/entitlements, fee evasion, matching against unpublished marks); a network attacker on plain HTTP/WS.
- **Trusted, by design:**
  - In trusted-relay mode, the relay key holder.
  - The pinned Pyth and Chainlink signer registries, which the operator loads from chain.
  - The channel monitor attestation in HFT-05/06 acknowledgements; it is a stand-in for real LDK evidence.
  - In the deployed Python relayers, the TLS-fetched public sources, which carry no signatures.

## Known gaps (do not re-report; challenge the mitigation instead)

1. FROST keygen is a trusted dealer, and all five members share one host and operator (demonstration).
2. Member links and the public relayers use plain HTTP/WS without TLS. There is no WS heartbeat; a dead member is detected only by TCP close.
3. Live Pyth/Chainlink connectors (`live.rs`) are written from documentation and have never run against the services.
4. `LightningAdapter` has only `MockAdapter`. The LDK design (`SHZ_HFT_06_LDK.md`) is not implemented.
5. Chainlink v3 whole-second timestamps make the HFT-04 500 ms skew bound HOLD a large share of slots (gate G-SRC-3).
6. Multi-host delivery timing and clock uncertainty are unmeasured; all latency numbers are loopback.
7. DLC nonce shares and DKG ciphertexts cross a single host's loopback; an outcome packet seen by no member before attestation leaves a bounded choice (at most 6 VALID packets in the 30 s window) to the coordinator.
8. A coordinator crash after members signed an unpublished seq costs that seq. A malicious coordinator holding such an aggregate could publish it out of order. Clients reject it only because they require increasing seq with `previous` = last seen digest.

## How to run

```
cargo test --locked -p shz-oracle -p shz-relay -p shz-dex -p shz-dlc -p shz-margin
cargo test --locked -p shz-dex --test hft06_e2e_relay
cd ops/public-relay && python3 -m unittest test_public_relay test_frost test_dlc
cargo test --locked -p shz-dlc --test frost_oracle_settlement
cargo test --locked -p shz-cli
cargo run --release --bin shz -- dlc-oracle-regtest <path-to-bitcoind-31.1>
python3 ops/public-relay/verify_client.py http://170.75.168.145:8091 --pubkey 68b52a25233d8b87f5c09d44a71fb5e15bfd025c2dde56f9674468e1f1c3d312 --follow 10
```

Windows: add `+stable-x86_64-pc-windows-msvc` to cargo. CI: workflow `shz-hft06-oracle-relay` (last green run 45438548161).

Deliverable expected: findings ranked by severity with reproduction (test or command) against `20a8edc`. Fixes land on this branch.
