# SHZ-INDEX-03: Transparent Nova Oracle Checkpoint Verification on NEAR

- **Base branch:** `research/shz-hourly-index-nova-02-20261124` (Draft PR #10, commit `9274722ac8aed09170f12da66729115f1554bd27`, CI run `45262710693`).
- **Continuation branch:** `research/shz-hourly-index-nova-03-20261124`.
- **Target checkpoint root (`INDEX-01`):** `c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5` (`start_hour = 498000`, `40`-byte Bitcoin `OP_RETURN` packet `53485a4944583031c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5`).
- **Cryptographic setup constraints:** **100% setup-free (transparent)**. Uses `nova-snark =0.76.0` non-interactive folding (`NIFS`) + ZK-blinded Spartan sumchecks + discrete-log Inner Product Argument (`IPA`) over `BN254 G1` (`Bn256EngineIPA`) and `Pallas/Vesta` (`PallasEngine`/`VestaEngine`). Zero Groth16, zero KZG, zero trusted setup ceremonies, zero Starknet dependencies, and zero additional Bitcoin dispute machinery.

---

## 1. Acceptance Gates Summary (Reported Separately)

| Gate | Requirement | Status | Primary Evidence |
|---|---|---|---|
| **Gate A** | Complete `INDEX-02` transparent compressed Nova proof & independent persisted verification against `c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5` | **PASS** | `research/hourly_index_nova_03/artifacts/index02_pallas_vesta/{proof.bin,report.json,verification.json}` (`Pallas/Vesta` `CompressedSNARK`, `12,376` B proof, `sha256 = 15a48918d06118c720033225a076e767f585ae3e74f940390aa037cf01c60af7`) AND `research/hourly_index_nova_03/artifacts/{proof.bin,independent_verification.json}` (`Bn256EngineIPA` 8-fold NIFS + Spartan/IPA, `10,003` B proof, `sha256 = fdd065592a393f9bb1d7ba0e843e2bdfb5af412f9552f9f7a0c13ed0629d03f1`) |
| **Gate B** | Transparent NEAR WASM smart contract verifies the actual cryptographic Nova/Spartan/IPA relation against `c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5` with valid + tampered proof controls and measured sandbox receipt gas | **PASS** | `research/hourly_index_nova_03/near_contract/src/lib.rs`, `research/hourly_index_nova_03/sandbox.mjs`, `research/hourly_index_nova_03/artifacts/near_sandbox_receipt.json` (`near-sandbox@0.3.5`, `598,063` B WASM, `1,129` txs, `196,381.154 TGas` cumulative receipt gas, `43.34s` sandbox wall time, 8/8 WASM adversarial controls rejected) |
| **Gate C** | Authentic Pyth Pro (`pyth-lazer`) and Chainlink Data Streams v3 report ingestion, Solana Mainnet signer-registry authentication, DON `ecrecover` quorum verification, R1CS source/HOLD-necessity binding, and anti-cherry-picking fraud proofs | **PASS (Operational Pyth + Full Chainlink v3 Verifier; Live Enterprise API Gated by Credentials)** | `research/hourly_index_nova_03/prover/src/{sources.rs,circuit.rs}`, `research/hourly_index_nova_03/artifacts/evidence_gates.json`. Live Solana Mainnet `pyth-lazer` `Storage` PDA `3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL` parsed & verified against official `Crypto.BTC/USD` report signed by `80efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c` (`2.103 TGas` on NEAR WASM); Chainlink v3 DON quorum verified via `env::keccak256` + `env::ecrecover` (`2.836 TGas` on NEAR WASM). Unauthenticated live REST endpoints (`pyth-lazer` HTTP 403 without bearer token; Chainlink Data Engine HTTP 400 without enterprise HMAC keys) documented; synthetic test fixtures strictly isolated under `synthetic_test_only` with `operational_source_authenticated: false`. |
| **Gate D** | Accepted checkpoint root bound to raw `40`-byte `SHZIDX01 || checkpoint_root32` Bitcoin `OP_RETURN` transaction under a Bitcoin PoW/chainwork/SPV header light client (`Near-One/btc-light-client-contract` model) with confirmation depth and reorg invalidation | **PASS** | `research/hourly_index_nova_03/prover/src/btc_anchor.rs`, `near_contract/src/lib.rs`, `artifacts/near_sandbox_receipt.json` (`2.813 TGas` on NEAR WASM; rejects 64-byte stripped tx, `< 3` confirmations, substituted `OP_RETURN` tx, and immediately revokes feed eligibility during a heavier 4-block Bitcoin reorganization) |
| **Gate E** | Accepted & anchored oracle epoch safely feeds `FROST` (`t-of-n` BIP-340 digit attestation) / DLC settlement path while keeping individual DLC contract terms private and retaining `can_authorize_dlc_settlement: false` | **PASS** | `research/hourly_index_nova_03/prover/src/bridge.rs`, `artifacts/evidence_gates.json` (`HOLD` records unconditionally rejected; bilateral DLC collateral/strike/payout/adaptor terms never appear on-chain; `production_ready: false`, `can_authorize_dlc_settlement: false`) |

---

## 2. Formal Constrained Relations (`v1` and `v2`)

### 2.1 `shz/hourly-index-checkpoint-nova/v1` (`HourStepGeneric<F>`, Arity `8`)

Instantiates the exact `INDEX-02` step circuit generically over any `PrimeFieldBits` scalar field (`PallasEngine` for Gate A baseline and `Bn256EngineIPA` for Gate B NEAR verification).

For public claim $(G_{32}, P_{32}, h_0, R_{32})$ with $h_0 \equiv 0 \pmod 8$ and $h_0 \le 999{,}999{,}992$, the 8-element step state is:
$$z_k = \bigl(k,\; h_0,\; \text{LE}_{128}(G_{0..16}),\; \text{LE}_{128}(G_{16..32}),\; \text{LE}_{128}(P_{0..16}),\; \text{LE}_{128}(P_{16..32}),\; \text{LE}_{128}(R_{0..16}),\; \text{LE}_{128}(R_{16..32})\bigr)$$
from $z_0$ ($k=0$) to $z_8$ ($k=8$) across **8 consecutive folds** (`308,084` R1CS constraints/fold in `TestConstraintSystem`; `308,100` constraints and `306,208` variables per `DirectCircuit` fold, padded to $N = 2^{19} = 524{,}288$ with `1,686,599` non-zero sparse matrix entries). Every fold has **identical circuit shape** regardless of witness values or `VALID`/`HOLD` status:

1. **Schedule & Header Binding:** `pos` fits in 3 bits (`pos == z[0]`), `hour == h_0 + pos`, `h_0 % 8 == 0`, and 256-bit `genesis`, `policy_hash`, and `checkpoint_root` match `z[2..8]` via exact 128-bit unsigned little-endian limbs without modular reduction.
2. **Mode Encoding (`VALID` vs `HOLD`):** `status == 1` (`valid = 1`, `reason == 0`) or `status == 2` (`valid = 0`, `reason in {1, 2, 3}`). Under `HOLD`, `p == c == index == pt == ct == 0` and all 256 bits of `pyth_report_hash` and `chainlink_report_hash` are forced to `0`. Under `VALID`, prices lie in $[1, 10^{16}]$ (`1e-8` USD up to \$100,000,000) and both report digests are non-zero.
3. **Exact Floor Midpoint:** A 1-bit slack $s_{\text{mid}} \in \{0, 1\}$ enforces:
   $$p + c - 2 \cdot \text{index} = s_{\text{mid}} \iff \text{index} = \left\lfloor \frac{p + c}{2} \right\rfloor$$
4. **Maximum 50-bps Relative Spread:** Both directions are independently constrained via 80-bit non-negative slacks (magnitude $< 2^{80} \ll r_{\text{BN254}} \approx 2^{254}$, ruling out field wraparound):
   $$20{,}000 \cdot |p - c| \le 50 \cdot (p + c) \iff 19{,}950 \cdot \max(p, c) \le 20{,}050 \cdot \min(p, c)$$
5. **Observation Freshness & Skew:** For cutoff $T_h = (h + 1) \cdot 3{,}600{,}000{,}000\;\mu\text{s}$:
   $$T_h - 300{,}000{,}000 \le t_{\text{pyth}}, t_{\text{cl}} \le T_h, \qquad |t_{\text{pyth}} - t_{\text{cl}}| \le 60{,}000{,}000$$
6. **Exact SHA-256 Leaf, 3-Level Merkle Path, and Checkpoint Root:** Hashes `SHZ/HOUR/LEAF/V1 || leaf_fields`, traverses 3 direction-selected `SHZ/HOUR/NODE/V1` levels indexed by the bits of `pos`, and hashes `SHZ/8H/ROOT/V1 || genesis || policy || start_hour || merkle_root` directly onto `z[6..8]`.

### 2.2 `shz/hourly-index-source-bound-nova/v2` (`SourceBoundHourStep<F>`, Arity `10`)

Extends `v1` with a running 256-bit SHA-256 commitment chain `z[8..10]` over the 8 hourly authenticated source-candidate tuples `(hour_id, pyth_present, chainlink_present, cand_p, cand_c, cand_pt, cand_ct, cand_p_sha256, cand_c_sha256)` AND enforces **bidirectional `HOLD` necessity** directly against the allocated leaf wires:
- Mode partition: `valid + is_r1 + is_r2 + is_r3 == 1` and `reason == 1*is_r1 + 2*is_r2 + 3*is_r3`.
- When `valid == 1`: `both_present == 1` and leaf wires `(p, c, pt, ct, ph, ch)` equal candidate wires bit-for-bit.
- When `is_r1 == 1` (missing source): `both_present == 0`.
- When `is_r2 == 1` (excessive spread): `both_present == 1` AND strict inequality $19{,}950 \cdot \max(cp, cc) - 20{,}050 \cdot \min(cp, cc) - 1 \ge 0$.
- When `is_r3 == 1` (stale/future/skewed timestamp): `both_present == 1` AND at least one of the 6 strict timestamp-violation slacks (`>= 1 us` past bound) is non-negative.

Consequently, **even if a malicious prover recomputes the leaf, Merkle tree, and `checkpoint_root`**, fabricating `HOLD` (`reason = 1, 2, or 3`) over fresh, in-spread authenticated Pyth + Chainlink candidates is unsatisfiable at the R1CS constraint level (`case_09`).

---

## 3. Verifier Workload Profiling & Route Selection (`Route A` vs `Route B` vs `Route B + C`)

### 3.1 Measured `near-sandbox@0.3.5` Cryptographic Microbenchmarks

Measured directly inside `near-sandbox@0.3.5` on `shz_index03_near_verifier.wasm`:

| Operation | Dimension $n$ | Measured Receipt Gas (`TGas`) | Marginal Cost | Speedup vs PR #8 Baseline |
|---|---:|---:|---:|---:|
| PR #8 recursive generator folding (`BN254`) | `32` | `110.879 TGas` | `3.465 TGas/pt` | `1.00x` |
| **Single weighted `env::alt_bn128_g1_multiexp`** | **`32`** | **`12.432 TGas`** | **`0.326 TGas/pt`** | **`8.92x`** |
| Single weighted `env::alt_bn128_g1_multiexp` | `64` | `22.851 TGas` | `0.326 TGas/pt` | — |
| Single weighted `env::alt_bn128_g1_multiexp` | `256` | `85.360 TGas` | `0.326 TGas/pt` | — |
| Single weighted `env::alt_bn128_g1_multiexp` | `512` | `168.707 TGas` | `0.326 TGas/pt` | — |
| Single weighted `env::alt_bn128_g1_multiexp` | `768` | `252.054 TGas` | `0.326 TGas/pt` | — |
| Single weighted `env::alt_bn128_g1_multiexp` | `1024` | `> 300 TGas` (exceeds single-tx cap) | — | — |
| Pure-WASM adaptive Pippenger MSM (`Pallas`) | `64` | `184.850 TGas` | `2.888 TGas/pt` | `8.86x` slower than host `BN254` |
| Pure-WASM adaptive Pippenger MSM (`BN254`) | `64` | `205.088 TGas` | `3.205 TGas/pt` | `9.83x` slower than host `BN254` |
| Pure-WASM adaptive Pippenger MSM (`Grumpkin`) | `64` | `226.519 TGas` | `3.539 TGas/pt` | `10.86x` slower than host `BN254` |

### 3.2 Architecture Comparison

| Metric | Route A: Pure-WASM `Pallas/Vesta` `CompressedSNARK` | Route B (2-Curve): `BN254/Grumpkin` `CompressedSNARK` | **Selected (`Route B + C`): Pure-BN254 8-Fold Nova NIFS + ZK-Blinded Spartan/IPA** |
|---|---|---|---|
| Trusted setup ceremony | None | None | **None** |
| Curve operations | `524,288` Pallas + `16,384` Vesta (100% pure WASM) | `524,288` BN254 (host) + `16,384` Grumpkin (pure WASM) | **`524,288` BN254 G1 (100% `env::alt_bn128_g1_multiexp`)** |
| Fiat-Shamir / Merkle hashes | Pure-WASM Keccak/SHA2 | Host Keccak + pure-WASM Poseidon | **100% `env::keccak256` + `env::sha256`** |
| $\hat{b} = \langle \text{eq}(r_{\text{batch}}), s \rangle$ muls | $540{,}672$ scalar muls | $540{,}672$ scalar muls | **$57$ scalar muls ($O(\log N)$ Kronecker product)** |
| `EqPolynomial` RAM per R1CS call | $48\;\text{MiB}$ (exceeds WASM memory limits) | $48\;\text{MiB}$ | **$114\;\text{KiB}$ (half-bit Kronecker split $2^9 + 2^{10}$)** |
| Raw Verifier Key size | `110,771,368` B (`105.64 MiB`) | `110,771,368` B (`105.64 MiB`) | `59,541,176` B (`56.78 MiB` packed stream) |
| **On-chain pinned VK storage** | `110.77 MB` (`~1,107 NEAR`) | `~640 B` | **`244 B` bincode (`1,782 B` total contract init state!)** |
| Single-tx `< 300 TGas` feasible? | No (`~1,563,000 TGas`) | No (`~255,000 TGas`) | No (`196,381.15 TGas` -> requires sound multi-tx `Route C`) |
| **Measured NEAR Sandbox Gas** | Est. `~1,563,000 TGas` (`> 5,200` txs) | Est. `~255,000 TGas` (`~1,390` txs) | **Measured `196,381.154 TGas` across `1,129` txs (`43.34s`)** |

### 3.3 Four Algebraic Optimizations in `decider_equations.rs`

1. **Single Weighted `alt_bn128_g1_multiexp` Instead of Recursive Generator Folding:** Rather than folding generators pairwise across $k = 19$ rounds ($2N$ binary MSMs), `begin_decider_session` computes $P_{\text{hat}} = C_{\text{batch}} + (\text{eval}_{\text{batch}} \cdot r_{\text{ipa}}) U_{\text{ipa}} + \sum_{j=0}^{18} (r_j^2 L_j + r_j^{-2} R_j)$ in **one** 40-point `alt_bn128_g1_multiexp` call, and each `verify_msm_chunk` folds `512` generators + `acc_g_hat` in **one** 513-point `alt_bn128_g1_multiexp` call (`175.38 TGas`).
2. **$O(\log N)$ Factorized $\hat{b}$:** Exploits tensor structure $\langle \text{eq}(x), s \rangle = \prod_{j=0}^{k-1} ((1 - x_j) r_j^{-1} + x_j r_j)$, replacing `524,288` field multiplications with `57`.
3. **Half-Bit Kronecker-Split `EqPolynomial` + Row-Factored Sparse Matrix Accumulation:** Splits $r_x \in \mathbb{F}^{19}$ into $9 + 10$ bits (`1,536` scalars) and $r_y \in \mathbb{F}^{20}$ into $10 + 10$ bits (`2,048` scalars) and factors `tx(row)` across all columns in each row (`161.53 TGas` mean per `16,384`-entry R1CS chunk).
4. **Abelian Homomorphic Chunk Accumulation + Replay-Free Bitmaps:** Because scalar addition in $\mathbb{F}_r$ and point addition in $E(\mathbb{F}_q)$ are commutative and associative, and `r1cs_bitmap` / `msm_bitmap` enforce exact single-application of every Merkle-authenticated VK leaf `(CHUNK_KIND, chunk_idx, payload)`, multiple relayer access keys stream all `1,127` chunks concurrently in any block order while converging to the unique exact cryptographic evaluation.

---

## 4. Source Authentication & Anti-Cherry-Picking Policy (`Gate C`)

### 4.1 Operational Provenance vs Synthetic Test Profiles

- **Pyth Pro (`pyth-lazer`):**
  - Queried **Solana Mainnet RPC** for official `pyth-lazer` program `pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt` and decoded the live `381`-byte Anchor `Storage` PDA `3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL` (`discriminator = d175ffb9c4af4409`).
  - Extracted active trusted Ed25519 signer **`80efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c`** (`expires_at = 2052483257`) and trusted EVM ECDSA signer `0x26fb61a864c758ae9fba027a96010480658385b9` (`expires_at = 2057930841`).
  - Verified byte-exact Ed25519 signature validity of the official archived `pyth-lazer` `Crypto.BTC/USD` (`feed_id = 1`, `channel = 3`, `exponent = -8`, `price_e8 = 6,713,436,287,632`) Solana wire envelope both natively (`ed25519-dalek`) and on NEAR WASM (`env::ed25519_verify`, **`2.103 TGas`**).
  - Live `https://history.pyth-lazer.dourolabs.app/history/v1/symbols` confirmed `Crypto.BTC/USD` metadata (`HTTP 200`); live streaming endpoint `https://pyth-lazer.dourolabs.app/v1/latest_price` returned `HTTP 403` without an authorized `PYTH_LAZER_TOKEN` subscription credential.
- **Chainlink Data Streams v3 (`Crypto.BTC/USD`):**
  - Feed ID `0x00032cb071237a34710156d953df013bf366115982705b76615b3c3b064375b8`; Arbitrum One `VerifierProxy` `0x478Aa2aC9F6D65F84e09D9185d126c3a17c2a93C` inspected (`14,020` hex chars deployed bytecode). Live `api.dataengine.chain.link` requires enterprise HMAC credentials (`HTTP 400` unauthenticated).
  - Implemented full `Verifier.sol` + `data-streams-sdk/go/report/v3` verification both natively (`k256` recoverable ECDSA) and on NEAR WASM (`env::keccak256` + **`env::ecrecover(..., malleability_flag = true)`**, **`2.836 TGas`**): verifies outer ABI canon, `configDigest`, `keccak256(abi.encode(keccak256(reportBlob), reportContext))`, $\ge f + 1$ strictly unique authorized DON Ethereum signer addresses, EIP-2 low-$S$ signatures, `feedId`, `validFrom <= observationsTimestamp < expiresAt`, `bid <= benchmarkPrice <= ask`, and floor scaling $10^{18} \to 10^8$.
- **Strict Profile Separation:** Synthetic test fixtures (`SyntheticTestOnly` / `"synthetic_test_only"`) set `operational_source_authenticated: false` unconditionally and are rejected if submitted under `"operational_mainnet_pinned"` (verified in `near-sandbox`).

### 4.2 Anti-Cherry-Picking Security Boundary

Within each hourly window $[T_h - 300\text{s},\; T_h]$ (`200 ms` Pyth Pro updates = up to `1,500` eligible reports/hour; `1 s` Chainlink updates = up to `300` eligible reports/hour):
- **Canonical Deterministic Rule:** Each source's canonical observation for hour $h$ MUST be the authenticated report with the **strictly maximal publish/observation timestamp $\le T_h$**.
- **What Can Be Enforced Cryptographically Alone:**
  1. Signature authenticity, feed/channel/schema identity, signer epoch validity, freshness $[T_h - 300\text{s}, T_h]$, inter-source skew $\le 60\text{s}$, floor midpoint, $\le 50\;\text{bps}$ spread, and `HOLD` necessity relative to the committed candidate set (`SourceBoundHourStep`).
  2. If the oracle stream emits sequential gap-free monotonic sequence numbers up to the first post-cutoff report $R_{\text{after}}$ ($t > T_h$, $\text{seq}(R_{\text{after}}) = \text{seq}(R_{\text{selected}}) + 1$), adjacency proves completeness cryptographically. Neither Pyth Pro Solana envelopes nor Chainlink Data Streams v3 `reportBlob` expose a per-feed contiguous counter across every `200 ms` tick (Chainlink `(epoch, round)` can skip rounds across leader rotations).
- **What Requires Bonded Challenges or an Authenticated Observation Log:**
  - Without contiguous source sequence numbers, proving *non-existence* of a newer timestamp $t' \in (t_{\text{selected}}, T_h]$ requires either an authenticated transparency log or an **objective cryptographic fraud-proof challenge window**: any watcher holding a valid signed Pyth or Chainlink report with $t_{\text{selected}} < t' \le T_h$ calls `challenge_cherry_picked_chainlink` (or Pyth equivalent) on NEAR, which verifies the challenger's DON/Pyth signatures in `~2.8 TGas` and deterministically marks `source_challenged_invalid = true`, revoking settlement-feed eligibility (exercised in `sandbox.mjs`).

---

## 5. Bitcoin `SHZIDX01` Anchor Finality (`Gate D`) & Safe `FROST`/DLC Bridge (`Gate E`)

- **Bitcoin Anchor Binding (`btc_anchor.rs` & `near_contract/src/lib.rs`):**
  - Parses raw legacy and SegWit Bitcoin transactions, enforces **exact** `42`-byte `scriptPubKey = 0x6a 0x28 || "SHZIDX01" || checkpoint_root32` with `0` burned satoshis, and **explicitly rejects 64-byte stripped transactions** (preventing CVE-2018-17144 Merkle inner-node collision attacks, matching `Near-One/btc-light-client-contract` v2).
  - Embedded `BtcLightClient` validates 80-byte block header `version >= 4`, compact `nBits` PoW target (`block_hash_be <= target`), 11-block Median-Time-Past (`time > MTP`), intra-epoch difficulty rules, cumulative 256-bit chainwork, heaviest-chain reorganizations (evicting orphaned mainchain heights), SPV Merkle inclusion, and confirmation depth `>= min_confirmations`.
  - `get_checkpoint_feed_status(start_hour)` dynamically re-queries canonical mainchain membership against the live light-client tip so any subsequent Bitcoin reorganization that orphans the anchor block immediately flips `eligible_for_frost_dlc_feed` to `false`.
- **FROST / DLC Settlement Bridge (`bridge.rs`):**
  - `attest_frost_from_verified_checkpoint` requires `near_nova_verified == true`, `canonical_mainchain_verified == true`, `confirmations >= min_confirmations`, and `status == 1` (`HOLD` records are unconditionally rejected), then produces a verifiable `2-of-3` `FrostConfederation` BIP-340 digit attestation over `SHZ-INDEX03-BTCUSD-H<hour>-<root_prefix>`.
  - Individual bilateral DLC contract terms (`collateral_sats`, `strike_usd`, `payout_curve`, counterparty keys, Taproot trees, and adaptor points) remain **100% private and off-chain**. All authority flags remain `can_authorize_dlc_settlement: false` and `production_ready: false`.

---

## 6. Complete 18-Case Adversarial Soundness Matrix

All 18 required adversarial classes are exercised in `research/hourly_index_nova_03/prover/tests/adversarial_suite.rs` (`13/13` test groups passing) and `research/hourly_index_nova_03/sandbox.mjs`:

| # | Adversarial Case | Level Tested | Rejecting Constraint / Verification Check | Result |
|---:|---|---|---|---|
| 1 | Incorrect hourly midpoint (ceil on odd `p+c` or shifted midpoint) | R1CS (`TestConstraintSystem`, root recomputed) | `midpoint floor/bounded gated difference` (1-bit slack) | **REJECTED** |
| 2 | `1e-8` USD (one-sat-equivalent fixed-point) price mutation | R1CS (`v1` & `v2`, root recomputed) | `midpoint floor` (`v1`) & `valid p == cand_p` (`v2`) | **REJECTED** |
| 3 | Spread above 50-bps threshold (`50 bps` passes; `+1e-8` USD fails) | R1CS (root recomputed, both `p>c` & `c>p`) | `spread p-c` / `spread c-p` 80-bit slacks | **REJECTED** |
| 4 | Stale (`>300s`), future (`>cutoff`), or skewed (`>60s`) observation | R1CS (root recomputed) | `fresh source`, `nonfuture source`, `source skew` slacks | **REJECTED** |
| 5 | Wrong network `genesis`, `policy_hash`, or misaligned `start_hour` | R1CS & NEAR WASM `build_v1_claim_state` | `public header 0/1 low`, `eight hour alignment` | **REJECTED** |
| 6 | Missing, duplicated, or reordered hour | R1CS (root recomputed) & NIFS counter | `position equals fold count`, `consecutive UTC hour` | **REJECTED** |
| 7 | Substituted source-report digest | R1CS (`v1` zero-hash, `v2` non-zero swap) & `verify_hour_source_bundle` | `nonzero report` (`v1`), `valid ch_lo == cand_ch_lo` (`v2`) | **REJECTED** |
| 8 | Unauthorized Pyth/Chainlink signer, `< f+1` DON quorum, cherry-picking | Native & NEAR WASM (`ed25519_verify`, `ecrecover`) | Signer registry / DON set / `challenge_cherry_picked_chainlink` | **REJECTED** |
| 9 | Fabricated `HOLD` (`reason = 1, 2, 3` over valid sources, root recomputed) | R1CS (`SourceBoundHourStep` & `v1`) | `r1 requires missing source`, `r2 strict spread`, `r3 violation partition` | **REJECTED** |
| 10 | Altered Merkle sibling | R1CS | `checkpoint low` / `checkpoint high` | **REJECTED** |
| 11 | Different `checkpoint_root` | R1CS, CLI, & NEAR WASM (`begin_nova_verification`) | NIFS folded public IO -> `outer sumcheck` mismatch | **REJECTED** |
| 12 | Wrong Nova step count (`steps = 7` or mutated `z_k[0]`) | CLI & NEAR WASM (`begin_nova_verification`) | `proof.steps == 8` & `z_k[0] == k + 1` check | **REJECTED** |
| 13 | Substituted verification key (`vk_digest`, R1CS chunk, or MSM chunk) | CLI & NEAR WASM (`verify_r1cs_chunk`, `verify_msm_chunk`) | `verify_vk_merkle_branch_with` against pinned `vk_chunks_merkle_root` | **REJECTED** |
| 14 | Mutated, truncated, trailing-byte, or off-curve compressed proof | CLI & NEAR WASM (`begin_nova_verification`) | `WireRelaxedR1csSnark::decode_strict`, `bn_near64_to_affine`, sumchecks | **REJECTED** |
| 15 | Invalid intermediate verification state (premature finalize, chunk replay, corrupted acc) | Native session & NEAR WASM | `r1cs_bitmap`/`msm_bitmap`, chunk counters, final Spartan & IPA checks | **REJECTED** |
| 16 | Replayed proof | Native & NEAR WASM (`consumed_proof_nullifiers`) | `proof_sha256` nullifier set & `verified_checkpoints` map | **REJECTED** |
| 17 | Bitcoin tx substitution (64-byte stripped tx, wrong `SHZIDX01` root, bad SPV branch) | Native & NEAR WASM (`anchor_verified_checkpoint_to_bitcoin`) | `verify_shzidx01_transaction` & SPV `double_sha256` Merkle check | **REJECTED** |
| 18 | Bitcoin reorganization, `< 3` confirmations, or invalid PoW header | Native & NEAR WASM (`submit_btc_header`, `get_checkpoint_feed_status`) | `BtcLightClient` PoW/MTP/chainwork mainchain eviction | **REJECTED** |

---

## 7. Compute Policy, Versions, and Measured Telemetry

- **Compute & Threading Discipline:** CPU-only execution (`0` MiB VRAM; no unrelated local workloads displaced), max 1 prover job at a time (`RAYON_NUM_THREADS=4`, `CARGO_BUILD_JOBS=4`).
- **Pinned Repository & Dependency Versions:**
  - Base repository commit: `9274722ac8aed09170f12da66729115f1554bd27`
  - `nova-snark`: `0.76.0` (crates.io)
  - `halo2curves`: `0.9.0`
  - `ff`: `0.13.1`
  - `near-sdk`: `5.17.2`
  - `near-sandbox`: `0.3.5` / `near-api-js`: `7.5.3`
  - Lockfiles committed at `research/hourly_index_nova_03/prover/Cargo.lock` and `research/hourly_index_nova_03/near_contract/Cargo.lock`.

| Metric | Gate A (`INDEX-02` `Pallas/Vesta`) | Gate B (`INDEX-03` `Bn256EngineIPA` + NEAR WASM) |
|---|---:|---:|
| Constraints per fold (raw / padded) | `319,463` (+ `10,349` secondary) | `308,100` / `524,288` (`0` secondary) |
| Variables per fold (raw / padded) | `317,550` | `306,208` / `524,288` |
| Sparse R1CS non-zeros (`A + B + C`) | `~1,718,000` | `1,686,599` |
| Setup wall time (`4` CPU threads) | `23.815 s` | `21.136 s` |
| Recursive / NIFS + Spartan/IPA prove time | `63.340 s` (`5.19s` fold + `58.15s` compress) | `94.803 s` |
| Peak prover RSS RAM | `994,398,208 B` (`948.3 MiB`) | `1,137,610,752 B` (`1,084.9 MiB`) |
| Persisted proof size | `12,376 B` (`12.09 KiB`) | `10,003 B` (`9.77 KiB`) |
| Raw Verifier Key stream size | `110,771,368 B` (`105.64 MiB`) | `59,541,176 B` (`56.78 MiB` Merkle-chunked) |
| On-chain pinned VK / init state | N/A | `244 B` bincode (`1,782 B` total init state) |
| Independent CLI verify wall time | `31.270 s` (incl. VK regen) | `6.166 s` (incl. 4 negative controls) |
| NEAR WASM binary size | N/A | `598,063 B` (`584.05 KiB`) |
| NEAR sandbox transactions | N/A | `1,129` (`1` begin + `103` R1CS + `1,024` MSM + `1` finalize) |
| NEAR sandbox receipt gas (`begin`) | N/A | `151.526 TGas` |
| NEAR sandbox receipt gas (`103` R1CS chunks) | N/A | `16,637.105 TGas` (`161.525 TGas` mean, `211.616 TGas` max) |
| NEAR sandbox receipt gas (`1,024` MSM chunks) | N/A | `179,587.939 TGas` (`175.379 TGas` mean, `175.387 TGas` max) |
| NEAR sandbox receipt gas (`finalize`) | N/A | `4.585 TGas` |
| **Total NEAR Nova verification receipt gas** | N/A | **`196,381.154 TGas` (`43.34 s` sandbox wall time)** |
| Active session / finalized checkpoint storage | N/A | `5,291 B` (reclaimed) / `2,153 B` |

---

## 8. Reproduction Commands

```bash
# 1. Run all 18 adversarial R1CS, NIFS, Spartan/IPA, source-auth, Bitcoin-SPV & FROST tests
cargo test --release --locked --manifest-path research/hourly_index_nova_03/prover/Cargo.toml

# 2. Reconstruct Merkle VK chunks & independently verify the persisted 8-hour BN254 proof
cargo run --release --locked --manifest-path research/hourly_index_nova_03/prover/Cargo.toml --bin shz-index03-prover -- \
  export-vk-chunks /tmp/shz-idx03/vk_chunks.bin /tmp/shz-idx03/compact_vk.json /tmp/shz-idx03/route_profile.json

cargo run --release --locked --manifest-path research/hourly_index_nova_03/prover/Cargo.toml --bin shz-index03-prover -- \
  verify-bn254 research/hourly_index_nova_03/artifacts/proof.bin /tmp/shz-idx03/vk_chunks.bin research/hourly_index_nova_03/artifacts/claim.json

# 3. Build NEAR WASM contract and run full 1,129-tx near-sandbox verification & adversarial harness
(cd research/hourly_index_nova_03/near_contract && cargo build --release --locked --target wasm32-unknown-unknown)
cargo run --release --locked --manifest-path research/hourly_index_nova_03/prover/Cargo.toml --bin shz-index03-prover -- \
  export-sandbox-vectors /tmp/shz-idx03/sandbox_vectors.json research/hourly_index/fixtures/checkpoint.json
cp research/hourly_index_nova_03/artifacts/proof.bin research/hourly_index_nova_03/artifacts/claim.json /tmp/shz-idx03/
npm --prefix research/hourly_index_nova_03 install
SHZ_INDEX03_PROOF_DIR=/tmp/shz-idx03 SHZ_INDEX03_VECTORS=/tmp/shz-idx03/sandbox_vectors.json \
  npm --prefix research/hourly_index_nova_03 run sandbox
```
