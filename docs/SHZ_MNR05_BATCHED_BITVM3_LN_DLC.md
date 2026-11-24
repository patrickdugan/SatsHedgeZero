# SHZ-MNR-05: Batched BitVM3 Taproot Settlement, In-Circuit `Secq256k1` BIP-340 Authorization, Sparse Nullifiers, and PTLC Lightning Clearing

## 1. Executive Summary

`SHZ-MNR-05` delivers a setup-free, cryptographically verified multilateral settlement pipeline for Lightning-bridged Discreet Log Contracts (`LN-DLC`) on unmodified `Bitcoin Core v31.1.0` (`BIP-340/341/342`, zero covenant soft-forks, zero Groth16/KZG trusted setup ceremonies):

1. **Gate 1 — Unified `304`-Byte BitVM3 Batch Statement & Live `Bitcoin Core v31.1.0` Taproot `Assert` / `Disprove` / `Timeout` Tree:**
   - Binds the `SHZ-INDEX-03` 8-hour BTC/USD oracle checkpoint root (`SHZIDX01` `OP_RETURN` anchor), the exact `348`-byte stripped 3-input/5-output Bitcoin clearing `txid`, the 8-signature `Secq256k1` authorization accumulator root, and the Sparse Vault Nullifier Tree root into the canonical `304`-byte `UtxoRefL2SettlementStatementV0` (`UTXOREF_L2_SETTLEMENT_GROTH16_V0\0`) public limbs `[stmt_hi128_be, stmt_lo128_be]`.
   - Executes a 4-leaf BIP-341 NUMS `P2TR` `BitVm3AssertionTree` (`U_Assert`) on live `Bitcoin Core v31.1.0` regtest, confirming CSV-gated optimistic bond reclaim (`145 vB`), immediate anti-griefing boundary-fraud slashing (`181 vB`, `72 B` witness `<= 80 B` `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`), and dual-hash intermediate wire equivocation slashing (`189 vB`).
2. **Gate 2 — Constrained In-Circuit BIP-340 Schnorr Batch Authorization + Outpoint Nullifier State Machine:**
   - **Primary Authorization Proof (`shz/mnr05-secq256k1-bip340-batch-auth/v1`):** 8-step Nova + Spartan/IPA compressed SNARK over `Secq256k1Engine` / `Secp256k1Engine` (`144,959` primary R1CS constraints/step, `11,980 B` proof). Because `Secq256k1Engine::Scalar` equals `secp256k1`'s exact base field $\mathbb{F}_p$, full BIP-340 Schnorr verification ($s \cdot G - E_{\text{raw}} \cdot P = R$, even-$Y$ `lift_x` on $P$ and $R$, $0 < s < n$, and in-circuit `SHA256("BIP0340/challenge")`) executes natively in R1CS with **zero foreign-field limb emulation**.
   - **Unified Batch-Clearing Proof (`shz/mnr05-unified-bitvm3-batch-clearing/v1`):** 3-fold Nova + Spartan/IPA compressed SNARK over `Bn256EngineIPA` / `GrumpkinEngine` (`962,221` primary R1CS constraints/step, `12,784 B` proof) proving exact `348`-byte `SHA256d` `txid`, satoshi conservation across all 3 vault inputs and 5 P2TR outputs, `EMPTY -> CONSUMED` outpoint nullifier transitions read directly from the allocated transaction wire bits, `INDEX-03` `VALID` hourly oracle opening (`<= 50 bps` Pyth/Chainlink spread), and `304`-byte BitVM3 statement commitment.
3. **Gate 3 — Atomic PTLC Lightning <-> L1 Double-Offline Clearing (`Bob` AND `Alice` Both Offline at Maturity):**
   - Bridges a `2-of-3` `FrostConfederation` threshold attestation (`$60,000.00000000`) from `INDEX-03` with an off-chain Lightning PTLC atomic swap (`Alice <-> RouterLP` locked to $Y = y \cdot G$).
   - `Bob` disconnects after `t = 0` origination (`0x83` `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`). At `$60,000`, `Alice` claims **`71,498,500` sats** (`60,500,000` margin + **`11,000,000` realized winner PnL** `- 1,500` fee share) instantly off-chain over Lightning and **also disconnects** (`bob_sk` and `alice_sk` both out of scope). `RouterLP` extracts $y$ via `shz_dlc::adaptor_extract_secret_verified`, completes `Alice`'s L1 `0x01`/`0x00` adaptor signatures, completes `Bob`'s `0x83` adaptor signatures with the FROST scalar $t$, and confirms the 3-input, 5-output clearing transaction on `Bitcoin Core v31.1.0` (`6dc7c59c6e4473ae8b121e5cb9d1e562f7ebf6ec7b9c9d89920065a27aba2530`).

---

## 2. Formal Cryptographic Relations

### 2.1 `Secq256k1` Native-Field BIP-340 Schnorr Step (`Mnr05SecqBip340Step`)

Over `Secq256k1Engine` ($\mathbb{F}_{\text{scalar}} = \mathbb{F}_p$ of `secp256k1`, $p = 2^{256} - 2^{32} - 977$), state vector $z_i = (\text{step\_idx}, \text{acc}_{\text{lo128}}, \text{acc}_{\text{hi128}}) \in \mathbb{F}_p^3$ transitions across $i \in \{0, \dots, 7\}$:

1. **Canonical Field & Scalar Bounds:**
   - $0 \le P_x, P_y, R_x, R_y < p$ via exact 256-bit big-endian `(hi128, lo128)` slack decomposition.
   - $0 < s < n$ ($n = \text{0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141}$).
2. **Curve Membership & Even-$Y$ Parity (`BIP-340` `lift_x`):**
   - $P_y^2 \equiv P_x^3 + 7 \pmod p$, $\text{LSB}(P_y) = 0$.
   - $R_y^2 \equiv R_x^3 + 7 \pmod p$, $\text{LSB}(R_y) = 0$.
3. **In-Circuit `BIP0340/challenge` & Exception-Free Scalar Multiplication:**
   - $E_{\text{bits}} = \text{SHA256}(\text{SHA256}(\text{"BIP0340/challenge"}) \parallel \text{SHA256}(\text{"BIP0340/challenge"}) \parallel R_x \parallel P_x \parallel m)$.
   - Because $n$ is prime and $E(\mathbb{F}_p)$ has cofactor $1$, $n \cdot P = \mathcal{O}$, so $E_{\text{raw}} \cdot P = (E_{\text{raw}} \bmod n) \cdot P = e \cdot P$ identically without modular reduction mod $n$.
   - Starting from deterministic NUMS offset $A_0 = Q_0$, for bit $j = 0 \dots 255$:
     $$A_{j+1} = 2 A_j + s_j G - E_j P$$
     followed by unbiasing $F = A_{256} + (-2^{256} Q_0)$ and enforcing $F_x = R_x, F_y = R_y$.
4. **Domain-Separated Authorization Chain:**
   $$\text{acc}_{i+1} = \text{SHA256}(\text{"SHZ/MNR05/AUTH_ACC/V1"} \parallel \text{acc}_i \parallel i \parallel \text{sighash\_flag}_i \parallel P_x \parallel m \parallel R_x \parallel s)$$

### 2.2 Unified Batch-Clearing & Sparse Nullifier Step (`Mnr05UnifiedBatchStep`)

Over `Bn256EngineIPA` / `GrumpkinEngine`, arity-11 state $z_k$ folds across $k \in \{0, 1, 2\}$ (`U_AB`, `U_BC`, `U_CA`):

1. **Exact `348`-Byte Bitcoin Wire Format & Conservation:**
   - Allocates `2,784` boolean wires for `stripped_tx_348b`, enforces `version == 2`, `n_vin == 3`, empty `scriptSig`s, `n_vout == 5`, `vout[4] >= 330`, `miner_fee >= 300`, and $\sum_{i=0}^2 \text{in}_i = \sum_{j=0}^4 \text{vout}_j + \text{miner\_fee}$.
   - Computes `txid = Reverse32(SHA256(SHA256(stripped_tx_348b)))` and binds to public `z[5..7]`.
2. **Wire-Bound Vault Outpoint Nullifier Transition:**
   - Multiplexes `vin[k]`'s 36-byte outpoint directly from `tx_bits` (`bytes 5..41`, `46..82`, `87..123`).
   - Computes $\nu_k = \text{SHA256}(\text{"SHZ/MNR05/NULL/V1"} \parallel \text{outpoint}_k)$, verifies 3-level Merkle inclusion of `[0u8; 32]` (`EMPTY`) under `cur_nullifier_root` (`z[1..3]`), and transitions the exact same Merkle path to $\nu_k$ (`CONSUMED`) -> `next_nullifier_root`.
3. **Authenticated `INDEX-03` Oracle Opening:**
   - Enforces `VALID` status (`[1, 0]` — `HOLD` records cannot clear!), floor midpoint $p + c - 2 \cdot \text{idx} \in \{0, 1\}$, relative spread $\le 50\text{ bps}$ ($20050 c \ge 19950 p \land 20050 p \ge 19950 c$), and 3-level Merkle inclusion to `oracle_checkpoint_root` (`z[3..5]`).
4. **Canonical `304`-Byte `UtxoRefL2SettlementStatementV0` Binding:**
   - Binds `settlement_txid`, `verifying_key_hash = auth_accumulator_root`, `policy_hash = oracle_checkpoint_root`, and (on terminal fold $k = 2$) `commitment_hash = final_nullifier_root`, hashing all `304` bytes in-circuit to `[stmt_hi128_be, stmt_lo128_be]` (`z[9..11]`).

### 2.3 `BitVm3AssertionTree` Tapscript Leaves & Core 31.1 Standardness Policy

`U_Assert` uses the unspendable `UTXORef` NUMS internal key and 4 balanced BIP-342 `0xc0` leaves:

- **Leaf 0 (`optimistic_payout_leaf`):** `<csv> OP_CSV OP_DROP <P_Op> OP_CHECKSIG` (`145 vB` spend).
- **Leaf 1 (`disprove_boundary_leaf`):**
  `OP_SHA256 OP_DUP <op_boundary_commit32> OP_EQUALVERIFY <canonical_boundary_hash32> OP_EQUAL OP_NOT OP_VERIFY <P_Chal> OP_CHECKSIG` (`181 vB` spend).
  - **Empirical Core 31.1 Standardness Finding:** Bitcoin Core enforces `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80` bytes on initial Tapscript witness items (`policy/policy.h`); a `92 B` boundary preimage triggers `bad-witness-nonstandard`. Using the compact 8-byte tag `"SHZBND01"` yields a `72 B` (`8 + 32 + 32 <= 80 B`) witness item accepted by both standard mempool relay and block consensus.
- **Leaf 2 (`disprove_equivocation_leaf`):**
  `OP_SHA256 <h_wire_1> OP_EQUALVERIFY OP_SHA256 <h_wire_0> OP_EQUALVERIFY <P_Chal> OP_CHECKSIG` (`189 vB` spend, two `52 B <= 80 B` state-connector preimages).
- **Leaf 3 (`cooperative_close_leaf`):** `<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG`.

---

## 3. Measured Benchmarks & Cryptographic Receipts

Measured on WSL2 `Ubuntu-24.04` (`RAYON_NUM_THREADS=4`, `CARGO_BUILD_JOBS=4`, single sequential prover job, **`0 MiB` GPU VRAM** — `nova-snark =0.76.0` runs purely on CPU, leaving host GPU workloads untouched; live `0% -> 100%` stage & fold telemetry streamed via `rbzk-nova-progress-v1` to `rbzk-prover-ui`):

| Metric | `Secq256k1` 8-Sig BIP-340 Auth SNARK | `Bn256EngineIPA` 3-Fold Unified Batch SNARK |
|---|---:|---:|
| Relation ID | `shz/mnr05-secq256k1-bip340-batch-auth/v1` | `shz/mnr05-unified-bitvm3-batch-clearing/v1` |
| Curve Cycle | `Secq256k1Engine` / `Secp256k1Engine` | `Bn256EngineIPA` / `GrumpkinEngine` |
| Trusted Setup Ceremony | `false` (transparent IPA) | `false` (transparent IPA) |
| Recursive Folds | `8` (`3 + 3 + 2` Taproot sigs) | `3` (`U_AB`, `U_BC`, `U_CA`) |
| Primary R1CS Constraints | `144,959` | `962,221` |
| Secondary R1CS Constraints | `10,787` | `10,538` |
| Setup Time (`4` threads) | `6.41 s` | `23.22 s` |
| Recursive Folding Time | `3.34 s` | `3.16 s` |
| Spartan/IPA Compression | `32.57 s` | `123.33 s` |
| In-Memory Verify Time | `0.63 s` | `4.60 s` |
| Persisted Proof Size | `11,980 B` (`11.70 KiB`) | `12,784 B` (`12.48 KiB`) |
| Pinned VK SHA-256 | `da8001750089b51e77c778b0f65c2de30a6f711ff482431c0cf0a32c966cb126` | `3d35e9d007cb300a0977248aa4b04a283aae4ef0ce4cc7a66aba6a05104ad9d6` |
| Persisted Proof SHA-256 | `0e71f5584d13c21790c2d04f59060f083bb52f5ba72bc117d4c22075706b678b` | `2fe9382559b439006c2bc4054d185cd0292b19a03664331cae39b535f103950e` |
| Peak Process RSS | `2.47 GiB` (`2,594,004 KiB` combined run) | `2.47 GiB` (`0 MiB` VRAM) |

### Live `Bitcoin Core v31.1.0` Regtest Consensus Transactions

| Transaction Role | Confirmed TXID | Size | Notes |
|---|---|---:|---|
| `SHZIDX01` Oracle Anchor | `e417069ac992f14a37dc0d2697a93e8cc073ec7046e42e1c0fbdc29cc853a952` | `OP_RETURN` `40 B` | `ckpt = 412a3b80...5aca051d` |
| Double-Offline PTLC Clearing | `6dc7c59c6e4473ae8b121e5cb9d1e562f7ebf6ec7b9c9d89920065a27aba2530` | `599 vB` (`348 B` base) | **Both `Bob` & `Alice` offline!** |
| CPFP Anchor Child (`vout[4]`) | `0d0eacd52e9e00400570ef8aaad60715980905cb6a14ef29d848f0bf1ff4610d` | `153 vB` | Spends `330`-sat `P2TR` anchor |
| Honest BitVM3 `U_Assert` | `b1cfc3f93d8074cb992bd8ffd7825e4457ef84dddb2ee57e6c0cdd79f062dc2f` | `1,000,000` sats | Unslashable by Challenger |
| BitVM3 Optimistic Reclaim | `43f4686456e7cc91a7c788c298e66e52590fb25956e5a1023f55e2a6ff1ebbd7` | `145 vB` | Confirmed after `CSV = 10` |
| BitVM3 Boundary Fraud Slash | `fc4d90d270cf307350d9c82be86b8db7c6740b2ca4d36b90c02866f2f1dc7ff7` | `181 vB` | Immediate Leaf 1 slash |
| BitVM3 Equivocation Slash | `a4db7cc2a7fe57bb7d8ea0c3b40bc549bd600bc0e68873c704931a5ef4c4a611` | `189 vB` | Immediate Leaf 2 slash |
| Unilateral CLTV Fallback (`AB`/`BC`) | `74821f30...26218cdd` / `d4e4705c...619843fb` | `1-in/3-out` | Confirmed at `height = 170` |

---

## 4. Capability Flags & Explicit Security Boundaries

```json
{
  "trusted_setup_ceremony": false,
  "bitvm3_tapscript_disprove_regtest_verified": true,
  "full_groth16_garbled_circuit_l1_verified": false,
  "nova_secq256k1_bip340_auth_verified": true,
  "nova_unified_batch_nullifier_verified": true,
  "ptlc_atomic_ln_double_offline_verified": true,
  "production_ready": false
}
```

### What Is Newly Proven Here vs. Remaining Pre-Mainnet Work
- **Proven in `SHZ-MNR-05`:**
  1. Native-field `Secq256k1` R1CS verification of all 8 BIP-340 Taproot signatures (`0x83`, `0x01`, `0x00`) with zero foreign-field emulation and zero trusted setup.
  2. Wire-bound Sparse Vault Nullifier non-membership -> consumption inside the 3-fold `Bn256EngineIPA` circuit, preventing double-settlement or skipped vaults.
  3. Atomic off-chain Lightning PTLC <-> L1 clearing enabling **both `Bob` and `Alice`** to be completely offline when L1 settlement executes at maturity, while preserving unilateral `CLTV` recovery if `RouterLP` withholds payment.
  4. Real `Bitcoin Core v31.1.0` Taproot `BitVm3AssertionTree` execution for CSV optimistic bond reclaim, boundary-commitment mismatch slashing, and dual-hash intermediate wire equivocation slashing.
- **Remaining Before Mainnet (`production_ready: false`):**
  1. `BitVm3AssertionTree` enforces on-chain boundary mismatch and state-connector wire equivocation slashing (`bitvm3_tapscript_disprove_regtest_verified: true`), whereas full L1 garbled-circuit gate evaluation of an arbitrary SNARK verifier (`full_groth16_garbled_circuit_l1_verified: false`, tracked separately in `zk-rusto-no-bitcoino` `M13/M14`) is not yet embedded inside `U_Assert` Tapleaves.
  2. `Mnr05UnifiedBatchStep` binds `auth_accumulator_root` (`z[7..9]`) and `stripped_tx_348b` (`z[5..7]`) across the two setup-free proofs via the public `304`-byte statement; full in-circuit `TapSighash` reconstruction from `stripped_tx_348b` inside `Secq256k1` (removing external verifier cross-check of the 8 sighash digests against `stripped_tx_348b`) is a straightforward next hardening step.
  3. Live Lightning node (`LDK`/`CLN` custom PTLC TLV wire messages) integration and external cryptographic audit.
