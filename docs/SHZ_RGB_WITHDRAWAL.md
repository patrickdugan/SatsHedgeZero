# SHZ-RGB-01E/F & SHZ-RGB-02: Durable BTC Withdrawal Reservations and Native RGB Lightning Settlement

## 1. Overview and Scope

This document specifies the native durable BTC withdrawal reservation mechanism implemented in `crates/shz-dex` (`SHZ-RGB-01E`), the canonical Rust-to-JavaScript signed receipt boundary connecting `DurableTieredRouter` to the UTEXO RGB sidecar (`integrations/utexo-rgb/`), the CI failure audit against `main`, and the source-level and experimental analysis of RLN native atomic BTC/RGB Lightning swaps (`SHZ-RGB-02`).

Production invariant boundaries preserved without change:

- Existing `shz-margin` inverse contract economics (`VanillaBtc` v0 funding, `ZeroFeePolicy::ZERO`, dyadic CET compression) are untouched.
- Existing `LnDlcSubchannel` unilateral DLC recovery and `SHZWAL06` `TIERED_ACK_TAG` / `V2` / `V3` signed channel acknowledgement formats are unchanged.
- Existing `SHZWAL06` WAL journals without withdrawal events replay with byte-identical `config_hash` and `JournalTip` digests.
- UTEXO WDK mainnet Lightning disablement (`mainnet-lightning-rejection-v1`) is preserved and never bypassed.

---

## 2. Mathematical Derivation of the Revised Conservation Invariant (SHZ-RGB-01E)

### 2.1 Account Balance Partition

Prior to `SHZ-RGB-01E`, each account lane $a$ in `shz-dex` held an immutable allocation share $\text{cap}_a \in \mathbb{N}$ and signed realized PnL $\text{realized\_pnl}_a \in \mathbb{Z}$, partitioned across five buckets:

$$\text{free}_a + \text{resting}_a + \text{pending}_a + \text{committed}_a + \text{paid\_fees}_a = \text{cap}_a + \text{realized\_pnl}_a$$

To support durable, non-overspendable BTC withdrawals without mutating settled clearing history or realized PnL, we introduce two disjoint unsigned buckets on `Balance`:

- $\text{withdrawal\_reserved}_a \in \mathbb{N}$: satoshis atomically moved out of $\text{free}_a$ into active, submitted, ambiguous, or pre-reconcile frozen withdrawal reservations. Because order placement (`TieredRouter::post`, `TieredRouter::take`) and concurrent withdrawal reservations read only $\text{free}_a$, satoshis in $\text{withdrawal\_reserved}_a$ are structurally excluded from order margin allocation and concurrent withdrawal spending.
- $\text{withdrawn}_a \in \mathbb{N}$: satoshis finalized out of the venue after independent reconciliation (`Reconciled`, and retained if subsequently flagged `Frozen { was_reconciled: true }` upon a chain conflict/reorg alert).

**Revised Account Conservation Invariant:**

$$S(b_a) \triangleq \text{free}_a + \text{resting}_a + \text{pending}_a + \text{committed}_a + \text{paid\_fees}_a + \text{withdrawal\_reserved}_a + \text{withdrawn}_a = \text{cap}_a + \text{realized\_pnl}_a$$

Let $W_a$ be the set of all durable `WithdrawalRecord` entries for lane $a$. Define the **Withdrawal Partition Invariants**:

$$\text{withdrawal\_reserved}_a = \sum_{\substack{w \in W_a \\ w.\text{state} \in \{\text{Reserved},\, \text{Submitted},\, \text{Ambiguous},\, \text{Frozen}(\text{false})\}}} w.\text{amount\_sats}$$

$$\text{withdrawn}_a = \sum_{\substack{w \in W_a \\ w.\text{state} \in \{\text{Reconciled},\, \text{Frozen}(\text{true})\}}} w.\text{amount\_sats}$$

Remaining on-venue equity is $E^{\text{venue}}_a = (\text{cap}_a + \text{realized\_pnl}_a) - \text{withdrawn}_a$.

### 2.2 State Progression and Transition Proofs

```text
Free -> Reserved -> Submitted -> Reconciled
                        |            |
                        v            v
                    Ambiguous -> Reconciled
                        |            |
                        v            v
                  Frozen(false)  Frozen(true)
```

Plus independent-evidence cancellation:

- `Reserved -> Cancelled`: requires `monitor` + (`owner`, OR `peer` when `now >= expires_us`) BIP340 signatures over unique non-zero `cancellation_evidence`.
- `Submitted | Ambiguous -> Cancelled`: requires BOTH independent `peer` AND `monitor` BIP340 signatures over unique non-zero `cancellation_evidence` establishing irrevocable non-dispatch. Clock advancement or owner signature alone can never release a `Submitted` or `Ambiguous` reservation.

Let $v = w.\text{amount\_sats} > 0$:

| Transition | Precondition | $\Delta \text{free}$ | $\Delta \text{withdrawal\_reserved}$ | $\Delta \text{withdrawn}$ | $\Delta S(b_a)$ |
| --- | --- | --- | --- | --- | --- |
| `Reserve` (`Free -> Reserved`) | $\text{free}_a \ge v$, valid owner BIP340 sig, $\text{nonce} > \text{last\_nonce}_a$, $\text{now} < \text{expires\_us}$, valid native SegWit script, committed clearing batch if $\text{clearing\_sequence} > 0$ | $-v$ | $+v$ | $0$ | $0$ |
| `Submit` (`Reserved -> Submitted`) | $\text{state} = \text{Reserved}$, $\text{now} < \text{expires\_us}$, unique non-zero `payment_hash` | $0$ | $0$ | $0$ | $0$ |
| `MarkAmbiguous` (`Submitted -> Ambiguous`) | $\text{state} = \text{Submitted}$ | $0$ | $0$ | $0$ | $0$ |
| `Reconcile` (`Submitted \| Ambiguous -> Reconciled`) | `peer` + `monitor` BIP340 sigs over unique non-zero `btc_evidence` $\ne$ `settlement_evidence` (disjoint from fee receipts) | $0$ | $-v$ | $+v$ | $0$ |
| `Freeze` (`Submitted \| Ambiguous -> Frozen(false)`) | `monitor` BIP340 sig over unique non-zero `conflict_evidence` | $0$ | $0$ | $0$ | $0$ |
| `Freeze` (`Reconciled -> Frozen(true)`) | `monitor` BIP340 sig over unique non-zero `conflict_evidence` | $0$ | $0$ | $0$ | $0$ |
| `Cancel` (`Reserved \| Submitted \| Ambiguous -> Cancelled`) | Independent `cancellation_evidence` + required BIP340 quorum; nonce stays permanently consumed | $+v$ | $-v$ | $0$ | $0$ |

**Safety Properties Established:**

1. **Exact Conservation**: Every transition has $\Delta S(b_a) = 0$ and preserves both partition sums.
2. **No Concurrent Overspending**: Since $\text{free}_a$ is decremented atomically inside the single-writer WAL transaction before any receipt is exported, concurrent orders and subsequent withdrawal reservations see only $\text{free}_a - v$.
3. **Monotone Finalized Debits**: $\text{withdrawn}_a$ never decreases on any transition, including post-reconcile `Freeze` (a reorg alert freezes for investigation rather than silently crediting `free`).
4. **No Nonce Reuse / Replay**: `last_nonce[lane]` strictly increases on `Reserve` and is never decremented on `Cancel`, `Freeze`, or `Reconcile`.
5. **No Duplicate Funding**: `used_payment_hashes` and `used_evidence` (plus `fee_receipts` cross-check) prevent any payment hash or BTC/RGB proof digest from funding more than one withdrawal.
6. **Clearing Independence**: `ClearingState::open` and `BatchClearing` depend on `realized_pnl` and open `Position` lots, neither of which is mutated by withdrawals.

### 2.3 Exhaustive Small-State Model Verification

`crates/shz-dex/tests/shz_rgb01e_withdrawals.rs` includes `exhaustive_small_state_withdrawal_conservation_and_safety`, which performs a complete BFS to fixpoint over two concurrent withdrawal slots plus an interleaved order hold (`cap = 5, amt = 2`), verifying exact conservation, partition invariants, monotone `withdrawn`, terminal-state finality, and non-overspend across every reachable state (91 distinct reachable states explored exhaustively to fixpoint).

---

## 3. Canonical Cross-Language Serialization and Receipt Boundary

### 3.1 Owner Authorization Digest (`SHZ/HFT06/WITHDRAWAL-REQ/V1`)

`withdrawal_id = tagged_hash("SHZ/HFT06/WITHDRAWAL-REQ/V1", preimage)` where `preimage` is the little-endian binary concatenation:

1. `network` (32 bytes; canonical `tagged_hash("SHZ/NETWORK/V1", utf8(network_name))`)
2. `router_config` (32 bytes; `DurableTieredRouter::config_hash()`)
3. `router` (`u32` LE)
4. `channel.txid` (32 bytes) || `channel.vout` (`u32` LE)
5. `owner` (32-byte x-only BIP340 pubkey)
6. `nonce` (`u64` LE, strictly monotone, `> 0`)
7. `amount_sats` (`u64` LE, `> 0`)
8. `destination_script.len()` (`u32` LE) || `destination_script` (native SegWit only: P2WPKH `0014<20B>`, P2WSH `0020<32B>`, or P2TR `5120<32B>`)
9. `expires_us` (`u64` LE)
10. `clearing_sequence` (`u64` LE)
11. `batch_digest` (32 bytes)
12. `clearing_digest` (32 bytes)

The owner signs `withdrawal_id` using BIP340 Schnorr (`owner_sig`).

### 3.2 Exported Withdrawal Receipt (`SHZ/WITHDRAWAL-RECEIPT/V1`)

`DurableTieredRouter::export_withdrawal_receipt` signs `receipt_digest = tagged_hash("SHZ/HFT06/WITHDRAWAL-RECEIPT/V1", receipt_preimage)` with the pinned router/monitor receipt key (`router_sig`), where `receipt_preimage` is:

- `len(network_name)` (`u32` LE) || `utf8(network_name)`
- `withdrawal_id` (32 bytes)
- `reserved_at_us` (`u64` LE)
- `journal_tip.records` (`u64` LE) || `journal_tip.digest` (32 bytes)
- `len(state)` (`u32` LE) || `utf8(state)`
- `router_signer` (32-byte x-only BIP340 pubkey)

Canonical JSON serialization sorts all object keys lexicographically with no insignificant whitespace and encodes all `u64` fields as base-10 decimal strings to avoid IEEE-754 precision loss across JavaScript's `Number.MAX_SAFE_INTEGER`.

Cross-language golden vectors generated by Rust (`cargo run -p shz-dex --example shz_withdrawal_vectors`) are checked in at [withdrawal-vectors.json](../integrations/utexo-rgb/withdrawal-vectors.json) and verified byte-for-byte by both Rust (`shz_rgb01e_withdrawals.rs`) and zero-dependency pure-JS BigInt BIP340 verification (`integrations/utexo-rgb/withdrawal-receipt.mjs`, tested in `withdrawal-bridge.test.mjs`).

### 3.3 Sidecar Enforcement (`integrations/utexo-rgb/`)

- **`withdrawal-receipt.mjs`**: Pure-JS BIP340 verifier, canonical receipt verifier (`verifyWithdrawalReceipt`), conversion quote verifier (`verifyConversionQuote`) binding `SHZ/RGB/CONVERSION-QUOTE/V1` (exact quote arithmetic via `quoteConversion`, RGB contract ID + precision allowlist, pinned provider Ed25519 signature, fresh oracle snapshot, fee ceiling, destination payee + BTC scriptPubKey, payment hash, expiry $\le$ receipt expiry).
- **`shz-candidate.mjs`**: Stamps `receiptEligible: false` on explorer observations; `verifyDurableWithdrawalReceipt` explicitly refuses explorer candidates and simulated channel acknowledgements.
- **`journal.mjs`**: Supports receipt-bound `SHZ/RGB/JOURNAL/V2` headers pinning `(network, routerConfig, routerSigner)`, re-verifies `WithdrawalReceiptV1` + `ConversionQuoteV1` on every append and reopen/replay, tracks consumed `receiptDigest` and `txid:vout:nonce` lane keys to block duplicate receipt consumption, and exposes `createReserveAuthorizer`.
- **`checkpoint.mjs`**: Propagates `receiptPolicy` through `createCoordinator` / `openCoordinator` for atomic journal + CAS tip verification.
- **`evidence.mjs` & `native-peer.mjs`**: Provide `verifyReceiptBackedBinding` and `observeReceiptBackedNativeRgb` binding independent Core BTC funding and dual-peer RGB Lightning observations directly to the verified Rust withdrawal receipt and signed conversion quote.

---

## 4. CI Failure Investigation (Section 5)

| Workflow | Branch / Commit | Run ID | Failing Step | Root Cause | Status on Current `main` (`d63596e`) |
| --- | --- | --- | --- | --- | --- |
| `shz-rust-and-core-regtest` | `research/shz-rgb-01-utexo-sdk` (`30e3f31`, merged from `9d5ac54`) | `45854935809` | `Run strict clippy check` | `clippy::needless_range_loop` in `crates/shz-margin/src/payoff.rs:192` (`for i in 0..n`) on Rust 1.99. | **Fixed on `main` by `d63596e`** (CI run `45857573374` **PASSED**). Resolved on this branch by merging `origin/main`. |
| `shz-mnr05-bitvm3-ln-dlc` | `research/shz-rgb-01-utexo-sdk` (`30e3f31`) and `main` (`d63596e`) | `45854935928` (branch), `45857573576` (`main`) | `Strict clippy check on MNR-05 crate` | Standalone workspace `research/mnr05_bitvm3_ln_dlc/Cargo.lock` is out of sync with path dependencies (`crates/shz-dex`, `crates/shz-oracle`, etc.) modified on `main`. `cargo clippy --manifest-path research/mnr05_bitvm3_ln_dlc/Cargo.toml --all-targets --locked -- -D warnings` fails immediately with `error: cannot update the lock file ... because --locked was passed to prevent this`. | **Reproduces identically on current `main` (`d63596e`)**. Unrelated to SHZ-RGB; intentionally NOT mixed into SHZ-RGB commits. Fix requires regenerating `research/mnr05_bitvm3_ln_dlc/Cargo.lock` in a separate PR. |

---

## 5. Research Extension: RLN Native Atomic BTC/RGB Swaps (`SHZ-RGB-02`)

### 5.1 Source-Level Evaluation (`rgb-lightning-node` @ `ecc69f20308231400561f6f060fea88acfa40cc4`)

The pinned Node binding (`@utexo/rgb-lightning-node-nodejs@0.2.0-beta.5`) exposes five swap primitives omitted from the WDK facade: `makerInit`, `makerExecute`, `taker`, `listSwaps`, and `getSwap`. Inspection of `src/routes.rs` (lines 1074–1105, 2950–3005, 4141–4440, 5657–5690) and `src/ldk.rs` (lines 520–599, 1439–1482, 2991–3059, 3603–3779) establishes the exact protocol:

1. **Circular Self-Payment Loop (`Maker -> ... -> Taker -> ... -> Maker`)**:
   - `makerInit(qty_from, from_asset, qty_to, to_asset, timeout_sec)` creates a single Lightning `(payment_hash, payment_secret)` via `channel_manager.create_inbound_payment`, verifies local maker RGB balance (`qty_to <= max_local_rgb_amount`), persists `SwapData` in `maker_swaps`, and returns `swapstring`.
   - `taker(swapstring)` validates `now <= expiry`, checks outbound RGB balance if `from_asset` is RGB, and persists the whitelisted swap in KV store (`taker_swaps`, `SwapStatus::Waiting`).
   - `makerExecute(swapstring, payment_secret, taker_pubkey)` computes two LDK routes:
     - **Leg 1 (`Maker -> Taker`)**: carries `htlc_min_msat` (3,000,000 msat carrier) + `(to_asset, qty_to)` RGB units.
     - **Leg 2 (`Taker -> Maker`)**: sets `IS_SWAP_SCID` on hop 0 and carries `qty_from + htlc_min_msat` BTC msat.
   - Maker dispatches a single `send_spontaneous_payment_with_route` carrying `payment_preimage`.
2. **Exact Amount Conservation & Carrier Cancellation**:
   - On a direct channel (zero forwarding fee), Maker sends `htlc_min_msat` + `qty_to` RGB on Leg 1 and receives `qty_from + htlc_min_msat` BTC on Leg 2. The 3,000-sat carrier cancels identically:
     $$\Delta \text{BTC}_{\text{taker}} = -\text{qty\_from}, \quad \Delta \text{RGB}_{\text{taker}} = +\text{qty\_to}$$
     $$\Delta \text{BTC}_{\text{maker}} = +\text{qty\_from}, \quad \Delta \text{RGB}_{\text{maker}} = -\text{qty\_to}$$
   - Multi-hop routing fees are bounded by `max_swap_fee_msat` and deducted from Maker's circular route budget.
3. **Atomicity Conditions (Settle-Both or Unwind-Both)**:
   - **Preimage sharing**: Both legs share a single `payment_hash` / `payment_preimage`. Maker cannot claim Leg 2 (BTC from Taker) without revealing `payment_preimage`, which enables Taker to claim Leg 1 (RGB from Maker).
   - **Intercept enforcement**: When Leg 1 arrives at Taker, LDK fires `Event::HTLCIntercepted`. Taker forwards Leg 2 only if `(payment_hash, from_asset, qty_from, to_asset, qty_to, expiry)` matches its persisted `taker_swaps` entry. Any mismatch, missing whitelist, or expiry causes Taker to fail the HTLC backwards so both legs unwind with zero partial execution.
   - **Necessary CLTV & Unilateral Condition**: Let $\Delta_{\text{CLTV}} = \text{cltv}_{\text{leg1}} - \text{cltv}_{\text{leg2}} > 0$. Atomic settlement holds unconditionally iff:
     1. $\Delta_{\text{CLTV}}$ exceeds Taker's worst-case on-chain confirmation horizon so Taker can claim Leg 1 on-chain if Maker disappears after revealing `payment_preimage` on Leg 2; AND
     2. Taker's signer can broadcast and sweep an RGB force-close commitment + HTLC-timeout/success transaction on L1.
   - **Critical Strict-Signer Caveat (`S01`)**: Under the pinned `0.2.0-beta.5` strict external signer (`permissiveSignerPolicy: false`), upstream gate `S01` leaves RGB force-close commitment acceptance and mature BTC sweep **unqualified**. Therefore, while cooperative execution and abort-unwind are atomic off-chain, **unilateral adversarial recovery during an in-flight swap remains blocked by upstream `S01`**, disqualifying `SHZ-RGB-02` from production mainnet deployment until `S01` closes.

### 5.2 Comparison: Native RLN Atomic Swap vs. Two-Leg Conversion Provider

| Property | Two-Leg Conversion Provider (`SHZ-RGB-01`) | Native RLN Atomic Swap (`SHZ-RGB-02`) |
| --- | --- | --- |
| WDK Facade Exposure | Exposed (`sendPayment`, `createLightningInvoice`) | **Not exposed** in WDK; requires direct `SdkNode` binding |
| Settlement Atomicity | **Non-atomic** (separate BTC funding leg + RGB LN leg; requires independent observers, conflict freeze, and explicit compensation) | **Cryptographically linked** via single HTLC preimage across circular route |
| Carrier BTC Overhead | Taker/payer permanently transfers `>= 3,000` sats carrier per RGB payment | **Cancels to 0 net carrier** on direct channel (`+htlc_min_msat` and `-htlc_min_msat`) |
| Channel Liquidity Requirement | Payer needs RGB channel outbound; BTC leg can settle on-chain or separate LN channel | Requires bidirectional liquidity on shared RGB channel (or multi-hop route with Maker outbound RGB and Taker outbound BTC $\ge \text{qty\_from} + 3{,}000\text{ sat}$) |
| Unilateral Recovery under Strict Signer | On-chain BTC funding leg independently verifiable on Core; RGB leg still bound by `S01` / `P03` | Unilateral HTLC claim if Maker stalls after revealing preimage directly depends on `S01` RGB force-close |
| Qualification Gate | `SHZ_DISPOSABLE_REGTEST=YES` | Separately gated (`SHZ_RGB02_EXPERIMENT=YES` + `SHZ_DISPOSABLE_REGTEST=YES`); mainnet disabled |
