# ZKL-29: settlement circuit audit (properties P1-P9)

Research only. No production code changed, nothing committed, no Rust built, no Nova proof run.

Pinned sources: `SatsHedgeZero` main `62003a6003c9263d135b56d5cc86c1e38b9b2223`. File:line references in this
document are line numbers of the blobs at that SHA. Short names: `clearing.rs` = `crates/shz-dex/src/routing/clearing.rs`;
`bitvm3.rs` = `crates/shz-nova-bitvm/src/bitvm3.rs`; `unified` = `research/mnr05_bitvm3_ln_dlc/src/unified_batch_circuit.rs`;
`step` = `research/lightninger_bitvm3_clearing/src/clearing_step.rs`; `tap` = `.../tapsighash_step.rs`; `gad` = `.../gadgets.rs`;
`fold` = `.../fold.rs`; `cet` = `.../cet.rs`; `rel` = `research/lightninger_dlc_batcher/relation/src/lib.rs`;
`batcher` = `research/lightninger_dlc_batcher/src/lib.rs`.

Artifacts of this task:

- Lean: `MathCan/ZKLeanSettlement.lean` (imports only `MathCan.ZKLean`; 61 theorems, every one followed by `#print axioms`; the final
  build reports only `propext` and `Quot.sound`; no `sorry`, no `native_decide`, no `Classical.choice`).
- Tests: `research/zk_lean/test_settlement_adversarial.py` (27 tests, stdlib `unittest`, all pass).
- Existing specs reused: `research/zk_lean/clearing_spec.py` (`clear`, `prorata`) and `MathCan/ZKLean.lean`
  (`collectLoss`, `allocateDefault`, `ledgerIdentity`, `Trace`, `BoundTrace`, `no_wrap_eq`).

Two circuit families are in scope. The **replacement** (`step`, `tap`, `rel`) is the circuit the DLC batcher uses. The **unified**
circuit (`unified`, `bitvm3.rs`) is the earlier 3-fold nullifier/oracle/transaction circuit. A status is stated for the replacement;
where the unified circuit differs it has its own sentence.

Scope limits. `m17_nova_script@f80c364` (the script-execution fold named at `rel`:528), `Mnr05SecqBip340Step`
(`shz_mnr05_bitvm3_ln_dlc::secq_schnorr_circuit`), `positions::settle`, the SP1 wrap guest and the venue router are not in the
read set. Statements about them are marked as outside the audit.

## 1. Property table

Status: ENFORCED = the circuit or checked relation fixes the property and no gap in the read set is known; PARTIAL = part is fixed,
the stated remainder is not; MISSING = nothing in the read set fixes it. "Enforced" always means at the constraint level; the
R1CS-to-spec refinement proof is a separate obligation (section 4) and is open for every row.

| P | Property | Status (replacement) | Status (unified) |
|---|---|---|---|
| P1 | cash / claims / fund / carry conservation | ENFORCED (`carry_in` of `rel` open) | MISSING |
| P2 | exact haircut priority, pro-rata remainder | ENFORCED | MISSING |
| P3 | authenticated per-account claim state | PARTIAL | MISSING |
| P4 | batch digest and signed authorization binding | PARTIAL (digest ENFORCED; ack signatures MISSING) | MISSING |
| P5 | Taproot key, tapleaf, tx input binding | PARTIAL (key path ENFORCED, script path PARTIAL) | PARTIAL |
| P6 | nullifier uniqueness, replay resistance | MISSING in-proof (L1 spend only) | PARTIAL |
| P7 | oracle root authentication | MISSING | PARTIAL |
| P8 | canonical integer encoding, field-wrap exclusion | ENFORCED | ENFORCED |
| P9 | exact initial state, terminal state, fold count | PARTIAL (count and terminal ENFORCED, initial state PARTIAL) | PARTIAL |

### P1 cash / claims / insurance fund / carry conservation

- Independent spec: `ledgerIdentity`, `ledger_identity_delta`, `net_conservation`, `cash_floor` (`ZKLean.lean`:201-214, 304-314);
  `stepApply`, `batch_delta`, `batch_preserves_identity`, `clearStep_identity`, `batch_net_zero`, `batch_cash_floor`,
  `bound_trace_identity` (`ZKLeanSettlement.lean`). The identity `cash - claims - fund + carry = book` is preserved by every batch because
  `delta(cash - claims - fund + carry) = losses - gains = -sum(pnl) = delta(book)`; the Lean theorem takes the row sums as aggregates.
- Rust reference: `clearing.rs`:223 (cash += collected), 225-227 (fund), 252 (carry), 263-269 (payments, cash -= paid), 272-273
  (net-zero and cash-floor guards); identity text 25-33 and `Summary::identity` 92-96.
- Circuit: `step`:291-293 (`identity_in`), 391-392 (`cash1 = cash0 + collected_total`, i64 range), 452-458 (`cash_after`, i64 range,
  floor `cash_after >= min(cash0, 0)`), 620-623 (`identity_out` with `book1 = book0 - sum(pnl)`), 632-639 (outputs bound to the
  constrained values).
- Status: ENFORCED for the clearing step. Open in `rel`: `Account.carry_in` (`rel`:146) enters the payout `collateral + carry_in + net`
  (`rel`:401) and the manifest hash (204-216) but no check ties it to the unsettled nets of an earlier epoch; the settlement
  signatures of the traders are the only guard. In `unified` no clearing arithmetic exists: output amounts are bound only by
  `sum(inputs) == sum(outputs) + fee` (`unified`:579-584) and the three input amounts and the fee are free witnesses
  (`unified`:557-578, not in `z`), so the equation holds for any outputs (finding N1).
- Missing proof obligations: (a) the per-row to aggregate summation behind `BatchAgg` (rows' `claim_after = due - paid`, non-batch
  haircuts) is not formalized; (b) R1CS refinement of `cash1`, `identity_in/out`; (c) the `legacy` and negative-cash start
  (`clearing.rs`:77-86) is covered by the i64 cash range only.
- Adversarial test: `ModelGroundTruth.test_random_walk_preserves_identity_and_net_zero`, `AttackC2Claims.test_c2_dropped_claim_breaks_identity`.

### P2 exact haircut priority and pro-rata remainder

- Independent spec: `prorata`, `dist`, `floors`; `prorata_sum` (shares sum to the total when `total <= sum`), `prorata_caps`
  (floor <= share <= amount), `prorata_priority` (a prefix is filled to its amount, at most one item partial, the rest keep their floors);
  waterfall: `collectLoss_priority` (`ZKLean.lean`:173), `collectLoss_order`, `allocateDefault_conserves`,
  `allocateDefault_haircut_after_fund`, `allocateDefault_carry_after_haircut`, `allocateDefault_invariant`.
  The remainder rule is `x = rest.min(a - o); o += x; rest -= x` in item order.
- Rust reference: `clearing.rs`:187-194 (`prorata`), 211-222 (margin, own claim, shortfall), 225-227 (fund), 231-255 (owed,
  haircut over claims in key order then gains in batch order, carry), 258-268 (`paid = prorata(available, dues)`).
- Circuit: `step`:341-347 (collected, own, shortfall via `min_claimed`), 395-398 (fund), 400-412 (haircut = `min(owed, base)`, `prorata`,
  carry), 414-458 (dues, `tpay = min(due, available)`, `prorata`); `gad`:186-214 (`le`, `select`, `min_claimed`), 220-260 (`prorata`:
  `q` 64-bit, `r` 72-bit, `r < s'`, `total*a = q*s' + r`, in-order remainder with `le` and `select`); layer 514-536.
- Status: ENFORCED. The gadget does not constrain `total <= sum(amounts)` or that the final remainder is zero; both callers feed
  `total = min(x, sum(amounts))` (`step`:407, 437), and `prorata_sum` shows the final remainder is zero under that precondition.
- Missing proof obligations: R1CS refinement of `min_claimed` (needs `|b - a| < 2^66`, supplied by the 64-bit ranges), of the `q, r`
  division relation (unique quotient: `divSpec_unique`, `ZKLean.lean`:133, applies; the 72-bit `r` and the `sp = 1` branch for a zero sum
  are not yet matched to it), and of the in-order remainder loop to `dist`.
- Adversarial test: `AttackC3Waterfall` (3 tests: loss skips margin into fund, haircut shifted between winners, remainder order),
  `ModelGroundTruth.test_prorata_exact_and_capped`.

### P3 authenticated per-account claim state

- Independent spec: `ZState`, `zenc_inj`, `commitment_binds_claims` (equal commitments under no collision give equal per-slot claims,
  keys and header).
- Rust reference: `clearing.rs`:71 (`claims: BTreeMap<Outpoint, u64>`), 88, 203 (`claim_before` per channel), 235-250 (haircut over
  every claim in key order, `claim_haircuts` for non-batch accounts), 264, 278-279.
- Circuit: `step`:269-272 (each slot's claim range-checked from `z`), 273-290 (table keys bound to bytes, strictly ascending),
  327-339 (claim and key chosen by the row's one-hot slot), 459-472 (`claims3` per slot, range-checked), 637-639 (per-slot claims
  emitted); `cet`/`rel`:583 hash `z_0` and `z_K` into `commitment_hash`.
- Status: PARTIAL. Claims are folded state, not a sum, so C2 is closed. Open: the pre-state `z_0` (claims, keys, cash, fund, carry,
  book) is never compared with a venue-attested state: `rel` `guest_statement` checks only chain zero and sequence (556-567). The
  table must list every account that holds a claim or occurs in a batch (`step`:16-19); nothing checks completeness. The step
  inputs `(slot, pnl, released)` are free (finding N2).
- Missing proof obligations: authentication of `z_0` (venue state commitment or signature); table completeness; R1CS refinement of the
  one-hot selection and of `key_lt` (97-bit comparisons of 96-bit limbs).
- Adversarial test: `AttackC2Claims.test_c2_claim_moved_between_accounts`, `AttackBatchInputs.test_batch_inputs_are_not_authenticated_by_the_step`.

### P4 batch digest and signed authorization binding

- Independent spec: `BatchPre`, `enc_inj` (the preimage of row count, rows, claim-haircut count, entries and tail is injective for
  fixed widths), `digest_binds_batch` (hash equality plus the premise `NoCollisionAt H a.enc b.enc` gives equal batches),
  `chainR`, `chain_binds_digests` (hypotheses `CR3 H` and genesis outside the image of `H`), `chain_genesis_needed`.
  Collision resistance is a hypothesis of each theorem, never an axiom.
- Rust reference: `clearing.rs`:133-137 (`ClearingRow::put`), 160-169 (`digest`), `rel`:73-101 (`Batch::digest`), 107-125 (`chain_next`,
  `chain_of`); `batcher`:222-268 (`venue_batches` compares with `BatchClearing::digest`).
- Circuit: `step`:538-593 (exact variable-length preimage, row and claim-haircut counts by multiplexers, tagged SHA-256 from a
  precomputed midstate), 612-618 (`chain' = SHA256(tag || chain || seq_le64 || digest)`); `gad`:482-511 (`sha256_var`).
- Status: PARTIAL. The digest is a function of the constrained rows (C1 closed). The signed authorization is not bound: no lane
  acknowledgement signature over `BatchClearing::digest()` is verified in the circuit or in `rel` (`guest_statement` 548-602). `rel`
  recomputes the chain from the prover-supplied `batches` (568-571), which proves self-consistency only. Authorization of the money
  movement rests on the settlement transaction signatures: traders sign SIGHASH_SINGLE|ANYONECANPAY over their own input and output
  (`batcher`:155-157, 409-421) and `check_settlement` forces each output to equal `collateral + carry_in + net` (`rel`:397-413).
- Missing proof obligations: verification of the lane acknowledgement signatures against the chained digests; Rust/circuit byte
  equality of the preimage (Lean proves injectivity of the abstract encoding, not that the circuit builds those bytes).
- Adversarial test: `AttackC1FreeDigest.test_c1_free_digest_witness`, `AttackBatchInputs...`.

### P5 Taproot key, tapleaf and transaction input binding

- Independent spec: none in Lean. The reference is the Python model in the test file (`sig_msg`, `tap_tweak_key`, `keypath_signer_ok`,
  `scriptpath_signer_ok`, `plan_ok`), validated against the BIP-341 wallet vector for all seven hash types and the vector's output key
  (`ModelGroundTruth.test_bip341_vector_sigmsg_and_sighash`, `test_taproot_tweak_matches_vector`).
- Rust reference: `tap`:167-238 (`sig_msg_ext`, `tap_sighash_ext`), 255-269 (`params_next`), 272-276 (`spent_commitment`);
  accounts `batcher`:155-162 (`account_output`: settle leaf `<T> CHECKSIGVERIFY <B> CHECKSIG`, refund leaf), 79-97 (`tweak`);
  `rel`:383-422 (`check_settlement`: inputs equal manifest outpoints), 221-227 (`spent`).
- Circuit: `tap`:446-479 (txid = SHA256d of the transaction bytes with shape constants for counts and lengths, bound to `z[3..4]`),
  481-497 (amounts and scriptPubKeys committed in `z[5..6]`), 499-527 (one-hot input among the Taproot inputs, signed mask, outpoint,
  amount, scriptPubKey, sequence selected), 528-533 (scriptPubKey must be `0x22 0x51 0x20 <x>`), 546 (key-path key is `<x>`),
  536-547 and 690-712 (bind mode: script-path `key`, `tapleaf`, `codesep` are free witnesses carried into the parameter accumulator),
  552-571 and 626-671 (hash type and message layouts), 673-689 (authorization accumulator).
- Status: key path ENFORCED. Script path PARTIAL, which is the path the account outputs use in variant A (`batcher`:158-162): the
  circuit does not tie `key` and `tapleaf` to the spent output key. The accumulator is compared with M17's deferred signatures in
  `cet::verify_binding` (64-96), a native function; `rel` `guest_statement` checks only `tap_zk[3..7]` (573-582) and commits
  `hz(tap_zk)` (583). Nothing at the pinned SHA checks a control block or the Taproot tweak of the spent output key against the
  leaf, and `Manifest.accounts[i].account_spk` (`rel`:133-147) is taken as given, not recomputed from `(owner, batcher, refund
  height)` (finding N3). In `unified`, the transaction is bound by txid (586-601) and the outpoints are read from the same bytes
  (603-608); input amounts are free (N1).
- Missing proof obligations: in-circuit or verifier-side control-block check (leaf hash, merkle path, tweak of the internal key
  equal to `spk[2..34]`); recomputation of `account_spk` in `check_settlement`; BIP-341 layout refinement for every shape.
- Adversarial test: `AttackT1SignerBinding` (2), `AttackT2InputIndex`, `AttackT3HashType`.

### P6 nullifier uniqueness and replay resistance

- Independent spec: `accept`, `runAll`, `runAll_rejects_repeat` (a list with a repeat is rejected), `runAll_rejects_spent` (a spent
  nullifier is never accepted again), `runAll_some_nodup` (success implies the list is `Nodup`), `accept_nodup` (the spent list stays
  `Nodup`); `slot_allows_duplicate` (the slot-emptiness rule alone accepts one nullifier in two slots).
- Rust reference: `unified`:107-112 (`nullifier_for_outpoint`), 151-168 (`consume_vault_slot`: only `leaves[slot] == 0` is checked).
- Circuit: `unified`:603-678 (selected outpoint hashed with `NULL_LEAF_DOMAIN`, empty leaf to inserted leaf along a depth-3 path,
  `slot < 8` at 614-620, old root bound to `z[1..2]` at 646-658, new root bound at 660-678), 479-507 (three folds). The replacement
  has no nullifier: `step` and `tap` carry none.
- Status: replacement MISSING in-proof: replay of a settlement is stopped only because `check_settlement` makes each input spend a
  manifest account outpoint (`rel`:398-399), which Bitcoin consumes once; `carry_in` is a manifest field with no nullifier (N4).
  Unified PARTIAL: the slot is free (`vault_slot` is a witness) and only emptiness is checked, so uniqueness of the nullifier
  content rests on the three outpoints of the txid-bound transaction being distinct; the initial root is a verifier input
  (`unified`:242-265).
- Missing proof obligations: content-level non-membership (a sorted or indexed tree, or a hash-addressed slot); pinning of the
  initial root to the previous epoch's final root; a nullifier for `carry_in`.
- Adversarial test: `AttackNullifier` (2).

### P7 oracle root authentication

- Independent spec: `climb`, `climb_binds`, `oracle_leaf_bound` (a leaf opened at the same position under the pinned root is the
  authentic leaf, given `CRNode node`).
- Rust reference: `unified`:171-227 (`OracleOpeningWitness::checkpoint_root`).
- Circuit: `unified`:680-779 (leaf with constant VALID bytes at 737, depth-3 inclusion at 749-761, root at 762-767, bound to `z[3..4]`
  at 768-779 and to the statement `policy_hash` at 818-830), midpoint floor 695-705, 50 bps spread 706-730.
- Status: unified PARTIAL: inclusion and the record predicate are enforced; the root is a public input and its authenticity is a
  verifier pin (`unified`:229-266). The record's `hour_id` is not tied to the statement `epoch_id` (a free body field, 783-789) and
  the price does not feed any amount (N1). Replacement MISSING: `Manifest` (`rel`:159-174) holds an `event_id` string, no oracle key,
  nonce or root; the oracle outcome enters as a BIP-340 adaptor point at signing (`batcher`:395-396, 450-466), outside every circuit.
- Missing proof obligations: signature or on-chain anchoring of the checkpoint root; binding of oracle key and event into the
  manifest hash; use of the opened price in the amounts.
- Adversarial test: `AttackOracleRoot` (2).

### P8 canonical integer encoding and field-wrap exclusion

- Independent spec: `limbVal_lt`, `limbVal_inj` (bounded limbs encode a unique integer), `limbs_no_wrap` (equal residues of bounded
  limb values are equal when `2^(w*n) <= p`), `two_limbs_fit` and `four_limbs_wrap` (BN254), `wrap_counterexample` (`p + k` and `k`
  collide), `wrap_value_out_of_range`, `int_identity_no_wrap`, `i64_wrap_free`, `i64_wrap_counterexample` (`2^63` and `-2^63`
  collide without the signed range), `ofLE_toLE`, `toLE_inj`, and `no_wrap_eq` (`ZKLean.lean`:111).
- Rust reference: u64/i64 fields `clearing.rs`:57-72, 110-131; little-endian encoding 133-137, 160-169; statement `bitvm3.rs`:96-112,
  `rel`:443-458.
- Circuit: `gad`:140-145 (`range`), 148-154 (`range_i64`, two's complement), 158-168 (`claim_u64`, `claim_i64`: the published bits are
  the bits of the constrained value); `step`:261-272, 316-319, 342-347, 388-392, 402-406, 430-434, 468 (ranges on every input and
  intermediate), 292-293 and 622-623 (`book` has no range check of its own; it is pinned because the identity's other terms are
  bounded below 2^72); `step`:228-230 (key limbs from bytes, 96-bit); `gad`:351-378 (128-bit digest halves); `unified`: bit
  decompositions throughout (`le_lc` of allocated bits).
- Status: ENFORCED at the constraint level. `tap`:81-84 asserts compact sizes below 253, so larger shapes are rejected at witness
  generation, not accepted wrongly; `rel::compact` (230-236) supports larger sizes.
- Missing proof obligations: a table of the magnitude of every linear combination in `step` (the bound used above, `2^72`) with
  the Lean lemmas `limbs_no_wrap` / `int_identity_no_wrap` applied to each; byte-width equality of every digest field with its
  range-checked bits.
- Adversarial test: `AttackFieldWrap` (3).

### P9 exact initial state, terminal state and fold count

- Independent spec: `trace_seq`, `bound_trace_steps` (`steps = terminal.seq - initial.seq`), `fold_count_unique`,
  `wrong_count_rejected`, `genesis_pin`, `bound_trace_identity` (invariant along `BoundTrace`), `nongenesis_trace_exists` (the
  identity alone does not pin the initial state), built on `Trace` and `BoundTrace` (`ZKLean.lean`:218-240).
- Rust reference: `fold`:60-130 (verifier supplies `steps.len()` and `z0`; negative controls at 93-103); `rel`:548-571.
- Circuit: `step`:261 (seq 64-bit), 632 (`seq' = seq + 1`), 294-295 (chain input bound to `z`), 612-618; `rel`:553-571 (batch count equals
  steps; `z_0` chain is zero; `z_0.seq` equals the first batch; `z_K.seq` equals last + 1; `z_K` chain equals `chain_of(batches)`).
  `tap`:676-677, 714-721 (step byte bound to `z[0]`, increment) and `unified`:479-507, 861-869 (`fold_idx` equals `z[0]`, three
  folds, a fourth step is unsatisfiable).
- Status: fold count ENFORCED (sequence arithmetic plus the verifier's step count). Terminal state ENFORCED against the batches
  supplied to the guest. Initial state PARTIAL: only chain and sequence are pinned (finding N2/P3); `guest_statement` also indexes
  `batches[0]` and `batches.last().unwrap()` (562, 565), so `steps == 0` panics the guest (denial of service only), and it writes
  `assertion_txid = [0; 32]` (593) where `UtxoRefL2SettlementStatementV0::validate_nonzero` requires a non-zero value
  (`bitvm3.rs`:150-169; the guest does not call it).
- Missing proof obligations: pin of `z_0` to the attested venue state; Nova-level statement that `num_steps` is exactly the number of
  accumulated instances (assumption layer, section 4).
- Adversarial test: `AttackFoldCountAndGenesis` (2).

## 2. Re-check of C1-C4 and T1-T3 against the replacement circuits

Findings are from `docs/SHZ_CLEARING_CIRCUITS_REVIEW.md` (lines 27-60 for C, 111-125 for T).

| Finding | Verdict | Evidence |
|---|---|---|
| C1 digest is a free witness | CLOSED | `step`:538-593 build the exact preimage from the constrained rows and hash it; 594-610 show a substituted digest is bound to the computed one by equality constraints; `rel`:73-101 and `batcher`:262 recompute it natively. Remaining: R1CS refinement and byte-equality proofs (section 4). |
| C2 per-account claims not in folded state | CLOSED | `step`:5, 269-272, 459-472, 637-639: one claim per table slot in `z`, re-emitted per slot. Residual authentication of `z_0` is P3. |
| C3 waterfall order and rounding unenforced | CLOSED at constraint level | `step`:341-347, 395-398, 407-412, 436-438 and `gad`:210-260 recompute every `min` and both pro-rata splits. Lean proves the spec properties (`prorata_sum`, `prorata_priority`, `allocateDefault_*`); the gadget refinement is open. |
| C4 fixed 4 lanes, claim haircuts folded into rows | PARTIALLY CLOSED | `step`:298-313 (R variable rows, one-hot slot, rows distinct 370-376), 474-512 (claim-haircut list for non-batch accounts, key order), `rel`:353-361 (every batch row belongs to a manifest account or a carried channel). Open: an account outside the A-slot table or a batch above R rows cannot be represented (`step`:149 asserts), and table completeness is not checked. |
| T1 signer not bound to the transaction | PARTIALLY CLOSED | Key path closed: `tap`:528-533, 546. Script path open: `tap`:536-547 take `key` and `tapleaf` as free witnesses; the only binding is the parameter accumulator (690-712) compared natively in `cet`:64-96; no control-block or tweak check at the pinned SHA; `account_spk` unchecked (`rel`:133-147). |
| T2 input index free per step | PARTIALLY CLOSED | `tap`:499-521 (one-hot index, signed mask, each key-path input at most once, mask in `z[7]`). Open: completeness of the mask and script-path inputs are not enforced in-circuit; `rel`:573-582 does not read `tap_zk[7]`, the signature count or the parameter accumulator. |
| T3 hash types and spend types | CLOSED | `tap`:552-571 (seven valid types), 575-618 (annex, `ext` and `annex` flags in `spend_type`), 626-671 (layouts). The Python model reproduces the BIP-341 vector for all seven types. T4 (annex) and T5 (shape) are closed by the same lines (575-608, 444-465). |

Other items of the review: H1 closed (`step`:632, 613-617), H2 closed (514-536), H3 closed (`range_i64`, 262-263, 316), H4 closed in
the guest (it rebuilds every statement field natively, `rel`:584-600), H5 partial (initial state, P3), M1 closed (`fold`:93-103
run the verifier). New findings from this audit:

- **N1** unified conservation is vacuous: `input_amounts_sats` and `miner_fee_sats` are free witnesses (`unified`:557-578) not bound
  to `z` (229-266), so `sum(in) = sum(out) + fee` (579-584) holds for any outputs.
- **N2** the step inputs `(slot, pnl, released)` and `z_0` are not authenticated against the router or the lane acknowledgements
  (the `tests/mutation_sweep.rs` header records that a mutated batch input can satisfy the step while its output differs from the router's post-state).
- **N3** `check_settlement` takes `account_spk` from the manifest without recomputing the owner/batcher output key (`rel`:221-227, 383-422).
- **N4** `carry_in` is unconstrained by earlier epochs (`rel`:146, 401).
- **N5** the guest panics on `steps == 0` (`rel`:562, 565) and emits `assertion_txid = 0` (593).

## 3. Test index

27 tests in `test_settlement_adversarial.py`: 5 model checks (BIP-341 vector, taproot tweak vector, honest step, random walk, prorata)
and 22 attack tests. One test per attack: C1 `test_c1_free_digest_witness`; C2 `test_c2_claim_moved_between_accounts`,
`test_c2_dropped_claim_breaks_identity`; C3 `test_c3_loss_skips_margin_into_fund`, `test_c3_haircut_shifted_between_winners`,
`test_c3_remainder_order`; C4 `test_c4_account_outside_the_table`, `test_c4_claim_haircut_of_non_batch_account`; T1
`test_t1_keypath_key_must_be_spk_key`, `test_t1_scriptpath_unbound_key_and_leaf`; T2 `test_t2_free_input_index_and_missing_signatures`;
T3 `test_t3_wrong_or_invalid_sighash_type`; replay `test_duplicate_nullifier_replay`, `test_replay_across_epochs_needs_pinned_initial_root`;
oracle `test_forged_oracle_root`, `test_oracle_record_midpoint_and_spread`; wrap `test_field_wrap_value_p_plus_k`,
`test_i64_two_complement_boundaries`, `test_fixed_width_encoding_is_canonical`; fold `test_wrong_fold_count`,
`test_non_genesis_initial_state`; inputs `test_batch_inputs_are_not_authenticated_by_the_step`. Each asserts that the specification
rejects the attack. Where the implementation accepts (C3 and C2 under sum-only checks, slot-only nullifier insertion, the guest's
`z_0` check) the test also asserts that the transcribed implementation check accepts, so the gap stays visible.

## 4. Obligation layers per circuit

Three layers are kept apart. A proof at one layer does not discharge another.

### Layer A: ordinary R1CS equivalence to the spec

Statement per step circuit `F`: for all `z`, rows, `z'`: `(exists w. R1CS_F(z, z', w))` iff `z' = Spec(z, rows)` and `Valid(z, rows)`,
over the circuit's field (BN254 scalar field for `step`, `tap`, `unified`).

| Circuit | Spec side | Proven | Open |
|---|---|---|---|
| `ClearingStep` (`step`) | `clear` (`clearing_spec.py`, Lean `prorata_*`, `allocateDefault_*`, `collectLoss_*`, `batch_*`) | P1 and P2 properties of the spec; P3/P4 binding statements; P8 no-wrap lemmas; P9 counting | refinement of each gadget (`range`, `range_i64`, `nonzero`, `le`, `select`, `min_claimed`, `prorata`, `one_hot`, `mux_bits`, `sha256_var`) to its spec; uniformity of the constraint shape for every witness (`gad`:1-7 states it, nothing proves it); completeness; uniqueness of witnesses for published fields |
| `SighashStep` (`tap`) | BIP-341/342 `SigMsg` (Python `sig_msg`, checked against the vector) | none in Lean | layout refinement per hash type and annex length; SHA-256 gadget; key selection; mask update |
| `Mnr05UnifiedBatchStep` (`unified`) | nullifier insertion, oracle inclusion, transaction hash | P6 and P7 binding statements (`runAll_*`, `climb_binds`, `slot_allows_duplicate`) | refinement of the depth-3 insert and inclusion paths, of the 348-byte transaction relation, and of the statement binding |

Evidence that is not a proof: `audit.rs` (single-variable and constraint-local pair mutation, occurrence audit, iden3 `.r1cs` export),
`tests/mutation_sweep.rs`, `TestConstraintSystem` runs in `step`:679-691, the BIP-341 and Core regtest artifacts. None of these was run
in this task. The existing `ZKLean.lean` evaluator `rowHolds` (34-35) is the ordinary R1CS semantics a refinement proof targets.

### Layer B: relaxed-R1CS (Nova folding) equivalence

Nova folds instances of `A z o B z = u (C z) + E` (relaxed R1CS) over the augmented circuit `F'` (step circuit plus the in-circuit
verifier of the other curve). Obligations: (B1) an ordinary instance is the relaxed instance with `u = 1`, `E = 0`; (B2) folding two
satisfied relaxed instances with the verifier's challenge gives a satisfied relaxed instance (a field identity, provable in Lean
over a field; not done here); (B3) the augmented circuit computes `z_{i+1} = F(z_i, w_i)` and the hash chain over public parameters
and counters the verifier checks; (B4) the number of folded instances equals `num_steps` the verifier passes (`fold`:76, 90).
`ZKL22`, `ZKL24` and `ZKL25` capture and replay the augmented shapes of the existing MNR05 step; no equivalent capture exists for
the `step` and `tap` circuits at the pinned SHA, and no relaxed-R1CS evaluator exists in `MathCan`. All of B1-B4 are open.

### Layer C: Nova protocol soundness (assumption)

Taken as an assumption, not proven here: knowledge soundness of Nova folding over the BN254/Grumpkin cycle (`nova-snark` 0.76.0,
`bitvm3.rs`:25-26), soundness of the Spartan/IPA compression (`fold`:17-20), the random-oracle or hash-binding assumptions behind
the instance hashing, and SHA-256 collision resistance used by the digest chain, the commitment hash, `nullifier` and the Merkle
nodes. Every Lean binding theorem above takes the collision-resistance premise as an explicit hypothesis (`NoCollisionAt`, `CR3`,
`CRNode`). Verifier-supplied inputs (`vk`, `z_0`, `num_steps`) are outside the proof and are the pins listed under P3, P6, P7, P9.

## 5. What is open

1. The R1CS-to-spec refinement of every gadget (layer A) and all of layers B and C.
2. P3 and P9: `z_0` is not pinned to an attested venue state; table completeness is unchecked.
3. P4: no verification of lane acknowledgement signatures over the chained digests; step inputs are unauthenticated (N2).
4. P5 and T1/T2: script-path key and tapleaf have no in-circuit or in-guest tie to the spent output key; the guest ignores the signed
   mask, signature count and parameter accumulator; `account_spk` is not recomputed (N3).
5. P6: no nullifier in the replacement; `carry_in` unconstrained (N4); unified nullifier check is slot emptiness only.
6. P7: no oracle root in the replacement; unified root is a verifier pin, `hour_id` not tied to the epoch, price unused (N1).
7. P1 in `unified`: conservation is vacuous (N1).
8. Guest robustness: `steps == 0` panic and zero `assertion_txid` (N5).
9. Closed at constraint level but unproven in Lean: C1, C2, C3, T3; the Lean file proves the specifications those constraints must meet.
