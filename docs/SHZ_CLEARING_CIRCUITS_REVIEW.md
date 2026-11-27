# Review: Neon's draft clearing and TapSighash circuits

Reviewed 2026-11-27. These are the unreviewed drafts in
`C:\Users\patri\.gemini\antigravity\scratch\Lightninger-bitvm3-nova-campaign\research\lightninger_bitvm3_clearing\src\`:
`v3_clearing_circuit.rs` (1,067 lines), `venue_trace.rs` (615), `tapsighash_nova_circuit.rs` (827), `lib.rs`.
I compared them line by line against `crates/shz-dex/src/routing/clearing.rs` (main `42a3890`),
`crates/shz-nova-bitvm/src/bitvm3.rs` (304-byte statement), `research/mnr05_bitvm3_ln_dlc/src/secq_schnorr_circuit.rs`
and BIP-341/342. Line numbers below refer to the draft files.

The drafts were not compiled. `lib.rs` declares `pub mod core_bitvm3_drill;` and no such file exists, so the crate does not build
as delivered. All findings come from reading the code against the real code and the BIPs.

The replacement implementation is `research/lightninger_bitvm3_clearing` (see `docs/SHZ_CLEARING_CIRCUITS.md`). It reuses the
ideas marked "reusable" below and nothing else.

## Verdict

| Draft | Sound for its stated claim? | Why not |
|---|---|---|
| `v3_clearing_circuit.rs` + `venue_trace.rs` | **No** | The batch digest is a free witness never computed from the rows (C1). Per-account deferred claims are not part of the folded state (C2). The waterfall is checked only by conservation sums, so any split of a loss across margin, own claim, fund, haircut and carry passes (C3). |
| `tapsighash_nova_circuit.rs` | **No** for "the inputs' owners authorized the clearing tx" | The signing key is a free witness bound to nothing in the transaction (T1). The tapleaf hash is a free witness (T1), the input index is free per step (T2), and only script-path messages for 3 of the 7 hash types are built (T3). |

## A. `v3_clearing_circuit.rs` / `venue_trace.rs` against `clearing.rs`

### Critical

**C1. The circuit does not reproduce `BatchClearing::digest()`; the digest is unconstrained.**
`batch_digest` is allocated as 256 free bits (`alloc_bytes_bits(.., &self.batch_digest)`, line 544) and only fed into the chain hash
(lines 545-555). None of the lane values constrained in section 2 (gain, loss, collected, own_claim_used, shortfall, haircut,
claim_before/after, paid) appear in its preimage. A prover can satisfy the arithmetic with one set of rows and chain the digest of a
different batch, or any 32 bytes. The lanes sign the real digest (V3 ack, `ClearingRow::put` + `digest()`), so the proof says
nothing about the rows they signed. The real preimage also has fields the circuit never builds: the channel outpoint (36 B), the
signed `pnl` and `net` (i64 LE), the variable-length `claim_haircuts` list with its count, the batch totals, the `layer` byte,
signed `cash_before/after`, and the `SHZ/HFT/CLEARING/V1` BIP-340-style tagged-hash prefix.

**C2. Per-account deferred claims are not carried across folds.**
The IVC state (`z`, lines 310-320) holds only the claims total (`claims_in`). Each step allocates every lane's `claim_before` as a
fresh witness (line 373) and checks only `sum(claim_before) == claims_before` (line 474). A prover can move deferred claims
between accounts from one batch to the next (pay A's claim to B) and every step still verifies. In `clearing.rs` the claim map
is state (`ClearingState.claims`) and `claim_before = next.claim(&a.channel)`.

**C3. The waterfall order and its rounding are not enforced, only conservation.**
`clear()` is deterministic: `collected = min(need, released)`; `own_claim_used = min(rest, claim_before)`;
`fund_absorbed = min(shortfall, fund)`; `haircut = min(owed, base)` split by `prorata` (floors, then the remainder one unit at a
time in order: deferred claims in key order, then the batch's gains in batch order); `paid = dues` or
`prorata(available, dues)`. The draft checks only `<=` bounds and sums:
- `collected <= released` (line 397) but not `collected == min(loss, released)`. A loss can skip released margin and go
  straight to shortfall, so the fund absorbs a loss margin should have covered.
- No constraint ties `fund_absorbed` to `min(shortfall, fund)`. The waterfall equation (line 462) lets any mix of
  `fund_absorbed`, `sum(haircut)` and `carry_after` absorb the shortfall: haircut winners while the fund is untouched, or carry a
  deficit the fund could pay.
- Haircut shares are free. `prorata` is not implemented, so the whole haircut can land on one winner.
- `paid` is free subject to `claim_before + gain == own + haircut + paid + claim_after` (line 419). The pool can pay nothing,
  turn every gain into a deferred claim and keep the cash, or pay one winner ahead of another.

**C4. Accounts outside the 4 fixed lanes and claim haircuts on non-batch accounts break the model.**
`CAMPAIGN_LANES = 4` lanes always; `claim_haircuts` (deferred claims of accounts not in the batch) are folded into lane rows
(`venue_trace.rs` lines 426-444), so the circuit's rows are not `BatchClearing.rows`. Any venue with a fifth account, or a batch
whose `rows` order differs from lane order, cannot be represented.

### High

**H1. No batch sequence chaining.** `batch_seq` is a free 64-bit witness per step (line 341). It is hashed into the chain but not
tied to `z` or incremented, so the circuit does not reject skipped, repeated or reordered batches. Only an off-circuit verifier
that already knows the full `(seq, digest)` list could notice. With C1 and C2 that list is not bound to anything anyway.

**H2. The `layer` byte is not computed.** `Waterfall` (None/Margin/OwnClaim/Fund/Haircut/Carried, `max` over the batch) is
carried as a string in the trace and never constrained. In `clearing.rs` it is part of the digest.

**H3. Signed values rejected or mis-modelled.** `cash_before/after` are 56-bit unsigned (lines 323-325), and `venue_trace.rs`
panics on negative cash (`u64::try_from(report.cash_before).expect(..)`, line 462). `ClearingState::open` sets
`cash = fund0 - realized` and it is negative after a legacy V2 deficit (`legacy < 0`). `pnl` and `net` are i64 in the digest.
The draft splits pnl into `gain`/`loss` with `gain * loss == 0` but never builds the i64 two's-complement encoding, and has no
`net` at all. It also does not reproduce the strict `pnl < 0` filter: a row with `pnl == 0` is not a loser and does not raise
the layer to Margin.

**H4. Statement fields other than `commitment_hash` and `settlement_txid` are free per step.** Lines 586-622 check the magic,
the reserved bytes and 7 bits of the network byte. They bind `commitment_hash` to the chain and `settlement_txid` to `z`. Chain
genesis, contract id, assertion txid/vout, program hash, VK hash, policy hash and epoch are free witnesses re-chosen every step.
The output limbs are then `SHA256` of a statement the prover chose. This is harmless only if the verifier rebuilds the whole
statement itself, and then hashing it inside every step (about 5 SHA-256 blocks per fold) buys nothing.

**H5. The initial state is wrong for a real venue.** `z0()` (line 698) fixes `cash = initial_cash`, `carry = 0`,
`claims = 0`, `book = 0` (shifted). `ClearingState::open` derives `fund` and `carry` from the V2 history, and `book` from open
lots. The `initial_cash_sats = fund0` in `venue_trace.rs` holds only for a fresh venue.

### Medium

**M1. The negative controls are tautologies.** `mutated_cash_1sat_rejected = verified_out != bad_cash` (line 990) compares a
vector with itself plus one. No proof is checked against it, so it is always `true`. The same holds for the chain-root and
statement-limb controls. Only the bit-flipped proof bytes test (line 978) exercises the verifier.

**M2. No differential test against the real digest.** Nothing compares a circuit-computed digest with
`BatchClearing::digest()`. Because of C1 nothing could.

### Reusable

- The solvency identity `cash + carry == claims + fund + book` (shifted by a bias) and the book update
  `book_after = book_before - sum(pnl)` (lines 487-513). These hold for every batch of `clear()`. Per batch,
  `Δ(cash - claims - fund + carry) = sum(collected + own + shortfall) - sum(gain) = -sum(pnl)` exactly, so the identity is
  preserved iff `Δbook = -sum(pnl)`. The replacement carries `book` in the state and checks the identity on input and output.
- The per-row check `claim_before - own_claim_used + gain == haircut + paid + claim_after` holds in `clear()`. It is a
  consequence of the exact computation, not a substitute for it.
- The `venue_trace.rs` harness that drives `DurableTieredRouter` (registry, intents, `seal_batch` / `prepare` / `resolve` with
  signed approvals and acks) is the right way to produce real `BatchClearing` values from outside the crate. The replacement's
  generator follows it, with more accounts, multi-trade batches and the liquidation-drill price path.
- The `128-bit LE limb` convention for 32-byte digests in `z` matches `Mnr05SecqBip340Step` and is kept.

## B. `tapsighash_nova_circuit.rs` against BIP-341/342 and `Mnr05SecqBip340Step`

### Critical

**T1. The signer is not bound to the transaction.** `pubkey_x` (line 520) and `tapleaf_hash` (line 377) are free witnesses. The
circuit computes a script-path (`ext_flag = 1`) sighash for an arbitrary leaf hash and chains `(pubkey_x, sighash, sig)` into
the accumulator. Nothing ties `pubkey_x` to the spent output's script (the P2TR output key, or a key inside the leaf whose hash
is committed by the output key's Taproot tweak). The Secq step proves "some key signed this message". With the two proofs
together the verifier learns only that 8 signatures by unknown keys exist over sighashes of the transaction. To learn who
signed, it must already hold the 8 keys and recompute the chain, which needs the signatures and makes the proofs redundant.
There is no control block or merkle-path check, so any 32-byte leaf hash yields a valid-looking message for a script that may
not exist.

**T2. The input index is free per step and not accumulated.** `input_index` (lines 341-355) is chosen per step and appears in
neither `z` nor the accumulator. Nothing forces each input to be signed, or signed by the right parties. All 8 slots could
sign input 0.

### High

**T3. Only script-path, and only 0x00 / 0x01 / 0x83.** `spend_type` is the constant `0x02` (line 423/477), so every message is
`ext_flag = 1, annex absent`. Key-path spends (`ext_flag = 0`, no leaf extension), which are the cooperative-close path for
P2TR lanes, cannot be expressed. SIGHASH_NONE (0x02), SINGLE (0x03), 0x81 and 0x82 are not built. The three supported
branches are otherwise laid out correctly per BIP-341: epoch `0x00`, then `hash_type`, version, locktime; the four
`sha_*` digests skipped for ANYONECANPAY; `sha_outputs` only for ALL; spend_type; the input data, or the input index;
`sha_single_output` after the input data; then the BIP-342 `tapleaf_hash || 0x00 || 0xffffffff`. `0x00` and `0x01` share the
ALL layout and differ only in the hash_type byte, which is right.

**T4. The annex is never hashed.** With `spend_type` fixed and no `sha_annex` branch, a witness carrying an annex
(`0x50`-prefixed last witness element) has a different sighash than the one proven. Its signature would fail on chain, so this
is not a theft path. It is a completeness gap, and a draft that claims "exact BIP-341" should either reject an annex or hash it.

**T5. The fixed 3-input / 5-output layout is assumed, not checked.** The byte offsets (lines 374-375, 466-468) assume
`n_in = 3`, empty scriptSigs, `n_out = 5` and 34-byte P2TR outputs. The tx bytes are free bits bound only through the txid.
That is sound when the verifier's public txid is a transaction of exactly that shape, but the circuit does not pin the count
and length bytes. Prevout scriptPubKeys are assumed 34 bytes (`compact 0x22` constant, line 387).

### Medium

**T6. No ground truth.** `expected_sighash32` (line 202) is a second copy of the same layout logic. Nothing checks either copy
against BIP-341 test vectors or a Bitcoin Core-signed transaction. The mutated-accumulator control (line 767) is the same
tautology as M1.

### Reusable

- Accumulating `SHA256(AUTH_ACC_DOMAIN || acc || step || flag || pubkey_x || sighash || r_x || s)` exactly as
  `Bip340StepSlot::next_accumulator` does is the right link. Two independent Nova proofs over different curves (Bn256 for the
  hashing, Secq256k1 for the curve arithmetic) that end in the same 256-bit accumulator are bound by SHA-256 collision
  resistance. The replacement keeps this accumulator byte for byte. It adds what T1/T2 lack: in-circuit
  `pubkey_x == scriptPubKey[2..34]` of the input being signed (key-path P2TR output key), and a signed-input bitmask in `z`.
- Binding the transaction by an in-circuit `SHA256d` txid and the prevouts by a commitment in `z` is kept.
- Its message layout for 0x00 / 0x01 / 0x83 (script path) matches BIP-341/342.

## What the replacement does differently (summary)

1. Clearing: the step recomputes the whole of `clear()` for one batch from `z` (cash, fund, carry, book, every account's
   deferred claim, the account table) plus the batch inputs `(slot, pnl, released)`. It covers margin, then own claim, then
   fund, then the pro-rata haircut with the exact remainder rule, then carry, then pro-rata payment. It builds the exact
   variable-length `SHZ/HFT/CLEARING/V1` digest preimage in-circuit (rows, `claim_haircuts`, totals, layer) and hashes it. The
   digest is chained as `SHA256(tag || chain || seq || digest)` with `seq` incremented in `z`.
2. TapSighash: one uniform step for all seven valid hash types, key path, optional annex, any fixed transaction shape (including
   the BIP-341 test vector's 9-input transaction with P2PKH and P2WPKH prevouts). The signer key is pinned to the P2TR output
   key of the input being signed. Ground truth is the BIP-341 vectors plus Bitcoin Core 31.1 regtest consensus.
