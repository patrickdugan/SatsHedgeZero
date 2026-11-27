# Lightninger clearing circuits: V3 clearing fold and BIP-341 TapSighash fold

Code: `research/lightninger_bitvm3_clearing` (standalone Cargo workspace, `nova-snark =0.76.0`,
`Bn256EngineIPA` / `GrumpkinEngine`, Spartan `RelaxedR1CSSNARK` over IPA, no trusted setup).
It depends by path on `crates/shz-dex` (the real clearing code, used to generate every trace),
`crates/shz-dlc`, `crates/shz-nova-bitvm` (the 304-byte statement) and
`research/mnr05_bitvm3_ln_dlc` (`Mnr05SecqBip340Step` and its accumulator, used unchanged).
The review of the earlier drafts these replace is `docs/SHZ_CLEARING_CIRCUITS_REVIEW.md`.

| Module | What it is |
|---|---|
| `src/gadgets.rs` | u64/i64 decompositions, `min`, `nonzero`, `prorata` (exact remainder rule), one-hot, bit selection, SHA-256 from a midstate, variable-length SHA-256 |
| `src/clearing_step.rs` | `ClearingStep`: one committed V3 batch through `clearing::clear` |
| `src/tapsighash_step.rs` | `SighashStep`: one BIP-341 key-path signature message, chained into the MNR-05 accumulator; native BIP-341 reference (`sig_msg`, `tap_sighash`), tx parser |
| `src/trace.rs` | real traces from `DurableTieredRouter` (post, take, seal, prepare, resolve with signed approvals and lane acks) |
| `src/fold.rs` | fold, compress, verify, negative controls |
| `src/audit.rs` | recording constraint system, mutation and under-constraint search, iden3 `.r1cs` export |
| `src/cet.rs` | binding of M17 (Bitcoin Script on Nova, git dependency) to the TapSighash and Secq folds; the joint statement |
| `src/main.rs` | CLI: `shape`, `trace-stats`, `prove-clearing`, `prove-tapsighash`, `prove-cet`, `audit` |
| `tests/clearing_diff.rs` | clearing step against the router, tampers, identity, skipped/reordered batches |
| `tests/mutation_sweep.rs` | field-level mutation sweep of the clearing step |
| `tests/tapsighash_vectors.rs` | BIP-341 wallet test vectors (`keyPathSpending`) |
| `tests/core_regtest.rs` | Bitcoin Core 31.1 regtest: wallet-signed transactions for all 7 hash types, annex spends through `generateblock` |
| `tests/core_scriptpath.rs` | Bitcoin Core 31.1 regtest: script-path spends (2-signature leaf, codeseparator) for the bind mode |
| `tests/core_cet.rs` | Bitcoin Core 31.1 regtest: DLC CET and CLTV refund spends through M17 and the bind relation |

Build and test (git bash, as the other research workspaces):

```
cd research/lightninger_bitvm3_clearing
export CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=D:/shz/target-msvc TMP=D:/shz/tmp TEMP=D:/shz/tmp RUSTUP_HOME=$USERPROFILE/.rustup
cargo +1.99.0-x86_64-pc-windows-msvc test --locked --test clearing_diff --test tapsighash_vectors --test mutation_sweep -- --test-threads=1
LIGHTNINGER_BITCOIND=C:/Users/patri/AppData/Local/Programs/BitcoinCore/bitcoin-31.1/bin/bitcoind.exe \
  cargo +1.99.0-x86_64-pc-windows-msvc test --locked --test core_regtest -- --ignored
cargo +1.99.0-x86_64-pc-windows-msvc run --locked --release -- shape
cargo +1.99.0-x86_64-pc-windows-msvc run --locked --release -- audit 20000000
cargo +1.99.0-x86_64-pc-windows-msvc run --locked --release -- prove-clearing drill_fund 4
cargo +1.99.0-x86_64-pc-windows-msvc run --locked --release -- prove-tapsighash core:annex
```

Results are written to `artifacts/` (JSON receipts; proofs are not kept in the repo).

## 1. The V3 clearing step

### Statement

For a fixed account table of `A` slots and at most `R` rows per batch, one step proves:

> Given the folded pool state `z_i` and a batch of rows `(slot, pnl, released)` in batch order,
> `clearing::clear` produces the `BatchClearing` whose `digest()` is `d`, and the pool state after
> it is `z_{i+1}`, with `chain_{i+1} = SHA256("LIGHTNINGER/V3CLEAR/CHAIN/V1" || chain_i || seq_i (u64 LE) || d)`
> and `seq_{i+1} = seq_i + 1`.

After `K` folds the verifier holds `z_0` (the state when the proof starts) and `z_K`, and checks
`chain_K` against the digests the lanes acknowledged (each V3 ack, `SHZ/HFT06/CHANNEL-ACK/V3`,
signs the batch's `digest()`).

`z` (arity `7 + 4A`; 31 for `A = 6`):

| index | field |
|---|---|
| 0 | `seq` of the next batch |
| 1 | `cash` (i64, field-encoded signed) |
| 2 | `fund` |
| 3 | `carry` |
| 4 | `book` (i128, signed entry value of every open lot) |
| 5 .. 5+A | each slot's deferred claim |
| 5+A .. 5+4A | each slot's key, 3 limbs: `txid[0..12]`, `txid[12..24]`, `txid[24..32] ‖ vout` (big-endian) |
| 5+4A, 6+4A | `chain`, little-endian 128-bit halves (the MNR-05 convention) |

The account table lists every account that can hold a claim or appear in a batch, in strictly
ascending `(txid, vout)` order. The step checks the order every time, so table order is the
`BTreeMap` order `clear` walks deferred claims in. Unused slots carry sentinel keys
(`[0xff; 32]`, `vout = i`) and a zero claim; a row naming one produces a digest no lane signed.

### What one step enforces (all in R1CS, mirroring `clear` line by line)

1. Input state: `seq`, `fund`, `carry` and every claim in `[0, 2^64)`, `cash` in i64, keys
   decomposed and sorted, `chain` bound to its 256 bits, and the identity
   `cash - Σclaims - fund + carry - book == 0`.
2. Rows: an active prefix of `R` row slots; each active row selects exactly one table slot and no
   slot is selected twice; an inactive row has `pnl = released = 0`. `pnl` is decomposed as an
   i64 (two's complement, the digest's encoding); `gain = (1 - neg)·pnl`, `loss = gain - pnl`.
   The row's channel bytes and `claim_before` come from the selected slot.
3. Losses: `collected = min(loss, released)`, `own_claim_used = min(loss - collected, claim_before)`,
   `shortfall = loss - collected - own_claim_used`. A loser's own claim drops by `own_claim_used`.
4. `cash1 = cash + Σcollected` (i64), `fund_absorbed = min(Σshortfall, fund)`.
5. Haircut: `owed = Σshortfall - fund_absorbed + carry`, `base` = every slot's claim (key
   order) plus every row's gain (batch order), `haircut = min(owed, base)`, shares
   `prorata(haircut, base items)`: `q_i = floor(haircut·a_i / Σa)` checked as
   `haircut·a_i = q_i·Σa + r_i, 0 ≤ r_i < Σa`, then the remainder one unit at a time in order,
   each share capped at its item (`x_i = min(rest_i, a_i - q_i)`). `carry_after = owed - haircut`.
   Zero claims in the table take no share, as absent `BTreeMap` keys do.
6. Payment: `due_k = gain_k - cut_k + claim_k`, `paid = prorata(min(Σdue, max(cash1, 0)), dues)`
   (equal to `dues` when the pool can pay everything), `claim_after_k = due_k - paid_k`,
   `net_k = paid_k - collected_k` (i64), `cash_after = cash1 - Σpaid` (i64), and
   `cash_after ≥ min(cash_before, 0)`.
7. `claim_haircuts`: slots outside the batch whose share is non-zero, in key order, compacted into
   a list whose length `H` selects the digest layout.
8. `layer`: Carried if `carry_after > 0`, else Haircut if `haircut > 0`, else Fund if
   `fund_absorbed > 0`, else OwnClaim if any `own_claim_used > 0`, else Margin if any `pnl < 0`,
   else None (`clear` takes the `max` of these).
9. The digest: the exact `BatchClearing::digest()` preimage, `rows.len()`, every row's 116 bytes
   (`put_op` channel, pnl, released, collected, own_claim_used, shortfall, haircut,
   claim_before, claim_after, paid, net), `claim_haircuts.len()` and entries, the totals, the
   layer byte, `cash_before/after`, `fund_after`, `carry_after`, `claims_after`. Its length is
   `81 + 116·rows + 44·H` bytes. It is hashed as the BIP-340-style tagged hash
   `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` with tag `SHZ/HFT/CLEARING/V1` (the constant tag block
   is a precomputed midstate). The variable layout is built in three selection stages (claim
   haircuts, rows, padding for the exact length) and the digest is read after the matching block.
10. The chain update, `seq + 1`, `book - Σpnl`, and the identity on the output state.

Every published field is decomposed into bits and bound to its derivation, so a prover cannot
publish a value other than the one the rules compute.

### Proven vs assumed

| Proven by the step | Assumed (outside the circuit) |
|---|---|
| The clearing of the batch from `(slot, pnl, released)` and the folded state, to the sat, including rounding, waterfall order, deferred claims, claim haircuts, carry, the layer and the digest | That `(pnl, released)` per row are what `positions::settle` gives for the batch's fills. They are bound by the digest, which each lane acknowledges, so a lane signs off on its own row. The circuit does not re-derive lots, prices or margins. |
| Continuity: each batch starts from the previous batch's state; `seq` increments | That `z_0` is the venue's state at the start of the proved window (the verifier supplies it; on a fresh `EnableClearing` it is `cash = fund0 - realized`, `fund`, `carry`, empty claims, `book`) |
| The account table is sorted and passes through unchanged | That the table lists every account that holds a claim during the window |
| `book` changes by `-Σpnl`; the identity holds before and after | That `book` in `z_0` is the open book's signed entry value (the identity ties it to cash, claims, fund and carry) |
| | Values below 2^63 (sats); products are formed in the field and range-checked where `clear` uses `checked_add` |

### Constraint counts

Primary constraints of one step (`shape`; Nova's augmented circuit adds 14,678 on top of
these in the folded relation, e.g. 451,732 for `A = 6, R = 4`):

| A (accounts) | R (rows) | arity | constraints | variables |
|---:|---:|---:|---:|---:|
| 4 | 2 | 23 | 284,851 | 284,451 |
| 6 | 4 | 31 | 437,054 | 436,440 |
| 8 | 4 | 39 | 498,269 | 497,567 |
| 16 | 8 | 71 | 891,726 | 890,472 |

Per gadget for `A = 6, R = 4` (437,054): the digest's SHA-256 (up to 14 compression blocks
after the tag midstate) 339,623 (78 %); the chain hash 49,071; the digest layout selection
31,485 (claim-haircut stage 5,720, row stage 16,865, padding 5,828, output 3,072); the
account-table keys and their order 3,276; channel bytes of rows and claim-haircut entries
3,045; rows, waterfall, prorata, payment, claim haircuts, layer and state bindings 10,554. The per-namespace breakdown is
`artifacts/audit_r1cs.json` → `constraints_per_gadget`.

## 2. The TapSighash step

### Statement

For a fixed transaction shape (input count, scriptSig and prevout scriptPubKey lengths, output
script lengths, maximum annex length), one step proves:

> The transaction whose display txid is `txid` (in `z`), spending outputs committed by `spent`
> (in `z`), has an input `i` with a P2TR prevout `OP_1 0x20 <x>`, not yet marked in `signed_mask`,
> and `m` is its BIP-341 key-path signature message for hash type `t` (and annex `a`, if any).
> The accumulator becomes `SHA256("SHZ/MNR05/AUTH_ACC/V1" ‖ acc ‖ step ‖ t ‖ x ‖ m ‖ r_x ‖ s)`
> and bit `i` is set in the mask.

`z` (arity 8): `[step, acc_lo, acc_hi, txid_lo, txid_hi, spent_lo, spent_hi, signed_mask]`, with
`spent = SHA256(sha_amounts ‖ sha_scriptpubkeys)`.

The accumulator is `Bip340StepSlot::next_accumulator` byte for byte. Folding the same slots
through `Mnr05SecqBip340Step` (Secq256k1, unchanged) proves each `(x, m, r_x, s)` is a valid
BIP-340 signature. The two proofs are bound by ending in the same 256-bit accumulator: a
verifier accepts the pair only if both final states carry equal `acc` limbs. Because `x` is the
spent output's key, "valid key-path signature by the owner of each signed input" follows. The
final `signed_mask` says which inputs are covered.

### What one step enforces

- The stripped transaction from its bytes (count and length bytes are shape constants), `SHA256d`
  reversed, equal to `txid` in `z`; the prevout amounts and scripts hashed into `spent` in `z`.
- `sha_prevouts`, `sha_amounts`, `sha_scriptpubkeys`, `sha_sequences`, `sha_outputs`, the selected
  input's outpoint, amount, scriptPubKey and nSequence (one-hot over the P2TR inputs only),
  `sha_single_output` of the matching output (variable length: outputs may differ in size), and
  `sha_annex = SHA256(compact_size(len) ‖ annex)` for an annex of 1 to `annex_max` bytes whose
  first byte is `0x50` (bytes past the length must be zero).
- Hash type one of `0x00 0x01 0x02 0x03 0x81 0x82 0x83`; `0x00` and `0x01` share the ALL layout and
  differ in the hash-type byte; SINGLE needs `i < n_out`.
- `spend_type = annex_present` (`ext_flag = 0`: key path, no BIP-342 extension).
- `SigMsg` for the six layouts × annex present/absent, hashed as the `TapSighash` tagged hash.
- The input is not yet in the mask; the step counter increments.

### Proven vs assumed

| Proven | Assumed |
|---|---|
| The message each signature signs, from the transaction itself | That the verifier's `txid` and prevouts are the ones on chain (it supplies `z_0`) |
| The signing key is the P2TR output key of the input it signs | Script-path spends (tapscript) are not covered by this step |
| Each input is signed at most once; the mask reports which | That `step` stays below 256 (one byte in the accumulator, as in MNR-05) |
| With the Secq proof: every accumulated signature is a valid BIP-340 signature | |

### Constraint counts

| Shape | constraints | variables |
|---|---:|---:|
| BIP-341 vector: 9 inputs (7 P2TR, 1 P2PKH, 1 P2WPKH), 2 outputs (25 and 32 bytes), no annex | 886,447 | 885,539 |
| 3 P2TR inputs, 3 P2TR outputs, annex up to 40 bytes (the Core runs) | 673,274 | 672,532 |
| 3 P2TR inputs, 3 P2TR outputs, no annex | 619,673 | 619,025 |
| 1 P2TR input, 1 P2TR output, no annex | 431,919 | 431,454 |

SHA-256 dominates: the txid (`SHA256d` of the whole transaction), the five BIP-341 component
hashes, `sha_single_output`, `sha_annex`, the `TapSighash` message (up to 5 blocks after the tag
midstate) and the accumulator. Each step recomputes the component hashes, so the relation's
cost grows with the transaction, not with the number of signatures.

### Bind mode: script-path signatures (`TxShape::bind`)

With `bind` set, the same step also covers tapscript (script-path) signatures, as DLC CETs that
spend a script leaf need. Per signature the witness adds a `ScriptPath { key, tapleaf, codesep }`
(absent for key path), and:
- `SigMsg` gains the BIP-342 extension `tapleaf ‖ 0x00 (key_version) ‖ codesep_pos (u32 LE)` and
  `spend_type = 2·ext + annex` (6 layouts × annex × ext = up to 24 configurations);
- the signing key is the script-path key for a script-path signature and the P2TR output key
  otherwise; on a key-path signature the script-path fields must be zero;
- the key-path mask counts key-path signatures only (a leaf can carry several signatures);
- `z` has arity 10: the 8 fields above plus a **parameter accumulator**
  `par' = SHA256("LIGHTNINGER/TAPSIG/PARAMS/V1" ‖ par ‖ input ‖ hash_type ‖ ext ‖ tapleaf ‖ codesep ‖
  key ‖ r_x ‖ s ‖ annex_present ‖ sha_annex)` (zeros for absent fields).

The authorization accumulator binds each message to a valid BIP-340 signature (with the Secq
fold). The parameter accumulator tells a verifier which input, key, leaf and codeseparator
position each signature was checked for, in terms it rebuilds from the spend's script execution
(M17's claims and compiled program) with no curve or sighash work. Key-path relations (`bind`
off) are unchanged: the shapes above have the same constraint counts as before bind mode.

| Shape | constraints |
|---|---:|
| 3 P2TR inputs, 3 P2TR outputs, bind, no annex | 748,719 |

`prove-tapsighash` takes `vector`, `core:<label>` (`artifacts/core_sighash_txs.json`),
`corescript:<label>` (`artifacts/core_scriptpath_txs.json`) and `testnet4:<label>`
(`artifacts/testnet4_demo/txs.json`). A file holds `[{label, signed_hex, amounts, spks, slots}]`
with each slot `{input, hash_type, annex, sig_rx, sig_s, script_path: null | {key, tapleaf,
codesep}}`; bind mode is used when any slot has a script path.

## 3. Ground truth

### Clearing against `shz_dex::routing::clearing`

`tests/clearing_diff.rs` runs seven router traces (synthetic funds):

| Trace | Pattern |
|---|---|
| `liquidation_drill(1_000_000)` | docs/SHZ_LIQUIDATION_DRILL.md price path: A/B/C/D long at 10x/10x/8x/10x against two makers at 100,000, mark 92,000 (A closes inside margin), gap to 88,000 (B and C close past bankruptcy), back to 100,000, unwind |
| `liquidation_drill(0)` | the same with no fund: the shortfall is carried, then haircuts later gains |
| `own_claim` | a winner deferred (no cash in the pool) later loses more than its released margin |
| `legacy_deficit` | V2 history first (finding A1 leaves the venue 10,408 sats short), then clearing with fund 0: negative pool cash and a carried deficit from the first V3 batch |
| `random_walk(fund 200,000, seed 7, 14 windows)`, `random_walk(fund 0, seed 11, 14 windows)`, `random_walk(fund 200,000, seed 7, 160 windows)` | 6 accounts, leverage 1x/8x/10x/100x, up to two fills per window (orders the router rejects are cancelled), then flattened |

Every batch of every trace is synthesized on its real pre-state and must satisfy every
constraint and output exactly the router's post-state and the chain over the router's
`BatchClearing::digest()`. Result: all 202 batches satisfied, each with the router's exact
post-state and chain. All six waterfall layers occur (None, Margin, OwnClaim, Fund, Haircut,
Carried), 3 batches start from negative cash, and 12 batches carry claim haircuts on accounts
outside them. `prorata` is also checked against `clearing::prorata` on
8 hand cases.

Rejected (`tests/clearing_diff.rs`), each at the constraint named:

| Tamper | Rejected at |
|---|---|
| `net + 1` | `pay0/net/pack_i64` |
| collect 1 sat less margin, 1 more shortfall | `row0/collected/sel/sel` |
| carry 1 sat the fund could absorb (fund_absorbed −1, fund_after +1, carry_after +1) | `fund_absorbed/sel/sel` |
| `cash_after + 1` | `cash_after/pack_i64` |
| `claims_after + 1` (broken identity) | `claims_after/pack` |
| layer Fund → Haircut | `layer_b0` |
| a different digest | the digest binding |
| `claim_before + 1` | `row0/cb/pack` |
| own claim used before margin (reordered waterfall) | `row0/collected/sel/sel` |
| haircut remainder moved to the first claim | `cut/rem8/x/sel` |
| haircut 1 sat short | `haircut/sel/sel` |
| pay 1 sat less and defer it | `pay1/paid/pack` |
| move 1 sat of deferred claim between accounts | `claim3_0/rng/pack` |
| `book + 1` in `z` (identity) | `identity_in` |
| unsorted account table | `sorted1_lt` |
| claims moved between slots in `z` | `claim0_0/pack` |

A skipped batch (batch 3's rows folded on the state after batch 1) and swapped rows both satisfy
the step, as any batch input does, and reach neither real state nor the real chain, so the
verifier's chain check rejects them. A changed `pnl` likewise satisfies the step with a digest
no lane signed.

### TapSighash against BIP-341 and Bitcoin Core 31.1

- BIP-341 wallet test vectors (`keyPathSpending`, copied to `tests/vectors/`): a 9-input,
  2-output transaction with P2TR, P2PKH and P2WPKH prevouts and non-P2TR outputs (25 and 32
  bytes), seven taproot inputs covering all seven hash types. The native reference matches every
  `sigMsg` and `sigHash`, the vectors' signatures verify against it, and the step is satisfied on
  all seven inputs with the expected accumulator, txid, `spent` and mask.
- Bitcoin Core 31.1 (`/Satoshi:31.1.0/`, isolated regtest, `tests/core_regtest.rs`):
  - three transactions spending the Core wallet's own P2TR coinbase outputs, 3 inputs / 3 P2TR
    outputs each, every input signed by `signrawtransactionwithwallet` with its own hash type
    (`[0x83 0x01 0x00]`, `[0x03 0x02 0x82]`, `[0x81 0x00 0x01]`: all seven), accepted by
    `testmempoolaccept`, broadcast and mined;
  - one transaction spending three `rawtr` outputs whose keys the test holds, signed with the
    native reference, with a 5-byte annex on input 0 (DEFAULT), a 33-byte annex on input 1 (ALL)
    and none on input 2 (SINGLE|ANYONECANPAY). `testmempoolaccept` refuses it
    (`bad-witness-nonstandard`: policy); `generateblock` (consensus) mines it. The same
    transaction signed without committing to the annex is rejected by `generateblock`.
  - For all 12 inputs the native sighash verifies the signature (Core's, or consensus-accepted),
    and the step (one relation, shape 3-in/3-out P2TR, `annex_max = 40`) is satisfied with the
    expected outputs.
- Script path (`tests/core_scriptpath.rs`, Bitcoin Core 31.1 regtest): one transaction whose
  input 0 spends a leaf `<A> CHECKSIGVERIFY <B> CHECKSIG` (two signatures: DEFAULT and ALL),
  input 1 a leaf `1 DROP CODESEPARATOR <C> CHECKSIG` (SINGLE|ANYONECANPAY, codeseparator at
  opcode 2), input 2 a key-path `rawtr` output. Signed with the native BIP-341/342 reference;
  `testmempoolaccept` allows it and it is mined. Input 1 signed for "no codeseparator" is
  refused (`Invalid Schnorr signature`). All four slots satisfy the bind relation with the
  expected accumulators; a tapleaf on the key-path slot, or another codeseparator position,
  does not reach the real outputs.
- Rejected: hash types `0x04` and `0x80` (`ht_one`), an input signed twice (`not_signed_yet`),
  SINGLE on input 3 of a 2-output transaction (`single_has_output`), a `z` with another txid, a
  prevout amount that disagrees with `spent`.

## 4. Nova proofs (CPU, small K)

Each fold below generates its trace with the real router (or reads the Core / vector
transaction), folds every step, checks the folded output against `z_K` computed from the real
data (router post-state and digests; BIP-341 / Core sighashes), compresses with Spartan/IPA,
verifies the decoded proof, and records that the verifier rejects the proof for `z_0` with one
element changed, for `K - 1` steps, and with one proof bit flipped (`artifacts/*.json`; all four
checks passed in every run). Laptop: Ryzen AI 9 365 (20 threads), 48 GB, Windows 11; a
single-threaded mutation sweep ran alongside. Peak working set sampled every 0.5 s
(`scripts/peak_mem.ps1`).

| Fold | K | Batches / slots | Primary / secondary constraints | Setup | Fold | Compress | Verify | Proof | Peak working set |
|---|---:|---|---|---:|---:|---:|---:|---:|---:|
| clearing, `liquidation_drill_fund1000000` | 2 | None,None | 451,732 / 10,538 | 11.6 s | 1.6 s (0.80 s/step) | 31.9 s | 0.66 s | 13,112 B | 1,135 MiB |
| clearing, `liquidation_drill_fund1000000` | 4 | None,None,Margin,Fund | 451,732 / 10,538 | 11.0 s | 3.6 s (0.90 s/step) | 31.7 s | 0.93 s | 13,112 B | 1,134 MiB |
| clearing, `liquidation_drill_fund0` | 5 | None,None,Margin,Haircut,None | 451,732 / 10,538 | 9.2 s | 4.5 s (0.90 s/step) | 26.9 s | 1.13 s | 13,112 B | 1,134 MiB |
| clearing, `legacy_deficit` | 3 | Carried,Haircut,Margin | 451,732 / 10,538 | 13.1 s | 5.7 s (1.91 s/step) | 34.1 s | 0.72 s | 13,112 B | 1,135 MiB |
| clearing, `random_walk_n6_fund200000_seed7` | 8 | None,None,None,None,None,Margin,None,None | 451,732 / 10,538 | 11.9 s | 8.6 s (1.07 s/step) | 53.2 s | 1.06 s | 13,112 B | 1,135 MiB |
| clearing, `random_walk_n6_fund0_seed11` | 12 | None,None,Margin,Margin,Margin,OwnClaim,Margin,None,OwnClaim,None,None,Carried | 451,732 / 10,538 | 10.7 s | 9.5 s (0.79 s/step) | 27.4 s | 0.74 s | 13,112 B | 1,149 MiB |
| TapSighash, `core_annex` | 3 | 0x00+annex5,0x01+annex33,0x83 | 684,821 / 10,538 | 31.9 s | 4.6 s (1.55 s/step) | 116.1 s | 2.19 s | 12,688 B | 1,875 MiB |
| ↳ Secq256k1 BIP-340, same slots | 3 | accumulator `4ded2d69fd545ab7…` equal: True | 144,959 / 10,787 | 8.3 s | 1.5 s | 35.4 s | 0.42 s | 11,980 B | (same process) |
| TapSighash, `core_wallet_0` | 3 | 0x83,0x01,0x00 | 684,821 / 10,538 | 24.4 s | 2.9 s (0.97 s/step) | 208.4 s | 13.25 s | 12,688 B | 1,874 MiB |
| ↳ Secq256k1 BIP-340, same slots | 3 | accumulator `64642b941761b8a1…` equal: True | 144,959 / 10,787 | 13.5 s | 11.8 s | 54.1 s | 1.67 s | 11,980 B | (same process) |
| TapSighash, `bip341_vector` | 7 | 0x03,0x83,0x01,0x00,0x02,0x82,0x81 | 897,994 / 10,538 | 29.5 s | 8.8 s (1.26 s/step) | 86.2 s | 2.78 s | 12,688 B | 2,135 MiB |
| ↳ Secq256k1 BIP-340, same slots | 7 | accumulator `a62892f297589eb0…` equal: True | 144,959 / 10,787 | 5.5 s | 3.5 s | 28.3 s | 0.92 s | 11,980 B | (same process) |

Bind mode, `corescript:scriptpath` (3 script-path signatures and 1 key-path signature, one
transaction): 760,268 primary constraints, setup 17.5 s, fold 3.2 s for 4 steps, compression
90.7 s, verification 4.1 s, 12,752-byte proof, 1,967 MiB peak; negative controls rejected. The
Secq256k1 fold over the same 4 signatures (fold 1.4 s, compression 24.3 s) ends in the same
authorization accumulator, and the parameter accumulator is `54ed2a40…`.

- The clearing relation has one verifying key for every K
  (`e314976c5d20bca0735782d216d2431e43cc8dec40ea48dedcb38dbd5467b1e5` for `A = 6, R = 4`).
  Folding is about 0.8–1.1 s per batch; compression (27–53 s) and verification (under 1.2 s)
  do not grow with K; the proof is 13,112 bytes.
- `legacy_deficit` starts from pool cash −10,408 sats (the V2 deficit), its first batch is
  Carried, and the fold proves the carry being haircut away. `random_walk(fund 0)` K = 12 ends
  in a Carried batch that haircuts the deferred claims of 4 accounts outside the batch.
- Each TapSighash fold is paired with a fold of the same slots through `Mnr05SecqBip340Step`;
  the two end in the same accumulator, so the Secq proof's signature checks apply to the
  messages the TapSighash proof computed. For `core_wallet_0` that is Bitcoin Core's own
  signatures (SINGLE|ANYONECANPAY, ALL, DEFAULT); for `core_annex`, two signatures over annex
  messages that Core accepted in a block.
- The 304-byte statements and their BitVM3 limbs are in each clearing receipt
  (`bitvm3_statement_hex`, `bitvm3_public_limbs_be`).

## 5. The 304-byte BitVM3 statement

`prove-clearing` writes a `UtxoRefL2SettlementStatementV0` (`crates/shz-nova-bitvm/src/bitvm3.rs`,
`UTXOREF_L2_SETTLEMENT_GROTH16_V0\0`) with
- `commitment_hash = SHA256("LIGHTNINGER/V3CLEAR/COMMIT/V1" ‖ z_K)` where each element of `z_K` is
  its 32-byte little-endian field representation; `z_K` holds every field the statement stands
  for (chain, seq, cash, fund, carry, book, every claim, the account table);
- `program_hash = SHA256("lightninger/v3-clearing-batch-fold/v1/A{A}/R{R}")`;
- `verifying_key_hash = SHA256(bincode(vk))` (fixint encoding);
- `epoch_id = seq` of the next batch; the other fields are the deployment's (zero in these runs;
  `settlement_txid` is the txid the TapSighash fold proves when the two are combined).

The statement is a function of `z_K` and public constants, so it is computed by the verifier
from the proof's checked output rather than hashed in every fold (the draft hashed it per step
with all fields other than `commitment_hash` and `settlement_txid` unconstrained). The BitVM3
public inputs are `split_statement_digest_be_u128(SHA256(statement))`.

## 6. Audit

The acceptance criteria and how each was met.

### 6.1 Executable spec and completeness

The spec is the native code: `clearing.rs` for the clearing step, the native BIP-341 reference
in `tapsighash_step.rs` (itself checked against the BIP-341 vectors and Bitcoin Core) for the
TapSighash step. Completeness: every batch of the seven router traces (202 batches; scripted edge cases with
Fund, Haircut, Carried, OwnClaim, negative cash, claim haircuts; three seeded random walks) and
every signature in the vector and Core transactions is accepted with the reference's exact
output (section 3).

### 6.2 Mutation soundness

Field level (`tests/mutation_sweep.rs`, `artifacts/mutation_sweep.json`): on one batch per
waterfall layer plus the claim-haircut batch, every named witness field (per row: pnl,
claim_before, collected, own_claim_used, shortfall, haircut, paid, claim_after, net; batch:
shortfall, fund_absorbed, fund_after, haircut, carry_after, cash_after, claims_after, layer;
every slot's claim after; every claim-haircut entry; every prorata remainder step of the haircut
and of the payment), every `z_in` element, and every batch input (pnl, released, slot), each
perturbed by +1 and by −1, plus row swaps, a dropped row, a replaced digest, and nine compensating
pairs that keep every conservation sum the draft circuit checked. A mutation counts as rejected
if the step is unsatisfied, or (for batch inputs, which are the prover's choice) its output
differs from the router's post-state and chain. Result: **1,216 of 1,216 mutations rejected**
over six batches (Margin, Fund, Haircut, OwnClaim, Carried, and the Carried batch with 4 claim
haircuts): 1,096 leave the step unsatisfied, and 120 are batch-input changes (pnl, released,
slot, row order, a dropped row) that satisfy the step but output a state and chain other than the
router's. `released − 1` on a row that released nothing is not a mutation of a `u64` and is
skipped.

Variable level (`audit` command, `artifacts/audit_r1cs.json`): every variable of the recorded
R1CS perturbed alone by +1 and by a pseudo-random field element; and for every constraint, pairs
among its first 8 variables where one is perturbed and the other re-solved from that constraint
(when linear in it), then every constraint touching either is re-checked. A perturbation that
keeps every constraint satisfied is a second witness with the same public IO.

| Instance | Constraints | Variables | Single mutations rejected | Pair mutations rejected | Free |
|---|---:|---:|---:|---:|---:|
| clearing A6 R4, None (drill, seq 1, 4 rows) | 437,054 | 436,441 | 872,880 / 872,880 | 1,998,199 / 1,998,199 | 0 |
| clearing A6 R4, Margin (legacy, seq 6, negative cash) | 437,054 | 436,441 | 872,880 / 872,880 | 1,969,040 / 1,969,040 | 0 |
| clearing A6 R4, OwnClaim (walk fund 0, seq 6, 4 rows) | 437,054 | 436,441 | 872,880 / 872,880 | 2,010,662 / 2,010,662 | 0 |
| clearing A6 R4, Fund (drill, seq 4, 4 rows) | 437,054 | 436,441 | 872,880 / 872,880 | 2,018,824 / 2,018,824 | 0 |
| clearing A6 R4, Haircut (drill fund 0, seq 4, 4 rows) | 437,054 | 436,441 | 872,880 / 872,880 | 2,016,924 / 2,016,924 | 0 |
| clearing A6 R4, Carried with 4 claim haircuts (walk fund 0, seq 12) | 437,054 | 436,441 | 872,880 / 872,880 | 2,020,183 / 2,020,183 | 0 |
| clearing A4 R2 (small, exported) | 284,851 | 284,452 | 568,902 / 568,902 | 1,292,192 / 1,292,192 | 0 |
| TapSighash vector input 0, SINGLE | 886,447 | 885,540 | 1,771,078 / 1,771,078 | 4,164,191 / 4,164,191 | 0 |
| TapSighash vector input 1, SINGLE\|ANYONECANPAY | 886,447 | 885,540 | 1,771,078 / 1,771,078 | 4,165,758 / 4,165,758 | 0 |
| TapSighash vector input 4, DEFAULT | 886,447 | 885,540 | 1,771,078 / 1,771,078 | 4,163,114 / 4,163,114 | 0 |
| TapSighash Core annex input 0 (5-byte annex) | 673,274 | 672,533 | 1,345,064 / 1,345,064 | 3,196,955 / 3,196,955 | 0 |
| TapSighash bind, Core script-path slot 1 (65-byte ALL signature, leaf with 2 keys) | 748,719 | 747,875 | 1,495,748 / 1,495,748 | 3,553,899 / 3,553,899 | 0 |
| TapSighash bind, Core key-path slot 3 | 748,719 | 747,875 | 1,495,748 / 1,495,748 | 3,550,873 / 3,550,873 | 0 |
| TapSighash 1-in/1-out (small, exported) | 431,919 | 431,455 | 862,906 / 862,906 | 2,033,735 / 2,033,735 | 0 |

(Variables include the constant one; "single" counts two perturbations per variable.)

### 6.3 Under-constraint search

The single-variable and pair search above is the search for two satisfying witnesses that agree
on the public IO. It ran on real instances (not only small ones) and found none. Two
non-uniqueness sources were found while building it and fixed before these runs: the inverse in
`nonzero` was free when its input was zero (now `inv·(1-b) = 0`), and the annex buffer's bytes
past the annex length were free (now forced to zero). The search is local (one variable, or two
sharing a constraint); a whole-system uniqueness proof needs an external tool, for which the
R1CS is exported (6.5).

### 6.4 Variable audit

Variables in fewer than two constraints, on every audited instance, are exactly the public IO:
- each output of `z_{i+1}` (`out_*`, `chain_out/lo|hi`, `acc_out/lo|hi`, `mask_out`, `step_out`)
  is bound once, to the linear combination it publishes. In the folded relation it is also an
  input of the next step, where Nova's augmented circuit absorbs it into the hash of `z`;
- the digest-valued inputs (clearing: `chain` lo/hi; TapSighash: `acc`, `txid`, `spent` lo/hi) are
  bound once, to the 128 bits that represent them, and those bits feed SHA-256.
No witness variable is unused or appears only in its own assignment.

### 6.5 R1CS export

`audit` writes small instances in the iden3 `.r1cs` v1 binary format
(`https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md`, prime = BN254 scalar
field, the field circom uses), readable by circom tooling (Picus, snarkjs `r1cs info`):
wire 0 is the constant one, then the public IO (`z_in`, then `z_out`) as public outputs, then the
private witness; section 3 maps wires to this system's variable indices, and a `.wires.txt`
file beside it gives each wire's namespace path. The files are 62 MB and 94 MB, so they are not
committed; `audit` regenerates them deterministically:

| File | Bytes | SHA-256 |
|---|---:|---|
| `clearing_A4_R2_small.r1cs` (own_claim trace, a 2-row batch) | 61,523,892 | `f17f490a481e8385f56f628a727b415f9874c8934a993fbc8ffee90e5f367c6f` |
| `tapsighash_1in_1out_small.r1cs` (setup witness shape) | 93,732,112 | `302d026234c09ec599dff666e634f908b1a0fd4694da54674ac5dd1f83efc048` |

Both regenerate byte for byte (two `audit` runs gave the same digests). Constraint counts
per gadget for every audited instance are in `artifacts/audit_r1cs.json`.

### 6.6 Nova binding

- `z_i` carries every field the statement claims: the clearing state, every claim, the account
  table and the digest chain (clearing); the accumulator, txid, prevout commitment and mask
  (TapSighash). `commitment_hash` is a hash of all of `z_K`.
- The verifier calls `CompressedSNARK::verify(vk, K, z_0)` and compares the returned `z_K` with
  the one it expects; every receipt also records that the proof is rejected for `z_0` with one
  element changed, for `K - 1` steps, and with one bit of the proof flipped.

## 7. CET spends: M17 with in-circuit signatures, and the joint statement

### What changed in M17

M17 (garbled-snark-verifier `nova-bitvm3/m17`, Bitcoin Script on Nova over Pallas/Vesta) gained
Taproot in commit `f80c364`; this crate takes it as a git dependency at that commit:
- key path and tapscript on the same step machine with no new instruction (OP_CHECKSIGADD
  compiles to `SWAP TOALT CHECKSIG FROMALT ADD`; tapscript runs as script id 4, whose opcode
  count the circuit keeps at zero; 6,812 constraints);
- the native engine agrees with Bitcoin Core on **all 4,995** script vectors, including the
  **2,239 Taproot** ones (every category: applic, sighash, tapscript, siglen, opsuccess, unkver,
  alwaysvalid, spendpath, compat, compact, sig, output);
- the step circuit is satisfied with the engine's exact next state on every step of the 2,930
  valid cases (247,785 steps) and refuses the failing step of 1,042 invalid ones (833 more fail
  a claim check, 190 at compile time);
- six Taproot cases Nova-proved and checker-verified; the mutation suite on them refused every
  change to a read field (910 tampered steps).

`engine::verify_claims_deferring_taproot` checks every claim natively except the Taproot
signatures (it still applies their encoding, pubkey-type and validation-weight rules) and returns
them; `circuit::fold_case` folds and verifies an input that way.

### The binding (`src/cet.rs`)

For each input, M17's deferred signatures `(sig, key, key_path, codeseparator register)` and the
compiled program's tapleaf and annex give the bind-mode slots the TapSighash fold must have
covered, in claim order. A verifier accepts the spends when
1. every M17 input fold verifies (program consumed, no phase in progress, step count exact,
   claims consistent, non-signature claims such as CLTV checked natively);
2. the parameter accumulator rebuilt from those slots equals the TapSighash fold's, and the fold's
   signature count, txid and spent-output commitment are the transaction's;
3. the TapSighash and Secq folds end in the same authorization accumulator.

So each CET signature is checked in-circuit, not by a native claim: the message by the TapSighash
fold, the BIP-340 equation by the Secq fold. The verifier computes SHA-256 of fixed-size records
and no curve operation.

### Ground truth: DLC CET and refund on Bitcoin Core 31.1 (`tests/core_cet.rs`)

A funding output P2TR(internal key, {CET leaf `<A> CHECKSIGVERIFY <B> CHECKSIG`, refund leaf
`<h> CHECKLOCKTIMEVERIFY DROP <A> CHECKSIGVERIFY <B> CHECKSIG`}). The CET spends one funding
output through the CET leaf; the refund (nLockTime `h`) spends another through the refund leaf.
Both are signed with the native reference, accepted by `testmempoolaccept` and mined; a CET signed
for the refund leaf's tapleaf is refused. M17 runs each input (valid), and its deferred
signatures are exactly the slots that were signed (leaf, key, codeseparator).

### The joint statement (`prove-cet`)

| Fold | Steps | Primary constraints | Fold | Compress | Verify | Proof |
|---|---:|---:|---:|---:|---:|---:|
| M17, CET input | 20 (3 claims) | 6,812 per step | 1.65 s | (not compressed) | 0.07 s | |
| TapSighash bind, CET (2 signatures) | 2 | 624,543 | 1.4 s | 62.8 s | 1.21 s | 12,752 B |
| Secq256k1 BIP-340, CET | 2 | 144,959 | 0.6 s | 19.5 s | 0.32 s | 11,980 B |
| M17, refund input | 23 (4 claims, incl. CLTV) | 6,812 per step | 1.86 s | | 0.07 s | |
| TapSighash bind, refund | 2 | 624,543 | 1.5 s | 65.4 s | 1.15 s | 12,752 B |
| Secq256k1 BIP-340, refund | 2 | 144,959 | 0.6 s | 19.7 s | 0.31 s | 11,980 B |
| Clearing, liquidation drill (None, None, Margin, Fund) | 4 | 451,732 | | 38.6 s | 1.7 s | 13,112 B |

One run, 295 s, 1,909 MiB peak (`artifacts/cet_joint_statement.json`). For each transaction the
binding check passed and rejected six altered cases: signatures in another order, one signature
dropped, a signature checked for another tapleaf, for another codeseparator position, a
TapSighash fold over another transaction, a Secq fold ending in another accumulator.

The statement is a `UtxoRefL2SettlementStatementV0` with `settlement_txid` = the CET's txid and
`commitment_hash = SHA256("LIGHTNINGER/CET-SPENDS+CLEARING/V1" ‖ c_cet ‖ c_refund)`, where each
`c` hashes, under the same tag, the clearing fold's `z_0` and `z_K`, the TapSighash and Secq
folds' `z_K`, and each M17 input fold's `z_0` and `z_K`. `program_hash` names the four relations
and the M17 commit, `epoch_id` is the clearing chain's next `seq`. Run: commitment
`971b4eed…`, statement SHA-256 `c67ee0ca…`.

**What "one statement" means here.** The seven proofs (per transaction an M17 fold, a TapSighash fold and a Secq fold, plus the clearing fold) are over three curve cycles (clearing and
TapSighash Bn256/Grumpkin, Secq Secq256k1/Secp256k1 for native secp256k1 arithmetic, M17
Pallas/Vesta), so they are not one Nova fold. The statement commits to all of their public IO,
and the verifier above checks each proof and the bindings. Folding them into one proof needs a
wrapper that verifies all of them (the SP1 path in section 8). The statement does not tie the CET's
payout amounts to the clearing rows: it covers both facts side by side.

### Audit of the binding

- Spec and completeness: the specs are M17's native engine (agreeing with Core on all 4,995
  vectors) and the native BIP-341/342 reference (checked against BIP-341 vectors and Core's
  consensus). Both Core CET-pattern spends are accepted end to end.
- Mutation: six altered bindings rejected per transaction (above); M17's mutation suite on
  Taproot cases (910 tampered steps); the bind-mode TapSighash steps' variable audit (section 6.2
  table, no free variable).
- Not run: the variable-level audit (`audit`) is written for the BN254 scalar field, so M17's
  Pallas circuit has not been through it; only M17's own field-mutation suite covers it.

## 8. GPU campaign handoff

### What runs where

- **nova-snark 0.76.0 has no GPU backend.** Its features are `io` (default), `evm`,
  `experimental`, `flamegraph` and `test-utils`; folding and Spartan/IPA compression use
  halo2curves' CPU multi-exponentiation. On a Colab GPU runtime these circuits use only the
  VM's CPU cores and RAM. The folds in section 4 are CPU-bound, and memory, not time, is the
  limit at large `A`/`R`.
- **`nova-bitvm3/prover-gpu` (`nb3-prove-gpu`, garbled-snark-verifier) is SP1 6.9's CUDA shard
  prover for SP1 RISC-V guests**, the backend that proved M13's guest A (the Nova verifier as a
  guest) and M16. It does not prove Nova step circuits. As-is it proves none of this repo's
  circuits: not the clearing step, the TapSighash step, the Secq step, or M17. What it can prove
  once a guest exists, which is the route to one Groth16 proof for the joint statement:
  1. *Wrap (the BitVM3 path):* an SP1 guest that runs `CompressedSNARK::verify` on a clearing
     or TapSighash proof, as guest A does for M16's proof, and commits `z_0`, `K`, `z_K` and the
     304-byte statement as its public values; `nb3-prove-gpu` proves it, then
     `m13 shrink-wrap` / `wrap-only-v2` produce the Groth16 proof whose two public inputs are
     the statement limbs. Guest A verifies proofs on M16's curve cycle; this crate uses
     Bn256/Grumpkin (and the Secq step Secq256k1/Secp256k1), so the guest needs those engines
     (halo2curves compiles for `riscv32im`; the MSMs in the IPA verifier dominate the cycle
     count). For the joint statement the guest verifies all seven proofs and runs
     `cet::verify_binding` and M17's `verify_claims_deferring_taproot`, then commits
     `commitment_hash`. Not built.
  2. *Direct:* an SP1 guest that runs the native `clear()` over a batch chain and recomputes
     `chain_K`, with no Nova at all. `nb3-prove-gpu` would prove it as-is once the guest exists.
     Not built.

### Colab CPU sweep (Nova, this crate)

On a Linux VM with the SatsHedgeZero checkout (the workspace depends by path on
`crates/shz-dex`, `crates/shz-dlc`, `crates/shz-margin`, `crates/shz-nova-bitvm` and
`research/mnr05_bitvm3_ln_dlc`):

```
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.99.0
cd SatsHedgeZero/research/lightninger_bitvm3_clearing
cargo build --release --locked
B=target/release/lightninger-bitvm3-clearing
$B shape                                        # constraint counts, artifacts/shape_constraints.json
for K in 8 16 32 64 128; do
  /usr/bin/time -v $B prove-clearing walk:160 $K 6 4  2>&1 | tee sweep_A6_R4_K$K.log
done
for AR in "8 4" "16 8"; do set -- $AR
  for K in 8 32 128; do /usr/bin/time -v $B prove-clearing walk:160 $K $1 $2 2>&1 | tee sweep_A$1_R$2_K$K.log; done
done
$B prove-tapsighash vector                      # 7 steps, 9-input shape
$B prove-tapsighash core:annex                  # needs artifacts/core_sighash_txs.json (committed)
```

Record per run: `fold_seconds_per_step`, `compress_seconds`, `verify_seconds` and
`proof_bytes` from `artifacts/clearing_walk160_k{K}_A{A}_R{R}.json`, and "Maximum resident set
size" from `time -v`. Expected shape: folding is linear in K (about 0.8–1.1 s per step here, 20
threads), compression and verification do not depend on K (they prove one relaxed instance),
and the proof stays about 13 KB. For the CET pieces:
`$B prove-tapsighash corescript:scriptpath`, `$B prove-cet drill_fund 4` (needs
`artifacts/core_cet_txs.json`, committed) and `prove-cet walk:160 128` for the joint statement
over a long clearing chain.

`walk:160` produces 149 batches with at most 4 rows.
The step needs `R` at least the largest batch, and `A` at least the 6 accounts. Grow both only to
measure the relation's cost; the `(16, 8)` relation is 891,726 constraints per step.
Each `(A, R)` is its own relation, with its own setup and verifying key.
