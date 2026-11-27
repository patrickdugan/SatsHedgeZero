# Lightninger DLC batcher: many DLC trades, one settlement, a BitVM3 claim

The testnet4 DLC demo (9f1df2c, 2ed2b68) locked one venue fill in one DLC: one funding output per trade,
1,022 CETs, one CET on chain. The batcher replaces per-trade funding with **per-participant collateral
accounts** and settles every account of an epoch in **one N-input transaction** that pays each trader
the net the venue's V3 clearing gave them. The operator pays any net the pool owes out of its own
liquidity in that transaction and is reimbursed by the pool through a **BitVM3 claim graph** that
asserts a 304-byte statement: the clearing fold's `z_K` and the settlement txid, bound by the joint
statement of 7b792af. A wrong statement is refused by a garbled Groth16 verifier whose reject label
opens the claim's disprove leaf.

Code: [`research/lightninger_dlc_batcher`](../research/lightninger_dlc_batcher) (accounts, settlement,
statement, claim graph, SP1 wrap guest), [`research/lightninger_dlc_batch_gc`](../research/lightninger_dlc_batch_gc)
(garbled Groth16 instances), [`ops/venue-bench/dlc_batch/fills.mjs`](../ops/venue-bench/dlc_batch/fills.mjs)
(venue trades). Results: [`research/lightninger_dlc_batcher/artifacts`](../research/lightninger_dlc_batcher/artifacts).

## 1. Parties and keys

| Party | Key | Role |
| --- | --- | --- |
| Trader `i` | `T_i` (x-only) | Owns collateral account `i`. `T_i` is the account's venue owner key, so the key that signs the venue's batch approvals and channel acks also signs the account's settlement input. |
| Batcher | `B` | Second key of every account's settle leaf; builds and co-signs the settlement. |
| Operator | `O` | Adds liquidity to the settlement (fronts the pool's net), claims reimbursement. In practice the batcher and the operator are one business; the scripts keep the keys apart. |
| Pool committee | `D` | Holds the pool vault (the venue's clearing fund, LP money). Presigns each claim graph. |
| Watchers | `W` | Anyone holding a reject label: evaluate the garbled verifier, spend the disprove leaf. |
| Oracle | FROST 3-of-5 | Attests `SHZ-BTCUSD-<maturity>` every 15 minutes; a maturity closes an epoch. |

## 2. Collateral account

```
account_i = P2TR( NUMS H,
                  settle: <T_i> CHECKSIGVERIFY <B> CHECKSIG
                  refund: <h> CHECKLOCKTIMEVERIFY DROP <T_i> CHECKSIG )
```

`H` is BIP-341's unspendable internal key, so there is no key path. A trader funds one account and
keeps it across trades and epochs; the venue registers the account's outpoint as the trader's channel
(today a demo allocation; `kind: "utxo"` registration points the venue at a real outpoint).

**Refund guarantee.** At any height `>= h` the trader alone spends the whole account to any address.
No other script path exists except `settle`, which needs the trader's own signature. If the batcher
stalls (never builds a settlement, never co-signs, disappears), the trader recovers the full collateral
at `h`. The refund returns principal, not PnL: a winner whose epoch never settled gets its collateral
back and holds its gain only as a claim on the venue (the venue's V3 ledger), and a loser whose epoch
never settled gets its full collateral back too. Choosing `h` trades capital lock-up against the time
the batcher has to settle; the regtest run uses `h` = funding height + 30.

## 3. Epoch and settlement

An epoch is the span of venue batches between two oracle maturities. Each venue batch clears under
V3 (`crates/shz-dex/src/routing/clearing.rs`): every row carries `net = paid - collected`, the sats
between the account and the pool, and every lane's V3 acknowledgement signs the digest of the whole
row vector. At the maturity the batcher builds one transaction:

| | Index | Content |
| --- | --- | --- |
| Inputs | `0..N` | account `i`, through the settle leaf |
| | `N` | operator liquidity (`<O> CHECKSIG` leaf) |
| Outputs | `0..N` | `collateral_i + sum over the epoch's batches of net_i` to trader `i`'s payout key |
| | `N` | `OP_RETURN "SHZB" ‖ manifest_hash` |
| | `N+1..` | operator change (and a pool return when the pool is owed) |

Signatures: trader `i` signs input `i` with `SIGHASH_SINGLE|ANYONECANPAY` (0x83), which commits to
its own input and output `i` and nothing else, so the batcher can assemble all `N` traders' inputs and
add its own without the traders seeing each other's signatures. The batcher signs every account input
with `SIGHASH_DEFAULT`, the operator its liquidity input. `fronted = sum(payouts) - sum(collateral) =
sum(net)` is what the pool owes the epoch's accounts (minus what it is owed); the operator pays it out
of the liquidity input plus the fee, and the pool reimburses it through the claim graph (section 5).

The **manifest** names the epoch: network, maturity event id, epoch id (last venue batch), batcher key,
per account (venue channel, owner key, account outpoint, collateral, account script, payout script),
and the operator's input. `manifest_hash` is a tagged SHA-256 of it, and output `N` puts it in the
settlement txid.

The **settlement relation** (`relation::check_settlement`), checked natively, in the SP1 guest and
(through the signatures) by Bitcoin:

1. input `i` spends account `i`'s outpoint, input `N` the operator's;
2. output `i` pays exactly `collateral_i + sum(net_i)` (at least 330 sats) to account `i`'s payout script;
3. every row of every batch belongs to a manifest account (nothing that moved is left out);
4. output `N` is `OP_RETURN SHZB ‖ manifest_hash`.

The batches are authenticated by the clearing fold: their full `BatchClearing` vectors, digested as
`shz_dex` does and chained from zero as `clearing_step::chain_next`, must give the chain in the fold's
`z_K`.

## 4. Statement

`UtxoRefL2SettlementStatementV0` (304 bytes, `UTXOREF_L2_SETTLEMENT_GROTH16_V0\0`), as
`shz_nova_bitvm::bitvm3` encodes it; Groth16/BitVM3 public inputs are the two big-endian 128-bit halves
of its SHA-256.

| Field | Value |
| --- | --- |
| `network_code`, `chain_genesis_hash` | regtest 0 / testnet4 1, and that chain's genesis hash |
| `contract_id` | `SHA256("LIGHTNINGER/DLC-BATCH/CONTRACT/V1" ‖ event id ‖ manifest_hash)` |
| `commitment_hash` | the 7b792af joint commitment over one transaction: `SHA256(JOINT_TAG ‖ SHA256(JOINT_TAG ‖ hz(clearing z_0) ‖ hz(clearing z_K) ‖ hz(TapSighash z_K) ‖ hz(Secq z_K) ‖ per input (i, hz(M17 z_0), hz(M17 z_n))))` |
| `settlement_txid` | the settlement (display order) |
| `program_hash` | `SHA256` of the relation list (clearing fold, TapSighash bind, Secq BIP-340, M17 @ f80c364, batch relation v1) |
| `verifying_key_hash` | `SHA256` of the clearing fold's bincode verifier key |
| `policy_hash` | `manifest_hash` |
| `epoch_id` | last venue batch of the epoch |
| `assertion_txid`, `assertion_vout` | zero (the claim transaction commits to the statement, not the reverse) |

## 5. BitVM3 claim graph

One graph per claim, after the settlement confirms (the In-and-Out-Burger graph of Spiral 76071a0 with
the pool as vault and the batch statement as claim):

```
vault V   NUMS + { claim:   <D> CHECKSIGVERIFY <O> CHECKSIG
                   reclaim: <144> CSV DROP <D> CHECKSIG }
   |  claim tx: D presigns at setup, O signs to start the window
   v
claim K   NUMS + { payout:   <6> CSV DROP <D> CHECKSIG                  -> operator (D presigned)
                   disprove: SHA256 <H(reject)> EQUALVERIFY <W> CHECKSIG -> back to the pool }
          + OP_RETURN "SHZC" ‖ claim_id
claim_id = SHA256(tag ‖ statement SHA-256 ‖ Groth16 key SHA-256 ‖ ciphertext commitment ‖ H(accept) ‖ H(reject) ‖ payout script)
```

The vault holds `max(fronted, 0) + settlement fee` plus the graph's own fees. The operator garbles the
Groth16 verifier (gsv's streaming BN254 verifier, Free-XOR and half gates) for the claimed statement's
public inputs, commits the ciphertext stream's BLAKE3 hash and both output-label hashes in `claim_id`,
and hands watchers the input labels of its proof and of the claimed statement's limbs. A watcher
regarbles nothing: it evaluates the streamed tables, re-hashing them against the commitment. A valid
proof of the claimed statement yields the accept label, which opens nothing, and the payout matures
after 6 blocks. Any other statement yields the reject label: the watcher spends the disprove leaf and
the vault's sats return to the pool; the operator's payout input is then spent.

## 6. What each party trusts, step by step

| Step | Trader trusts | Bitcoin enforces |
| --- | --- | --- |
| Deposit | nothing beyond Bitcoin and its own key | the account is spendable only by settle (`T_i` and `B`) or refund (`T_i` after `h`) |
| Trading (venue batches) | the venue's matching and V3 clearing arithmetic; the trader signs each batch approval and each V3 lane ack over the batch's whole net vector, so it knows its `net` per batch | nothing yet (channel adapter is simulated on testnet) |
| Settlement signing | its own check that output `i` = `collateral + sum(net)` from the acks it signed | its 0x83 signature covers input `i` and output `i`: any change to its payout (amount or script) invalidates the signature (regtest: Core refuses a settlement paying account 3 one sat less, `Invalid Schnorr signature`) |
| Batcher stalls | nothing: refund at `h` | refund leaf; the batcher cannot spend an account without the trader's signature |
| Operator fronting | nothing: its payout is in the settlement it signed | operator liquidity input; traders never depend on the claim graph |
| Pool reimbursement (pool's trust, not the trader's) | — | who may start a claim (`D` presign + `O`), the claim's commitments, the 6-block window, that only this instance's reject label stops the payout |

The pool's remaining trust in the claim graph, as in FlatCheck FC03 / In-and-Out-Burger T1–T3:
**T1** the tables are a correct garbling of the Groth16 verifier for the committed key (no
cut-and-choose here; gsv has cut-and-choose and soldering modes that are not wired in);
**T2** the operator delivers the input labels for its proof and the claimed statement (input labels are
not authenticated on Bitcoin); **T3** the committee's presigned graph stands in for a covenant
(1-of-n deletion). Plus: one honest watcher online within 6 blocks; the Groth16 key's setup; and, for
the SP1 wrap, SP1's Groth16 ceremony.

What the SP1 guest proves and what it leaves out: it verifies the clearing `CompressedSNARK` in the
zkVM, recomputes the batch chain and checks it against `z_K`, checks the settlement relation on the
raw settlement, checks that the TapSighash fold's `z_K` names the settlement's txid and spent outputs,
and commits the statement. The TapSighash, Secq and M17 proofs are verified natively by watchers, not
in the guest; their outputs enter `commitment_hash` as given (each extra Nova verification would add
tens of billions of zkVM instructions). The guest does not prove the settlement is confirmed: a
production guest adds SPV inclusion under a header chain (M16 does this for mainnet) so the pool does
not have to check confirmation itself.

## 7. Built and measured

All on this laptop (Windows, Bitcoin Core 31.1, release builds), 2026-11-27/28.

**Venue epoch** (`artifacts/venue_batches.json`). Eight demo accounts on the live testnet venue: four
$100 pairs at 10x open (batches 306–309), the mark moves $18.71 in 121 s, the eight close in a ring
against new counterparties (310–313). Every batch committed with all approvals and V3 acks (1.5–2.4 s
each). Nets: −28, +28, −36, +36, −80, +80, −80, +80 sats (sum 0; the pool's cash ends where it began,
1,000,114). A first attempt that signed the eight accounts one after another missed the venue's 10 s
deadline and its four batches (302–305) aborted; nothing moved.

**Regtest phase A** (`tests/core_batch.rs`, `artifacts/regtest/{receipt,txs,manifest,batches}.json`):

| | |
| --- | --- |
| funding `22510e4b…a281` | 8 accounts × 20,000 + liquidity 100,000 |
| settlement `27e753de…9eb0` | 9 inputs, 10 outputs, 17 signatures (8 × 0x83, 8 × batcher, 1 operator), 1,382 vB, fee 2,764, mined at 141; payouts 19,972 / 20,028 / 19,964 / 20,036 / 19,920 / 20,080 / 19,920 / 20,080; fronted 0 |
| settlement paying account 3 one sat less | Core: `Invalid Schnorr signature`; relation: `output 3 pays 20035 sats, the clearing gives account 3 20036` |
| account 0 refund (CLTV 140) | `non-final` at 139, accepted at 140, `missing-inputs` once the settlement is mined |

**Proofs and statement** (`dlc-batcher prove regtest 8 2`, `artifacts/regtest/joint_statement.json`, 213 s total):

| Fold | Steps | Primary constraints | Fold | Compress | Proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| V3 clearing, table 8, 2 rows/batch | 8 | 393,479 | 3.6 s | 22.4 s | 13,368 B |
| TapSighash bind (9-in/10-out shape) | 17 | 1,316,051 | 15.3 s | 82.7 s | 13,064 B |
| Secq256k1 BIP-340 | 17 | 144,959 | 3.7 s | 15.6 s | 11,980 B |
| M17, per settlement input | 20 (17 for the operator's) | — | 1.1–1.6 s each | — | — |

Binding verified with 7 altered bindings rejected (signatures swapped, operator's dropped, 0x83 claimed
as 0x00, another tapleaf, another transaction, other spent outputs, another Secq accumulator). The
settlement relation holds with 4 negatives rejected (a row's net +1, accounts reordered, one account
left out, a payout key changed). Statement SHA-256 `b05dccf54f9308ce47317ebf4b767f4570fb0ab186105ef1260c5ba1e9c4cf32`
(`contract_id 9e76cce4…`, `commitment_hash 7d764833…`, `verifying_key_hash` = clearing key
`c660c21a…`, `policy_hash` = manifest `e881d969…`, epoch 313, event `SHZ-BTCUSD-20261127T1545Z`).
`shz_nova_bitvm::bitvm3::UtxoRefL2SettlementStatementV0::decode` round-trips it, and the guest's own
relation (`relation::guest_statement`) rebuilds the same 304 bytes natively.

**Garbled verifier** (`research/lightninger_dlc_batch_gc`, `artifacts/regtest/garbled/`). The
stand-in Groth16 key pins the statement's limbs (key `2cadec56…`); SP1's Groth16 of the guest replaces
it when the Neon run returns. Each claim instance garbles gsv's streaming BN254 Groth16 verifier once to
commit (849–914 s), then regarbles into a channel while the evaluator runs (1,218–1,277 s); the
evaluator's BLAKE3 of the stream equals the commitment in both. This build used software AES (no
`target-feature=+aes`); the 658 s / 857 s probe run alone on the machine.

| Claimed statement | Native Groth16 | Garbled verdict | Label |
| --- | --- | --- | --- |
| `b05dccf5…` (the settlement mined) | accepts | accept | accept label (`H = ca8f21f3…`) |
| `313b611c…` (settlement_txid of the tampered settlement) | rejects | reject | reject label (`H = 6ed44de5…`) |

**Regtest phase B** (`dlc-batcher claim-graph`, `artifacts/regtest/claim_graph.json`, same chain,
settlement confirmed): vaults of 3,564 sats (fee reimbursement; fronted is 0 this epoch).

| Graph | Step | Core |
| --- | --- | --- |
| honest | claim `a207458a…` | accepted, mined |
| | disprove with the evaluated (accept) label | refused, `OP_EQUALVERIFY` |
| | payout one block after the claim | `non-BIP68-final` |
| | payout after 6 blocks `a1fb1993…` | accepted, mined, operator paid |
| wrong statement | claim `e08f5869…` | mined |
| | disprove with a label one bit off the reject label | refused, `OP_EQUALVERIFY` |
| | disprove with the evaluated reject label `b7a3e656…` | accepted, mined, sats back to the pool |
| | operator's payout after 6 blocks | `missing-inputs` |

**SP1 wrap guest** (`sp1/`): builds under SP1 6.9.0 (ELF `b74a4ac9…`) with the M15 patches (vendored
halo2curves with `uint256_mulmod`, sha2 and sha3 precompiles). Executed in SP1's executor (WSL2) on
the regtest inputs: **163,595,198,099 instructions, 3,557 s, exit code 0**, public values byte-equal to
the statement `b05dccf5…` (ELF `b74a4ac9…`). Rebuilt from main after the relation gained `carry_in` /
`carried` (91dae33, `guest_in.bin` re-encoded): ELF `bafd2c1d…`, 163,595,198,247 instructions,
4,037 s, exit 0, same statement. Most of that is decoding the 131,995,888-byte clearing key with compressed
points; M15's raw-key encoding (`m15/keyconv`) cut guest A's decode by about 70% and is not applied
here. The host's refusal cases (settlement paying account 3 one sat less, a batch row's net +1, a
flipped proof bit, a TapSighash `z_K` naming another transaction) each re-run the whole guest and
were not completed (the run was stopped to free WSL memory).
Proving it is the Neon prompt in [`sp1/NEON_PROMPT.md`](../research/lightninger_dlc_batcher/sp1/NEON_PROMPT.md).

**Testnet4**: the builder (`cargo test --release --test core_batch testnet4 -- --ignored`, collateral
1,000 per account, liquidity 2,000, 1 sat/vB, refund at tip + 432) signs funding, settlement, refund
and the tampered settlement and checks them as packages with `testmempoolaccept`; it is not run yet
for lack of a funded wallet on this machine (the staging wallet holds 2,954 unconfirmed sats after the
single-trade demo's broadcast; `m16` is empty).

## 8. Not built

- DLC outcomes for positions still open at maturity: the batch settles realized `net` (the regtest
  epoch's eight accounts are flat after the close round). Open positions marked at the attested price
  need per-outcome adaptor signatures (0x83, one per CET outcome per account) as in the single-trade
  demo's 1,022 CETs; the oracle attestation then completes every account's signature for the attested
  outcome and the trader can be offline at maturity.
- Real `kind: "utxo"` accounts on the venue: the eight venue accounts are demo allocations; the regtest
  and testnet4 accounts reuse their owner keys and venue channels in the manifest.
- Cut-and-choose of the garbled verifier, on-chain authentication of input labels, SPV of the settlement
  inside the guest, and the TapSighash/Secq/M17 verifications inside the guest.

## 9. A/B: script leaf (A) vs MuSig2 key path (B)

Both variants are built by [`tests/ab.rs`](../research/lightninger_dlc_batcher/tests/ab.rs) from the same
venue batches (306..313), the same eight accounts and the same oracle event
(`SHZ-BTCUSD-20261127T1345Z`, CET 527 of the single-trade demo). One funding transaction creates both
variants' accounts, liquidity and CET outputs. Every signature a trader contributes is an adaptor
signature under CET 527's anticipation point, completed with the oracle's attestation scalar.

- **A:** accounts `<T> CHECKSIGVERIFY <B> CHECKSIG` plus the CLTV refund leaf, on the NUMS internal
  key. The trader signs a BIP-340 adaptor (shz-dlc `adaptor_sign`) and the batcher a plain signature.
  The CET funding output uses `<pk0> CHECKSIGVERIFY <pk1> CHECKSIG`.
- **B:** accounts with internal key MuSig2(trader, batcher) (BIP-327, `crates/shz-dlc/src/musig2.rs`),
  same CLTV refund leaf. One MuSig2 adaptor signature per account input: nonces bound to the
  sighash, partial signatures verified, then aggregated and completed. The CET funding output is
  MuSig2(pk0, pk1) plus a refund leaf. The operator's liquidity is a key-path P2TR.

| | A (script leaf) | B (MuSig2 key path) |
| --- | ---: | ---: |
| Settlement, N = 8 (9 inputs, 10 outputs) | 1,382 vB (5,528 WU), 17 signatures | **964 vB** (3,856 WU), 9 signatures |
| Settlement, N = 7 | 1,231 vB | 864 vB |
| Per-input marginal | 151 vB | **100 vB** |
| CET (1 input → Bob, Alice, anchor) | 247 vB | **197 vB** |
| Funding | identical outputs (P2TR, 43 B each); the shared funding is 971 vB for 21 outputs | same |
| Signing rounds, settlement, per account | 1 (trader → batcher: adaptor signature) | 2 (nonces, then partial signatures) |
| Bytes exchanged, settlement, per account | 65 | 196 (2 × 66 nonces + 2 × 32 partials) |
| Signing rounds, CET | 1 | 2 (nonces for every CET can go in one batch ahead of time) |
| Bytes per CET | 130 (two adaptor signatures) | 196 |
| All 1,022 CETs of the demo grid: sign and verify | **1.03 s**, 132,860 bytes | 6.68 s, 200,312 bytes |
| Settlement build and sign (N = 8, this laptop) | 0.012 s | 0.061 s |
| Regtest (Core 31.1) | settlement, CET mined (height 112); tampered settlement refused; refund `non-final` | same |
| Testnet4 (`testmempoolaccept`, not broadcast) | settlement `af10ba81…`, CET `16c9f34c…` accepted | settlement `060fa639…`, CET `abf0238f…` accepted |
| Prover: signatures folded (TapSighash bind + Secq steps) | 17 | 9 |
| Prover: M17 steps, account input / operator input | 20 / 17 | 17 / 17 |
| Prover: TapSighash step constraints | 1,304,502 | 1,304,502 |
| Prover: compress seconds, peak RAM | from the Colab run (`artifacts/ab/A/README.md`) | from the Colab run (`artifacts/ab/B/README.md`) |

Reading: B saves 51 vB per account input (one 65-byte signature on the key path, against two signatures
plus a 70-byte leaf script and a 65-byte control block) and 50 vB per CET, and folds half the
signatures. It costs a second signing round and about 6.5× the signing CPU on the CET grid. The
MuSig2 session recomputes the key aggregation in each signing and verification call (5 times per CET);
caching it per funding output removes most of that gap, which this run does not do.
Measured times come from one run on this laptop. Prover inputs for both variants and the commands
are in [`artifacts/ab/`](../research/lightninger_dlc_batcher/artifacts/ab/). Locally only a K = 2
smoke check ran (`ab_prover_inputs_smoke`); the full proofs run on Colab.
