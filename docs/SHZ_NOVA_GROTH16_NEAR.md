# SHZ-NOVA-G16-01: BN254 Groth16 verification on NEAR, roadmap to a Nova decider

**Research specification / November 23, 2026.** Parent: SatsHedgeZero `3db6fb889a20c630eb0d8cf00df0f64244c26ddf`, SHZ PR #3. References: `zk-rusto-no-bitcoino` PR #28 at `f6a8d129285869f339c86f1e2e7f1124bc09c37a`. Source support: NEAR SDK 5.17.2 alt_bn128 pairing host functions; `zeropoolnetwork/near-groth16-verifier` historical implementation; `ethereum/sonobe` Nova/CycleFold Groth16 + KZG on-chain decider.

## 1. Two independent statements

**Existing:** `lnmarkets/sha256-transcript-accounting/v2`, Nova 0.76.0, Pallas/Vesta, compressed Spartan/IPA. The 12,376-byte Nova proof's R1CS binds three signed 600-byte transcripts, SHA256 digest, batch-accounting state, epoch and journal hash. Source signatures, oracle acceptance, Bitcoin Taproot witnesses, and transaction construction remain partly native. The published MNR-03 `bitvm3_statement.assertion_txid` points at the real Bob-offline clearing transaction, while the signed-row journal's batch TXID names a distinct constructed transaction.

**New candidate:** `shz/nova-groth16-decider/v1` with public state commitment:

```
(network_genesis, exact_bitcoin_txid, funding_root, payout_root,
 oracle_epoch, native_pyth_receipt_hash, chainlink_report_hash,
 policy_hash, nova_init_state, nova_final_state, nova_verifier_key_id)
```

The packed public-input encoding MUST avoid mapping arbitrary 256-bit hashes into BN254 Fr by reduction: split every digest into two 128-bit limbs or use a constrained hash-to-field scheme with collision resistance. The circuit must check the claimed Nova verifier identity, row relations, and exact public input mapping. A standalone Groth16 arithmetic proof of a price average is a different versioned relation.

## 2. Why the existing Pallas proof cannot simply be reissued as Groth16

A Pallas/Vesta Nova proof verified by Spartan/IPA has its own elliptic-curve and transcript verification equations. BN254 Groth16 verification verifies a BN254 R1CS relation. To wrap the Pallas proof, the Groth16 circuit must explicitly constrain **all** Nova verification equations, including field arithmetic, IPA commitments, transcript challenges, verifier-key constants, and final-state checks. Pallas arithmetic is non-native in BN254, likely expensive. A certificate containing only the Pallas proof hash is an insufficient witness. A Sonobe BN254/Grumpkin Nova decider is a plausible alternative for *new* episodes, but historical MNR-03 Nova proofs must remain historically distinct and cannot inherit Sonobe's soundness.

## 3. Stage gates

| Gate | Required artifact | Allowed claim |
| --- | --- | --- |
| G0 NEAR BN254 host | strict binary G1/G2/Fr codec, known Groth16 vector, mutated proof/inputs rejected | BN254 pairing verification works on NEAR runtime |
| G1 oracle arithmetic | BN254 Groth16 proof of bounded two-feed mean and spread | Aggregation arithmetic proved; source auth external |
| G2 source authenticity | native Pyth signature and Chainlink signed-report verification/chain inclusion pinned to distinct trusted issuers | Source reports authentic under stated assumptions |
| G3 actual Nova decider | constrained verification of exact Nova proof or Sonobe decider with full MNR-04 statement, independent verification and soundness tests | Nova folding state proved in Groth16 |
| G4 Bitcoin binding | exact funding/spend and payout relation, oracle epoch, MNR-04 preauth and nullifiers, on-chain Core acceptance | bitcoin-exact economic relation proved |
| G5 NEAR deployment | finalized state and live NEAR testnet pairing call, measured gas, VK activation governed and immutable, replay protected | testnet operation |
| G6 cross-chain | accepted NEAR proof result linked by independent NEAR finality/inclusion evidence to BTC/BitVM authorization | cross-chain verifier composition |

For G0/G1 the prototype's contract's method is intentionally named `verify_price_mean_pilot`, NOT `verify_nova`. No production issuance or settlement path consumes this output.

## 4. Dual-Oracle arithmetic circuit

Public: unsigned `pyth_price_e8`, unsigned `chainlink_price_e8`, unsigned `index_e8`, each range-constrained to 64 bits and positive. Private: signed-difference orientation bit, absolute difference, parity bit for rounding-half-up, spread slack. The constraints enforce:

```
2 * index_e8 = pyth_price_e8 + chainlink_price_e8 + parity
abs_diff = |pyth_price_e8 - chainlink_price_e8|
50 * (pyth_price_e8 + chainlink_price_e8) - 20000 * abs_diff = spread_slack
0 <= spread_slack < 2^96, parity in {0,1}
```

All values are bounded; a forged field-wraparound assignment must fail. The inequality is equivalent to no more than 50 bps disagreement measured against the source midpoint. The two authenticated feeds are distinct economic sources; no mechanism lets duplicate Pyth relays count as a second source.

## 5. NEAR verifier deployment model

Immutable VK at initialization plus application-level governance that pins the VK digest, program version, BN254 field encoding, source registry IDs, and permitted epoch. The research contract uses one immutable VK for `PRICE_MEAN_V1`. A later `NOVA_DECIDER_V1` is deployed as a separate contract with a separately reviewed setup and VK. NEAR's `alt_bn128_g1_multiexp`, `alt_bn128_g1_sum`, and `alt_bn128_pairing_check` supply native pairing arithmetic; proofs carry ordered little-endian uncompressed field elements. Always verify against precommitted source state and canonical prices before finalizing an epoch. No mutable VK substitution by a caller.

The full wrapper verification key may be large, and proving requires a circuit-specific setup. Benchmark contract gas, upload/storage cost and any setup provenance before expecting feasible production deployment.

## 6. Follow-on plan

1. Independently reproduce the Groth16 pilot vector with arkworks in CI, import into the near-sdk mocked host and deploy to NEAR testnet with deterministic public-input bytes; record `gas_burnt`, account, block and proof/hash.
2. Reproduce Sonobe's **real Nova → BN254 Groth16/KZG decider** on a small SHA256 accumulator with public input limbs, then on the SHZ-MNR-04 application relation. Pin exact Sonobe commit, Ethereum-style verifier details, key and setup.
3. Compare native verifier output and constrained decider output for adversarially modified Pallas batch witness, wrong transcript/row, stale oracle root, wrong actual BTC transaction and mismatched payout. Do not accept proof-of-receipt shortcuts.
4. Keep existing `lnm-nova` as the regression baseline and document any migration of the proof system as a new relation, with byte-level bridge to original funding/payout commitments.

Source: https://sonobe.pse.dev/usage/decider.html ; https://docs.rs/near-sdk/latest/near_sdk/env/index.html ; https://github.com/zeropoolnetwork/near-groth16-verifier ; https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/28
