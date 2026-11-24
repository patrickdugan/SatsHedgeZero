# SHZ-IPA02: public-state-bound transparent IPA on NEAR

**Research registration.** Base: SHZ PR #7 `96611c63fab97804f1eba429275930a1a073efbe`. Independent upstream Nova proof source: `patrickdugan/zk-rusto-no-bitcoino` PR #28 `f6a8d129285869f339c86f1e2e7f1124bc09c37a`. Exact MNR-03 receipt remains on SHZ PR #3 `3db6fb889a20c630eb0d8cf00df0f64244c26ddf`.

## Pre-registered tests and decision gates

- **Dimension scalability:** 8, 16, 32 independently hash-derived BN254 G/H/U generator vectors; G/H share the IPA-01 derivation domain. Test genuine prover and verifier in Node, NEAR's native Rust host, and actual NEAR sandbox WASM. Record transaction receipt gas (TGas) and witness/proof bytes per dimension.
- **Immutable settlement projection:** the transparent argument is bound through Fiat-Shamir to the frozen MNR-03 price receipt, actual Bitcoin clearing TXID, archived Nova journal hash and proof hash. A domain-separated snapshot root pins the Nova verifier-key hash, separate Nova journal batch TXID, and initial/final transcript commitments. Explicitly record that the journal is a different transaction from the Bitcoin clearing.
- **Negative controls:** one-satoshi change to collateral, substitute Pyth receipt, alter journal, switch to Nova journal batch TXID, change proof hash/rounds/scalar, and forge snapshot root. All must fail.
- **Source evidence audit:** hash the actual archived Nova proof bytes; compare the journal and manifest, and reconstruct Bitcoin's TXID from full SegWit bytes without witnesses. Treat the prior receipt's reported Nova verification as historical evidence, not an in-contract verification.
- **Resource acceptance:** record dimension 8/16/32 sandbox gas within the NEAR transaction budget; if any exceeds the budget, publish the failure and performance limits. The previous 4-element pilot measured 21.690105195258 TGas.

## Soundness claims

An IPA opening proves an inner-product relation over the committed vector, assuming discrete-log hardness for the fixed generator points and Fiat-Shamir behavior. The vectors here represent *already public* MNR-03 accounting fields. The native verifier checks those values and performs the conservation arithmetic separately.

**Proof of the selected public tuple's inner product is not proof that the archived Nova folding constraints were satisfied.** The MNR-03 Spartan/IPA verifier's Pallas/Vesta R1CS and proof relation are still external to this NEAR contract.

Separate source authentication and full Nova verification from a header containing a Nova proof hash. For Bitcoin enforcement, require a circuit proving the exact transaction/witness relation, with an independent onchain path to challenge invalid settlement claims. The earlier MNR-03 journal's 450-sat fee and the actual Bitcoin clearing's 610-sat miner fee use different accounting objects. Any production settlement statement must reconcile those intentionally rather than assuming identity.

## Milestones

**IPA-02:** frozen state binding and vector-scaling benchmark. **IPA-03:** an independently reviewed complete transparent folding decider that verifies the actual Nova relation (or an explicitly migrated, equivalent relation) on NEAR. **ORACLE-04/MNR-04:** live Pyth/Chainlink authentication and Bitcoin-exact closeout binding. No milestone automatically activates production readiness.

## Frozen empirical receipt

GitHub Actions [#45202930807](https://github.com/patrickdugan/SatsHedgeZero/actions/runs/45202930807) passed the 45 Node tests, original MNR-03 archive proof hash/TXID checks, native Rust host tests, WASM compilation, and NEAR sandbox proof acceptance/tamper rejection. Actual transaction receipt gas was **37.566946552755 TGas (8 vectors)**, **63.156292021030 TGas (16)**, and **110.879454240841 TGas (32)**. The frozen receipt is `research/near_nova_ipa_02/evidence/sandbox-20261123.json`. No Pallas/Vesta Nova compressed verifier ran on NEAR in these tests.
