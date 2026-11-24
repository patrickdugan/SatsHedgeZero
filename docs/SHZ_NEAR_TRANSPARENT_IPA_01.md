# SHZ-NOVA-IPA-NEAR-01: Transparent-verifier acceptance dossier

Date: 2026-11-23. Owner: SatsHedgeZero protocol research. Status: **unverified NEAR-WASM feasibility pilot; native JS proof tests pass**.

## Decision

The established SHZ Pallas/Vesta Nova v2 (Spartan/IPA compressed proof) verifier reconstructs a 101,826,448-byte serialization of its verifier key. NEAR provides native BN254 G1 multiexponentiation and pairing host functions, but no native Pallas/Vesta arithmetic. A *new transparent BN254 inner-product verifier* therefore offers a bounded experiment for the NEAR execution and gas budget without changing the frozen Nova receipt, introducing toxic waste, or assuming a Groth16 wrapping circuit exists.

## Security boundary

The verifier exercises a genuine Fiat-Shamir inner-product argument with fixed independently derived BN254 generators. It establishes equality of a publicly committed vector's inner product, under the discrete-log assumption and hash-to-curve/Fiat-Shamir assumptions. Its public input is a demo BTC/USD midpoint, and its generators must be audited before adversarial use. This experiment does not provide witness privacy or a complete knowledge-extractor analysis; the folded final scalars are public.

The NEAR native host checks points and canonical scalar encodings; the contract rejects invalid scalar ranges, stale public-price agreement, tampered proof scalars, missing epoch binding and unrecognized generator parameters. The acceptance result alone is **not** a Pyth/Chainlink signature verification, a Nova folding verification, a NEAR finalized oracle price, a Bitcoin transaction authorization, or a BitVM3 proof.

The precise protocol transition to be proven at later stages is `VerifiedSignedPythReport ∧ VerifiedChainlinkReport ∧ AlignedEpoch ∧ ExactIndex ∧ ValidNovaFoldingProof ∧ BitcoinExactClearing`, with each component binding identical epoch and payment commitments. Where external verification remains trusted, disclose that fact in the proof receipt.

## Evidence before CI

- Local Node.js `node --test research/near_nova_ipa/test/ipa.test.mjs`: **12/12 pass** on reference BN254 group arithmetic, proof generation, deterministic generator derivation, epoch tampering, mean/spread policy, scalar and curve mutation.
- NEAR Rust host-unit result: **pending CI**; local environment has no `cargo` or `rustc`.
- Compiled WASM & real near-sandbox gas: **pending CI**.
- Actual Pallas/Vesta Nova proof verified inside NEAR: **false**.
- Production protocol authorization: **false**.

## Independent gates

A verified sandbox receipt must record the exact compiled WASM artifact hash, successful valid proof, failed altered proof, receipt gas burnt, max prepaid gas, and toolchain revision. A prepared proof bundle/transaction receipt produced by the prover does not establish independent public acceptance unless an actual verifier has run it.

Keep this isolated from stacked Groth16 PR #6. The Groth16 arithmetic pilot is a comparison baseline only; the transparent proof path contains no Groth16 setup or secret parameter ceremony.

## Executed NEAR sandbox acceptance (2026-11-23)

GitHub Actions [run 45190204126](https://github.com/patrickdugan/SatsHedgeZero/actions/runs/45190204126) **passed** at source commit `55ec16eb7c18f81f0e882c7047d791a6260abfe1` using `near-sandbox@0.3.5` and `near-api-js@7.5.3`. Native host tests, Wasm compilation, deterministic transparent proof fixture, the real sandbox's valid-proof acceptance and mutated-proof rejection all passed. The actual raw transaction receipt reports **21,690,105,195,258 gas**, or **21.690105195258 TGas**. The receipt is retained as a GitHub Actions artifact and mirrored into `research/near_nova_ipa/evidence/sandbox-20261123.json`.

**Acceptance limited to IPA-01:** a four-element BN254 transparent inner-product argument. The measured gas does not extrapolate to Pallas/Vesta Nova/Spartan verification. Pyth and Chainlink source authentication, actual Nova folding verification, production deployment, and DLC settlement authority remain gated off. The price vector is publicly reconstructible, so this toy proof supplies computational-feasibility evidence rather than private witness security.
