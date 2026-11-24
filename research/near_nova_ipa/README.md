# SHZ-NOVA-IPA-NEAR-01: Transparent verifier feasibility

This isolated experimental contract verifies a **genuine transparent inner-product argument** on BN254 using NEAR's native `alt_bn128_g1_multiexp` host operation. The nine fixed BN254 generators are deterministically derived from `SHA256("SHZ/NEAR-IPA-BN254/GENERATOR/V1" || label)` by searching for an x-coordinate whose `x³+3` has an even-y square root. Their derivation and full byte encodings are reproducible in `fixtures/build_fixture.mjs`; no toxic-waste ceremony is used. This is a *feasibility and gas benchmark* for native NEAR transparent verification, **not an implementation of Nova verification or a production oracle**.

## Frozen upstream references

- SatsHedgeZero base: `3db6fb889a20c630eb0d8cf00df0f64244c26ddf`, PR #3.
- Frozen MNR-03 Testnet4 receipt: `evidence/mnr03_testnet4_bob_offline_receipt.json` and its Pyth receipt hash `7a0a6d8d97a231fd0adcef7892d29232d131adfe8c92391deb228b9dd598e51e`.
- Nova source: `patrickdugan/zk-rusto-no-bitcoino` `f6a8d129285869f339c86f1e2e7f1124bc09c37a`, `LNMarkets/nova`, `nova-snark 0.76.0`.
- NEAR SDK: `near-sdk 5.17.2`; native BN254 host multiexp ABI uses `[G1.x(32LE), G1.y(32LE), Fr(32LE)]` per term.

## Exact prototype statement

The 4-element vector is `a=[pyth_price_e8, chainlink_price_e8,0,0]` and `b=[1,1,0,0]` on BN254 Fr. The contract calculates the public commitment `C=Σ a_i G_i+Σ b_i H_i` from caller-supplied prices, and derives the public `c=sum(a_i*b_i)`. It checks `mean_e8 = floor(c/2)` and a 50-basis-point pairwise spread using checked `u128` arithmetic. The IPA proof establishes `P=C+cU` with the usual two rounds of `(L,R)` and Fiat-Shamir challenges, final `(a',b')`, and verifier equality `P' = a'G' + b'H' + (a'b')U`.

This demonstrates transparent polynomial/inner-product verification using NEAR G1 host functions. Prices are **not independently authenticated by this contract**. The proof is intentionally redundant for this disclosed-price toy statement. Real settlement authorization requires verifying Pyth and Chainlink provenance, folding-state transitions, and Bitcoin exact transaction relations.

## Run and measure

```sh
node research/near_nova_ipa/fixtures/build_fixture.mjs
node --test research/near_nova_ipa/test/ipa.test.mjs
cargo test --manifest-path research/near_nova_ipa/near_contract/Cargo.toml
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown --manifest-path research/near_nova_ipa/near_contract/Cargo.toml
npm --prefix research/near_nova_ipa install
SHZ_IPA_SANDBOX_RECEIPT=/tmp/ipa-receipt.json npm --prefix research/near_nova_ipa run sandbox
```

The sandbox integration executes a real NEAR-WASM contract, tests a tampered proof and records **receipt gas burnt**. Native `near-sdk` unit-test gas is only a mocked estimate. The sandbox environment must have its normal binary download support.

## Advancement gates

1. **IPA-01:** independently verify the fixed-dimension BN254 inner-product argument on actual NEAR WASM with valid/mutated cases and record total gas and WASM size.
2. **IPA-02:** benchmark realistic IPA vector dimensions and pin verifying parameters for a transparent folding decider. Reject witnesses that copy public observations without proving their origin.
3. **IPA-03:** bind Nova's *actual* Pallas/Vesta compressed proof or migrate to a reviewed transparent BN254-based folding relation. Produce real cross-field composition, verifying the folding challenge and public state, then benchmark gas.
4. **ORACLE-04:** authenticate two independent BTC/USD source reports under pinned keys and a precommitted timestamp policy, bind accepted index/root to the folding public input and NEAR challenge contract.
5. **SHZ-MNR-04:** require Bitcoin-exact serialized transaction and BIP341 signatures before lifting `can_authorize_nova` or DLC readiness flags.

The frozen Nova verifier reconstructs an approximately **101,826,448-byte serialized verifier key** and performs Pallas/Vesta Spartan/IPA arithmetic. This BN254 native-host research verifier is **not** that verifier. No accepted IPA-01 proof counts as a valid Nova proof. `can_authorize_nova=false`, `can_authorize_dlc_settlement=false` and no mainnet funds.
