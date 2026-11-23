# SHZ-NOVA-IPA-NEAR-02: MNR-03 frozen public-state binding and IPA dimension benchmarks

This is an isolated continuation of SHZ-NOVA-IPA-NEAR-01, stacking on PR #7 at `96611c63fab97804f1eba429275930a1a073efbe`.

## Verified relation (limited)

`shz/near-ipa02-frozen-mnr03-state/v2` proves the transparent BN254 inner-product relation with known independently hash-derived generators, the IPA public commitment, and the **selected frozen MNR-03 public accounting tuple**:

- Epoch 177, three contracts, 3,900 sats Nova journal collateral, 3,450 sats Nova journal payout and 450 sats Nova journal fee.
- Pyth-format receipt hash `7a0a6d8d...`, real Bitcoin clearing TXID `ca258b44...`, Nova journal hash `d87e0892...`, archived compressed Nova proof hash `14e9985b...`.
- A SHA256 snapshot root additionally pins the Nova prover key hash, the **distinct journal batch TXID** `5e439e3c...`, and the archived initial/final Poseidon transcript commitments. The root is embedded in the research verifier as a fixture pin.

For vector dimension `n in {8,16,32}`, public vectors are:

```
a=[3, 3900, 3450, 450, 0, ..., 0]
b=[1, 5, -5, -5, 0, ..., 0] mod BN254.Fr
c=<a,b>=3 + 5*(3900-3450-450)=3 mod BN254.Fr
```

The NEAR contract independently checks each public amount and commitment, then uses BN254 multiexponentiation to verify the inner-product argument over `log2(n)` rounds. This is a cost and binding experiment. Most of these values are public, so IPA here has no privacy advantage and the verifier already computes the accounting equality itself.

The `state_root_hex` binds the selected recorded MNR-03 public inputs. Its archived receipt is checked separately by `evidence_gate.mjs`: public journal/statement consistency, archived proof SHA256, genesis/epoch pins, and actual Bitcoin TXID reconstruction from the complete SegWit transaction. These checks **do not constitute an on-chain Nova proof verification**.

## Scope boundary

- Real transparent BN254 IPA proof: **yes**.
- Frozen MNR-03 selected public fields and source-report hash included in the Fiat-Shamir transcript: **yes**.
- Original Nova Pallas/Vesta/Spartan compressed proof verified by NEAR: **no**.
- Original Pyth Pro signer or independent Chainlink report verified: **no**.
- Bitcoin BIP341 witnesses proved inside the IPA: **no**.
- Existing MNR-03 journal `batch_txid` equals actual Bitcoin clearing `txid`: **no**; the mismatch remains recorded.
- Authorization of settlement funds or oracle epochs: **disabled**.

The negative tests must reject changes to any source hash, original Bitcoin TXID, frozen accounting amount, proof scalar, proof L/R point and proof length. Acceptance of the generated IPA must never be promoted into `nova_verified=true`.

## Run

```
node research/near_nova_ipa_02/fixtures/build.mjs
node --test research/near_nova_ipa_02/test/*.test.mjs
node research/near_nova_ipa_02/evidence_gate.mjs
cargo test --manifest-path research/near_nova_ipa_02/near_contract/Cargo.toml
rustup target add wasm32-unknown-unknown
RUSTFLAGS='-C target-feature=-reference-types,-bulk-memory,-multivalue,-nontrapping-fptoint,-sign-ext,-extended-const' cargo build --release --manifest-path research/near_nova_ipa_02/near_contract/Cargo.toml --target wasm32-unknown-unknown
npm --prefix research/near_nova_ipa_02 install
npm --prefix research/near_nova_ipa_02 run sandbox
```

Compare measured sandbox gas for dimensions 8, 16 and 32 against the prior 4-vector **21.690105195258 TGas** pilot. Save the exact gas receipts and deployment size. A dimension-32 verification exceeding the gas budget is a performance failure and should be recorded, not hidden by dropping the test.

## Remaining full-Nova decider work

The original compressed Nova proof uses `nova-snark 0.76.0`, Pallas/Vesta, a Spartan/IPA verifier and a reconstructed ~101.8 MB verifier key. The small BN254 IPA arguments proven here are a separate relation.

To verify its correctness trustlessly on NEAR, either:

1. Implement a fully constrained transparent verifier of the **exact existing** Nova proof, including its evaluation arguments, folding challenge, R1CS shape, verifier-key identity, journal pin, and consistency with original Bitcoin settlement. Need Pallas/Vesta arithmetic in NEAR WASM; estimated resource cost is unknown and possibly prohibitive.
2. Migrate to a reviewed transparent folding/decider stack with a compatible NEAR BN254 IPA proof, independently proving every folded constraint and binding it to the exact original MNR-03 public statement. This requires a new verified circuit and new proof artifacts. It is not a format conversion of the existing 12,376-byte proof.

The full MNR-04 Bitcoin-exact relation, native Pyth and Chainlink source authentication, and NEAR finality are separate acceptance gates. Keep `production_ready=false`, `can_authorize_nova=false` and `can_authorize_dlc_settlement=false` throughout IPA-02.
