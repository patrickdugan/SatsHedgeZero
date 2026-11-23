# MNR-04 Bitcoin-exact Nova clearing

The verifier derives a Nova statement from the exact transaction that Bitcoin Core accepted. The experiment covers the three-input, five-output MNR-03 layout. It checks both offline Bob signatures under BIP341 `0x83` and derives fee-adjusted payouts using the UTXORef integer PnL function. The external verifier checks witness authorization and reconstructs every public Nova input from a trusted fixture before verifying the compressed proof.

## Transaction and proof boundary

| Check | Where enforced |
| --- | --- |
| Double SHA-256 of the 348-byte stripped transaction | Nova R1CS |
| Five little-endian output values and conservation of funding, fee and outputs | Nova R1CS |
| Exact scripts, input order, legacy TXID and SegWit WTXID | Native Bitcoin decoding and trusted fixture |
| Both Bob `0x83` signatures against same-index outputs, online `0x01` and `0x00` signatures, and Taproot control blocks | Native BIP340 and BIP341 verifier |
| Regtest block acceptance, CLTV unilateral fallback, CPFP and reorg freeze | Bitcoin Core 31.1 and the regtest harness |
| Pyth-format envelope and clearing epoch for the fixture | Native deterministic signer and trusted archive |
| Authenticated original contract set, authorization nullifiers, accounting roots, reserve permissions and revocation | Requires a separate trusted authorization layer or composed proof |

The relation identifier is `shz/mnr04/bitcoin-exact-clearing/v1`. Nova packs the raw 32-byte SHA256d digest into two unsigned, big-endian 128-bit limbs. Bitcoin explorer display reverses the digest bytes. The proof receipt shows the display TXID and WTXID. The R1CS also equates the five output amounts to their unsigned 64-bit encodings at offsets 129, 172, 215, 258 and 301. The independently reconstructed unsigned funding inputs and fee keep the conservation equation within the integer range supported by the circuit field.

The native commitment hashes the relation domain, Bitcoin genesis hash, a SHA-256 commitment to consensus-encoded ordered outpoints and funding outputs, the clearing session, the fee, and the length-prefixed full SegWit transaction. Its two public limbs are carried through Nova. The verifier authenticates their relationship to the witness and oracle through the native entry point. The circuit does not implement Schnorr or Ed25519, parse arbitrary Bitcoin transactions, or establish trust in funding profiles or signer registries.

The original MNR-03 journal recorded Testnet4 TXID `5e439e3cdf3f4f61c61edaf3bba197d32b6ab54c88fef8092ac9c7ae0bf7d5e8`. The MNR-04 archived Testnet4 fixture uses clearing TXID `ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1` and WTXID `3ffb76424476f676055bd9e549cf6759196528cfcd51e761ee7f37132db847cd`. The Testnet4 proof uses the recorded historical transaction bytes. The local run sent no public Bitcoin transactions.

For the fresh macro regtest, Bob received 90,000,000 sats across both pinned outputs. Alice realized 11,000,000 sats before fees, and Carol received 82,500,000 sats before fees. The accepted outputs are 55,000,000, 35,000,000, 71,498,500, 82,498,500 and 330 sats. The miner fee is 2,670 sats. Alice and Carol each contribute 1,500 sats to the miner fee and anchor.

## Reproduce

Build with Rust 1.99.1 and Bitcoin Core 31.1. The workflow pins the Core distribution with SHA-256. Set `RAYON_NUM_THREADS` to the CPU budget before starting.

```sh
cargo test --release --locked -p shz-nova-bitvm --features mnr04-nova mnr04::
cargo build --release --locked --bin shz --features mnr04-nova
bash scripts/bench-mnr04.sh target/release/shz /path/to/bitcoin-31.1/bin/bitcoind ./new-mnr04-output
```

The benchmark runs the isolated Core ceremony, derives the verification-key digest in a separate process, produces a compressed proof, and invokes a fresh verifier. `mnr04-verify` requires a trusted archive and verifying-key digest. Derive the key digest with `mnr04-key-hash` using the pinned source and reconstruct the key when reproducing the proof. The proof receipt includes the verifying-key SHA-256 and proof SHA-256. The larger verification key is generated locally.

An external oracle profile accepts a real envelope, a separately authenticated Pyth registry, the expected SHA-256 of that registry, and an observation time. Run `shz mnr04-oracle-external ENVELOPE REGISTRY TRUSTED_REGISTRY_SHA256 OBSERVED_AT_US`. It checks the envelope against that registry and refuses the known deterministic signer. The included proof evidence uses the deterministic signer. Operational provenance and NEAR finality require separately authenticated evidence.

## Measurements

The local CPU baseline used Nova 0.76.0, Pallas/Vesta, Spartan IPA and one Rayon thread. The A100 serves the separate Ark CUDA workload when the two are run together. These measurements are from the local preflight.

| Measure | Fresh regtest |
| --- | ---: |
| Primary augmented R1CS constraints | 195,563 |
| Secondary augmented R1CS constraints | 10,349 |
| Setup | 19.64 s |
| Folding | 0.25 s |
| Compression | 49.89 s |
| Full proving command | 76.57 s |
| Proving peak RSS | 598,620 KiB |
| Accepted-proof verification | 1.52 s |
| Compressed proof | 12,224 bytes |
| Prior MNR-03 proof | 12,376 bytes |

`evidence/mnr04/local-regtest-benchmark.json` links these measurements to the fresh Core transaction, individual controls, verification-key digest and proof bytes. `evidence/mnr04/local-regtest-core-archive.json` records the verifier's trusted fixture for reproduction. The independently verified historical Testnet4 proof and its receipt are included alongside the regtest evidence. Both compressed proofs are 12,224 bytes.

## Adversarial coverage

Native probes reject one-satoshi changes to each Bob output by checking its own `0x83` signature first. Additional probes reject swapped Bob outputs, input reordering, outpoint substitution, duplicate input use, fee or anchor changes, a changed online payout, and a changed locktime. The fixture loader rejects substituted oracle epochs and prices. R1CS tests reject modified TXID and payout limbs and a changed fee. The independent compressed verifier rejects a proof presented with the wrong public TXID. The reorg drill confirms the harness freezes its journal.

The experiment does not authorize arbitrary channel states. Tests of reused authorizations, revoked channel commitments, and a forged accounting root need those state transitions to be incorporated into the verification relation. The inherited fallback and reorg drills operate on the MNR-03 regtest state machine. Block acceptance for the fresh proof establishes the tested transaction and protects neither a later reorg nor an unauthorized application-layer clearing policy by itself.

This partial relation uses modular verification so the native trust assumptions are explicit. A composed Secq signature proof would have to bind the exact BIP341 message, pubkey and signature bytes to the same proof state. Claimed UTXORef roots and nullifier consumption would also have to be recomputed from authenticated contracts and a persistent prior state. Both `production_ready` and `bitvm3_onchain_verified` are false.

## Source pins

SatsHedgeZero base `3db6fb889a20c630eb0d8cf00df0f64244c26ddf`. Referenced upstream heads were zk-rusto-no-bitcoino PR 28 at `f6a8d129285869f339c86f1e2e7f1124bc09c37a` and UTXO-Ref PR 13 at `82105e25208903167aac3ffaaaedb9d28a8b06de`. This implementation reuses the checked-in PnL function and the published Nova crate.

## Concurrent Hyperstack pilot

The same isolated Core 31.1 replay and Nova prover completed on the CPU alongside Ark SP1 CUDA on an NVIDIA A100 80 GB PCIe VM. The MNR-04 proving command took 147.67 seconds and used 599,060 KiB peak RSS. The compressed proof was 12,224 bytes. The CPU prover and Ark each had an assigned logical CPU and a 2 GiB RAM ceiling.

The cloud Core transaction was `2b855bf2694a1f6bfede361666ee663f46ec5f25ff2a5630c4de5123c70fe23f`. The proof was verified on the VM and then independently verified after retrieval against the locally pinned verification-key digest. Both verifiers refused the modified public TXID. See the `a100-*` records in `evidence/mnr04/`.
