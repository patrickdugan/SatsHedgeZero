# SHZ-ORACLE-03 / CHANNEL-03 / MNR-03 Acceptance & Evidence Matrix

Builds directly off [`16562a15ef7c4332318a367398a40a80ae6f3455`](https://github.com/patrickdugan/SatsHedgeZero/commit/16562a15ef7c4332318a367398a40a80ae6f3455) on branch `research/near-pyth-channel-01-20261123`, closing the next engineering gates listed in [`SHZ_ORACLE02_CHANNEL02_ACCEPTANCE.md`](./SHZ_ORACLE02_CHANNEL02_ACCEPTANCE.md) and [`SHZ_NEAR_PYTH_CHANNEL_NETTING.md`](./SHZ_NEAR_PYTH_CHANNEL_NETTING.md).

---

## 1. Closed Gates in `ORACLE-03 / CHANNEL-03 / MNR-03`

| Gate | Implementation | Verification Evidence |
| --- | --- | --- |
| **Native Rust Pyth Pro (`pyth-lazer`) Ed25519 + LE `PayloadData` Verifier & Governed Signer Rotation** | `crates/shz-oracle/src/pyth_lazer.rs` + `crates/shz-oracle/src/fraud_proofs.rs` (`CanonicalReferenceEvidence::NativePythProDualConsensus`) | `cargo test -p shz-oracle --locked` (`6/6` tests passing, including official `pyth-lazer-public` wire sample parity, threshold guardian key rotation/revocation, and native Pyth Pro + TradeLayer VWAP dual-consensus slashing) |
| **NEAR Bonded Fraud-Guard Multi-Key Rotation, Replay Nullifiers & Source-Substitution Slashing** | `research/near_pyth_channel/near_contract/src/lib.rs` (`PinnedPythSigner`, `rotate_pyth_signers`, `revoke_pyth_signer`, `consumed_payload_hashes`, `consumed_event_ids`, `submit_source_substitution_challenge`) | `cargo test --manifest-path research/near_pyth_channel/near_contract/Cargo.toml --locked` (`2/2` `VMContextBuilder` unit tests) + `cargo check --target wasm32-unknown-unknown --locked` |
| **Independent JS Bitcoin Commitment, Revocation-Ordering, Staggered CLTV & Reorg Verifier** | `research/near_pyth_channel/src/wallet_settlement.mjs` + `research/near_pyth_channel/test/wallet_settlement.test.mjs` | `npm --prefix research/near_pyth_channel test` (`61/61` tests passing, including `UTXORef` cross-repo NUMS `P2TR` vector parity, `0x83`/`0x01`/`0x00` BIP-341 `TapSighash` verification without `bobSecretKey`, SHA-256 prior-state revocation ordering, `>= 6`-block CLTV hop staggering, and `HALTED_ON_REORG` ledger freeze) |
| **`SHZ-MNR-03`: 3-Party Multilateral Atomic Clearing with Bob 100% Offline (`0x83`) + Oracle-Bound Nova/BitVM3 Bridge** | `crates/shz-utxoref/src/mnr03.rs` + `crates/shz-nova-bitvm/src/oracle_epoch_bridge.rs` + `bins/shz-cli/src/mnr03_harness.rs` | `cargo test --workspace --locked` (`32/32` Rust tests passing) + `cargo clippy --workspace --all-targets --locked -- -D warnings` (`0` warnings) |
| **Bitcoin Core v31.1 Regtest + 6-Block Reorganization Watchtower Drill + Unilateral `CLTV` Fallback + CPFP Child + `lnm-nova` SNARK** | `shz mnr03-regtest` -> `evidence/mnr03_bob_offline_core_nova_receipt.json` + `evidence/mnr03_nova_bundle/` | Confirmed 3-input, 5-output Bob-offline clearing tx `bfe5511f84b6d3cf9cc8bf19b7cca244302041464435f81b46bbad69765cecb4` (`599 vB`), CPFP child `9018543e91b71689a7bf4ee62eb41a2e56d5ff0bc3811735851f444dd2b91d1c`, 5 Core consensus rejections, 6-block `invalidateblock` reorg freeze, unilateral `CLTV` fallback (`a17a9d81...` / `f41e26cc...`), and `12,376B` `CompressedSNARK` (`044fbe98242da389e5113ff0d68bf06047006105581117b92d2671da69c61677`) |
| **Live Public Bitcoin Testnet4 3-Party Bob-Offline (`0x83`) Broadcast + `lnm-nova` SNARK** | `shz mnr03-testnet4-live` -> `evidence/mnr03_testnet4_bob_offline_receipt.json` + `evidence/mnr03_testnet4_nova_bundle/` | Live Testnet4 funding tx [`2ac7713ebe39faee61f73d1cd5440a0ad3432c487da967709e820b391c51d7b3`](https://mempool.space/testnet4/tx/2ac7713ebe39faee61f73d1cd5440a0ad3432c487da967709e820b391c51d7b3) + live 3-input, 5-output Bob-offline clearing tx [`ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1`](https://mempool.space/testnet4/tx/ca258b44b2700a493360512bc5d6f7f4640ed794edd90ed6d3560d61af8470c1) (`599 vB`, anchor height `162,934`) + `12,376B` `CompressedSNARK` (`14e9985b67569c2db18b10eb43e0036cfe76fac21ab2674b35ae6324fe08a043`) |

---

## 2. How `SHZ-MNR-03` Resolves Multilateral Clearing When Bob Is 100% Offline

In [`SHZ_NEAR_PYTH_CHANNEL_NETTING.md`](./SHZ_NEAR_PYTH_CHANNEL_NETTING.md), the previous public Testnet4 3-party pilot (`c9136b4e...`) signed all three inputs interactively with all three parties online. `SHZ-MNR-03` eliminates any requirement for `bob_sk` after contract origination (`t = 0`):

1. **Origination (`t = 0`, Bob Online):**
   - `U_AB` (`Alice Long` vs `Bob Short`) and `U_BC` (`Bob Long` vs `Carol Short`) use 3-leaf `Mnr02TaprootTree` NUMS `P2TR` scripts (`Leaf 0`: `<P_Online> OP_CHECKSIGVERIFY <P_RouterGuard> OP_CHECKSIGVERIFY <P_Bob> OP_CHECKSIG`, `Leaf 1`: grace-delayed `OP_CLTV` 2-of-2 unilateral CET, `Leaf 2`: refund-delayed `OP_CLTV` 2-of-2 refund).
   - For each price outcome, Bob pre-signs a 1-in/1-out `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) adaptor signature committing to his exact bilateral residual output.
   - `bob_sk` is immediately dropped (`bob_online_during_clearing_or_proving: false`).
2. **BIP-341 Position-Independence at Multilateral Clearing (`t = 2`, Bob Offline):**
   - Under BIP-341 `SigMsg(0x83, ext_flag = 1)`, `ANYONECANPAY` omits `input_index` and commits strictly to `this_input` (`outpoint || amount || scriptPubKey || nSequence`) and `SHA256(outputs[input_index])`.
   - Therefore, placing `U_AB` at `vin[0]` paired with `(bob_ab_sats, bob_spk)` at `vout[0]` and `U_BC` at `vin[1]` paired with `(bob_bc_sats, bob_spk)` at `vout[1]` reproduces the **byte-identical `TapSighash`** Bob signed at `t = 0`!
   - `Alice + RouterGuard` co-sign `vin[0]` with `SIGHASH_ALL (0x01)`, `Carol + RouterGuard` co-sign `vin[1]` with `SIGHASH_ALL (0x01)`, and `Alice + Carol` co-sign `U_CA` (`vin[2]`) with `SIGHASH_DEFAULT (0x00)`, binding the entire 5-output atomic settlement (`vout[0]` Bob `AB`, `vout[1]` Bob `BC`, `vout[2]` Alice principal + routed PnL, `vout[3]` Carol freed margin, `vout[4]` `330`-sat CPFP anchor).
3. **Zero `bob_sk` in Nova/BitVM3 Proving (`oracle_epoch_bridge.rs`):**
   - Each `LNMBAT01` witness row is signed strictly by the online clearing quorum (`(alice_sk, guard_sk)`, `(carol_sk, guard_sk)`, `(carol_sk, alice_sk)`) with `oracle_event_id == pyth_receipt.receipt_hash`, `batch_id == session_hash`, and `BitVm3SettlementRecord.assertion_txid == mnr03_atomic_clearing_txid`.

---

## 3. Explicit Remaining Non-Goals & Honesty Flags

Every emitted Rust and JS record preserves strict machine-readable honesty boundaries:

- **`near_finality_verified: false` (`nearObserverAttested: true` in JS):** Independent NEAR observer Ed25519 attestations are NOT a NEAR validator light-client block-header / Merkle-inclusion proof. Full NEAR light-client verification and live NEAR testnet deployment remain separate engineering gates.
- **`bitvm3_onchain_verified: false`:** While `lnm-nova` (`nova-snark 0.76.0`) proves and verifies the 3-step `12,376`-byte `CompressedSNARK` (`nova_snark_verified: true`) and binds the `304`-byte `UTXOREF_L2_SETTLEMENT_GROTH16_V0` statement (`assertion_txid == mnr03_atomic_clearing_txid`), wrapping Nova into a Groth16 BitVM3 Bitcoin-script challenge/response verifier on L1 remains unimplemented.
- **Pre-maturity offline UTXO release impossibility:** As proven in `SHZ-MNR-02`, raw L1 UTXOs involving an offline counterparty cannot be spent on Bitcoin before `maturity_height` without an oracle scalar or covenant soft-fork; pre-maturity exits require LP-funded advances (`Candidate 4`).
- **Live Pyth Pro operational key pinning:** Test fixtures use deterministic/sample Ed25519 keys alongside the official `pyth-lazer-public` wire vector; operational deployment requires freezing production Pyth Pro governance public keys.
- **`production_ready: false`:** Research and testnet prototype only; unaudited for mainnet funds.
