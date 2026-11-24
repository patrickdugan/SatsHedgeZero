# SHZ-ORACLE-01 / SHZ-CHANNEL-01 starter

**Status:** research-only. No BTC signing, Lightning channel update, live NEAR deployment, or permission to settle real funds. This subfolder does not modify the upstream Rust protocol's production gates.

## Run the executable tests

```sh
node --test research/near_pyth_channel/test/*.test.mjs
```

`src/oracle.mjs` authenticates an **independent verifier receipt** on a Pyth payload hash with an allowlisted Ed25519 key. This is a separate trust tier from Pyth's native signature. It binds price, feed ID, confidence, expiry, feed-update timestamp, network, NEAR contract, event, round, relayer identity, and precommitted state root. It builds objectively checkable double-signing and source-substitution fraud evidence. Reported verdicts never say NEAR or Bitcoin already executed a slash.

`src/pyth_native.mjs` checks the actual Pyth Pro `solana` signature envelope format, using a pinned original Pyth Ed25519 signer key. It strictly parses the envelope, validates the Ed25519 signature on its original bytes and rejects trailing data. The new `src/pyth_payload.mjs` module verifies **the same signed bytes and their inner `PayloadData`** for price, exponent, confidence, feed-update timestamp, feed ID 1, channel and freshness. It passes the official `pyth-lazer-public` wire sample. Real Pyth signer keys must be independently pinned and rotated by an audited policy before this route can authorize anything.

`src/channels.mjs` computes exact inverse PnL, net USD delta, a bounded-capacity profit routing graph, and a proposal tying the clearing mark to a signed oracle receipt. Each original bilateral DLC remains a distinct enforceable contract. The proposal flags `readyToReleaseCollateral: false` pending wallet signatures, unilateral exits, and Bitcoin confirmation. In the test triangle Alice closes against Carol, Bob offsets against Carol, and all three are flat at the $125k mark.

`src/handshake.mjs` is a conditional multi-channel signing-order audit. It records package commitments, old-channel revocations, and a simulated hashlock reveal, while keeping `bitcoinSpendEnforced: false`. An actual LN-DLC implementation must provide HTLC/PTLC scripts, signed CET/refund/penalty paths, channel-state revocation proofs, distinct timeout windows, and watchtowers.

`near_contract/` is an experimental NEAR SDK contract: it verifies the Pyth Pro outer signature using NEAR's native Ed25519 host function, accepts a relayer's NEAR bond, and verifies two incompatible signed relay messages before slashing. The NEAR contract has compiled in an earlier CI revision but its latest parser and epoch changes await CI verification; it has not been deployed and its escrow rules require independent security review. Its signer must be pinned from Pyth governance. The new Rust decoder parses the authenticated price payload and records a monotone bonded oracle epoch with a challenge window. Deployment, cross-chain finality verification and custody-enforceable settlement remain outstanding.

## Connectors to implement next

- **Pyth registry integration:** use the now implemented exact `PayloadData` parser for Pyth Pro `solana` signed bytes. Pyth Pro identifies feeds with **u32 numeric IDs**, distinct from Pyth Core's 32-byte feed IDs. `Crypto.BTC/USD` is Pyth Pro ID **1**; it must be pinned in the signed settlement policy. The native-signed parser checks price, exponent, confidence, and `feedUpdateTimestamp` on authenticated bytes; freeze a live Pyth Pro response and pin the public signer registry to complete operational source authentication.
- **NEAR registry:** audited signer rotation, bond escrow, dispute deadlines, replay/nullifier history, and independent NEAR inclusion/finality proofs. No arbitrary relayer-supplied key may count as Pyth evidence.
- **UTXORef bridge:** hook a verified oracle price and settlement epoch to the existing `PnlBatchSnapshotV1`/`DurablePnlBatchBook` without self-authorizing confirmation or relying on mutable state roots.
- **MNR02 bridge:** assemble signed bilateral preauthorization packages (`0x83` / `CLTV`) and routed CET templates, including Bob-offline test cases. For an ordinary channel route, co-sign and revoke every affected commitment state.
- **Lightning integration:** implement mutually consented channel state changes and pre-signed failure/penalty transactions. The hash preimage is revealed only when both sides' irrevocable commitments are independently verified.

## Architectural warnings

NEAR Chain Signatures currently expose ECDSA/Ed25519 signing paths and should not be assumed to produce native BIP340 Taproot adaptor signatures. SatsHedgeZero's Bitcoin collateral stays under its own Bitcoin-enforced DLC witnesses. NEAR may index state, accept price evidence and slash its own bond, but it cannot make a bare price claim spend a Taproot output. Pyth Pro is a subscribed data service; keep API tokens off the browser and commit neither price API credentials nor private test keys.

Sources: [Pyth NEAR deprecation](https://docs.pyth.network/price-feeds/core/use-real-time-data/pull-integration/near), [Pyth signed formats](https://docs.pyth.network/pro/payload-reference), [official Solana signed wire layout](https://docs.rs/pyth-lazer-protocol/latest/src/pyth_lazer_protocol/message.rs.html), [NEAR Ed25519 verifier](https://docs.rs/near-sdk/latest/near_sdk/env/fn.ed25519_verify.html), [Kohen channel DLC conditional settlement](https://nkohen.github.io/blog/transferring-lightning-dlcs/).

### Separate WASM build gate

GitHub CI also builds the standalone NEAR contract for `wasm32-unknown-unknown` against pinned `near-sdk =5.17.2`. A green build establishes compilation only. The signer registry, on-chain signed-price parser, NEAR testnet deployment, bond economics, external state-proof checks, and Bitcoin settlement integration remain independent acceptance gates.

## ORACLE-02 / CHANNEL-02 continuation

See [`../../docs/SHZ_ORACLE02_CHANNEL02_ACCEPTANCE.md`](../../docs/SHZ_ORACLE02_CHANNEL02_ACCEPTANCE.md).

`src/pyth_payload.mjs` checks native Pyth signature and the corresponding BTC/USD fields in signed little-endian `PayloadData`, with an upstream wire sample and adversarial tests. The earlier `src/oracle.mjs` independent-verifier receipt is a distinct, weaker provenance route.

`src/closeout_epoch.mjs` re-verifies native signed bytes, derives a clearing session commitment from the netted bilateral closeout plan and all channel recovery hashes, checks ECDSA-signed wallet coordination approvals, and accepts an explicitly **trusted, signed NEAR observer statement**, subject to maturity/fallback limits. This proves the coordination statement under the supplied trust roots. It never pretends to hold a Bitcoin witness, NEAR light-client proof or real Lightning commitment revocation.

The experimental NEAR Rust contract also parses signed fields and records an on-NEAR Pyth price/challenge epoch. Both the NEAR contract and the Lightning wallet integration require further independent testing. Research tests are isolated to the `near_pyth_channel` subfolder.

## ORACLE-03 / CHANNEL-03 / MNR-03 continuation

See [`../../docs/SHZ_ORACLE03_MNR03_ACCEPTANCE.md`](../../docs/SHZ_ORACLE03_MNR03_ACCEPTANCE.md).

- `src/wallet_settlement.mjs` implements the independent external commitment & finality verifier consuming `WALLET_SETTLEMENT_REQUESTED` states from `src/closeout_epoch.mjs`:
  1. Re-derives exact `UTXORef` NUMS `P2TR` scripts and Tapscript control blocks (byte-exact with `UTXO-Ref/native/dlc-signer/tests/signing_target_vectors.json`) and verifies `secp256k1` BIP-340 Schnorr witnesses over BIP-341 `TapSighash` digests (`0x83` `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY` origination pre-signatures on offline Bob hops **without `bobSecretKey`**, `0x01` `SIGHASH_ALL` online/guard co-signatures, and `0x00` `SIGHASH_DEFAULT` interactive bilateral signatures).
  2. Enforces SHA-256 prior-commitment revocation secret disclosure strictly ordered before conditional preimage reveal (`revocationSequence < preimageRevealSequence`) and staggered incoming/outgoing hop `CLTV` deltas (`>= 6` blocks).
  3. Separates `authorizeBroadcastReadySettlement` (`readyForBitcoinBroadcast: true`, `collateralReleased: false`, `bitcoinSpendEnforced: false`) from `confirmBitcoinSettlement` (`bitcoinSpendEnforced: true`, `collateralReleased: true` only on active-chain confirmation, or `HALTED_ON_REORG` / `ledgerFrozen: true` on reorg or anchor-tip mismatch, while preserving `nearFinalityVerified: false`).
- `near_contract/src/lib.rs` adds epoch-bounded multi-key Pyth Pro signer rotation (`rotate_pyth_signers`) & emergency revocation (`revoke_pyth_signer`), payload/event replay nullifiers, objective source-substitution slashing (`submit_source_substitution_challenge`), and native `VMContextBuilder` unit tests alongside the `wasm32-unknown-unknown` CI build gate.
- Upstream Rust workspace adds `crates/shz-oracle/src/pyth_lazer.rs`, `crates/shz-utxoref/src/mnr03.rs`, `crates/shz-nova-bitvm/src/oracle_epoch_bridge.rs`, and `bins/shz-cli/src/mnr03_harness.rs` (`shz mnr03-regtest` + `shz mnr03-testnet4-live`).
