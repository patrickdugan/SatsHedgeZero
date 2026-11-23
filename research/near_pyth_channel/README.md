# SHZ-ORACLE-01 / SHZ-CHANNEL-01 starter

**Status:** research-only. No BTC signing, Lightning channel update, live NEAR deployment, or permission to settle real funds. This subfolder does not modify the upstream Rust protocol's production gates.

## Run the executable tests

```sh
node --test research/near_pyth_channel/test/*.test.mjs
```

`src/oracle.mjs` authenticates an **independent verifier receipt** on a Pyth payload hash with an allowlisted Ed25519 key. This is a separate trust tier from Pyth's native signature. It binds price, feed ID, confidence, expiry, feed-update timestamp, network, NEAR contract, event, round, relayer identity, and precommitted state root. It builds objectively checkable double-signing and source-substitution fraud evidence. Reported verdicts never say NEAR or Bitcoin already executed a slash.

`src/pyth_native.mjs` checks the actual Pyth Pro `solana` signature envelope format, using a pinned original Pyth Ed25519 signer key. It strictly parses the envelope, validates the Ed25519 signature on its original bytes and rejects trailing data. Its **inner signed price fields are not parsed yet**. A real Pyth feed must come from Pyth's authenticated signer registry, and the inner parser must be validated against official `pyth-lazer-protocol` vectors before this route authorizes anything.

`src/channels.mjs` computes exact inverse PnL, net USD delta, a bounded-capacity profit routing graph, and a proposal tying the clearing mark to a signed oracle receipt. Each original bilateral DLC remains a distinct enforceable contract. The proposal flags `readyToReleaseCollateral: false` pending wallet signatures, unilateral exits, and Bitcoin confirmation. In the test triangle Alice closes against Carol, Bob offsets against Carol, and all three are flat at the $125k mark.

`src/handshake.mjs` is a conditional multi-channel signing-order audit. It records package commitments, old-channel revocations, and a simulated hashlock reveal, while keeping `bitcoinSpendEnforced: false`. An actual LN-DLC implementation must provide HTLC/PTLC scripts, signed CET/refund/penalty paths, channel-state revocation proofs, distinct timeout windows, and watchtowers.

`near_contract/` is an experimental NEAR SDK contract: it verifies the Pyth Pro outer signature using NEAR's native Ed25519 host function, accepts a relayer's NEAR bond, and verifies two incompatible signed relay messages before slashing. The NEAR contract has not been built or deployed and its escrow rules require independent security review. Its signer must be pinned from Pyth governance. It does not yet decode Pyth's authenticated price payload.

## Connectors to implement next

- **Pyth inner decoder:** exact `PayloadData` parsing of Pyth Pro `solana` signed bytes. Pyth Pro identifies feeds with **u32 numeric IDs**, distinct from Pyth Core's 32-byte feed IDs. `Crypto.BTC/USD` is Pyth Pro ID **1**; it must be pinned in the signed settlement policy. Parse price, exponent, confidence, and `feedUpdateTimestamp` from authenticated bytes, then compare to the exposed normalized price.
- **NEAR registry:** audited signer rotation, bond escrow, dispute deadlines, replay/nullifier history, and independent NEAR inclusion/finality proofs. No arbitrary relayer-supplied key may count as Pyth evidence.
- **UTXORef bridge:** hook a verified oracle price and settlement epoch to the existing `PnlBatchSnapshotV1`/`DurablePnlBatchBook` without self-authorizing confirmation or relying on mutable state roots.
- **MNR02 bridge:** assemble signed bilateral preauthorization packages (`0x83` / `CLTV`) and routed CET templates, including Bob-offline test cases. For an ordinary channel route, co-sign and revoke every affected commitment state.
- **Lightning integration:** implement mutually consented channel state changes and pre-signed failure/penalty transactions. The hash preimage is revealed only when both sides' irrevocable commitments are independently verified.

## Architectural warnings

NEAR Chain Signatures currently expose ECDSA/Ed25519 signing paths and should not be assumed to produce native BIP340 Taproot adaptor signatures. SatsHedgeZero's Bitcoin collateral stays under its own Bitcoin-enforced DLC witnesses. NEAR may index state, accept price evidence and slash its own bond, but it cannot make a bare price claim spend a Taproot output. Pyth Pro is a subscribed data service; keep API tokens off the browser and commit neither price API credentials nor private test keys.

Sources: [Pyth NEAR deprecation](https://docs.pyth.network/price-feeds/core/use-real-time-data/pull-integration/near), [Pyth signed formats](https://docs.pyth.network/pro/payload-reference), [official Solana signed wire layout](https://docs.rs/pyth-lazer-protocol/latest/src/pyth_lazer_protocol/message.rs.html), [NEAR Ed25519 verifier](https://docs.rs/near-sdk/latest/near_sdk/env/fn.ed25519_verify.html), [Kohen channel DLC conditional settlement](https://nkohen.github.io/blog/transferring-lightning-dlcs/).
