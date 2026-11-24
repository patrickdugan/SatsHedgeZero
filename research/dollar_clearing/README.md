# SHZ-TL-USD-01: shared dollar reference verifier

Pure Node.js 20+ reference implementation of **typed liability and backing
commitments** for BTC-backed SHZ-USD and bridged TL-USDC. This research crate
is additive to the live SatsHedgeZero Rust/Core/Nova work and does not change
any production minting, Bitcoin spend, Lightning channels or TradeLayer rules.

Run:

```sh
node --test research/dollar_clearing/test/*.test.mjs
```

- `src/common.mjs`: canonical SHA-256 statement encoding, independently pinned
  Ed25519 observer receipt validation, exact integer amounts and outpoint IDs.
- `src/hedge.mjs`: each BTC UTXO funding a short 1x inverse DLC, bounded payout,
  precise stress grid and fee/haircut reserves, pending-redemption conservation.
- `src/usdc_bridge.mjs`: independently attested finalized escrow events,
  procedural TL-USDC minted/burned/outstanding balance, pending withdrawals.
- `src/tl_volume_adapter.mjs`: strict join of real Rust `VolumeRecord` to
  underlying original maker/taker trade quantities. Refuses missing history.
- `src/vwap.mjs`: exact directional BTC/USDC executed quote-weighted price,
  replay/wash/min-volume/concentration checks and separate Pyth price sanity.
- `src/joint.mjs`: disjoint resource and liability roots bound into one public
  digest, with all on-chain/proof/issuance capability flags explicitly false.
- `src/op_return.mjs`: **proposed only** 76-byte `TLUSDC` mint/burn proof-reference
  datum and strict local nullifier replay gate. OP_RETURN carries metadata, no
  automatic consensus validity or ZK proof.

Fixtures contain dummy source-chain addresses, temporary test keys and synthetic
trades. Their signatures show cryptographic binding to configured observers,
not evidence of real on-chain funds. Never accept receipts with keys or pinned
roots supplied by the same candidate prover.

Read [the complete statement and threat model](../../docs/SHZ_TL_DOLLAR_CLEARING_V1.md).
