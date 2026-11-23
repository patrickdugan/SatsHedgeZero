# SatsHedgeZero

Non-custodial, zero-fee Lightning Discreet Log Contract (DLC) DEX for inverse-quoted BTC/USD derivatives settled on vanilla Bitcoin UTXOs (`P2TR`), with pluggable **TradeLayer VWAP** and **Pyth et al. NEAR-compatible Borsh relay** oracles, a **`t-of-n` FROST state oracle confederation**, and **slashable fraud proofs** if the confederation equivocates or attests off-market prices.

## Quick Start

```sh
cargo test --workspace
cargo run --bin shz -- verify-all
cargo run --bin shz -- quote 2000 100000 10 1
cargo run --bin shz -- demo-dex
cargo run --bin shz -- demo-fraud
```

## Workspace Crates

| Crate | Responsibility |
| --- | --- |
| [`crates/shz-margin`](crates/shz-margin) | Exact `u128` inverse BTC/USD payoff math (`$1` notional contracts settled in sats), `0 bps` fee conservation law, covered `1x` synthetic-USD (`SatsHedge`) detection, `CollateralAsset` (`VanillaBtc` active in v0 + `TaprootAsset` commitment leaf hook for v1), and $O(\text{CETs})$ monotonic dyadic binary-prefix CET compression. |
| [`crates/shz-dlc`](crates/shz-dlc) | Pure-Rust `secp256k1` BIP-340 Schnorr signatures, even/odd-Y normalized Schnorr adaptor signatures (`adaptor_sign`, `adaptor_verify`, `adaptor_complete`, `adaptor_extract_secret`), multi-digit DLC anticipation point derivation $T(\vec{b}) = \sum (R_j + e_j X_{\text{oracle}})$, `P2TR` descriptors, and the `LnDlcSubchannel` off-chain cooperative close + unilateral L1 CET state machine. |
| [`crates/shz-oracle`](crates/shz-oracle) | **TradeLayer VWAP** (`TradeLayerVwapProof` with wash-trade & median-outlier filters + binary SHA-256 Merkle inclusion proofs), **Pyth + multi-provider NEAR Borsh relay** (`NearRelayEnvelope`), **`t-of-n` FROST state confederation** (Shamir + Feldman VSS + threshold-shared per-digit nonces + identifiable abort), and **`NearBondedOracleVault`** verifying Borsh-encoded `EquivocationFraudProof` and `DeviationFraudProof`. |
| [`crates/shz-dex`](crates/shz-dex) | Decentralized BIP-340 signed P2P order intents, price-time priority `0 bps` maker/taker matching (`ZeroFeeOrderBook`), automatic `LnDlcSubchannel` offer materialization, and real-time mark-to-market position telemetry. |
| [`bins/shz-cli`](bins/shz-cli) | `shz` CLI for quoting inverse contracts, running deterministic P2P LN-DLC simulations, and executing adversarial FROST slashing proofs. |

## Core Protocol Properties

### 1. Inverse-Quoted BTC/USD & 0-Fee Conservation (`shz-margin`)

Contracts are quoted in integer USD (`$1` per contract) and margined/settled strictly in satoshis (`VanillaBtc` in v0):

$$\text{PnL}_{\text{long}}(P_T) = \text{round}\!\left(Q_{\text{usd}} \cdot 10^8 \cdot \frac{P_T - P_0}{P_0 \cdot P_T}\right)$$

- **Strict Zero-Fee Conservation**: Across every compressed CET and off-chain Lightning update, `long_sats + short_sats == total_collateral_sats` (`maker_fee_bps = 0`, `taker_fee_bps = 0`, `settlement_fee_bps = 0`).
- **Covered `1x` Synthetic-USD (`SatsHedge`)**: When Short posts $\ge 1.0\times$ BTC value ($M_{\text{short}} \cdot P_0 \ge Q_{\text{usd}} \cdot 10^8$), `short_liquidation_price_usd()` is `None` — the short position cannot be liquidated at any upside BTC price and preserves constant USD value in sats across arbitrary BTC moves.
- **Monotonic Dyadic CET Compression**: Exploits monotonicity of clamped inverse payouts on $[0, 2^{20}-1]$ (`$0 .. $1,048,575`) to compress `1,048,576` price outcomes by `>99.4%` (e.g., `643` prefix CETs for a `10x/10x` `$1,000` contract at `<= 250 sats` max error, or `5,749` CETs for an unliquidatable `1x` `$2,000` SatsHedge spanning the full `$90,909 .. $1,048,575` domain at `<= 250 sats` error).

### 2. Non-Custodial Lightning Subchannels & TAP Extensibility (`shz-dlc`)

- **Instant Off-Chain Execution**: Counterparties lock margin inside a 2-of-2 `P2TR` Lightning subchannel buffer output, mutually verify BIP-340 adaptor signatures for every compressed dyadic CET prefix, and can cooperatively close or roll over at any agreed mark price in **0 L1 transactions** and **0 fees**.
- **Unilateral L1 Settlement**: Either peer can broadcast the buffer transaction and complete the counterparty's adaptor signature using $t = \sum_{j=0}^{m-1} s_j \pmod n$ from the oracle's BIP-340 digit attestation.
- **Taproot Asset (`TAP`) Hook**: `CollateralAsset::TaprootAsset` computes deterministic taptree commitment leaves while `validate_v0_funding()` enforces vanilla BTC UTXOs in v0.

### 3. Oracle Architecture & Bonded Fraud Proofs (`shz-oracle`)

- **TradeLayer L1 VWAP**: Aggregates block-windowed TradeLayer DEX fills, strips self-cross (`maker == taker`) wash trades and median-deviation spikes, commits accepted fills in a binary SHA-256 Merkle tree, and verifies indexer witness quorums.
- **Pyth et al. NEAR Relay**: Normalizes signed Pyth `(price, conf, expo)` updates alongside secondary feeds (`Switchboard`, `RedStone`, `Chronicle`) into canonical Borsh-encoded `NearRelayEnvelope` payloads.
- **`t-of-n` FROST Confederation + Dual Slashing**:
  1. **Nonce Equivocation (`EquivocationFraudProof`)**: Double-signing bits `0` and `1` on any pre-committed digit nonce $R_j$ algebraically leaks the confederation's `secp256k1` secret key $d = (s_0 - s_1)(e_0 - e_1)^{-1} \pmod n$, slashing 100% of the NEAR vault and unlocking L1 Bitcoin slash bonds.
  2. **Price Deviation (`DeviationFraudProof`)**: Collusive off-market attestations $P_{\text{frost}}$ (without nonce reuse) are proven fraudulent against Borsh-verified `Pyth` NEAR relay envelopes and/or `TradeLayer` VWAP proofs, slashing the confederation's NEAR bond, paying challenger bounties, and computing exact satoshi restitution for harmed DLC counterparties.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detailed cryptographic and state-transition specifications.

## License

MIT — Copyright (c) 2026 Patrick Dugan
