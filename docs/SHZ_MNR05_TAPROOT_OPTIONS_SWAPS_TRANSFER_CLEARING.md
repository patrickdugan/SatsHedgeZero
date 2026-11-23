# SHZ-MNR-05: Oracle Checker, Bilateral Taproot Options & Swaps, Position Transferability, and Cross-Margin Clearing Engine

Builds directly off [`fb12a48`](https://github.com/patrickdugan/SatsHedgeZero/commit/fb12a48) (`SHZ-MNR-04: Bitcoin-Exact Nova Clearing & A100 Concurrent Pilot`, Draft PR #5) and synthesizes the architectural gates introduced across PRs #4 (`SHZ-TL-USD-01`), #5 (`SHZ-MNR-04`), #6 (`SHZ-NOVA-G16-01`), and #7/#8 (`SHZ-NOVA-IPA-NEAR-01/02`).

---

## 1. Synthesis of Upstream Repository Workstreams

| Workstream / Draft PR | What Was Established | Follow-Up Closed in `SHZ-MNR-05` |
| --- | --- | --- |
| **`SHZ-MNR-04` (`fb12a48`, PR #5)** | Proved the 348-byte stripped `SHA256d` TXID, 5 output values, and input-output-fee conservation in `nova-snark 0.76.0` (`195,563` primary constraints, `12,224B` proof); noted that **contract-set authentication, authorization/transfer nullifiers, revoked pre-transfer states, and persistent accounting roots** remained external to the circuit/fixture. | `TransferAndClearingEngine` (`crates/shz-utxoref/src/transfer_and_clearing.rs`) enforces active-set registration, monotonic `ledger_state_root` continuity, and one-shot outpoint/transfer nullifiers (`SHZ/TRANSFER-CLEARING-NULLIFIER/V1`), while producing 348-byte mixed Swap+Option clearing transactions verified directly by `shz_nova_bitvm::mnr04::parse_transaction`. |
| **`SHZ-NOVA-G16-01` (`6f78b18`, PR #6)** | Defined the bounded dual-oracle integer midpoint relation (`2 * index_e8 = pyth_e8 + secondary_e8 + parity`, `<= 50 bps` spread slack `< 2^96`, `2 x 128-bit` big-endian public-input limbs, distinct non-Pyth second source). | `OracleCheckerEngine` (`crates/shz-oracle/src/checker.rs`) enforces `trusted_pyth_registry_sha256` pinning, distinct secondary source verification (`TradeLayerVwapProof` or allowlisted non-Pyth Ed25519 report), exact `SHZ-NOVA-G16-01` integer midpoint + `spread_slack`, and event/payload replay nullifiers. |
| **`SHZ-NOVA-IPA-NEAR-01/02` (`450da80`, PR #7/#8)** | Benchmarked transparent BN254 IPA verification on NEAR sandbox (`21.69 TGas` for 4 elements; `37.57 / 63.16 / 110.88 TGas` for `8 / 16 / 32` elements) bound to `MNR-03` public state. | Surfaced in the Oracle Checker telemetry & Deribit/OG-BitcoinWisdom UI alongside explicit non-equivalence flags separating public-tuple IPA checks from full Pallas/Vesta Nova R1CS verification. |
| **`SHZ-TL-USD-01` (`6201c74`, PR #4)** | Established discrete price-grid scenario solvency (`min_{P in G} assets(P)`) and `TL-BTC/USDC` spot VWAP anchoring. | `evaluate_swap_option_portfolio_margin` generalizes discrete stress-grid evaluation to mixed **Inverse Swap + European Call/Put Option** portfolios, quantifying exact cross-margin relief when options cap swap tail loss. |

---

## 2. Bilateral Matching of Option & Swap Contracts in Taproot

### 2.1 Payoff & Dyadic CET Compression (`crates/shz-margin/src/derivatives.rs`)
`DerivativeContractSpec` supports zero-fee (`ZeroFeePolicy::ZERO`), vanilla-BTC-collateralized (`CollateralAsset::VanillaBtc`, with `TaprootAsset` v1 commitment hooks) bilateral contracts across two instrument families:

1. **Inverse Swaps (`SwapTenor::PerpetualSubchannel` | `SwapTenor::Dated { expiry_timestamp }`)**:
   - USD notional $Q_{\text{usd}}$ at entry $P_0$; Long posts $M_{\text{long}}$, Short posts $M_{\text{short}}$.
   - Exact integer PnL: $\operatorname{round\_half\_even}\!\left(\frac{Q_{\text{usd}} \cdot 10^8 \cdot (P_T - P_0)}{P_0 \cdot P_T}\right)$, clamped to $[0, M_{\text{long}} + M_{\text{short}}]$.
2. **European Vanilla Options (`OptionKind::Call` | `OptionKind::Put`)**:
   - Underlying notional $N_{\text{sats}}$ (`contract_size_sats`), strike $K$ (`strike_price_usd`), upfront buyer `premium_sats` $P_{\text{prem}}$, and `writer_collateral_sats` $M_{\text{writer}}$ locked in a single shared `P2TR` output ($C_{\text{total}} = P_{\text{prem}} + M_{\text{writer}}$).
   - Exact BTC-settled intrinsic exercise to Option Buyer at expiry mark $P_T > 0$:
     $$\text{Call: } \min\!\left(C_{\text{total}},\, \operatorname{round\_half\_even}\!\left(\frac{N_{\text{sats}} \cdot \max(0, P_T - K)}{P_T}\right)\right)$$
     $$\text{Put: } \min\!\left(C_{\text{total}},\, \operatorname{round\_half\_even}\!\left(\frac{N_{\text{sats}} \cdot \max(0, K - P_T)}{P_T}\right)\right)$$
   - Writer receives $C_{\text{total}} - \text{buyer\_sats}(P_T)$ with `0` protocol fee. When $M_{\text{writer}} \ge N_{\text{sats}}$ on a Call (`is_fully_covered_call() == true`), $\frac{N_{\text{sats}}(P_T - K)}{P_T} < N_{\text{sats}}$ for every finite $P_T$, making the covered Call writer immune to default or liquidation at any upside BTC price.
   - `compress_derivative_cet_ranges` exploits monotonicity of all three payoff curves (`Swap`, `Call`, `Put`) to compress `[0, 2^B - 1]` into disjoint dyadic prefix CETs with worst-case error $\le \varepsilon_{\text{sats}}$, collapsing out-of-the-money option regions into minimal prefix ranges.

### 2.2 Balanced 4-Leaf `UTXORef` NUMS `P2TR` Tree (`crates/shz-dlc/src/taproot_derivatives.rs`)
Every matched Option or Swap locks collateral under the unspendable `UTXORef` NUMS internal key (`c99e9965166e7ff80516494709db8fdfdc31b0626500bb70dc3652fc2ff584ab`) and a balanced 2-level, 4-leaf Tapscript (`0xc0`) Merkle tree (`97`-byte control blocks):

- **Leaf 0 (`coop_novation_leaf`):** `<pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG` — 2-of-2 script path for instant cooperative close or **Mode 1 Atomic L1 Taproot Novation (`U_AB -> U_DB`)**.
- **Leaf 1 (`routed_clearing_leaf`, `nLockTime = maturity_height`):** `<P_Holder> OP_CHECKSIGVERIFY <P_ClearingGuard> OP_CHECKSIGVERIFY <P_Counterparty> OP_CHECKSIG` — enables `0x83` (`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`) origination pre-signatures for offline-counterparty multilateral clearing and **Mode 2 Offline Claim Assignment**.
- **Leaf 2 (`unilateral_cet_leaf`, `nLockTime = maturity_height + grace_blocks`):** `<maturity + grace> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG` — pre-signed BIP-340 adaptor CETs preserving trustless unilateral exercise/settlement.
- **Leaf 3 (`refund_leaf`, `nLockTime = maturity_height + refund_delay_blocks`):** `<maturity + refund_delay> OP_CLTV OP_DROP <pk0> OP_CHECKSIGVERIFY <pk1> OP_CHECKSIG` — pre-signed timeout recovery.

### 2.3 Multi-Series Zero-Fee Bilateral Orderbook (`crates/shz-dex/src/derivatives_book.rs`)
`TaprootDerivativesOrderBook` partitions resting BIP-340 signed order intents (`SignedDerivativeOrderIntent`) by `DerivativeSeriesKey`, matching Swaps by `limit_price_usd` and Options (`Call` / `Put`) by `limit_premium_per_lot_sats` at resting maker price/premium with partial fills and `0` fees, emitting `MatchedTaprootDerivativeTicket` records with verified `TaprootDerivativeTree` outputs.

---

## 3. Position Transferability & Portfolio Margin Clearing (`crates/shz-utxoref/src/transfer_and_clearing.rs`)

1. **Mode 1 — Interactive Atomic L1 Taproot Novation (`execute_atomic_taproot_novation`):**
   - Computes the deterministic unsigned novation `txid` first so incoming transferee `Dave` and continuing counterparty `Bob` pre-sign all refund, unilateral CET, and `0x83` clearing outcomes on successor `U_DB` (`vout[0]`) **before** `Alice` or `Dave` signs `novation_tx`.
   - Spends `[U_AB (Leaf 0, 0x00), U_Dave_Funding (key-path, 0x00)] -> [U_DB, Alice_Exit_BTC, Dave_Change, Anchor_330]`, paying `Alice` liquid BTC immediately before maturity while burning `U_AB`'s nullifier in `TransferAndClearingEngine`.
2. **Mode 2 — Counterparty-Offline (`0x83`) Claim Assignment (`authorize_offline_bob_claim_transfer`):**
   - When `Bob` is 100% offline (`bob_sk` absent), `Alice + ClearingGuard` sign `Leaf 1` (`0x01`) redirecting `Alice`'s maturity output (`vout[1]`) to `Dave` while preserving `Bob`'s origination-pinned `0x83` `vout[0]`, consuming `U_AB`'s assignment nullifier to block double-selling.
3. **Portfolio Cross-Margin & Nullifier-Gated Mixed Clearing (`execute_mixed_swap_option_bob_offline_clearing`):**
   - Evaluates worst-case loss across stress grid `G` (demonstrating `> 74%` cross-margin relief when a Short Swap is paired with a protective Long Call Option).
   - Enforces prior `ledger_state_root` equality and active-nullifier membership (rejecting stale pre-novation `U_AB` legs and replay attempts), solves `UTXORef` Edmonds-Karp max-flow routing, and signs a 3-input, 5-output (`348`-byte stripped) Taproot clearing transaction (`vin[0]` novated Swap `U_DB` with Bob `0x83` offline, `vin[1]` ITM Call Option `U_BC` with Bob `0x83` offline, `vin[2]` interactive Swap `U_CD` `0x00`), verified both by **Bitcoin Core v31.1** and **`shz_nova_bitvm::mnr04::parse_transaction`**.

---

## 4. Explicit Remaining Honesty Boundaries

- `bitvm3_onchain_verified: false` — Bitcoin L1 enforces Taproot script paths, `OP_CLTV` timelocks, and `0x83`/`0x01`/`0x00` Schnorr witnesses directly; no BitVM3 Groth16 verifier script is executed on Bitcoin L1.
- `near_groth16_onchain_verified: false` & `near_finality_verified: false` — `OracleCheckerEngine` verifies native Ed25519/Merkle signatures and the exact `SHZ-NOVA-G16-01` bounded midpoint arithmetic locally; live NEAR mainnet/testnet pairing execution and NEAR light-client header proofs remain separate gates.
- `production_ready: false` — Research and testnet/regtest implementation; unaudited for mainnet custody or capital deployment.
