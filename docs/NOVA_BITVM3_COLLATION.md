# Main-Thread Collation: DLC, UTXORef & BitVM3 Nova Prover Integration

Collated on main thread from pinned upstream repositories to govern `crates/shz-nova-bitvm` and the Deribit-style `SatsHedgeZero` Pro Terminal UI.

## 1. Pinned Upstream Sources & License Boundary

| Upstream Artifact | Source & Pin | License | Integration Rule |
| --- | --- | --- | --- |
| `lnm-batch-statement` (`LNMarkets/statement`) | `patrickdugan/zk-rusto-no-bitcoino` @ `f6a8d129285869f339c86f1e2e7f1124bc09c37a` (PR #28) | **MIT** (`#![forbid(unsafe_code)]`) | Safe to port/adapt directly into MIT `crates/shz-nova-bitvm` (`k256` + `sha2` only). |
| `lnm-nova` spec (`LNMarkets/nova/SOUNDNESS.md`) | `patrickdugan/zk-rusto-no-bitcoino` @ `f6a8d129285869f339c86f1e2e7f1124bc09c37a` (PR #28) | `LNMarkets/nova` crate is **GPL-3.0-only** (due to M18) | **DO NOT copy GPL-3.0 R1CS/M18 code** into `SatsHedgeZero` (MIT). Implement clean-room MIT native encoders/verifiers for the documented wire formats (`600B` transcript, `8`-field expectation JSON, `Secq` BIP340 claim) so external `lnm-nova` binaries can prove/verify exported witnesses out-of-process. |
| `UTXORef` L2 Groth16/BitVM3 Statement V0 | `patrickdugan/UTXO-Ref` (`zk-groth16-bitvm/STATEMENT.md`) | **MIT** | Implement exact `304-byte` `UTXOREF_L2_SETTLEMENT_GROTH16_V0\0` codec and `[uint128_be(d[0..16]), uint128_be(d[16..32])]` public-input splitter. |
| `SHZ-MNR-01` & `SHZ-MNR-02` | `patrickdugan/SatsHedgeZero` PR #1 (`3fe86cb`) & `main` (`894fc7e`) | **MIT** | Bridge `MatchedDlcTicket`, `LnDlcSubchannel`, and `SHZ-MNR-02` (`0x83 + two-tier CLTV`) settlements into `BatchWitness` rows and BitVM3 settlement statements. |

## 2. Exact Wire & Cryptographic Formats Required in `crates/shz-nova-bitvm`

### A. Native Batch Witness (`LNMBAT01`) & 276-Byte Public Journal (`LNMJNL01`)
- Domain: `"UTXORef/LNMarkets/bitcoin-regtest/lnmarkets/v1/"`
- Bounded limits: `MAX_ROWS = 32`, `MAX_OUTCOMES = 1024`, `MIN_OUTPUT_SATS = 330`, `MAX_ROW_FEE_SATS = 1_000_000`, `SMT_DEPTH = 256`, `JOURNAL_LEN = 276`.
- Per-row checks:
  1. 2-of-2 BIP-340 `summary_signatures` (`trader_key`, `maker_key`) over `DlcSummary`.
  2. `UTXORef` NUMS `P2TR` `funding_script` derivation match (`derive_funding_script`).
  3. Selected `Outcome` Merkle inclusion against `summary.outcome_root` (`trader_sats + maker_sats + anchor_sats + fee_sats == collateral_sats`).
  4. Strictly sorted 2-of-3 `oracle_attestations` verified via BIP-340 over `oracle_message(summary, outcome)`.
  5. 2-of-2 BIP-340 `batch_signatures` over `batch_consent_message(context, summary)`.
  6. Sequential 256-depth sparse Merkle nullifier consumption (`old_nullifier_root -> new_nullifier_root`) preventing double-settlement across batches.
  7. Exact unsigned Bitcoin batch transaction digest (`batch_tx_digest` & reversed `batch_txid`).

### B. 600-Byte Nova v2 Signed-Row Transcript (`lnmarkets/sha256-transcript-accounting/v2`)
All numeric fields little-endian:
- `0..46`: literal ASCII `"UTXORef/LNMarkets/Nova/validated-signed-row/v1"` (`46 bytes`)
- `46..78`: `summary_digest` (`32 bytes`)
- `78..110`: `batch_consent_digest` (`32 bytes`)
- `110..238`: `summary_signatures[0] || summary_signatures[1]` (`128 bytes`)
- `238..366`: `batch_signatures[0] || batch_signatures[1]` (`128 bytes`)
- `366..431`: `oracle_attestations[0].oracle_index (u8) || signature (64B)` (`65 bytes`)
- `431..496`: `oracle_attestations[1].oracle_index (u8) || signature (64B)` (`65 bytes`)
- `496..500`: `outcome.index` (`u32le`, `4 bytes`)
- `500..532`: `outcome.message` (`32 bytes`)
- `532..564`: `trader_sats, maker_sats, anchor_sats, fee_sats` (`4 x u64le = 32 bytes`, each `< (1 << 51)`)
- `564..596`: `funding_txid` in display order (`32 bytes`)
- `596..600`: `funding_vout` (`u32le`, `4 bytes`)

Also expose:
- **8-Field Nova Folded State Tracker**: `[count, total_collateral_sats, total_payout_sats, total_fee_sats, transcript_chain_digest_hex, journal_sha_low128_le, journal_sha_high128_le, epoch]` with 51-bit row / 56-bit cumulative overflow checks.
- **Secq BIP340 Single-Signature Claim Helper**: `[1, claim_low128_le, claim_high128_le]` over `SHA256(pubkey_x || msg32 || sig64)` + bridge check tying `pubkey_x` and `msg32` to a specific `Row`'s party/oracle slot!

### C. 304-Byte `UTXORef` BitVM3 L2 Settlement Statement (`utxoref_l2_settlement_groth16_v0`)
- Exact 304-byte layout:
  `ASCII("UTXOREF_L2_SETTLEMENT_GROTH16_V0\0") (33B) || u16le(0) || u8(network_code) || chainGenesisHash(32B) || contractId(32B) || commitmentHash(32B) || assertionTxid(32B) || settlementTxid(32B) || programHash(32B) || verifyingKeyHash(32B) || policyHash(32B) || u64le(epochId) || u32le(assertionVout)`
  where `network_code` at byte offset `35` follows `UTXO-Ref/zk-groth16-bitvm/STATEMENT.md` (`0 = regtest`, `1 = testnet4`; mainnet rejected in v0).
- Public inputs: `d = SHA256(encoded_304_bytes)` $\to$ `[u128::from_be_bytes(d[0..16]), u128::from_be_bytes(d[16..32])]`.
- Explicit honesty flags on all outputs: `native_statement_verified: true`, `nova_snark_verified: false` (until external `lnm-nova verify` receipt is attached), `bitvm3_onchain_verified: false`, `production_ready: false`.

## 3. Main-Thread Design Criteria for Deribit-Style Pro Terminal UI (`ui/`)

1. **Aesthetic & Information Density**:
   - Institutional Deribit / BitMEX dark-desk layout (`#0a0e14` canvas, `#11161f` panels, `1px solid #1e2636` hairline borders, `JetBrains Mono` / tabular-numeral alignment, `#00d285` bid/long, `#ff4d6d` ask/short, `#f59e0b` FROST/dispute alerts). Zero marketing fluff or purple gradients.
2. **Domain Fidelity (Zero-Mock Protocol Wiring)**:
   - Serve live protocol computations from the Rust `shz` binary (via a lightweight zero-dependency Node.js HTTP API bridge `ui/server.mjs` invoking `shz` or mirroring exact `BigInt` inverse + `MNR-02` + `Nova` endpoints, plus static bundle fallback) so quotes, dyadic CET counts, `1x SatsHedge` unliquidatable synthetic-USD checks, `MNR-02` `0x83` closeout witnesses, FROST fraud-proof slashing verdicts, and `600B/276B/304B` Nova/BitVM3 transcripts are **real cryptographic outputs** from `SatsHedgeZero`!
3. **Core Panels**:
   - **Header Ribbon**: `BTC-INVERSE-PERP` & dated DLC contracts, Mark Price, TradeLayer L1 VWAP (`tx14`), Pyth NEAR Relay (`±conf bps`), `3-of-5 FROST` status, `0.00% Maker / 0.00% Taker` badge.
   - **Interactive Chart & Inverse Convexity Curve**: Toggle between Price/VWAP Candles and **DLC Payoff & CET Prefix Density Visualizer** (showing exact $N(1/P_0 - 1/P_T)$ curve, `1x SatsHedge` synthetic-USD constancy, liquidation cliffs, and dyadic CET intervals).
   - **Orderbook & Recent Trades**: Price-time priority P2P inverse orderbook (`USD` size, `BTC/sats` cumulative, click row to populate order ticket).
   - **Order Entry Ticket**: `Long` vs `Short / 1x SatsHedge`, USD Notional, Limit Price, Leverage slider (`1x`–`50x`), Oracle Policy (`FROST Bonded`, `TradeLayer VWAP`, `Pyth Relay`), Collateral (`Vanilla BTC P2TR v0` active; `TAP Asset v1` preview badge), live Margin, Liq Price, CET count, `0 sats Fee`.
   - **Bottom Multi-Tab Workbench**:
     - `Positions & MNR-02 Closeout` (interactive **Bob-Offline Closeout** flow displaying `Leaf 0 (0x83)` vs `Leaf 1 (CLTV)` witness & Core 31.1 regtest txid!),
     - `LN-DLC Subchannels` (dyadic prefix table, instant 0-fee LN close vs L1 CET broadcast),
     - `FROST & NEAR Fraud Guard` (TVL cap bar, interactive `Equivocation` key-extraction & `Deviation` slash simulator),
     - `Nova / BitVM3 Inspector` (`600B` transcript hex/field highlighter, `276B` `LNMJNL01` journal, `304B` `UTXOREF_L2_SETTLEMENT_GROTH16_V0` limbs).
