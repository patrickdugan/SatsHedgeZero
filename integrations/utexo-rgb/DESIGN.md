# SHZ-RGB-01 | settlement design and acceptance

## Code audit and scope

Base SHZ commit 9d5ac542a590fe879ef2b0215489682ec825966c.
- [shz-margin](../../crates/shz-margin/src/lib.rs): v0 only VanillaBtc; TaprootAsset is a reserved commitment hook, not an RGB asset type. Inverse contracts and CET payouts are sats. Reusing this enum for RGB or replacing sats with dollar units would change economic semantics and signed encodings.
- [clearing](../../crates/shz-dex/src/routing/clearing.rs): V3 row.net = paid - collected in sats. Its batch identity and clearing fund stay in sats. A sidecar can act only after a durable authenticated commit and a separate user-authorized, realizable BTC withdrawal is reserved; deferred claims and pending margin do not qualify.
- [fee ledger](../../crates/shz-dex/src/routing/ln_fees.rs): FeeReceipt uses msat, preimage, payment hash, recipient, batch references and attestation. It cannot represent RGB base units. Keep BTC routing costs, fees and RGB amounts in separate accounts. No change to the existing zero DLC settlement fee policy.
- [LDK investigation](../../docs/SHZ_HFT_06_LDK.md): ChannelAck needs per-channel durable monitor evidence; a WDK invoice status, preimage or RGB balance is insufficient. No public beta.5 high-level monitor persistence callback has been established by this review. Retain LDK persistence work for HFT lanes.
- [UTXORef](../../crates/shz-utxoref): RGB state is client-side and needs consignment validation plus anchors and recovery. Existing Nova/BitVM statements prove BTC clearing, not RGB delivery.

## Architecture

Authenticated SHZ batch -> final BTC payout entitlement -> reserve withdrawable sats -> explicit user conversion quote -> separate liquidity provider/atomic exchange -> RGB invoice + matching payment -> receiver validation -> independently journal payout completion.

This is a proposed conversion service; it must not be described as atomic until both legs are proven atomic or safely compensated under adversarial failure. WDK beta.5 does not expose atomic swaps on the released account; LSP linked-asset execution is excluded. HODL invoices are primitives, not a complete BTC/RGB swap. No conversion provider, liquidity, asset issuance or transfer authority is assumed. Never let one successful leg discharge the other.

Quote exact units: floor(sats * BTC_USD_cents * 10^decimals / (100000000 * asset_USD_cents)). Use independently quoted asset/USD price, including depeg, explicit precision, and quote expiry. Keep remainder numerator/denominator and make rounding treatment explicit. Quote helper is a reference for gross conversion before spread/fees. The carrier is BTC millisatoshis; beta.5 declarations describe 3,000,000 msat (3,000 sats) minimum for RGB HTLCs. Carrier liquidity requirement is not necessarily a fee. Separate actual miner, routing, LSP and mint costs; obtain both-leg quotes before authorization. Utexo Mint advertises 0.1% per transfer plus source-network fees, distinct from DEX fee policy. No recurring bridge per fill; batch conversions after clearing.

A production quote must bind SHZ batch digest, withdrawal ID, customer destination, provider identity, source sat amount, oracle/market snapshot, network, exact RGB contract ID and precision, asset base units, carrier msat, fee ceiling, expiry, and invoice hash. The spike checks the invoice subset and arithmetic, not quote signatures, asset registry or fee cap. Use independently verified allowlist and metadata; ticker alone is insufficient. Do not use issued fixture assets as USDT.

Persist an idempotent conversion state machine (reserved -> authorized -> submitted -> observed -> reconciled, plus ambiguous/fenced and terminal failures); journal before a payment, key by obligation and payment hash, atomically consume the reserve once. Duplicate invoices or payment hashes cannot fund a second obligation. No blind payment retry after timeout, no credit/release on an expired invoice or single API response. Independently reconcile node state, payment hash/preimage, signed receiver evidence, exact asset amount and BTC funding leg. A matched invoice is not payment confirmation. Polling may continue after expiry for an already-initiated payment. Recovery must include RLN/LDK/RGB, VLS signer state and SHZ journal; a mnemonic or VSS snapshot alone is insufficient.

## Risk/feasibility matrix

| Use | Assessment |
| --- | --- |
| BTC-settled inverse contracts | Keep existing production model |
| Optional USD-denominated payout after clearing | Most useful experiment; needs two-leg exchange, liquidity and recovery |
| Stablecoin-backed direct margin | Research only; separate RGB channel/UTXO asset proof, liquidation, force-close and DLC/CET validity |
| HFT-06 commitment evidence | Blocked at SDK abstraction; independent LDK monitor evidence required |
| Lightning fees | BTC-only existing ledger; new asset accounting would need a versioned receipt |
| Mainnet RGB Lightning via beta.5 | Explicitly blocked by upstream policy |
| On-chain RGB payout | Alternative research path with confirmations and consignment validation; distinct WDK account |

Mint backing depends on locked USDT/USDT0 and issuer/bridge redemption; UTEXO Mint describes Arbitrum USDT0 backing, AWS Nitro Enclaves, a claimed Oxorio audit with public report unavailable. Bitcoin anchoring does not remove reserve, issuer, enclave, redemption, availability or freeze risk. The original article's "no bridge" statement does not describe that mint pathway. LSP trusted virtual channels are off by default here; assess peer failure and unilateral recovery separately.

## Regtest qualification plan

| Gate | Required receipt |
| --- | --- |
| RGB-01a | Exact pinned native dependency integrity and platform; Linux fresh install, test command, SDK shape capture, test asset issuance via separate on-chain wallet and transfer to RLN |
| RGB-01b | Two funded nodes + bitcoind/indexer/proxy; open normal RGB channels; exact invoice decode, successful inbound and outbound payment; compare balances and explicit carrier/routing fees; reject mismatched ID/amount/payee/network, expiry and amount below minimum |
| RGB-01c | Persist quote, payment intent, native payment identity and independent receiver evidence; inject kill after submit/before ack, duplicate events, ambiguous timeout, restart, reorg and force-close; exact ledger replay and no double credit |
| RGB-01d | Explicitly quote BTC to RGB conversion with funded counterparties; reject stale price, depeg, insufficient liquidity, slippage and over-cap fees; verify both legs or compensation |
| RGB-01e | Benchmark >=100 attempts per amount/liquidity bucket, p50/p95/p99 latency, total fee, failure and recovery rate; compare direct BTC Lightning, RGB Lightning and on-chain RGB. Do not put payment latency on matching hot path |
| RGB-01f | Independently verify upstream mainnet capability, public security review, audited mint/asset ID, redemption and operational limits before mainnet enablement; do not bypass the SDK's mainnet policy |

No real nodes, native packages, real balances, funds, latency or chain receipts were tested in this initial change. Mock fixtures exercise the JS boundary only. No acceptance gate above is marked complete.
