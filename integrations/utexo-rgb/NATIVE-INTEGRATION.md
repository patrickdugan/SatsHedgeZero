# SHZ-RGB-01D | Native WDK peer mapping and SHZ candidate boundary

Research only, 2026-11-26. SHZ base 85e70d2dc09fd808e4b5c1b2f18d7450336e60f9. No native SDK execution, live BTC/RGB transfer, Rust build or venue connection was available locally. Node 22.16.0 passed all 22 tests in journal, observers, checkpoint and native-integration suites (six new tests). Prior 01C sidecar CI passed (45853898512); Rust/core-regtest and MNR05 workflows failed at that head. Their causes were not investigated in this change.

## Exact sources

- [WDK read-only API](https://github.com/UTEXO-Protocol/wdk-rgb-lightning/blob/608937d849412a4c25e9b9a66a7571b561396ae0/index.d.ts), [read-only implementation](https://github.com/UTEXO-Protocol/wdk-rgb-lightning/blob/608937d849412a4c25e9b9a66a7571b561396ae0/src/wallet-account-read-only-rgb-lightning.js)
- [Node native binding declarations](https://github.com/UTEXO-Protocol/rgb-lightning-node-nodejs/blob/8b78387df4c33140a52c19c6de6fcc8d4aa7595c/index.d.ts), [binding implementation](https://github.com/UTEXO-Protocol/rgb-lightning-node-nodejs/blob/8b78387df4c33140a52c19c6de6fcc8d4aa7595c/index.js)
- [RLN payment type and get_payment](https://github.com/UTEXO-Protocol/rgb-lightning-node/blob/ecc69f20308231400561f6f060fea88acfa40cc4/src/routes.rs), [SDK payment tests](https://github.com/UTEXO-Protocol/rgb-lightning-node/blob/ecc69f20308231400561f6f060fea88acfa40cc4/src/test/lib_sdk/payment.rs)
- SHZ [venue explorer serialization](../../crates/shz-venue/src/core.rs), [HTTP handlers](../../crates/shz-venue/src/http.rs), [durable router](../../crates/shz-dex/src/routing/tiered_durable.rs), [V3 clearing](../../crates/shz-dex/src/routing/clearing.rs), [venue API](../../docs/SHZ_VENUE_API.md)

## Native peer mapping

Use only independently authenticated query transports bound to pinned local regtest peers. The direct Node SDK LightningPayment object contains snake_case fields (payment_type, asset_amount, amt_msat, payee_pubkey, preimage, etc.), unlike the normalized record used by 01C. The HTTP daemon envelope is distinct; do not silently unwrap or infer missing fields. Read configuration and actual network, ready state, node identity, both decoded invoices, both terminal payment histories, and recipient invoice status. Require exact asset ID, units, carrier, hash, payee, direction and both preimages hashing to the payment hash. Exact integer decimal strings or safe numbers only. Unknown or missing values fail closed. Native peer API can expose preimages: never publish them, invoice secrets or raw responses. Public qualification record contains only limited payment metadata.

qualifyNativePair is wired into the pinned RGB-LN regtest benchmark after both sides report success; its failure stops the run. observeAuthorizedNativeRgb uses a separately signed reserve-authority funding binding and requires invoice expiry exactly matching the reservation. It returns the existing normalized RGB observation for 01C. It does not sign reconciliation or prove channel balance deltas, force-close recoverability or independent native state persistence. SDK response mapping is source-grounded and tested with constructed fixtures, not captured responses. The benchmark has not executed. An observer must establish actual transport identity and node separation before signing; functions with different JS identities do not suffice.

## SHZ candidate, not a withdrawal receipt

The actual venue explorer returns committed batch data, settlements, clearing rows, current account balances and durable journal tip; acknowledgements are simulated. There is no withdrawal reservation mutation in inspected router/venue. inspectCandidate reads journal-before, batch, accounts, journal-after. Requires unchanged tip/config, committed phase and fee ledger, positive committed timestamp, matching owner/outpoint/approval/ack marker, V3 row consistency and global cash conservation, exact settlement net/payout, and current account ownership. Rust's nested clearing rows encode txid as bytes while explorer account/channel objects use hex; both are handled explicitly. Numbers outside JS safe integers fail closed. The conservative diagnostic cap is max(0,min(row.net,free,cumulative realized_pnl)); it is not a proof of entitlement, historical profit ownership or a reservation, and may undercount. It can be replayed; do not allow this observation to authorize spending. No verified actual venue receipt was available.

## Required SHZ changes for a real authorization

Implement a dedicated durable withdrawal mutation in the router rather than relying on explorer JSON:
- Owner BIP340 consent binds network/config, owner, lane, exact amount, destination script, withdrawal nonce/ID, expiration and relevant committed clearing batch/digest; quote details and provider identity must be bound by a separate versioned exchange authorization.
- Recheck current free balance and relevant reservations under the router's single-writer transaction; move the amount from free to a distinct reserved withdrawal account atomically with WAL persistence and prevent concurrent order spending or reuse. Extend balance conservation, replay and migration; do not mutate a signed clearing batch.
- Export a signed withdrawal receipt pinned to that durable mutation and independent channel-monitor/confirmed Bitcoin payout evidence. Independently verify the user's signature and actual funding. The journal reserve authority must refuse all explorer-only candidates.
- Commit debit/release only on authenticated terminal disposition; ambiguous external dispatch holds funds, reorg freezes state; cancellation requires independently proven non-dispatch or irrevocable cancellation. Preserve existing DLC unilateral recovery.
- Prove this across two concurrent withdrawals, trading during reservation, insufficient free funds, stale/replayed nonce, partial payment, crash boundaries and reorg. Add native observer to the funded harness, then verify full BTC/RGB delivery and fee/balance reconciliation. Mainnet policy remains disabled.

The reference code intentionally cannot invoke the actual reserve or dispatch APIs. The operator must provide a disposable native stack as documented in BENCHMARK.md, exact source and native package provenance, and private upstream build access. No production approval.

Run npm test; run node benchmark.mjs rgb-ln 1 25 first on the dedicated funded fixture before increasing to 100. Preserve actual failure and unexecuted counts.
