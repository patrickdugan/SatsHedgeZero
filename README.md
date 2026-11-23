# SatsHedgeZero (SHZ)

**Non-custodial Bitcoin inverse derivatives research.** The initial experiment is **SHZ-MNR-01: multilateral netted routing**, for users who need to economically close a position against a different counterparty from their original bilateral Discreet Log Contract (DLC).

A bilateral DLC commits a particular funding output and a fixed payout/recovery construction. The SHZ router seeks multilateral closeout liquidity *across* those bilateral contracts. It does **not** sell or assign the original DLC, and it does **not** assume an off-chain accounting entry can spend Bitcoin collateral.

## Research fixture

Alice holds a long BTC/USD inverse DLC against Bob, opened at $50,000. Carol offers to take the other side of Alice's closing order at $55,000. Alice opens a **new, offsetting short** against Carol using the same notional, oracle event, and maturity. The original Alice–Bob DLC stays intact. Across the agreed payout outcomes, Alice's combined BTC PnL is approximately the $55,000 closing mark, within a 1-sat rounding allowance per outcome. Bob and Carol retain their individual economic exposures.

At a $60,000 settlement outcome and a $50,000 notional, the bilateral obligations are Bob→Alice 16,666,666 sats and Alice→Carol 7,575,757 sats. Permitted multilateral netting *proposes* Bob→Alice 9,090,909 sats and Bob→Carol 7,575,757 sats. The settlement router can assess whether declared vault capacities and route edges can fund those payouts. An actual Bitcoin transaction needs signatures or enforceable pre-authorizations covering the routing change.

The *initial* benefit is an offsetting economic position. Alice still has gross bilateral collateral, credit, liquidity, and settlement exposure until an enforceable multilateral closeout becomes available.

```bash
npm test
npm run demo
```

Node.js 20+; dependency-free. All coins, outcomes, vaults, approvals, and height inputs are synthetic in MNR-01.

## Components

| Module | Responsibility |
| --- | --- |
| `src/closeout.js` | Create a third-party inverse offset; enumerate outcomes and quantify 1-sat rounding slippage |
| `src/netting.js` | Reduce a graph of bilateral realized PnL obligations to net payouts without changing account entitlements |
| `src/router.js` | Find an integer max-flow allocation from declared unencumbered vault capacity to exact recipient demands |
| `src/core.js` | Strict integer parsing, stable JSON serialization, domain-separated SHA-256 proposal digests |
| `test/mnr01.test.js` | Positive and negative marks, funding cuts, invalid counterparties and event scopes, replay duplicates, reserve violations |
| `docs/PROTOCOL.md` | Closeout protocol and enforcement requirements |
| `docs/THREAT_MODEL.md` | Open problems, security and production gates |

## Validation and limits

The router's positive result is `CAPACITY_FEASIBLE_PROPOSAL`. It authenticates **neither** its input vaults nor the authorizations that make the proposed routes spendable. Both `productionReady` and `bitcoinSpendEnforced` remain `false`. No signature verification, Bitcoin Core integration, Lightning channel update, FROST oracle, fraud-proof bond, or Nova proof is present in this repository yet.

No part of this experiment has mainnet spending authority. Zero refers to the intended exchange trading fee; Lightning routing, miner, watchtower, liquidity, and proof costs require their own explicit policy.

## Upstream research

- [UTXORef funded PnL batch netting](https://github.com/patrickdugan/UTXO-Ref/pull/13) contains the earlier deterministic funding graph, V2 signed checkpoint, and guarded regtest batch execution. Its production custody gate is still pending.
- [UTXORef bilateral LN Markets model](https://github.com/patrickdugan/UTXO-Ref/pull/14) contains regtest-funded Taproot DLC CET/refund recovery paths. It does not provide third-party closure.
- [LNMarkets Nova batch proofs](https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/28) contains transcript-accounting and separate BIP340 proof components; full composite DLC authorization remains unfinished.

The local MNR-01 solver has independent interfaces for now. A later integration should pin upstream commit SHA, port and equivalence-test the UTXORef max-flow rules, then bind the Nova proof to the exact funding outpoints, recovery digests, routing policy, and Bitcoin transaction.
