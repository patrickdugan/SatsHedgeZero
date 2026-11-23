# SHZ-MNR-01: security boundaries and adversarial criteria

**Simulation only.** A valid SHA-256 digest commits to bytes. It gives no evidence that an oracle, wallet, signer, chain, counterparty, or bond contract has endorsed the contents.

| Threat | Current MNR-01 check | Unmet production requirement |
| --- | --- | --- |
| Close order against wrong market, notional, expiry, or oracle event | Hard reject | Verify maker/trader BIP340 signatures and quote time against independent chain view |
| Different DLC payoff grids or rounding policies | Samples identical declared outcome grid, caps drift at 1 sat | Authenticate every CET leaf, quote terms and oracle outcome count; bind dust reserve |
| A-B position inadvertently assigned to C | Original bilateral contract remains unchanged in plan | Verify both original and offset funding outputs and unilateral recovery packages |
| Cyclic or duplicated PnL debits | Net balances rederived, duplicate obligation IDs rejected | Independently authenticate complete source ledger, consumed IDs and epoch root |
| Routing BTC from unrelated deposits | Explicit vault owners and netting-domain checks; reserves subtracted | Verify real UTXOs, script spending authority and per-vault signatures |
| Withdrawals or retained equity double-spent | Vault free capacity excludes protected and retained sats | Stateful journal reservation, one-shot signing gate, outpoint nullifier proofs |
| Route exists on paper but cannot spend DLC UTXO | `bitcoinSpendEnforced=false` on all results | Upfront authorized route script or complete co-signed spend transition |
| Multiple winners exceed one debtor vault | Integer max-flow with exact shortfall | Durable reservations across simultaneous clears and reorg handling |
| Honest users lost during batch abort | No settlement transactions are broadcast | Atomic commit, unilateral fallback, expiry coordination, watchtower test |
| Signed false VWAP, oracle conflict, reorg | Oracle data are explicit synthetic inputs | Pinned source/window, threshold verification, on-chain objective challenge policy |
| Confused-deputy or forged proof journal | All untrusted proposals mark `proofVerified=false` | Composite cryptographic relation and independently selected verifier key |
| Strong technical claims from tests | Explicit proposal-only status | Multi-party funded regtest and Bitcoin Core confirmation evidence |

## Release gate

No live signing or real-money execution until all of the following have independent test evidence: wallet-owned recovery, exact Taproot spend construction, correct multilateral authorization, authenticated oracle and payout tables, UTXO existence and reserve accounting, proof soundness if a proof is used, concurrent state recovery, and independent adversarial signet/testnet rehearsals.

A signed state root is a coordination object. Bitcoin enforces only the spending conditions built into the actual inputs. A post-hoc proof of a correct state transition cannot change those conditions.
