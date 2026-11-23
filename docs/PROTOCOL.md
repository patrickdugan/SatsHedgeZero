# SHZ-MNR-01: multilateral netted routing for bilateral DLCs

Date: 2026-11-23. Status: **research / synthetic execution only**.

## Target

A user closes a market exposure against a willing third-party trader, even when the original contract's counterparty is different or temporarily offline. Every underlying DLC remains an individually enforceable bilateral obligation. The multilateral network nets and routes *payout entitlements* through a separately authorized clearing transition.

This is a **counterparty-independent exit market**, not transfer of a DLC or its ownership. A trader can be economically offset immediately after a new fully-funded and valid bilateral DLC is opened. Releasing the trader's original collateral or retiring its old contractual obligation requires a valid settlement transition or an authorized liquidity advance.

## Definitions

Let `A` hold a long inverse contract against `B` with USD notional `N`, entry `P0`, and settlement `P2`. An independent counterparty `C` offers a new DLC where `A` is short, with the same notional and settlement event, entered at clearing price `P1`.

In exact BTC arithmetic:

\[
\pi_L(P_a,P_b)=N(1/P_a-1/P_b),\qquad
\pi_L(P_0,P_2)-\pi_L(P_1,P_2)=\pi_L(P_0,P_1).
\]

The closing user's PnL is constant across outcome prices. Both original and offsetting legs remain live. Each BTC-to-sats DLC payout typically rounds independently; the reference relation uses toward-zero integer division and checks the entire *declared* outcome grid for residuals of at most 1 sat. The production verifier must bind that grid to the signed oracle event and CET payout tables and reserve enough rounding dust.

## Clearing graph

Each settled bilateral leg contributes a directed PnL obligation from losing party to winning party. A matrix `A` of debtor/creditor incidence and vector `g` of obligations define signed net balances:

\[
b=Ag,\qquad \sum_i b_i=0.
\]

The solver creates a deterministic debtor→creditor transport plan preserving `b`. It may remove circulation and decrease total payable volume, subject to each participant's advance netting consent. The graph's account IDs, network, collateral asset, payout event, claim set, and epoch must all be authenticated and signed before any transaction is authorized.

Funding is a second graph. Each source vault `v` has available sats

\[
F_v=U_v-E_v-R_v-f_v
\]

where `U_v` is independently proven spendable collateral, `E_v` retained equity, `R_v` protected reserve, and `f_v` miner-fee budget. The maximum-flow solver can allocate up to `F_v` along **permitted** vault-to-payout edges; a positive residual shortfall rejects the proposal. In this prototype the edges are unverified declared policy data. A spendable system must verify the actual policy and signatures inside the party's signing or Bitcoin settlement boundary.

## Lifecycle proposal

1. **Register bilateral DLC:** each wallet saves the complete signed CET/refund package, checks both its own funding contributions and the consensus-valid unilateral exit, and pins the original funding outpoint and contract digest.
2. **Match third-party close:** a new liquidity provider signs a quote with notional, direction, inverse price, rounding and fee terms, oracle event, expiry, margin requirements, and recovery policy. The closers agree on the identical settlement event and bounded payoff grid.
3. **Fund offsetting DLC:** wallets sign and verify the new offsetting DLC's bilateral funding and recovery package. Only independent on-chain/channel state verification can mark this leg active. The initial economic-close claim requires both legs funded and enforceable.
4. **Build clearing epoch:** gather signed, unspent obligations under one authorized netting domain. Compute exact satoshi PnL and unencumbered vault capacities; find a max-flow funding witness. All touched parties must have opted into the netting policy before the closure is represented as settled.
5. **Commit and prove:** bind source-ledger root, netting domain, oracle event, original contract set, consumed authorizations, payout accounts/scripts, selected inputs and exact output bytes. Sign with every required spending key or use a reviewed, already enforceable script path.
6. **Atomic settle or recover:** prove that no participant loses their unilateral exit during a clearing interruption. Participants keep full original recovery copies until the new settlement is final. Watchtowers handle unilateral exits, fee bumps, and chain reorganizations.

### Offline original counterparty

Bob being offline after the original Alice–Bob DLC was funded is an explicit target case. It demands an original contract design that authorizes the later routing transition ahead of time, or a credit/liquidity arrangement that lets Alice exit economically while Bob's old DLC remains live. A signature from Bob cannot be conjured later by a FROST state oracle; a batch proof cannot override Bitcoin's spend conditions. MNR-01 tests accounting and funding feasibility, and leaves offline **enforceability** as the leading unanswered design challenge.

### Lightning model

Funding through Lightning requires a bilateral DLC-channel implementation with verified channel updates, contest delays, and unilateral exit paths. Multihop clearing should commit an atomic set of conditional changes; timeouts must be chosen with adequate margins for every hop and adversarial on-chain conditions. No Lightning or HTLC claim is implemented in the prototype.

### Oracle model

Start with Bitcoin USD inverse contracts and a common settlement-event ID. The SHZ oracle policy can use TradeLayer VWAP and relay observations from other sources, with rules for bucketing, missing observations, disagreement, replay, and equivocation. A FROST threshold group can sign an agreed state/price commitment; it is accountable only to whatever fraud evidence and slashing script are independently enforceable. A signed wrong price requires objective price-source and dispute rules, while two inconsistent signatures can support a narrower equivocation challenge.

### Next cryptographic relation

`SHZ.MNR02.CLEAR.v1` should prove for an independently pinned epoch: opening of all consumed bilateral claims; selected oracle outcome and signed payout-table membership; correct integer PnL including dust; zero-sum netting; complete vault backing; selected route and capacity policy authorization; distinct spent outpoint/nullifier tracking; and exact Bitcoin transaction input/output binding. Its full soundness claim additionally requires native chain verification and a spend path that enforces the same statement.

The preliminary Nova proof in `zk-rusto-no-bitcoino/LNMarkets` covers fixed-row SHA-256 transcript accounting and has a separate signature gadget. Those statements have not yet been composed into the complete clearing proof.
