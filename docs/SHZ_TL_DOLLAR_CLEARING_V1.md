# SHZ-TL-USD-01 | Shared dollar liability statement and TL-USDC spot anchor

Date: 2026-11-23. Research profile, additive to existing SatsHedgeZero and TradeLayer work.

## Objective

Build **one portable, independently pinned public statement** that relates two independently
redeemable dollar liabilities to **disjoint underlying collateral**:

1. `SHZ-USD`: BTC-margined, 1x inverse-short DLC hedge-vault dollar liability, potentially
   issued as a Taproot Asset and transferred over Lightning. The original DLCs stay bilateral.
2. `TL-USDC`: an accounting claim on USDC locked by a recognized source-chain escrow, with a
   future proof-verified TradeLayer procedural mint/burn and hybrid UTXO/OP_RETURN reference.

The statement does not merge the two liabilities, inherit one issuer's redemption rights,
or imply that an SHZ-USD redemption is equivalent to a bridged USDC redemption. TL perps
and a future TL-USD synthetic can read the **BTC / independently backed TL-USDC spot VWAP**;
USDT remains a separately redeemable fourth dollar instrument.

## Common public statement

`verifyJointDollarStatement` emits a single SHA-256 domain-separated commitment to:

- Both issuer identities and liability roots, the hedge-vault book root, source USDC bridge
  escrow book root, the accepted oracle epoch, and a separately pinned future Nova program ID.
- The verified TL BTC/USDC execution-window commitment and exact-integer VWAP in `USD × 10^8`.
- Each supply outstanding and pending (burned but unpaid) redemption in **microdollars**.
- Every unique backing resource reference, sorted and checked for overlap.

Domain: `SHZ/TL/JOINT-DOLLAR-LIABILITIES/V1`.

The caller supplies independently retained **expected** book and liability roots and the
trusted observer public keys. A prover-supplied root, a syntactically correct hash, or a
self-selected signer cannot establish chain authority. The fixture uses temporary local
Ed25519 observer keys to exercise this distinction; do not put such keys in deployed policy.

## SHZ inverse-short hedge stress relation

For a BTC/USD market price `P` in an independently selected stress grid `G`, a contract of
USD notional `N` opened at `P0` and currently held short has BTC PnL:

    pnl_short_sats(P) = round_half_away(N * 1e8 * (P0 - P) / (P0 * P))

The **bounded** claim available to the vault from one bilaterally funded DLC is:

    claim_sats(P) = clamp(short_margin_sats + pnl_short_sats(P),
                          0, short_margin_sats + counterparty_margin_sats)

This capped model is an upper bound on what the signed contract could pay after settlement
before liquidity, censorship, oracle deviation and funding-time risk. It assumes the exact
payout table is enforceable by the DLC. The research checker then requires:

    assets_sats(P) = reserve_sats + sum(claim_sats(P))
                     - exit_fee_sats - risk_haircut_sats
    floor(assets_sats(P) * P * 1e6 / 1e8)
      >= outstanding_SHZ_microUSD + pending_SHZ_redemptions_microUSD

for every `P` in `G`. A finite grid gives **scenario solvency only**. It cannot establish
continuous-interval solvency, market liquidation feasibility, counterparty margin
replenishment, fee-bump access, oracle correctness, or the asset holder's enforceable payout.

Every claimed Bitcoin UTXO is associated with a signed external observer assertion about
its network, funding/spend policy, exact value, chain tip, confirmations and unspentness.
Those assertions are NOT Bitcoin consensus proofs: actual UTXO observation, unilateral
recovery, presigned CETs, channel revocation and corresponding holders' Taproot Asset
proofs still require independent integration. All coin IDs are reserved once across
SHZ positions, SHZ free reserves, and any explicitly pledged bridge resource.

## TL-USDC bridge relation

The source-chain adapter accepts a *signed claim* of a finalized USDC escrow deposit
identifying the **exact** chain, token contract, escrow address, tx hash, event index,
amount in micro-USDC, beneficiary, output property and confirmation context. Its event
key is `usdc:<chain>:<token>:<tx>:<logIndex>`. The bridge policy independently pins
source/destination identities and the accepted escrow book and liability roots.

With total source deposits `D`, source-chain releases `R`, tokens minted `M`, tokens
burned `B`, outstanding tokens `O` and pending redemptions `Q`, the checker requires:

    O = M - B
    Q = B - R
    D - R >= O + Q
    0 <= R <= B <= M

This is a deliberately small **single-asset pool** model. Production needs proof that a
release corresponds to a particular authorized burn and that its destination is bound to
the same beneficiary; pending burns must stay encumbered and uniquely payable.

**Source claims MUST be replaced by verified chain events** before mint: Ethereum/Base
source contract log inclusion and finalized chain membership, NEAR Omni Bridge
attestation/finality where applicable, independent USDC issuer/token identity and
withdrawal capacity. A NEAR-signature receipt is one possible attestation tier;
NEAR bridging into TradeLayer does not automatically make a wrapped token issuer-
redeemable USDC. Chainwork/finality and escrow-control rules must be pinned.

No TradeLayer consensus supply mutation occurs in this research crate. Existing
`tradelayer.js` transaction types 33 (`coloredCoin`) and 34 (`crossLayerBridge`) have
wire handlers, but this experiment does not activate a new transaction type or claim
that the current code accepts procedural proof-controlled minting.

## BTC / TL-USDC spot VWAP

Take genuine on-ledger fills denominated in executed BTC sats and transferred USDC
micro-units. The window price in `USD × 10^8` is exactly:

    round_half_up( sum(executed_usdc_micros) * 1e8 sats/BTC * 1e8 priceScale
                   / (sum(executed_btc_sats) * 1e6 micro/USD) )

No binary floating-point prices or candle weights are used. A signed snapshot from the
independent TradeLayer indexer binds the sorted execution list, network, asset pair,
height and block hash. The independent verifier pins the expected execution root.
Checks also cover repeated trade IDs, self-crosses, stale windows, minimum realized BTC
volume, distinct makers, max per-maker volume concentration and deviation from a
separately accepted signed Pyth price. These checks bound obvious manipulations;
distinct accounts can still be Sybil controlled. Production requires trade provenance,
CLOB/AMM execution validity and an indexer that can prove match-level fees and transfers.

### Current TradeLayer-Rust integration

`TradeLayer-Rust/src/volume_index.rs` already has a unique-ID `VolumeHistory`, directional
`vwap` and rollback. The old JavaScript `saveVolumeDataById` overwrites pair-ID entries
and stores `rawVolume` where `getVWAP` reads `value.volume`; use the existing Rust repaired
history instead of copying the source's overwrite behavior.

The Rust `VolumeRecord` carries `event_id`, `pair.first`, `pair.second`,
`raw_volume_atoms`, `price_atoms`, `block_height`, `kind`; it does **not** carry the
original executed quote quantity or maker/taker. The additive
`convertVolumeHistoryWindow` adapter therefore *requires* an independently matched
trade-detail source and checks quantity, eight-decimal price and pair orientation.
It rejects a bare `VolumeRecord` as economic-price evidence. The adapter's next step
is an exporter in the Rust economic owner's authenticated receipt path.

## Proposed compact OP_RETURN bridge reference

Research-only `TLUSDC` v1 payload, 76 bytes in a minimal 79-byte script:

| Offset (in payload) | Length | Content |
|---|---:|---|
| 0 | 6 | ASCII `TLUSDC` |
| 6 | 1 | Format version `0x01` |
| 7 | 1 | Operation `1=mint`, `2=burn` |
| 8 | 4 | TradeLayer property ID, big-endian |
| 12 | 32 | Joint public statement SHA-256 |
| 44 | 32 | Unique origin-event nullifier |

Script: `OP_RETURN OP_PUSHDATA1 0x4c <76 bytes>`. The reference binds the proof, leaves
its 12 KB+ witness/proof in off-chain availability or another witness construction,
and carries no Bitcoin-side issuance authority. The experimental replay gate is an
in-memory detector and must be replaced by TradeLayer's persistent **consensus** replay
and valid supply state. It does not assert Bitcoin consensus has activated a new asset
bridge opcode. A data commitment cannot independently make a release atomic.

## Potential Nova/BitVM3 relation (future actual proof)

Public: network genesis, SHZ asset genesis, TL property ID, epoch oracle root, pinned
source verifier identities/program hashes, old/new USDC escrow + supply roots,
old/new SHZ liability + collateral roots, exact grouped Bitcoin settlement txid,
nullifier root, and resulting joint commitment.

Private: complete source deposit logs/receipt proofs, accepted Bitcoin UTXO membership
and spend/ownership witnesses, DLC payout/adaptor/recovery packages, token liability
updates, exact amounts, unique event paths, TL spot fills, authenticated timestamp
and fee-routing receipts.

Constraints must bind both source roots to *independently observed canonical state*,
check all signature/chain membership operations that the statement claims, verify
integer conservation and caps, establish a single active nullifier per funding or
mint/burn event, and prove both old-to-new ledger transitions. Any unconstrained
copy of a signed price, UTXO, or amount is a proof-soundness failure.

**The current Node implementation verifies signed-reference arithmetic only** and
sets `novaProofVerified`, `bitvm3OnchainEnforced`, `mintAuthorized`, `redeemAuthorized`
and `productionReady` to `false`. There is no native Nova circuit, BitVM3 verifier,
NEAR light client, Lightning wallet, or TradeLayer consensus mutation in this PR.

## Suggested integration gates

1. Pin actual source chain/token/escrow identities and source-specific finality verifier;
   add source-state proofs, event nonmembership and independently retained roots.
2. Export exact Bitcoin/Core UTXO and DLC recovery evidence from SHZ, including the
   Taproot Asset supply/genesis/burn proofs of every holder and tested 1x risk bounds.
3. Feed verified execution receipts from the existing TradeLayer-Rust economic owner
   to the strict BTC/USDC adapter and compare with independently signed Pyth mark.
4. Implement testnet mint/burn with persistent nullifier set in a separately authorized
   TradeLayer protocol change, including reorg/abort and redemption failure tests.
5. Implement and audit the Nova relation, pin VK/program hashes and test valid proof,
   forged input, external reorg, mixed-state root, and genuine Bitcoin/TradeLayer spend.

## Independent references

- [TradeLayer-Rust unique execution index](https://github.com/patrickdugan/TradeLayer-Rust/blob/40fbaebeba58c62e123c4cb71977807feac997cf/src/volume_index.rs)
- [TradeLayer-Rust source parity / volume issues](https://github.com/patrickdugan/TradeLayer-Rust/blob/40fbaebeba58c62e123c4cb71977807feac997cf/docs/volume-index.md)
- [SatsHedgeZero Testnet4 multilateral clearing](TESTNET4_3PARTY_NOVA_CLEARING.md)
- [SatsHedgeZero Pyth signed price and multilateral LN-DLC proposal](https://github.com/patrickdugan/SatsHedgeZero/pull/3)
- [Taproot Assets asset proof semantics](https://docs.lightning.engineering/the-lightning-network/taproot-assets/taproot-assets-protocol)
- [Taproot Assets PSBT atomic swap](https://docs.lightning.engineering/the-lightning-network/taproot-assets/trustless-swap)
- [NEAR Omni Bridge proof and MPC boundaries](https://github.com/Near-One/omni-bridge)
