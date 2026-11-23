# SHZ-ORACLE-01 + SHZ-CHANNEL-01: provenance-verified Pyth imports and cross-channel netted closeout

Date: 2026-11-23 · research proposal v0.1

## Goal

Offer noncustodial BTC-margined inverse positions a liquid, multilateral exit market even though each Discreet Log Contract and Lightning channel encodes rigid bilateral claims. A trader may close against a different trader without requiring a literal assignment of DLC ownership. The netting engine routes realized PnL to authorized beneficiaries while validating that every retained claim remains funded. Existing Alice–Bob and Alice–Carol contracts remain enforceable until an agreed closeout spends them or a preauthorized exit matures.

The oracle role is to bind every clearing epoch to a precise BTC/USD outcome with objective challenge evidence, using Pyth Pro signed prices, TradeLayer VWAP as an independent reference, and optionally a NEAR bonded observation registry. **Pyth Core retired NEAR on 2026-08-26.** A Pyth native data source is available via Pyth Pro's Ed25519 `solana` format; a custom NEAR verifier can check the signature but must also parse the signed inner payload and pin the approved signer registry. The legacy 32-byte Pyth Core feed ID is **not** the Pyth Pro `u32` feed ID. The Pyth Pro feed catalog identifies `Crypto.BTC/USD` as numeric feed ID **1**; pin that ID and catalog revision in the signed policy.

## Trust boundaries

| Boundary | What gets authenticated | Remaining trust / dependency |
|---|---|---|
| Pyth Pro Ed25519 frame | Exactly the payload bytes signed by a pinned approved key | Inner parsing, feed mapping and time policy; key-rotation governance |
| SHZ independent verifier | Decoded price, source hash and freshness signed by separate reviewer | The independent verifier must correctly parse and validate the native Pyth payload |
| NEAR bonded relay | Event, network, pinned contract, round, source receipt, relayer signature and bond | Native NEAR contract deployment, finality proof, escrow design |
| TradeLayer VWAP | Independently verified transaction/fill window and witness quorum | Correct canonical chain, window, liquidity and manipulation filters |
| FROST oracle | Bitcoin event/outcome attestation | Nonce safety, quorum, challenge policy; equivocation alone does not prove market-price truth |
| DLC / LN enforcement | Bitcoin signatures and unilateral recovery with confirmed UTXOs | LN-DLC implementation, pre-signed CET/refund/penalty packages, channel revocations and fee bumping |
| BitVM3 / Nova | Constraint-backed transcript/accounting root once full proof composition exists | Current SHZ receipts explicitly mark `bitvm3_onchain_verified: false` |

NEAR's Chain Signatures use threshold signing, including ECDSA/Ed25519 supported paths. This is a coordination feature, not an automatic bridge into the BIP340 adaptor-signature format used by our NUMS Taproot DLCs. Keep SHZ collateral in Bitcoin script paths controlled by participants and precommitted restrictions.

## Oracle flow

1. Pyth Pro `POST /v1/latest_price` requests `formats:["solana"]`, properties `["price", "exponent", "confidence", "feedUpdateTimestamp"]`, and the signed numeric feed ID. The backend safeguards the API key. Archive exact response bytes and key rotation epoch.
2. A pinned Pyth public key verifies the Ed25519 signature on the exact Lazer binary payload. Decode `PayloadData` from those bytes and independently check feed ID, exact integer price, exponent, carry-forward freshness, confidence and rounding. Reject unknown property tags and trailing bytes.
3. TradeLayer VWAP for the signed observation window is computed from consensus-pinned fills and the independent price agreement is checked against a configured error band. Different source identities must remain distinct: using two relayers for the same Pyth source does not make them independent economic observations.
4. A bonded relayer commits `eventId`, `round`, NEAR contract ID, chain ID, source digest, chosen settlement mark, policy digest and expiry. NEAR validates native Pyth evidence (when that on-chain parser lands), records the root and accepts fraud challenges. Read the finalized NEAR state with a light-client proof or an explicitly bounded quorum assumption.
5. FROST 3-of-5 signers attest outcome digits only after their policy accepts the evidence. Signer nonces are single-use. Missing updates and source disagreement trigger HOLD, precommitted timeout, or a conservative fallback instead of forced consensus.
6. UTXORef marks each funded batch against the accepted oracle epoch and independently opened prior ledger. Nova eventually proves source binding and settlement arithmetic together. A verifier pins both the public state root and exact Bitcoin txid.

## Fraud challenges

**Relay equivocation:** two valid Ed25519 signatures by the *same bonded relay key*, for the same contract/event/request/round, commit incompatible values or receipt roots. The local `proveEquivocation()` verifies both signatures and emits evidence hashes. NEAR contract acceptance and transfer of bonded funds are separate events. Repeated signed messages with matching commitments are valid repeats.

**Source substitution:** a signed relay claim binds an independently verified source receipt, but changes its price or time. Both signatures must verify and the source's feed/event/domain must match the same policy. The starter emits a challenge candidate and continues to reject the import.

**Price deviation:** if Pyth and TradeLayer differ, freeze and publish a challenge. A disagreement is not, by itself, proof that either source lied. Slash only when the policy defines a canonical outcome and a verifier can prove a signed violation. Price confidence, TWAP window, market dislocations and stale updates need explicit grace rules. Review the existing `shz-oracle::fraud_proofs` before using its `NearRelayEnvelope` as authoritative Pyth evidence; it currently accepts BIP340 signatures from *configured relayers* rather than proof of a Pyth native signature.

**FROST nonce reuse:** The existing scalar-extraction research only applies to conflicting signatures using the same nonce. Avoid generalizing that construction into guaranteed punishment for every oracle equivocation. Bonds must be locked in a script or NEAR contract that checks their own fraud relation; commitment hashes alone do not create slashing authority.

## Cross-channel multilateral closeout

Three distinct bilateral positions, at price P:

    C_AB: Alice long  $N at P0 vs Bob short
    C_BC: Bob   long  $N at P1 vs Carol short
    C_CA: Carol long  $N at P2 vs Alice short

The signed USD deltas for Alice, Bob and Carol each sum to zero. Realized Bitcoin PnL is exactly:

    pi_i = round(N * 10^8 * (P - P_entry) / (P_entry * P)) sats
    sum_i pi_i = 0

For micro-trades N=$1, entry levels 80k/100k/125k and mark 125k, Alice receives 450 sats; Bob loses 250 sats after his +200 offset; Carol loses 200 sats. A permitted UTXORef graph routes 250 Bob -> Alice and 200 Carol -> Alice. An accounting-only netting result proves where amounts should go. Spending an actual DLC requires signatures over exact proposed input/output transactions.

### Channel route handshake

- **PROPOSE**: close intent signs the accepted price state, old bilateral contract IDs, notional and per-channel funding authorization policy. Reserve sufficient capacity without prematurely spending anything.
- **PREPARE**: all parties validate complete CET and refund packages, dispute/penalty transactions, fee anchors, timelocks and payout templates, including an explicit Bob-offline `0x83` policy when applicable.
- **LOCK**: every relevant channel signs its new commitment and completes required revocation acknowledgements before any linked preimage is revealed. Use staggered expiries with a safety delta between hops, and penalty/fallback scripts that preclude mixed success/failure theft.
- **EXECUTE**: reveal HTLC/PTLC condition only under independently checked lock receipts and broadcast the matched settlement transactions; on timeout follow the pre-signed unilateral exits. Record reorg freezes and replay nullifiers.
- **SETTLE**: wait for Bitcoin-confirmed spends (or a fully enforced LN state transition) and reconstruct residual collateral. Only now may the ledger mark the original bilateral claims extinguished and release collateral. A synthetic offset alone can leave both initial DLCs funded and still outstanding.

The generic in-channel DLC conditional scheme in Nadav Kohen's work concerns a literal DLC transfer. SHZ instead needs its signing-order, HTLC escrow, state revocation, and penalty insights for multilateral **economic closeout**. Each bilateral DLC remains attached to its own channel until a signed settlement discharges it. Channel capacities, revocation windows and unilateral CET paths dictate which netting cycles are executable.

### Bob-offline path

The existing SHZ-MNR-02 three-leaf Taproot tree has a presigned `0x83` Bob output, Alice+guard routes at maturity, a CLTV unilateral CET fallback and later refund. Before maturity, a separate LP can advance Alice's liquidity against the future routed claim. The initial close against Carol changes exposure immediately, while collateral release waits for maturity or a Bitcoin-enforceable preauthorized exit. Integrating this with the 3-input Testnet4 clearing transaction is an explicit new test, since the current public Testnet4 pilot signs the batch with both parties' keys on each input.

## Experimental acceptance plan

1. Run the 26+ fail-closed Node tests and freeze a real Pyth Pro `solana` message as a signed test vector with the correct numeric BTC/USD feed ID. Confirm identical decoding in Rust and Node, and separately validate Pyth signer provenance.
2. Deploy `near_contract/` to NEAR testnet after compiling and auditing; test valid Pyth outer signature, spoofed key, stale inner feed, duplicate relayer round, on-chain challenge/slash and contract restart. The current contract only checks the outer signature, so the price-parser and policy tests are required before oracle-authorized settlement.
3. Connect real NEAR finality proofs, a TradeLayer VWAP witness and a 3-of-5 FROST policy with adversarial source disagreement.
4. Implement the 3-party triangle on independent LN-DLC channel nodes. Verify deterministic route solvency and full on-chain recovery for one node offline, then full sequence of revocations and penalty transactions.
5. Run Testnet4 with a real Bob-offline preauthorization and independent LP, keeping exact transaction receipts, proof verifier identities and chain confirmations pinned. Require explicit production sign-off after all validity and reorg checks.

## References

- Pyth Core NEAR support ended August 26, 2026: https://docs.pyth.network/price-feeds/core/use-real-time-data/pull-integration/near
- Pyth Pro signed formats and `feedUpdateTimestamp`: https://docs.pyth.network/pro/payload-reference
- Official Lazer Solana signed envelope: https://docs.rs/pyth-lazer-protocol/latest/src/pyth_lazer_protocol/message.rs.html
- NEAR host signature verification: https://docs.rs/near-sdk/latest/near_sdk/env/fn.ed25519_verify.html
- NEAR Chain Signatures architecture: https://www.near.org/chain-abstraction
- Nadav Kohen, transferring in-channel Lightning DLCs: https://nkohen.github.io/blog/transferring-lightning-dlcs/
- SHZ-MNR-02 regtest: docs/SHZ_MNR_02_BOB_OFFLINE_CLOSEOUT.md
- SHZ 3-party Testnet4 receipt: docs/TESTNET4_3PARTY_NOVA_CLEARING.md
