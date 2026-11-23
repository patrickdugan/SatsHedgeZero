# SHZ-ORACLE-02 / SHZ-CHANNEL-02: native signed price and cross-channel clearing epoch

Date: 2026-11-23. Research branch continuation of PR #3.

## Protocol question

A trader's economic closeout may match a new counterparty while the old bilateral DLC remains attached to its original Bitcoin/Lightning funding output. A solvency certificate for the *net* obligation graph therefore must be accompanied by executable signatures or pre-authorized exits for **every bilateral edge** whose collateral is being discharged. No contract ownership changes hands.

This work joins authenticated Pyth BTC/USD observations to an immutable multi-channel clearing session. The session plans actions and records wallet intent. It is not a Bitcoin witness, Lightning channel state transition, NEAR state proof, or production authorization.

## Native Pyth Pro verifier

`research/near_pyth_channel/src/pyth_payload.mjs` verifies the existing `solana` Ed25519 signed envelope under an explicitly provided, independently pinned signer allowlist, then parses the original **signed** payload bytes. The decoder matches the Pyth Lazer **standard, little-endian PayloadData** source at `pyth-network/pyth-lazer-public/sdk/rust/protocol/src/payload/standard.rs`:

- `PAYLOAD_FORMAT_MAGIC` (u32 LE `2479346549`), `timestamp_us` (u64 LE), `channel_id` (u8), feed count (u8).
- Each feed has numeric `feed_id` (u32 LE), property count (u8), tagged values. For `Crypto.BTC/USD`, the selected ID is **1**; signed fields include `Price` tag 0 (nonzero i64 mantissa), `Exponent` tag 4 (i16), `Confidence` tag 5 (nonzero i64 mantissa), and `FeedUpdateTimestamp` tag 12 (optional u64).
- Known extra tags are safely consumed. Unknown or duplicate tags/feed IDs, invalid optional-value flags, missing properties, trailing bytes and truncated payloads are rejected.
- Signed price normalization uses checked integer math into USD `e8`, and policy enforces independent signer registry, channel, freshness, carry-forward interval, future skew and confidence. The receipt binds original signed payload SHA-256, signer, timestamp, channel, BTC/USD feed ID and exact price components.

The official Pyth Rust source includes a captured wire sample with BTC/USD feed ID 1, 13 tagged properties, publication timestamp `1771339368200000`, raw price mantissa `6713436287632`, exponent `-8` and signed confidence mantissa `1500580860`. The JS unit test decodes that archived sample. Separate synthetic Ed25519 keys test adversarial signature scenarios. Pinned live Pyth signer identities and signer rotation policy remain operational dependencies; a locally generated key is never a real Pyth signer.

NEAR's experimental `near_contract/src/pyth_payload.rs` provides the corresponding strict LE decoder. The NEAR contract verifies the Ed25519 envelope under its owner-pinned key, parses the price fields, enforces a fixed BTC/USD feed and channel policy, then stores a monotonically numbered epoch with its payload hash and challenge-end block. The on-chain challenge window closure only governs that contract's own state. A remote Bitcoin/Lightning client still requires independently authenticated NEAR finality/inclusion, or must explicitly accept a trusted-observer quorum. The current JS adapter supports only a pinned **Ed25519 observer attestation**, clearly marked as that weaker trust assumption.

## Signed multilateral clearing epoch

`src/closeout_epoch.mjs` opens an epoch by **re-verifying the original signed Pyth frame**. It binds the signed price to a funded `buildCloseoutProposal` with zero aggregate USD delta, immutable channel IDs, signed package hashes (CET, refund, revocation), original channel commitment txids, pinned netting route policies, wallet identity set, network/genesis, prior accounting root and NEAR oracle event/epoch/challenge window.

Each per-wallet ECDSA secp256k1 receipt signs the same canonical `sessionHash`, `proposalHash`, `oracleReceiptHash`, channel input and full package digests. Those receipts authorize research-level channel coordination; they're *not* BIP340 Taproot sighashes, Lightning revocation secrets, CET adaptor signatures or confirmed BTC spends. The code rejects missing parties, duplicate approvals and cross-epoch replay, and never sets `collateralReleased` or `bitcoinSpendEnforced` true.

For `SHZ-MNR-02` Bob-offline legs, the epoch commits to the origination-time `0x83` adaptor preauthorization digest, fixed Bob payout digest, maturity height, grace end and refund height. A request made before maturity yields `AWAITING_MNR02_L1_MATURITY`. Past the protected priority interval, the route aborts to the unilateral fallback. This **does not** silently obtain Bob's lost signature or spend old DLCs off-chain.

### Three-party fixture

For inverse BTC/USD micro-notional $1 across $80k (Alice long/Bob short), $100k (Bob long/Carol short), and $125k (Carol long/Alice short), the $125k mark closes every net USD exposure. Alice earns 450 sats; a permissioned UTXORef graph routes 250 sats from Bob and 200 sats from Carol. Each underlying bilateral DLC remains an independent claim until an actual wallet-enforced off-chain revocation/settlement or valid Bitcoin exit.

### Evidence levels and next gates

| Gate | Current result | Next acceptance test |
| --- | --- | --- |
| Native signed Pyth price | JS unit tests validate signature + exact signed fields, official sample parity | Frozen live Pyth Pro signed BTC/USD payload and independently pinned signer/rotation source |
| NEAR binary parser | Rust implementation committed | Pinned `wasm32-unknown-unknown` compilation, on-chain price sample and adversarial NEAR sandbox tests |
| NEAR challenge registry | Bonded relayer epoch + delayed challenge window scaffold | Separate validator/observer, replay-proof finality witness, objective slashing, persistence and bond accounting |
| Price-to-clearing binding | Full session hash and signed intent receipts | Independent Lightning DLC wallet signature verifier that validates every path and original funding outpoint |
| Bob-offline closeout | Preauthorization commitment + locktime gate | Combined MNR02 `0x83` routed CET on real Testnet4 with offline counterparty and watchtower |
| BTC release | **Disabled** | Independent Bitcoin Core spends/confirmation, watchtower reorg drill and collateral conservation |
| BitVM3/ZK | Separate Nova transcript relation in existing SHZ | Constrain native oracle/authority and exact spend relation to same root; proof verified by actual enforcement mechanism |

Run locally: `node --test research/near_pyth_channel/test/*.test.mjs`. All test keys are synthetic and never authorize real funds.

## Known safety limits

The user who creates a policy must choose the Pyth signer keys and NEAR observer trust roots independently of the relayer. The signed Pyth data attests a reported price, not that any market is manipulation-free. Fraud challenges need a precise, independently verifiable infraction. FROST signatures settle only as specified by actual Bitcoin scripts. The multilateral router cannot free an old DLC's collateral solely from a graph proof.

## Protocol references

- Pyth Lazer authoritative layout: https://github.com/pyth-network/pyth-lazer-public/blob/main/sdk/rust/protocol/src/payload/standard.rs
- Pyth current signed messages: https://github.com/pyth-network/pyth-lazer-public/blob/main/sdk/rust/protocol/src/message.rs
- Pyth payload docs: https://docs.pyth.network/pro/payload-reference
- Kohen's in-channel DLC conditional transfers (for signing/failure-path insights): https://nkohen.github.io/blog/transferring-lightning-dlcs/
- Existing SHZ Bob-offline: `docs/SHZ_MNR_02_BOB_OFFLINE_CLOSEOUT.md`
- Existing SHZ live Testnet4: `docs/TESTNET4_3PARTY_NOVA_CLEARING.md`
