# SHZ-INDEX-01: hourly Pyth/Chainlink index and eight-hour Bitcoin checkpoint

Research source registration, 2026-11-23. Base: SatsHedgeZero PR #8 at `450da80507fab8ef409f9470b072d11a60f90ce6`. No mainnet operations authorized.

## Precise goal

Establish one canonical byte encoding that can later be checked by a transparent, zero-knowledge SNARK, a NEAR verifier, and a Bitcoin `OP_RETURN` packet. The immediate executable milestone is **public SHA-256 arithmetic and inclusion verification**, using exactly eight hourly leaves for an eight-hour checkpoint. This stage supplies circuit-level test vectors and the proof statement. It is **not yet a zero-knowledge proof**.

### Timing and identity

- `hour_id = floor(UTC Unix timestamp in microseconds / 3,600,000,000)`; a record closes at `(hour_id + 1) * 3,600,000,000` microseconds UTC.
- `start_hour = hour_id - (hour_id mod 8)` and each checkpoint contains exactly hours `start_hour` through `start_hour + 7`.
- Three disjoint eight-hour checkpoints per UTC day. The network genesis hash and SHA-256 policy digest are part of every leaf and checkpoint root.
- Each record is a normalized, authenticated Pyth Pro BTC/USD observation and Chainlink Data Streams BTC/USD observation selected by a frozen latest-observation policy. **Report sourcing, chain-linkage, signer-registry rotation, and proof of completeness are separate unsatisfied gates**. The reference treats report hashes as untrusted claims.
- The initial research acceptance policy is both source publications at most five minutes before the hour close and within 60 seconds of one another; fixed-point integer prices use 1e8 USD units.
- On acceptance, `index_e8 = floor((pyth_e8 + chainlink_e8)/2)` and `20,000 * |pyth-chainlink| <= 50 * (pyth+chainlink)` (50-bps maximum relative spread). All input prices are positive and <= `10^16` e8 units. The midpoint calculation is exact `u128` arithmetic.
- On source failure, the record is `HOLD`, `hold_reason in {1,2,3}`, with both prices, index, timestamps and report hashes identically zero. The Merkle tree *includes* such a leaf, which must never authorize a dollar mint or DLC settlement. A source-selection proof must eventually establish why HOLD was necessary.

### Canonical binary transcript

All fixed-width numerical values are **unsigned little-endian**, without implicit field reduction. SHA-256 digests are 32 raw bytes, displayed in hex in the original digest-byte order.

```text
leaf_preimage = ASCII("SHZ/HOUR/LEAF/V1")
             || network_genesis32 || policy_hash32 || hour_id_u64le
             || status_u8 || hold_reason_u8
             || pyth_e8_u64le || chainlink_e8_u64le || index_e8_u64le
             || pyth_publish_us_u64le || chainlink_publish_us_u64le
             || pyth_signed_report_sha256_32 || chainlink_signed_report_sha256_32
leaf = SHA256(leaf_preimage)
node(left,right) = SHA256(ASCII("SHZ/HOUR/NODE/V1") || left || right)
merkle = balanced_binary_tree_8(leaves[0..7])
checkpoint_root = SHA256(ASCII("SHZ/8H/ROOT/V1")
               || network_genesis32 || policy_hash32
               || start_hour_u64le || merkle_root32)
packet = ASCII("SHZIDX01") || checkpoint_root32   // 40 bytes
scriptPubKey = OP_RETURN OP_PUSHBYTES_40 packet    // 42 bytes
```

A Merkle membership witness contains exactly three siblings, ordered bottom-to-top, and the leaf position `hour_id - start_hour`, in the range 0 to 7. `checkpoint_root` binds the hour range and policy against cross-network replay. The package tests both witness and non-witness Bitcoin transaction serialization. Its Bitcoin header proof checks only TXID inclusion **relative to a supplied header**; finality requires an independently verified canonical Bitcoin light-client header with a suitable confirmation policy.

### Public input to a future transparent SNARK

```text
network_genesis32
policy_hash32
start_hour_u64le
checkpoint_root32
[public selected hour_id, selected index_e8, source-authenticated receipt roots]
optional bitcoin_anchor_txid32 and authenticated_btc_header_commitment32
```

Private witness when compression/privacy is desired:

```text
8 complete hourly preimages, qualified/HOLD status, canonical source report payloads
Pyth/Chainlink registry membership or independently authenticated receipt openings
8 index arithmetic statements and 7 tree nodes
optional BTC transaction and inclusion witness, and downstream private DLC route openings
```

**Required proof predicate:** with authenticated oracle inputs as a separate proven substatement, every qualified leaf follows the price arithmetic and timing policy, each HOLD leaf follows the committed failure policy, and the resulting eight leaves hash to the exact public checkpoint. If Bitcoin anchoring is claimed, require proof of the actual `OP_RETURN` bytes, transaction serialization/TXID, Merkle inclusion and a *verified canonical block header*. Use fixed field encodings and 128-bit limbs for a 256-bit digest in BN254/Pallas fields. Do not silently reduce 256-bit digests modulo a circuit field.

The intended prover is Nova with a transparent Spartan/IPA compression or an independently reviewed transparent Halo2-IPA route. Existing `lnmarkets/sha256-transcript-accounting/v2` is a distinct relation, with a different 600-byte transcript and eight-field state. Proof reuse requires explicit circuit changes, byte-exact public inputs and pinned verifier identity. Existing `research/near_nova_ipa_02` proofs do not verify this checkpoint predicate.

### Current native NEAR contract acceptance boundary

`research/hourly_index/near_contract` uses native SHA256 to validate the eight-hour root, selected record, 3-sibling Merkle path, two-source midpoint and freshness rules. An owner may stage **research** checkpoints; that act does not authenticate the root or prove Bitcoin finality. All source, anchor, ZK, Nova and DLC settlement authorization flags remain `false`.

The latest-Pyth / latest-Chainlink eligible observation completeness problem, source key rotation, report signature verification, challenge timeouts and an independently verified Bitcoin header must be resolved before turning on any of those flags. A 40-byte `OP_RETURN` packet itself stores a commitment, and a DLC settlement still requires its separate oracle adaptor/FROST scalar authorization and BIP341 transaction constraints.

## Adversarial acceptance tests

Synthetic vectors require: any changed price or index fails, signed-report hash substitution fails, epoch reorder fails, wrong policy/genesis fails, a malformed Merkle path fails, HOLD cannot return a price, stale/future source timestamps fail, malformed arithmetic encodings fail, changing packet bytes fails, and a bad TXID-to-header Merkle branch fails. NEAR sandbox must check the exact same fixture bytes and report actual receipt gas and WASM build size.

**Scope statement:** passing these tests establishes deterministic byte-level interoperability and a native NEAR inclusion verifier, providing public inputs to a future zero-knowledge system. It does not certify authentic feed ingestion, a trustless 8-hour Bitcoin anchor, Nova validity, or the correctness of private DLC obligations.
