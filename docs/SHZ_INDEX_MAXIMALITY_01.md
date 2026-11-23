# SHZ-INDEX-MAX-01: sealed ordered log and constrained latest-observation selection

Registered 2026-11-24. Parent: INDEX-POLICY-01 PR #11, `dc2a8935d368d0b31cc096261440314511ddb891`. Separate from Gemini's source adapters, NEAR verifier, Bitcoin SPV and FROST work. This extension addresses selection maximality and conditional absence, before the already verified policy relation classifies VALID/HOLD.

## 1. Statement and trust model

For each source, let the admitted log be a strictly time-ordered sequence of normalized positive BTC/USD reports. Admission must authenticate the source, exact signed bytes, digest, normalized price, publication time and registry policy. Duplicate times are rejected in this profile. The receiver pins the canonical log snapshot only after checking its append/seal history (or a sound proof of that history). The seal is an authorized, independently established watermark; it must reflect a real cutoff and finality/data-availability policy. The append verifier does not establish the wall clock or the provider's unseen messages.

For cutoff `t`, the result is the rightmost admitted record with `publish_us <= t`. If none exists, select a distinguished absence sentinel. A stale predecessor stays selected; INDEX-POLICY-01 then derives HOLD from freshness. A root chosen by the prover, a fabricated seal, and a withheld provider update remain outside the security guarantee. Authentic source reports alone do not prove completeness.

## 2. Authenticated minimum tree

A fixed-depth prefix tree has index 0 occupied by the canonical absent candidate `(0,0,0,zero32)`. Indices 1 through `count` contain admitted records in strictly ascending timestamp order. Remaining positions are empty with `min = 2^64-1`, a reserved timestamp. All integers are unsigned little-endian. Summaries contain `(min_u64, digest32)`.

```
leaf(c) = (c.time, SHA256("SHZ/LOG/LEAF/V2" || encode_candidate(c)))
empty = (MAX_U64, SHA256("SHZ/LOG/EMPTY/V2"))
parent(l,r) = (min(l.min,r.min), SHA256("SHZ/LOG/NODE/V2" || encode(l) || encode(r)))
pin = SHA256("SHZ/LOG/SNAPSHOT/V2" || genesis32 || policy32
             || source_u8 || depth_u8 || count_u64 || last_time_u64
             || sealed_through_u64 || root.min_u64 || root.digest32)
```

`encode_candidate` is exactly the 49-byte POLICY-01 encoding. Source IDs Pyth=1, Chainlink=2. Root minimum is zero because the sentinel remains present. Network, policy, source, depth, count, tail time and seal are immutable under the pinned snapshot identity. For a single append, open the next empty index in the old root and the same position with the new report in the new root, sharing the identical siblings. Require `new_count=old_count+1`, a strictly advancing timestamp above both the old tail and the old seal, unchanged context and unchanged seal. Recompute all summary minima and digests along both paths. A seal-only transition preserves the root and every other field and advances the watermark monotonically. Initialize from the independently computed sentinel-only genesis. This inductively establishes authenticated minima and ordered prefix structure under SHA256 collision resistance. Report authenticity and duplicate digest prevention belong to the admission policy: a real signed digest must bind its timestamp; the native full builder also rejects duplicate digests. The standalone append function does not maintain a separate digest-nullifier set. Authorized sealing and log availability remain required.

## 3. Maximality lemma

Given a verified ordered snapshot, prove one leaf at index j, its timestamp `u <= t`, `j <= count`, and `sealed_through >= t`. At each path level where the selected subtree is the left child, its right sibling covers a disjoint interval of later indices. Require the sibling's authenticated minimum to be strictly greater than t. These right siblings partition all indices greater than j. An empty sibling has infinite minimum and qualifies. Every earlier admitted index has a strictly lower publication time by the append invariant. Therefore the selected leaf is the unique latest eligible admitted predecessor. Sentinel j=0 is accepted exactly when all real entries are later than the cutoff (or the log is empty). The proof does not claim that no update existed outside the admitted log.

The new path uses `40D` sibling bytes (timestamp and digest), versus `64D` for two unoptimized plain Merkle membership paths at depth D. It requires D internal hashes rather than 2D, each using two SHA256 compression blocks under these encodings. A well-designed adjacent-pair multiproof shares the common suffix and can be smaller or equally efficient for adjacent leaves; this is a comparison to the naive two-path construction only. The augmented tree's benefits are one report opening, a predictable fixed circuit shape, and natural absence/tail handling. At depth 18 there are 262,143 real slots, enough for 144,000 synthetic 200-ms updates over eight hours. The reference limits full-list building to one million records. Larger circuit depths require new verifier keys and resource profiling; no depth-18 R1CS or NEAR cost claim is made.

## 4. Exact composition with POLICY-01

The companion depth-4 Nova application step selects both sources at one UTC hour, with 26 fields of public folded state:

```
count, start_hour, genesis[2], policy[2], pyth_snapshot_pin[2],
chainlink_snapshot_pin[2], evidence_queue[16]
```

Receiver pins both sealed snapshots and the eight-hour evidence root independently. It reconstructs the root from the eight leaf digests and maps every SHA256 digest to two injective 128-bit limbs. Each fold constrains hour=count+start, the canonical source-specific header bytes, candidate bounds/sentinel, prefix index, seal cutoff, one ordered minimum path per source, and the exact SHA256 snapshot pin. At every level select left/right from the constrained index bits; require ordered child minima and derive the parent minimum from the left. These equations are equivalent to native min on a valid ordered prefix. The same candidate bits enter the source tree leaf hash and the POLICY-01 evidence digest `SHA256("SHZ/HOUR/EVIDENCE/V1" || genesis || policy || hour || P || C)`. The evidence digest must match the queue head. Literal count increment and queue shift/zeroing require all eight positions.

Independent verifier acceptance requires the maximality and policy proofs to share the same network, policy, start hour, eight evidence digests and evidence root. POLICY-01 then derives the exact VALID/HOLD record and existing SHZIDX01 checkpoint root. The frozen fixture reuses the identical POLICY-01 evidence root `7bdb08099daaa69fd6762f79722fe26cb0989fbf77fcd7d14241cf7f06774c42`. The public pins are still synthetic. Append history is checked by the separate native reference, not inside the selection Nova circuit. No new trusted setup is introduced (Pallas/Vesta Nova with Spartan/IPA compression).

## 5. Registered tests and performance

The reference tests include genuine earlier-report membership paths, recomputed evidence root, sentinel suppression, stale and future selections, changed minima/hash/count/context, unsealed snapshots, append substitution/backfill, and exhaustive small-log selection compared with independent binary search. A local scale run builds 144,000 synthetic reports at depth 18 and checks eight authentic maximal and eight authentic non-maximal openings. See `research/hourly_index/maximality/evidence/scale-reference.json`. This is reference hashing timing, not proof timing or NEAR gas.

The Rust tests constrain the actual depth-4 R1CS. One negative fixture uses the actual preceding leaf and valid path under the unchanged source snapshot; the evidence queue head is deliberately recomputed to ensure maximality itself rejects the attack. CI runs exact shape/terminal state tests and transparent compressed proof generation plus independent proof verification against changed snapshot, changed evidence and wrong-step controls. Until green CI, the Rust and proof results are unverified. The `verify` CLI rebuilds the key from the fixed compiled circuit, compares the manifest to receiver-owned expectations, bounds proof bytes and rejects malformed/trailing encodings. A verifier must additionally authenticate snapshot pins and pin the approved circuit/version in governance.

## 6. Remaining gates

Source admission, independently authorized seal and provider availability/completeness, an actual proof of append/seal history if the registry is not trusted, depth-18 or optimized verifier scaling, transparent verification on NEAR, Bitcoin SPV and FROST/DLC authorization remain open. No mainnet authorization; `source_authentication=false`, `provider_completeness_proven=false`, `append_chain_verified_inside_nova=false`, `near_nova_verified=false`, `bitcoin_anchor_finality_verified=false`, `can_authorize_oracle_epoch=false`, `can_authorize_dlc_settlement=false`, `production_ready=false`. Only after an actual native proof succeeds may `maximality_relative_to_pinned_ordered_sealed_snapshot` be true. Admission and seal acceptance cannot be inferred from a proof hash.
