# HFT-02: indexed liquidity and authenticated admission

Stacked on HFT-01 commit d19dfcf49fc36c911f23d3913d7f01c88733b0fa. Preserve HFT-01 tariff, policy digest, canonical allocation, delay, FOK single-maker semantics, zero DLC fee, and oracle collar. No new signature trust model.

## Exact size/price indexing

A quote with remaining integer USD quantity q>0 occupies one size bucket floor(log2 q) on its side, ordered by the same (price rank, activation sequence) key as the reference book. For a requested size Q, discard buckets below floor(log2 Q). Range-scan each remaining bucket only inside the intersection of the oracle collar and the signed taker limit. Check exact remaining size and distinct owner. Select the minimum eligible book key over buckets. This equals the original first valid element of the global price-time book: partitioning is disjoint, the excluded smaller buckets cannot meet Q, and the intersection is computed with integer ceil/floor so no rounding ambiguity. The worst case can still scan many self-owned or too-small quotes in the threshold bucket. Index memory is one additional ordered key per resting quote, not a replicated segment tree. Update atomically on post, partial fill, complete fill, cancellation and expiry. Scan remains the default.

## BIP340 and scheduling

The joint verifier uses the same parsing, scalar bound checks, tagged challenge, even-Y and x-coordinate checks as the existing verifier; it computes sG-eP with k256 LinearCombination. Scope and signed fee ceilings remain unchanged. No signature is skipped; authorization of allocations and oracle updates is unchanged. Four-engine factorial: scan, indexed, joint, both. Compare serial arms on fixed one- and four-router assignments. Add both/parallel with one scoped thread per shard in admission and execution separated by a barrier. Each shard is a single writer with the same original local arrival order. This measures host CPU throughput, not network priority or cross-router liquidity.

## Registered gates

Pinned upstream TL generator seed 20261030; cross/deep at 20k and 100k orders, fixed total synthetic collateral. Four same-host CI matrix cells, nine arms/cell. Native adversarial parity for boundary size, self-match, partial fills, bid and ask price boundaries, cancellation, expiry, and mutated signatures. All ordered per-shard receipts and final channel balances hashed outside measured wall time. Exact digest, matched volume, fee accounting, rejected and resting counts must match within a shard count. Record CPU, RSS, admission/execute p50/p99, wall throughput. Pre-sign and oracle update outside timing. Serial control groups by shard for matched scheduling; not a byte-identical timer to the historical HFT-01 binary. Parallel effect isolated by comparing both/serial and both/parallel, with one thread per shard and host core count recorded.

Prospective optimization targets (report failures without retuning): indexed vs scan deep 100k one router >=2x execution throughput; joint vs scan admission >=1.15x; both vs scan combined >=1.25x; parallel vs serial both at four shards >=1.5x combined on hosts with at least four available logical CPUs (otherwise descriptive). All parity gates mandatory; report latency and memory tradeoff. No production deployment or live LN settlement.
