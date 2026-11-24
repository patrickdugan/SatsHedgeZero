# SHZ-INDEX-02: transparent Nova hourly-checkpoint relation

Base: `fb4d06ec00f7e157307a8c5bc44204d77b57ad3c` (PR #9). Proof system candidate: Nova 0.76.0 Pallas/Vesta with Spartan/IPA compressed verification. No trusted ceremony. The existing NEAR contract and 40-byte SHZIDX01 packet remain unchanged.

## Statement

Receiver independently pins `(network_genesis32, policy_hash32, start_hour, checkpoint_root32)`. Start is aligned to UTC eight-hour intervals and at most 999,999,992. The state has eight field elements: `count`, `start`, genesis low/high 128-bit limbs, policy low/high, root low/high. Initial count 0, terminal count 8, exactly 8 Nova folds. Digest limbs use unsigned little-endian integers of the original digest-byte sequence; no field reduction of 256-bit hashes.

Each fold proves knowledge of an exact private hourly record and three sibling hashes. The R1CS binds the leaf hour to `start + count`, fixes domain strings, enforces the original hourly policy for both VALID and HOLD, computes SHA-256 over the exact INDEX-01 leaf bytes, and constrains all three direction-selected Merkle nodes and the domain-separated checkpoint digest. The next state increments count by literal one and carries all pinned claim elements. Thus eight sequential authenticated openings (under collision resistance of SHA-256) cover exactly the eight positions. The membership paths need not be exported. Each fold has the same constraint shape regardless of position or status.

The signed report digests are witness bytes committed in the original leaf. This proves **record arithmetic and checkpoint membership**, not the provenance of source reports. HOLD reason is a bounded label and HOLD fields must be zero. Proof of unavoidable HOLD requires a separately committed source stream and selection/completeness policy. Raw Pyth/Chainlink reports are not authenticated or opened by this version. Source facts may also be publicly available or guessable; no claim of hiding publicly disclosed fixture values. The compressed proof is intended for private witnesses; verify the backend's zero-knowledge configuration before privacy-dependent production use.

## Soundness checks

All numeric witness values come from the same byte variables hashed by the SHA gadget. Every comparison uses a gated nonnegative bounded slack; signed expressions have magnitude far below the field modulus, ruling out modular wraparound. A 1-bit slack enforces exact floor midpoint. Both inequalities of spread and time skew are imposed independently. No host-language branch selects whether constraints exist. HOLD is explicitly represented in the hash, and all numeric and digest payloads must be zero. Separate hostile tests rebuild a matching root for malformed leaves, so rejection cannot be attributed merely to a stale hash.

## Evidence gate

CI compiles and tests actual R1CS, runs real 8-fold compression, then independently reconstructs the verifier key and verifies the persisted proof against the committed expected public root. The verifier also tests changed root and wrong step count with the same proof. It bounds proof/metadata sizes and rejects trailing data. Malformed proofs that panic during decoding/verification fail closed in the native process. Further public-facing resource isolation and verification-key auditing are required. Initial source has no measured proof run yet; CI generates its lockfile and includes it in evidence. Pin the resulting reviewed lockfile before promotion.

## NEAR composition

The existing NEAR contract natively verifies the same SHA checkpoint root and public hourly inclusion. A proof accepted by the native Nova verifier may target that root, but NEAR must actually verify the same Nova/Spartan equations (or a reviewed transparent decider) before setting `near_nova_verified`. A proof hash is never proof validity. Existing small BN254 IPA pilots do not establish these equations. The present contract can continue validating public commitments and bonded relayer challenges without relying on this new proof. Retain `source_authentication`, `hold_necessity_proven`, `near_nova_verified`, `bitcoin_anchor_finality_verified`, `can_authorize_oracle_epoch`, `can_authorize_dlc_settlement`, and `production_ready` as false. No funded transactions.
