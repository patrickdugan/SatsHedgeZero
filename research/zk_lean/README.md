# ZKL-02/05/06/07/09: proof-carrying V3 and Nova audit
Development only. No change to settlement verification, real funds or existing circuit code.

Pinned sources on main at b94a22cc086683f3c8f5992ec0e1091af27a2bfd:
- clearing.rs blob 6d3603533dcfb7af17613fae6c72f875ffa549ee
- bitvm3.rs blob 2ebdf87247e13651c85b57406dfcdc0b2a94b7ef
- unified_batch_circuit.rs blob f2447bdd57b992a49507132108cab972ddabf589
- docs/SHZ_CLEARING_CIRCUITS_REVIEW.md (C1–C4 and T findings).

Run from repo root:
```sh
(cd research/zk_lean && python -m unittest -v)
cargo run --locked --release --manifest-path research/mnr05_bitvm3_ln_dlc/Cargo.toml --example zkl_export > shape.json
python research/zk_lean/audit.py shape.json --canonical-out canonical.json
python research/zk_lean/audit.py shape.json --expected-sha256 <independently-pinned-hash> --lean-out ExportedShape.lean
```
The Rust example uses Nova 0.76 ShapeCS on the existing MNR05 bare step with
explicit public input/output allocations. It is **not** the augmented matrix used in
Nova PublicParams::setup. Capture both actual augmented matrices at setup and check
their ordered coefficients, field, dimensions and wire permutation against the
verifier's parameters before any production claim. The example was authored without a
Rust toolchain and requires compile/replay; cap RAM externally on large shapes.
The Python loader keeps row order, combines field terms and hashes normalized JSON.
Hash identity is evidence of byte identity under a collision-resistance assumption;
it is not semantic equivalence. Lean source emission is optional; large matrices
need streaming/chunked import and proof certificates.

The independent clearing model begins *after* positions::settle and abstracts checked
Rust machine integer bounds, output layer, batch digest, and book value.
C1: recompute exact tagged digest with signed LE values, row order, claim_haircuts,
totals, layer and cash; require it in signed lane consent and chain commitment.
C2: carry authenticated per-account claim map, including non-batch accounts; a total
alone cannot justify ownership. C3: enforce min priority and the exact pro-rata
remainder order (one visit per item, possibly several units to that item), including
legacy-negative cash. C4: prove capacity and padding rules for each supported shape.
T1–T3: bind key, tapleaf, input index, supported hash types and transaction context;
unsupported versions reject.

The 304-byte statement manifest is a *checklist*, not a proven byte-to-wire map.
Every derived field must have a constraint path and independently pinned expected
context. Verify initial state, final state, exact fold count and VK, plus negative
tests across wrong chain, epoch, roots, replay and field aliases.
The 276-byte native Journal in statement.rs is distinct from this 304-byte codec.
MNR05 uses BN254/Grumpkin rather than assuming Pallas/Vesta.

Backend experiment (ZKL-09): use independent pinned Clean/CLAP checkouts on a separate
dev fixture (min, boolean range, divrem); export their actual backend relation and
prove equivalence to the same bounded-integer spec with explicit public-wire
permutation and field lifting. Measure constraints, prover cost and checker trust
separately. No Clean/CLAP translation or Nova compatibility is established here.
References: https://github.com/Verified-zkEVM/clean and https://github.com/Clap-lang/clap-lean.
Companion branches: MathCan and DataGoblin research/zkl-01-09-20261127.
