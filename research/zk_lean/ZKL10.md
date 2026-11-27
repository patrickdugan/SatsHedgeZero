# ZKL-10: exact structural rewrite certificates

This development certificate covers deduplication and reordering of R1CS rows.
It proves pointwise equivalence on **all** assignments in the given field through
row membership; no enumeration of field elements is needed. It also preserves
the well-formedness condition, public wire order and witness interpretation.

Run:
```sh
cd research/zk_lean
python -m unittest -v
python row_certificate.py original.json replacement.json \
  --expected-original "$ORIGINAL_HASH" --expected-replacement "$REPLACEMENT_HASH" \
  --lean-out Rewrite.lean --receipt-out rewrite-receipt.json
# Copy Rewrite.lean to an independently checked MathCan checkout at
# 20889d02c8a02769cd2bd2e158d852317bb0602a (or reviewed successor).
# At that checkout:
lake build MathCan.ZKLean
lake env lean Rewrite.lean
```

The generated Lean theorem quantifies over public inputs, checks both row-list
inclusions and uses the exact shape values embedded in source. Review printed
axioms; do not accept sorryAx or an unapproved axiom. The receipt records
`lean_replayed: false`; it is deliberately not self-promoting. A trusted
runner must check the generated source hash, replay against the pinned module,
record the actual toolchain, kernel result and axiom audit, and bind both shapes
to the independently captured artifacts. SHA-256 is an identity commitment,
not a theorem of equivalence. Limit 256 rows until efficient membership
certificates are developed.

This equivalence concerns ordinary R1CS satisfiability. Row reordering can
change Nova commitments, verification parameters and relaxed error-vector
coordinates. It does not permit reuse of a verification key or certify the
augmented folding circuit. Regenerate parameters and re-establish production
binding and recursive verification obligations for each changed circuit.
The certificate refuses other deletions, even if a finite gym suggests they
are semantically valid. General redundancy requires an algebraic implication
proof with explicit witness mapping when wire sets differ.
