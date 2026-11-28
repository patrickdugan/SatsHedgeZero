# ZKL-11: quadratic-span certificates

For a well-formed ordinary R1CS shape, write the integer residual of a row as
(R_i(w)=A_i(w)B_i(w)-w_0 C_i(w)), with (w_0=1). Delete a row only if the independent
checker verifies the exact integer polynomial identity

```
R_target = sum(k_i * R_retained_i) + p * Q
```

where (p) is the declared modulus and (Q) is an explicit integer quadratic correction.
Constant multipliers make this a strict fragment of general polynomial ideal membership.
A failed span search is inconclusive, including for redundant rows requiring nonconstant
multipliers or finite-field identities. No prime hypothesis is needed for the implication
theorem itself; the solver uses a small reviewed prime allowlist.

`ideal_certificate.py` uses sparse modular Gaussian elimination to discover a candidate.
`verify` checks exact integer coefficients independently of elimination and binds both
ordered shape hashes, interface, modulus and exact deletion index. The resulting Lean
source embeds the original and replacement rows, checks membership and the polynomial
identity by reduction, and has an explicit original-well-formedness premise. The formal
kernel in MathCan PR #295 (initial algebra commit 61315a18c25fb65ac09ed4de8ee91713a9b70ead)
is separate from Python search. Run the generated source on a reviewed pinned successor
after its kernel and axiom checks pass.

```sh
cd research/zk_lean
python -m unittest -v test_ideal_certificate
python ideal_certificate.py original.json replacement.json --target 2 \
  --expected-original "$ORIGINAL_HASH" --expected-replacement "$REPLACEMENT_HASH" \
  --lean-out Ideal.lean --receipt-out ideal-receipt.json
# In the pinned MathCan checkout:
lake build MathCan.ZKLeanAlgebra
lake env lean Ideal.lean
```

Regression suite: 10 test methods; 192 generated span instances (64 per modulus);
10 certificate mutations; 1,674 exhaustively compared assignments across F7/F11.
One explicit BN254 transitivity example and 64 random BN254 linear span cases use exact
identities only. No claim is made about any production Nova constraint.
The search and verification are capped (256 rows, 4,096 sparse terms, 50,000
expansion terms). A full Nova export can exceed these bounds. A future local-subset
certificate must prove inclusion into the retained production matrix and bind the
full shape and verifier parameters. Ordinary R1CS equivalence does not imply equality of
relaxed R1CS commitments or justify reusing public parameters, verification keys, or
existing proofs. No production promotion.
