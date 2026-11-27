# ZKL-12: polynomial multipliers
The kernel checker supports arbitrary finite monomial multipliers. The Python
search is restricted to degrees 0–2 and reviewed prime moduli (7, 11, BN254 Fr).
It substitutes the constant wire 0 with 1, builds monomial multiples of retained
row polynomials, and uses incremental sparse elimination. The independent
checker verifies the exact integer coefficient identity R_target = sum(q_i R_i)
+ p Q; failure to find a certificate is inconclusive. Resource-limit failures
are errors, never evidence of redundancy or essentiality.

The verifier checks the exact nominated deletion, ordered source/replacement
hashes, interface, multiplier indices and degree. The proof generator embeds
the exact canonical rows and correction and invokes checked_poly_delete with
an explicit well-formedness premise. A scoped CI workflow runs tests and replays
six generated certificates over F7 and BN254 using a pinned MathCan checkout.
The new workflow and its results are development-only. Neither ordinary R1CS
equivalence nor successful kernel replay establishes augmented Nova shape
binding, key reuse, or production safety.

Run `cd research/zk_lean && python -m unittest discover -v`.
The test families include degree-zero scaling, variable multiplication,
degree-two cancellation (xy=z, x²=0 entails z²=0) and an essential row.
The current caps are 256 rows, 4096 support terms, 1024 monomial columns and
100000 elimination reductions. Search uses an explicit field allowlist.
