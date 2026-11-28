# ZKL-13: bounded search-policy interface

The new `Problem` and `Search` classes are a small-fixture proposal engine.
They prepare degree-0 through degree-2 monomial columns over active wires.
A policy offers one unused (retained-row index, monomial) at a time and sees
the remaining target polynomial and charged search work. The engine returns
a candidate ZKL-12 certificate, which must be verified by the independent
`poly_certificate.verify` against the exact canonical original/replacement
shape and independently pinned hashes. No kernel replay or production
acceptance is claimed by this engine.

The caps are 64 original rows, 16 wires, 2048 candidate columns, 4096 sparse
terms and 2,000,000 coefficient-work units. Work counts input support,
reduction operand sizes and pivot normalization; inversion count is separate.
These are deterministic proxies, not elapsed CPU or peak RSS. Full candidate
pool preparation is still performed. Only canonical, reviewed fixture
inputs are supported; do not feed untrusted arbitrary JSON to this API.

DataGoblin's ZKL-13 pilot uses this interface for paired column-budget search
policies. The existing MathCan ZKL-12 theorem is the intended certificate
kernel; it still needs confirmed replay of generated proofs. Production
matrix and parameter binding are unchanged.
