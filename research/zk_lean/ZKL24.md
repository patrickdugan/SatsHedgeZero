# ZKL-24: windowed degree-zero dependencies and explicit original positions

ZKL-22 actual capture (run 46042490831) succeeded: primary 962221 rows,
956072 wires, 5382691 coefficients; secondary 10538 rows, 10523 wires,
126857 coefficients. The first proportional-pair search abstained on
both. Rust peak RSS 1324012 KiB; Python streaming audit 18708 KiB.
The pin file records the prior captured hashes and source commit.

Reuse the same immutable run artifact, check the source commit, capture
manifest and VK byte hashes, and rehash the complete canonical row streams.
Search up to 65536 initial rows (entire secondary matrix) using disjoint
256-row windows. Candidates: exact duplicate, proportional nonidentical,
degree-zero combination of at least two retained rows. Count zero
residuals separately. Sparse elimination carries exact row representations,
with 128 support, 32 witness weights, 32 input terms and two million
reduction-work caps. A skipped or absent candidate does not prove
essentiality. Record the first candidate in each class, verify its exact
integer identity and global deletion hash, retain the receipt and replay
Lean. Every candidate is an independent single deletion from the original;
they must not be composed without rechecking dependencies.

MathCan a04649b9e91e79498f2986791b800273bd5c0c8c adds an indexed contextual theorem. The generated Lean
file specifies the original target position and each retained original
position. Given actual row lookups at those indices, the theorem derives
membership after eraseIdx and ordinary acceptance equivalence. Full
matrix well-formedness, target and retained lookup premises remain
external. This is stronger positional specification, not a kernel
proof that the captured bytes satisfy those premises. It does not
prove the Nova relaxed relation or authorize reuse of PP/VK/proofs.
No production matrix is rewritten. Same fresh setup pins are not
independently persisted production commitments.
