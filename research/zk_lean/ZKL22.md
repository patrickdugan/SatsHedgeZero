# ZKL-22: actual Nova augmented shape capture

The earlier zkl_export example describes the bare StepCircuit with explicit
input/output allocation. This new example captures the actual two augmented
R1CSShape objects supplied to Nova 0.76.0's commitment-key sizing callbacks
during PublicParams::setup. The callbacks delegate to the same Spartan/IPA
ck_floor methods as the existing MNR05 proof routine, preserving their
return values. Both captures are from the same fresh setup instance, and
their dimensions are checked against the returned public parameters.

Serialize the actual shapes via their pinned Serde/bincode encoding,
then deserialize the private-field mirror (num_cons, num_vars, num_io,
three CSR matrices). Require the mirror to reserialize to the same byte
hash. Validate row pointers, indices, field encoding and dimensions.
Convert native [auxiliary, one, public] into ordinary audit
[one, public, auxiliary] by a total column permutation. The augmented
circuits expose two public values, not the 22 values in the bare step
export. BN254 scalar modulus applies to the primary; BN254 base modulus
to the Grumpkin secondary. Retain the raw shape artifacts, native shape
digests, exact ordered canonical matrix hashes and row counts.

Compute the compressed VK from the very same returned PublicParams;
record its exact fixed-int bincode SHA256 and the native PP digest.
The independently executed Python streaming auditor validates the
capture and reproduces the existing audit.digest canonical shape hash
without retaining all rows. Unit fixtures check agreement with the
legacy in-memory auditor. The Rust mirror and column mapping remain a
trusted translation boundary; Python does not independently decode
the private native bincode. The lockfile pins crate versions and CI
records its hash and the exact source commit.

This is a fresh research setup on existing MNR05 circuit code, not a
match to an already deployed/persisted verification key, a proof of
exporter equivalence, or a relaxed-R1CS/Nova soundness theorem. No
constraint was removed. Do not reuse parameters or proofs after a
rewrite. Next gates: compare against independently persisted VK/PP
receipts, independently validate the native sparse encoding, produce
a local subset witness bound to exact global row positions, and prove
global implication before any optimization. The statement, authorization,
and clearing semantic proofs remain separate requirements.
The workflow uses a 6 GiB runtime virtual-address cap, two Rayon threads,
and compresses the two raw shapes and row streams after successful audit.
