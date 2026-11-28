# ZKL-30: proof-carrying pruning pilot (Colab only)

Lightninger / SatsHedgeZero research. Nothing here is a production change,
and none of it runs on the maintainer laptop (no local Nova setup or
proving). Synthetic funds, Bitcoin Core 31.1 regtest only.

## What is being tested

ZKL-26 found, in the pinned ZKL-22 capture of the Mnr05UnifiedBatchStep
augmented Nova circuits, rows that can be deleted without changing the
ordinary R1CS acceptance relation:

* dead-output rows (a non-public wire occurring once, in C only), and
* polynomial redundancies verified by an exact integer certificate.

`primary-plan.json` / `secondary-plan.json` (made by `zkl30_plan.py` in
workflow ZKL-30 from the pinned matrices) list the deletion set, the
certificate for each polynomial step, the exact canonical SHA256, row count
and nonzero counts the pruned matrices must have, and the native aux index
of each dead wire. `*-PrunedMatrix.lean` proves, for each matrix,
`accepts original x ↔ accepts pruned x`, chaining MathCan
`checked_indexed_poly_delete` and `dead_output_delete`; it replays in CI
with only `propext` and `Quot.sound`. Its row-lookup and single-occurrence
premises are established by the streaming scan, outside Lean.

The rows sit in Nova's own augmented verifier region (the same 235-row
offset in both matrices), so the experimental variant needs a modified
nova-snark: `zkl30.rs` + `apply_nova_patch.py` add a forwarding
constraint system at the 8 augmented-circuit synthesis sites of
nova-snark 0.76.0 (source hashes pinned). It is inert unless
`ZKL30_CIRCUIT=Mnr05UnifiedBatchStep`; then `ZKL30_SKIP_PRIMARY` /
`ZKL30_SKIP_SECONDARY` drop the listed global constraint indices, and
`ZKL30_TAMPER_{PRIMARY,SECONDARY}_AUX` adds one to a single aux value
during witness generation (adversarial runs). The Secq circuit in the same
process is never affected.

## Clean-checkout commands (Colab, CPU runtime, ≥ 12 GB RAM)

```
apt-get -qq install -y time build-essential pkg-config libssl-dev
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
git clone --branch research/zkl-01-09-20261127 https://github.com/patrickdugan/SatsHedgeZero.git
cd SatsHedgeZero
git checkout <commit named in research/zk_lean/ZKL25_30_REPORT.md>
bash research/zk_lean/zkl30/colab_pilot.sh
```

`colab_pilot.sh` runs, in order, with `/usr/bin/time -v` around each step
and a 6 GiB address-space cap on Nova runs:

1. Original build (crates.io nova-snark, `--locked`): `zkl_capture`
   (fresh setup, shapes, VK) and `run-all` (setup, 3 folds, compression,
   verification, wrong-txid and wrong-nullifier-root rejection, regtest).
2. Patched build, hook inert: `zkl_capture` must reproduce the ZKL-22 pins.
3. Pruned: `zkl_capture` with the skip lists (fresh public parameters and
   VK) and `run-all`.
4. Adversarial: dead-wire tamper on the original (must be rejected), the
   same tamper on the pruned circuit (accepted, identical public claims),
   control tamper of aux 0 on the pruned circuit (must be rejected), and the
   secondary dead wire on both.
5. `collect_results.py` writes `zkl30-colab/zkl30_colab_results.json`:
   constraint and variable counts, native nonzeros, VK bytes and SHA256,
   setup / fold / compress / verify seconds, proof bytes, peak RSS per step,
   and the binding checks (`original_reproduces_zkl22_pins`,
   `inert_hook_reproduces_pins`, `pruned_matches_plan_hash`,
   `pruned_constraint_counts`, the five adversarial checks).

## Gate

A production proposal needs every check true, the Lean replay of both
`*-PrunedMatrix.lean`, and a separate argument for the relaxed-R1CS
(folding) relation and Nova soundness, which this pilot does not prove.
The deleted rows are inside nova-snark, so any production change is an
upstream Nova change, not a SatsHedgeZero circuit edit.
