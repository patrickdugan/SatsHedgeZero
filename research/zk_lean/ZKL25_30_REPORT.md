# ZKL-25–30: proof-carrying circuit optimization campaign

SatsHedgeZero `research/zkl-01-09-20261127` (PR #36), MathCan
`research/zkl-01-09-20261127` (PR #295), DataGoblin
`research/zkl-01-09-20261127` (PR #109, read-only use at a7fa016).
Machine-readable summary: `zkl25_30_summary.json`. Every actual-matrix run
re-checks the ZKL-22 capture pins (run 46042490831, artifact 15220907562,
checkout 7b8d6030…, capture.json ffb298ec…, vk.bin 3d35e9d0…, primary
acf5a8b0…, secondary e3288035…). No Nova setup was repeated: the ZKL-22
workflow is now manual only (its PR trigger re-ran setup on every push).
Nova setup, folding, compression and verification measurements for ZKL-30
are prepared for Colab and not run here.

## Commits

| repo | commit | stage |
|---|---|---|
| SatsHedgeZero | 73a613c | ZKL-25 recovery tooling (recover_zkl25.py, ci_export/ci_import) |
| SatsHedgeZero | e5ed88e | ZKL-25 recovered receipts (zkl25_recovered/) |
| SatsHedgeZero | 37c097f | ZKL-26 full-matrix scan, four-arm search, counterexamples |
| SatsHedgeZero | 637330a | ZKL-26 actual results (zkl26_results/) |
| SatsHedgeZero | 43d6aff | ZKL-27 controller campaign |
| SatsHedgeZero | c32aec8 | ZKL-29 audit and adversarial tests |
| SatsHedgeZero | 7c7da6f | ZKL-30 plan, composed Lean, Nova hook |
| SatsHedgeZero | e703447 | ZKL-30 streamed pruned hash, Colab pilot script |
| SatsHedgeZero | f429afd | ZKL-27 real results, positive tasks |
| MathCan | 45747ba | ZKL-28 ZKLeanCompose |
| MathCan | 1ba953e | ZKL-29 ZKLeanSettlement |

CI evidence is read through public check-run annotations (`ci_export.py` /
`ci_import.py`, SHA256-checked), since artifacts need a token.

## ZKL-25: recovery

Workflow 46103947349 re-downloaded the run-46072770036 artifacts, rebound
and re-verified every receipt against the streamed matrices, regenerated the
Lean sources byte for byte and replayed them. 0 actual certificates in 256
attempts (64 targets × 2 arms × 2 matrices); the four replayed sources are
synthetic fixtures (`[propext, Quot.sound]`). Failure modes: 248 exhausted
the selected span, 8 work caps, 237 truncated 10-wire multiplier pools, 16
empty graph neighborhoods (all target wires saturated hubs). Details:
ZKL25.md, zkl25_recovered/.

## ZKL-26: expanded algebraic search

See ZKL26.md for method and full tables (workflow 46105804434).

* Full-matrix scan, both matrices: 0 unconstrained wires (each public wire
  occurs once, in its inputize row), 0 zero rows, 0 proportional duplicate
  rows; 2 C-only dead-output rows each (primary 4219, 5439; secondary
  3984, 5204), all in Nova's augmented verifier region.
* Search, 512 stratified + 512 motif targets per matrix, every arm at 100000
  work units and 40 ms CPU per target: 1 verified redundancy (secondary row
  5209, degree 1, directed arm after linear substitution); best outcome per
  distinct target: primary 888/1006 and secondary 870/989 explicit local
  counterexamples, 109 + 109 exhausted spans, 9 + 9 incomplete.
* A local counterexample shows only that the chosen neighborhood implies
  nothing; no outcome establishes global essentiality.
* Lean: 22 fixtures + 3 actual sources (two dead-output deletions, one
  polynomial deletion) replayed, all `[propext, Quot.sound]`.

## ZKL-27: research controllers

See ZKL27.md. Training: DataGoblin counterfactual teacher on synthetic
families (reproduces the DataGoblin ZKL-18 label counts exactly). Synthetic
block (64 tasks, 16 essential), certified at 96 / 24 columns:

| arm | 96 | 24 | held-out families, 96 |
|---|---|---|---|
| indexed | 42 | 34 | 37/56 |
| periodic | 41 | 34 | 36/56 |
| row_random | 39 | 24 | 36/56 |
| recurrent (ZKL-21 RNN) | 43 | 36 | 38/56 |
| reset (same weights) | 42 | 34 | 37/56 |
| trm (refinement) | 44 | 38 | 40/56 |
| ldt (adaptive loops) | 41 | 36 | 38/56 |

One evaluation block; differences of 1–3 tasks. Real held-out
neighborhoods, workflows 46107634179 and 46108263340
(retrained parameters equal the committed models; certified counts, offered
columns and coefficient work identical to the local Windows run).
128 held-out sampled neighborhoods per matrix (12 rows, 10 multiplier
wires, 792 columns): **0 certified by every arm at 96 and at 792 columns on
both matrices**. Primary 792-column CPU per 128 targets: indexed 2.7 s,
periodic 3.5 s, row_random 4.5 s, recurrent 5.3 s, reset 5.5 s, trm 6.1 s,
ldt 6.3 s. Positive task (secondary row 5209 with its verified retained rows
forced into the neighborhood): 0/1 for every arm even after all 792 columns,
so the directed arm's certificate (multipliers w5224, w5225 after linear
substitution) is outside the fixed 10-wire degree-≤2 span. On these Nova
matrices the bottleneck is column generation, not column ordering; the
learned gates do not change coverage. Neural outputs stayed outside the
trust boundary (every acceptance went through poly_certificate.verify).

## ZKL-28: compositional Lean certificates (MathCan 45747ba)

`MathCan/ZKLeanCompose.lean`, axioms only `propext` / `Quot.sound`:

| item | theorems |
|---|---|
| 1 sequential deletion | `seq_delete` |
| 2 dependency-aware simultaneous deletion | `simultaneous_delete` (rank-ordered, strong induction), `simultaneous_delete_outside`, `eraseAll`, `RankOK` |
| 3 public wire ordering | `withRows_interface`, `eraseIdx_interface`, `seq_eraseIdx_interface`, `eraseAll_interface`, `public_order_matters` |
| 4 global wire substitution | `rename_accepts` (witness renaming), `dead_output_delete` + `deadOutputCheck` (witness elimination) |
| 5 contextual polynomial implication | `poly_sound_ctx`, `discharge_assumptions`, `poly_sound_ctx_rows`, `assump_of_row` |
| 6 chunked verification | `holds_flatten`, `covers_flatten`, `getElem?_append_offset` |
| 7 row-index transport | `transport`, `transport_none_iff`, `transport_correct` |
| adversarial cycle | `cyc_delete_0`, `cyc_delete_1` (each deletion valid), `cyc_no_rank`, `cyc_joint_unsound`, `cyc_joint_not_equiv` |

Audit: every theorem has `#print axioms`; 4 show `[propext]`, the rest
`[propext, Quot.sound]`; no `sorryAx`, `Classical.choice`, `ofReduceBool`.

## ZKL-29: settlement circuit audit

`ZKL29_SETTLEMENT_AUDIT.md` (sources at main 62003a6), Lean specs in
MathCan `ZKLeanSettlement.lean` (61 theorems: 42 `[propext, Quot.sound]`,
12 `[propext]`, 7 axiom-free), `test_settlement_adversarial.py` (27 tests,
22 attacks, all pass).

| P | property | replacement circuits | unified_batch_circuit |
|---|---|---|---|
| P1 | conservation | ENFORCED (`carry_in` open) | MISSING |
| P2 | haircut priority / pro-rata | ENFORCED | MISSING |
| P3 | authenticated claim state | PARTIAL | MISSING |
| P4 | digest / signed authorization | PARTIAL (ack signatures missing) | MISSING |
| P5 | Taproot key / tapleaf / input | PARTIAL (script path) | PARTIAL |
| P6 | nullifiers / replay | MISSING in-proof | PARTIAL |
| P7 | oracle root | MISSING | PARTIAL |
| P8 | integer encoding / no wrap | ENFORCED | ENFORCED |
| P9 | initial/terminal state, fold count | PARTIAL (initial state) | PARTIAL |

C1, C2, C3, T3 closed by the replacement; C4, T1 (script path), T2 (guest
ignores signed mask, signature count, params accumulator) partially open.
New: N1 unified conservation vacuous (free input amounts and fee), N2
unauthenticated step inputs, N3 `account_spk` not recomputed, N4 `carry_in`
unchecked against earlier epochs, N5 guest panics on `steps == 0` and emits a
zero `assertion_txid`. Ordinary R1CS refinement, relaxed-R1CS equivalence
and Nova soundness are listed separately per circuit; none is proven.

## ZKL-30: proof-carrying pruning pilot

Plans (workflow 46108263304, `zkl30/*-plan.json`): probing the 16 rows on each
side of every dead output with all four arms found 4 more verified degree-1
redundancies per matrix, all at d+2 and d+5 of a dead row d, all by linear
substitution with two degree-1 multipliers. Dependency-free deletion sets:

| matrix | deleted rows | rows | nonzeros A/B/C | expected pruned SHA256 |
|---|---|---|---|---|
| primary | dead 4219, 5439; poly 4221, 4224, 5441, 5444 | 962221 → 962215 | 2296187/1020899/2065605 → 2296177/1020891/2065601 | 9c79bca7…0b44 |
| secondary | dead 3984, 5204; poly 3986, 3989, 5206, 5209 | 10538 → 10532 | 72539/44316/10002 → 72529/44308/9998 | 00d85e04…819b |

`primary-PrunedMatrix.lean` and `secondary-PrunedMatrix.lean` prove
`accepts original x ↔ accepts pruned x` for the whole set (six chained
`checked_indexed_poly_delete` / `dead_output_delete` steps, descending
index order). Both replay in CI and locally: `[propext, Quot.sound]`.
Every polynomial step's retained rows avoid the set and no deleted row is
retained by another step, so the ZKL-28 cyclic failure mode cannot occur.

All twelve rows lie in Nova 0.76.0's augmented verifier circuit, in two
gadget instances 1220 rows apart per matrix, at the same positions in both
matrices up to a 235-row shift. The experimental variant is therefore a
patched nova-snark (`zkl30/zkl30.rs`, `apply_nova_patch.py`, 8 synthesis
sites, inert unless `ZKL30_CIRCUIT` is set); it compiles against the mnr05
crate (job 140863837041). Fresh public parameters / VK, setup, fold,
compress and verify times, peak RSS, proof and VK size, the pruned-shape
hash check against the plan, and the honest/adversarial runs are prepared
in `zkl30/colab_pilot.sh` for Colab and not run here. Expected effect:
6 of 962221 primary rows (0.0006%), so no measurable cost change is
expected; the pilot's value is the end-to-end binding check. Any
production change would be an upstream Nova change, and needs a separate
relaxed-R1CS argument for each deletion. In Nova the relaxed instance
carries commitments to W and E, so relaxed equivalence of a deletion is a
statement about instances and commitments, separate from the ordinary R1CS
theorem proved here; it is not proven.

## Trust boundaries

* Kernel-checked: every `#print axioms`-audited theorem above, and each
  emitted instance given its stated premises.
* External premises (Python streaming binding, not Lean): global row
  lookups, single-occurrence of dead wires, well-formedness of the captured
  matrix, equality of the captured bytes with the Nova setup shapes.
* Untrusted: all search, substitution and neural controller outputs; only
  `poly_certificate.verify`, `check_counterexample` and Lean decide.
* Not proven: relaxed-R1CS equivalence of any deletion, Nova protocol
  soundness, Rust gadget refinement of the ZKLeanSettlement specs,
  production VK equality. Production acceptance flags stay false.

## Reproduction

```
cd research/zk_lean
python -m unittest test_zkl26 test_zkl30 test_graph_dependency test_settlement_adversarial
python recover_zkl25.py <primary.rows.jsonl> --expected-original <pin> --results <zkl25-actual/primary> --out r.json
python full_matrix_scan.py <rows.jsonl> --expected-original <pin> --out scan.json
python scan_findings.py <rows.jsonl> --expected-original <pin> --scan scan.json --out findings
python graph_dependency.py --zkl26 <rows.jsonl> --expected-original <pin> --target-count 512 --out search
PYTHONPATH=<DataGoblin a7fa016>/src:. python controller_campaign.py --out c27 --synthetic
python zkl30_plan.py <rows.jsonl> --expected-original <pin> --candidates 5209,5444 --around-dead 8 --out plan
python ci_import.py patrickdugan/SatsHedgeZero <job id> <dir>
```
MathCan: `lake build MathCan.ZKLeanCompose MathCan.ZKLeanSettlement`, then
`lake env lean <generated>.lean`. The pinned matrices come from artifact
15220907562; the workflows shz-zkl25-recover, shz-zkl26, shz-zkl27 and
shz-zkl30 run the actual-matrix steps.

## Colab handoff (ZKL-30 measurements)

Run `research/zk_lean/zkl30/colab_pilot.sh` from a clean checkout of this
branch at the commit that adds this report or later (zkl30/README.md lists
the commands). It writes `zkl30-colab/zkl30_colab_results.json`; commit
that file, `pilot.log`, the `*.time.txt` / `*.stderr.txt` files and each
`capture-*/capture.json` + `stream-audit.json` (not the `.rows.jsonl` or
`.shape.bin` files) under `research/zk_lean/zkl30/colab/`.
