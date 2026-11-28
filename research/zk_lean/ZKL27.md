# ZKL-27: DataGoblin exploration controllers on real Nova neighborhoods

Code: controller_campaign.py, imported DataGoblin modules pinned at
MoralityLabAI/DataGoblin a7fa01660bde00d7ce1286e263d2498b37d14612
(research/zkl-01-09-20261127, PR #109). The SatsHedgeZero checker used by
DataGoblin (84c1681) and this branch have identical neighborhood_search.py
and poly_certificate.py.

## Training (synthetic only)

zk_counterfactual_gym.collect on roots 18001–18008 and its five training
families (linear_chain3, product_zero, inverse_square, square_transport,
product_chain_zero). Labels come from verified completion of forked search
states scored by offered-column cost, so the training signal is verified
certificate discovery and measured computation. Local reproduction: 80
sequences, 1074 steps, 212 exploit / 28 explore / 834 masked labels, equal
to the DataGoblin ZKL-18 hosted receipt. models.json holds the three fitted
models (177 parameters each).

## Arms

| arm | source | decision |
|---|---|---|
| indexed | DataGoblin Hybrid.exploit | indexed frontier maximum every offer |
| periodic | ZKL-17 control | explore on every third offer |
| row_random | Hybrid.explore | random neighborhood row, its best unused column |
| recurrent | ZKL-21 unweighted 177-parameter RNN | gate p ≥ 0.5, hidden state carried |
| reset | same weights | hidden state zeroed before every decision |
| trm | same cell, refitted | 3 refinements of the latent per decision; label on the last |
| ldt | same cell, refitted | up to 4 loops per decision, label on every loop; halt at abs(p−0.5) ≥ 0.25 |

Architectural differences, stated exactly: the HybridTRMLDT TRMProposer is a
PyTorch encoder + GRUCell (latent 256, 6 recurrence steps) with four heads;
the trm arm here keeps the DataGoblin 12→8 tanh cell, numpy, and one gate
output, so only the recurrent-refinement structure is shared. The ldt arm is
a confidence-halting loop with deep supervision, not a looped transformer
and not a learned ponder cost. All three arms are trained by DataGoblin's
masked BPTT (fit) on the same labels; trm/ldt see each step repeated.
indexed and row_random here run inside Hybrid on one shared basis, unlike
DataGoblin's legacy indexed/row_random implementations.

## Evaluation

Synthetic: the eight DataGoblin FAMILIES (two essential) at fresh roots
27101–27108, F11 on odd roots and BN254 on even, column budgets 24 and 96.
Six of the eight families are absent from training; they are reported
separately. Real (held out from all training): 128 targets per matrix
sampled from the pinned ZKL-22 prefix (seed 270027), each with its ZKL-26
adaptive first-round neighborhood (12 rows, 10 multiplier wires, 792
columns), budgets 96 and 792 (full span), plus any verified duplicate pairs
from full_matrix_scan as positive tasks. Every certificate goes through
poly_certificate.verify; controllers only order columns.
