# CBM-CACHE-03 math: transporting flow and cut certificates across clearing mutations

Scope: the capacitated vault-funding network that `solve_and_verify_pnl_batch`
(`crates/shz-utxoref/src/pnl_batch.rs`) builds and solves with Edmonds-Karp. Everything
below is about deciding *feasibility* of that network faster. The canonical settlement
(route allocations, vault residuals, next accounting root) is a function of the specific
Edmonds-Karp flow and is not changed by anything here (section 6).

## 1. The network

Nodes: super source `s`, `src(v)` and `dst(v)` per vault, `pay(a)` per account, super sink
`t`. Edges and integer capacities (sats):

| edge | capacity |
|---|---|
| `s -> src(v)` | `avail_v = inputs_v - fee_v` |
| `src(v) -> dst(v)` (self retention) | `avail_v` |
| permitted route `src(u) -> dst(v)` (same netting set, `u != v`) | `c_r` |
| permitted route `src(u) -> pay(a)` (same netting set) | `c_r` |
| `dst(v) -> t` | `req_v = protected_v + sum_{a in v} e'_a` |
| `pay(a) -> t` (when `payout_a > 0`) | `payout_a` |

with `e'_a = e_a + b_a - payout_a` and `b = A g` the netted obligations. Write `D` for the
total sink capacity `sum_v req_v + sum_a payout_a`. The batch is feasible iff
`maxflow(s,t) = D`, i.e. iff some flow saturates every sink edge. Since `D` is an upper bound
on any flow value, **every feasible flow is a maximum flow**; feasibility and optimality
coincide for this network. (Validation steps 1-5 of the solver, including replay, domain and
locked-equity checks, are not graph properties; they are re-run on every candidate and never
cached.)

Node identity is by stable key (`s`, `src:<vault id>`, `dst:<vault id>`, `pay:<account id>`,
`t`), not by array index, so certificates survive insertion and deletion of vaults, accounts
and routes. An edge is identified by its ordered endpoint pair plus, for routes, its
`(from vault, target)`; parallel duplicate routes are merged by summing capacities, which
leaves every cut capacity and the max-flow value unchanged (the cold solver keeps them as
parallel edges; section 6 is why that does not matter for feasibility).

## 2. Certificates

* **Feasibility witness** `f`: integer `f_e` on every edge with `0 <= f_e <= c_e`, flow
  conservation at every node other than `s,t`, and `f_e = c_e` on every sink edge. Checking it
  costs `O(|E|)`; it proves feasibility by definition.
* **Infeasibility witness** `S`: a node set with `s in S`, `t notin S`. Its capacity
  `U(S,c) = sum_{e in delta+(S)} c_e` bounds every flow value (weak duality), so
  `U(S,c) < D` proves infeasibility with deficit at least `D - U(S,c)`. Checking costs `O(|E|)`.
  When Edmonds-Karp stops short of `D`, the residual-reachable set from `s` is a minimum cut
  with `U(S,c) = maxflow`, giving the exact deficit.

## 3. Transport conditions

A mutation maps `(G, c, D)` to `(G', c', D')`. Let `Delta` be the set of edges whose capacity
differs (an inserted edge has old capacity 0, a deleted edge new capacity 0; a demand change is
a capacity change on a sink edge).

**T1 (flow transport, exact).** A feasible `f` for `(c,D)`, extended by `0` on inserted edges,
is feasible for `(c',D')` iff (a) `f_e <= c'_e` for every `e in Delta`, and (b) `f_e = c'_e` for
every sink edge in `Delta`. *Proof.* Conservation does not mention capacities, so it is
untouched. Non-`Delta` edges keep their capacity, so their bounds and sink equalities still
hold. On `Delta` the conditions are exactly the definition. Cost `O(|Delta|)` after an
`O(|E|)` diff, or `O(|Delta|)` when mutations arrive as deltas. Condition (b) fails for any
demand increase: a demand increase can never be absorbed by an unchanged flow; it needs
repair (T4).

**T2 (cut transport, sound).** For a cut `S` (new nodes assigned as in T3),
`U(S,c') = U(S,c) + sum_{e in delta+(S) cap Delta} (c'_e - c_e)`. If `U(S,c') < D'` the mutated
batch is infeasible, with deficit at least `D' - U(S,c')`. *Proof.* Weak duality in `G'`. It is
not complete: a cut that stops proving infeasibility says nothing about feasibility, and the
exact deficit needs a fresh min cut.

**T3 (node insertion and deletion).** Deleting a node deletes its edges (capacity to 0, T1 and
T2 apply; a flow through it violates (a) unless it carried zero). An inserted node `x` may go on
either side of a cached cut; both give valid cuts. Put it in `S` iff
`sum_{e: x->notS} c'_e <= sum_{e: S->x} c'_e` (the smaller contribution); this is sound for any
choice. A flow extends by zero on a new node.

**T4 (residual repair from an old flow).** Let `f` be feasible for `(c,D)`. Build `f'`:
1. For every edge with `f_e > c'_e` (capacity cut, deleted route, demand decrease), remove the
   overflow `o_e = f_e - c'_e` by cancelling `s -> ... -> t` paths of `f` through `e`. A flow
   decomposition of `f` contains paths through `e` with total value `f_e >= o_e`, and cancelling
   value `o_e` along them keeps conservation and lowers every other edge, so the result is
   feasible for `c'` except that sink edges may be below `c'`.
2. Augment along shortest residual paths in `(G',c')` until the value reaches `D'` or no path
   exists (Edmonds-Karp warm-started from `f'`).

The result is a maximum flow of `(G',c')` (augmenting-path optimality does not depend on the
starting flow), so it decides feasibility exactly, and when it stops short its residual
reachable set is a minimum cut. *Work bound.* Step 1 cancels at most `sum_e o_e` sats, along at
most `|E|` decomposition paths per overflowing edge. Step 2 needs at most
`R = D' - val(f') <= (D' - D)^+ + sum_e o_e` augmentations, because each augments at least one
sat, and at most `O(|V||E|)` (the Edmonds-Karp bound, which holds from any feasible starting
flow). So repair costs `O(min(R, |V||E|) * |E|)`, against `O(|V||E|^2)` cold. It is cheap
exactly when the mutation moves few sats or few paths.

**T5 (simultaneous mutations).** T1-T4 are statements about the final `(G',c',D')` and the
union `Delta` of all changes, so any number of simultaneous edits is handled by applying the
checks to the union. No ordering of the edits is involved.

### 3.1 Mutation catalogue

| clearing event | effect on the network | certificate consequence |
|---|---|---|
| route capacity up | `c'_r > c_r` | flows transport (T1); cuts with `r` crossing lose `c'_r - c_r` of slack (T2) |
| route capacity down / route deleted | `c'_r < c_r` | flow transports iff `f_r <= c'_r`, else repair (T4); cuts gain proof strength |
| route inserted | new edge | flows transport; cut capacity grows only if `r` crosses `S -> notS` |
| partial fill / new obligation / novation | `b`, hence `e'_a` and `req_v`, and possibly `payout_a`, change | sink-capacity changes: demand up always needs repair; demand down needs overflow removal |
| liquidation close | large obligation, `req` moves between vaults | as above, typically several sink edges at once (T5) |
| fee change | `avail_v` changes on `s -> src(v)` and the self edge | T1/T2 on two edges |
| protected collateral change | `req_v` changes | sink-edge change |
| vault replacement (UTXO rotation) | `avail_v` changes; replay/spentness of the new UTXOs is re-validated outside the graph | certificate transport covers only the capacity part |
| deliberate infeasibility (demand above any cut) | `D' > U(S,c')` for some cached `S` | rejected by T2 without a solve |

## 4. What transfers from the BPD edge-reconstruction (ER) results

The ER-27..ER-42 line (BPD PR 174, `mechinterp/bpd/experiments/edge_reconstruction`) is about
exact MAP search over reconstructed circuit edges with interval screening and a prefix cache.
I read "Cogentic edge-reconstruction math" as that line; nothing else by that name was found
in the local checkouts. What transfers to directed capacitated graphs, and under which
assumptions:

* **Sound screening by bounds (ER-27/28 signed intervals, exact partial-probe screening).**
  ER rejects candidates whose upper bound is below the incumbent and only computes exact values
  for the rest. Here T2 is the same pattern: a transported cut is an upper bound on max flow, and
  candidates whose bound is below demand are rejected without a solve. The transfer is exact
  because weak duality holds for every directed capacitated network. What does not transfer is
  ER's floating-point screening: all quantities here are integers, so containment is exact,
  with no epsilon.
* **Batch-aware optional-admission interval oracle (ER-39).** The exchange argument assumes
  unit cost and unit size per entry: minimum misses equals requests minus the maximum number of
  retained reuse intervals, capacity `K` at every boundary. For certificates the sizes differ
  (a flow witness is `O(|E|)` integers, a cut is `O(|V|)` bits) and the savings differ (cold
  Edmonds-Karp cost depends on the graph and on the warm-start distance). The ER-39 greedy is
  then not optimal. The budgeted problem is section 5.
* **Causal admission features and the frozen learned scorer (ER-40/41).** These transfer only
  as *policies*: any admission rule is safe, because every certificate is re-verified in full
  before use (T1/T2 checks or a fresh solve). The ER-40 features (gap rank, probe order) have no
  analogue; the clearing analogues are structural (edge-set overlap, demand distance).
* **Compact history and partitioned top-K selection (ER-42).** These carry over as data
  structures: bounded per-certificate counters, and selection without a full sort.

Nothing in ER gives an invariant about flows. The flow invariants used here (T1-T5) are
classical max-flow facts (weak duality, augmenting-path optimality, flow decomposition).

## 5. Budgeted offline admission with unequal sizes and savings

Fix a trace of queries `q_1..q_T`. For a cached certificate `k`, a reuse at `u` with the
certificate created or last used at `t < u` saves `w = C_cold(q_u) - C_verify(k,q_u)` (ns, or
counted edge inspections), and occupies `m_k` bytes over `[t,u)`. With optional admission,
choosing which reuse intervals to keep, subject to `sum m_k <= B` at every boundary, is the
**unsplittable flow on a path** problem (UFP): tasks are intervals, demands `m_k`, capacity
`B`, weights `w`. UFP is strongly NP-hard, so unit-cost Belady and the ER-39 greedy are not
optimal oracles here. The constraint matrix is an interval matrix with columns scaled by `m_k`;
substituting `y = m_k x` restores consecutive ones, so the fractional relaxation is a min-cost
flow on the time path (`B` units from boundary 0 to `T`; idle arcs `t -> t+1` at cost 0; one arc
per interval of capacity `m_k` and cost `-w/m_k`). Its optimum is an exact **upper bound** on
savings for any admission policy over a fixed reuse structure. A density-greedy integral
schedule gives a matching lower bound. When structural retrieval lets several certificates
serve one query, the reuse structure itself becomes a choice; the infinite-cache savings is
then the bound reported.

## 6. Feasibility witnesses versus the canonical settlement

The cold solver's outputs `route_allocations` and `vault_residuals_sats` come from its specific
Edmonds-Karp flow, and `vault_residuals` enters `next_accounting_state_root`. Two different
feasible flows can fund the same demand from different vaults (`residual_v = req_v + avail_v -
inflow(src(v))`), so they give different residuals and a different root. Therefore:

* a transported or repaired flow proves feasibility; it is **not** the settlement;
* a transported cut proves infeasibility, with a deficit lower bound; the cold solver's
  `CapacitatedFlowDeficit { deficit_sats }` is exact, so an exact deficit needs a min cut of the
  mutated graph (repair gives one);
* the batch that will settle still runs the unchanged canonical solver once. Certificates
  remove the solves spent on candidates that are not chosen (candidate screening, batch growth,
  what-if checks), which is where repeated structure occurs.

Replacing the canonical allocation would need a canonical flow that is a function of
`(G,c,D)` alone (for example lexicographically minimal under a fixed edge order, or min-cost
with tie-free costs), an equivalence proof, and differential tests against the current root.
That is not attempted here.
