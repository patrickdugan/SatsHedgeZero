"""ZKL-27: DataGoblin exploration controllers on synthetic and held-out real neighborhoods.

Reuses DataGoblin research/zkl-01-09-20261127 a7fa016 (PR #109):
counterfactual collection (verified completion and offered-column cost as
the training signal, roots 18001-18008, five synthetic training families),
its masked-BPTT fit, the 12-feature/8-hidden tanh RNN (177 parameters) and
the Hybrid shared-basis search wrapper. TRM and LDT arms are minimal
reimplementations on the same cell, documented in ZKL27.md; they are not
the HybridTRMLDT or LoopedTransformers architectures.

Arms: indexed (always exploit), periodic (explore every third offer),
row_random (always explore: random neighborhood row, best unused column),
recurrent (ZKL-21 RNN gate), reset (same weights, hidden state zeroed each
step), trm (same cell refined 3 times per decision, trained with the label
on the last refinement), ldt (same cell looped up to 4 times, trained with
the label on every loop, halts when |p-0.5| >= 0.25).

Every certificate goes through poly_certificate.verify. Neural outputs only
order candidate columns; they never decide acceptance.
"""
import argparse
import json
import random
import sys
import time
from pathlib import Path

import numpy as np

from datagoblin.zk_advantage_gym import FAMILIES
from datagoblin.zk_counterfactual_gym import TRAIN, collect
from datagoblin.zk_exploration_gym import HIDDEN, Hybrid, fit, recurrent_step
from datagoblin.zk_neighborhood_gym import fixture, verified_certificate
from neighborhood_search import BN254_FR, mod

ARMS = ("indexed", "periodic", "row_random", "recurrent", "reset", "trm", "ldt")
TRAIN_ROOTS = range(18001, 18009)
EVAL_ROOTS = range(27101, 27109)
TRM_LOOPS, LDT_LOOPS, LDT_MARGIN = 3, 4, 0.25


def expand(sequences, loops, every):
    out = []
    for seq in sequences:
        e = []
        for x, label in seq:
            for k in range(loops):
                e.append((x, label if (every or k == loops-1) else None))
        out.append(e)
    return out


def train():
    start = time.process_time_ns()
    sequences, counts = collect(TRAIN_ROOTS)
    collect_ns = time.process_time_ns()-start
    models, fits = {}, {}
    for name, seqs in (("rnn", sequences), ("trm", expand(sequences, TRM_LOOPS, False)),
                       ("ldt", expand(sequences, LDT_LOOPS, True))):
        t = time.process_time_ns()
        model, _, updates = fit(seqs)
        models[name] = model
        fits[name] = {"updates": updates, "fit_cpu_ns": time.process_time_ns()-t,
                      "parameters": int(sum(v.size for v in model.values()))}
    counts = {k: v for k, v in counts.items() if not isinstance(v, (list, dict))}
    return models, {"collection": counts, "collection_cpu_ns": collect_ns, "fits": fits,
                    "train_families": list(TRAIN), "train_roots": [TRAIN_ROOTS.start, TRAIN_ROOTS.stop-1]}


def decide(arm, models, x, h):
    if arm == "recurrent":
        prob, h = recurrent_step(models["rnn"], x, h)
        return prob >= 0.5, h, 1
    if arm == "reset":
        prob, _ = recurrent_step(models["rnn"], x, np.zeros(HIDDEN))
        return prob >= 0.5, h, 1
    if arm == "trm":
        z = h
        for _ in range(TRM_LOOPS):
            prob, z = recurrent_step(models["trm"], x, z)
        return prob >= 0.5, z, TRM_LOOPS
    if arm == "ldt":
        z, k = h, 0
        while k < LDT_LOOPS:
            prob, z = recurrent_step(models["ldt"], x, z)
            k += 1
            if abs(prob-0.5) >= LDT_MARGIN:
                break
        return prob >= 0.5, z, k
    raise ValueError(arm)


def drive(problem, arm, budget, models, seed):
    start = time.process_time_ns()
    policy = Hybrid(problem, seed)
    setup_ns = time.process_time_ns()-start
    h = np.zeros(HIDDEN)
    loops = 0
    limit = min(budget, len(problem.keys))
    for t in range(limit):
        if policy.state.solved:
            break
        a = policy.exploit()
        if arm == "indexed":
            action = False
        elif arm == "periodic":
            action = t % 3 == 2
        elif arm == "row_random":
            action = True
        else:
            b = policy.explore()
            action, h, k = decide(arm, models, policy.features(a, b), h)
            loops += k
            policy.gate_decisions += 1
        if action and arm in ("periodic", "row_random"):
            b = policy.explore()
        policy.advance(b if action else a, action, t+1 < limit)
    cert, verify_ns = verified_certificate(problem, policy.state)
    return {"certified": cert is not None, "columns": len(policy.state.offered),
            "work": policy.state.work, "explore": policy.explore_actions, "loops": loops,
            "setup_ns": setup_ns, "verify_ns": verify_ns, "cpu_ns": time.process_time_ns()-start,
            "degree": cert["degree"] if cert else None}


def synthetic(models, budgets=(24, 96)):
    rows = []
    for family in FAMILIES:
        for root in EVAL_ROOTS:
            p = 11 if root % 2 else BN254_FR
            for budget in budgets:
                for arm in ARMS:
                    rec = drive(fixture(p, family, root), arm, budget, models, root)
                    rows.append({"family": family, "root": root, "p": "F11" if p == 11 else "BN254",
                                 "budget": budget, "arm": arm, "held_out_family": family not in TRAIN,
                                 **rec})
    return rows


def real(path, pin, models, count, seed, budgets, positive_pairs=()):
    from graph_dependency import PREFIX, Corpus26, LocalProblem
    from audit_capture import stream_audit
    from local_binding import require_pin
    from graph_dependency import local_shapes
    with path.open("rb") as f:
        header = json.loads(f.readline())
    corpus = Corpus26(PREFIX, header["wires"])
    full = stream_audit(path, visit=corpus.visit)
    require_pin(full["canonical_shape_sha256"], pin)
    rng = random.Random(seed)
    pool = sorted(corpus.rows)
    targets = [("sampled", t, None) for t in sorted(rng.sample(pool, min(count, len(pool))))]
    # Positive tasks: (target, retained rows of a verified certificate); those rows are forced in.
    for t, q in positive_pairs:
        q = [q] if isinstance(q, int) else list(q)
        if t in corpus.rows and all(j in corpus.rows for j in q):
            targets.append(("positive", t, q))
    rows = []
    for kind, target, forced in targets:
        nb = corpus.adaptive(target, 12, 4, 3)
        if forced:
            nb = sorted(set(forced) | set([j for j in nb if j not in forced][:12-len(set(forced))]))
        a, b = local_shapes(full, corpus, target, nb)
        focus = corpus.wires[target]
        freq = {}
        for j in nb:
            for w in corpus.wires[j]:
                freq[w] = freq.get(w, 0)+1
        wires = sorted(sorted(set(freq) | set(focus), key=lambda w: (w not in focus, -freq.get(w, 0), w))[:10])
        for budget in budgets:
            for arm in ARMS:
                problem = LocalProblem(a, b, wires)
                problem.target_support = set(mod(problem.target_poly, problem.p))
                rec = drive(problem, arm, budget, models, seed+target)
                rows.append({"kind": kind, "target": target, "rows": len(nb), "pool_columns": len(problem.keys),
                             "budget": budget, "arm": arm, **rec})
    return rows


def summarize(rows, keys):
    out = {}
    for r in rows:
        k = "/".join(str(r[x]) for x in keys)
        s = out.setdefault(k, {"tasks": 0, "certified": 0, "columns": 0, "work": 0, "cpu_ns": 0,
                               "explore": 0, "loops": 0})
        s["tasks"] += 1
        for f in ("certified", "columns", "work", "cpu_ns", "explore", "loops"):
            s[f] += int(r[f])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--models", type=Path)
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--stream", type=Path)
    ap.add_argument("--expected-original")
    ap.add_argument("--real-count", type=int, default=128)
    ap.add_argument("--positive", type=Path)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.models and args.models.exists():
        raw = json.loads(args.models.read_text())
        models = {n: {k: np.array(v) for k, v in m.items()} for n, m in raw["models"].items()}
        training = raw["training"]
    else:
        models, training = train()
        dump = {"training": training,
                "models": {n: {k: v.tolist() for k, v in m.items()} for n, m in models.items()}}
        (args.out / "models.json").write_text(json.dumps(dump, sort_keys=True)+"\n", encoding="utf-8")
    result = {"schema": "zkl27-controller-campaign-v1", "arms": list(ARMS), "training": training,
              "production_accepted": False}
    if args.synthetic:
        rows = synthetic(models)
        result["synthetic"] = summarize(rows, ("budget", "arm"))
        result["synthetic_held_out_families"] = summarize([r for r in rows if r["held_out_family"]],
                                                          ("budget", "arm"))
        (args.out / "synthetic_rows.json").write_text(json.dumps(rows)+"\n", encoding="utf-8")
    if args.stream:
        pairs = json.loads(args.positive.read_text()) if args.positive and args.positive.exists() else []
        for f in sorted(Path(__file__).with_name("zkl26_results").glob("*_degree*.json")):
            rec = json.loads(f.read_text())
            if rec["original_full_sha256"] == args.expected_original:
                pairs.append([rec["target_global_index"], rec["retained_global_indices"]])
        rows = real(args.stream, args.expected_original, models, args.real_count, 270027, (96, 792), pairs)
        result["real"] = summarize(rows, ("kind", "budget", "arm"))
        (args.out / "real_rows.json").write_text(json.dumps(rows)+"\n", encoding="utf-8")
    (args.out / "summary.json").write_text(json.dumps(result, sort_keys=True, indent=1)+"\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "training"}, sort_keys=True))


if __name__ == "__main__":
    sys.setrecursionlimit(10000)
    main()
