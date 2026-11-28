"""Collect ZKL-30 Colab pilot outputs into zkl30_colab_results.json and check bindings."""
import json
import re
import sys
from pathlib import Path

out, plan_dir = Path(sys.argv[1]), Path(sys.argv[2])
repo = plan_dir.parents[2]
pins = json.loads((repo / "research/zk_lean/zkl22_capture_pins.json").read_text())
plans = {s: json.loads((plan_dir / f"{s}-plan.json").read_text()) for s in ("primary", "secondary")}


def timing(name):
    p = out / f"{name}.time.txt"
    if not p.exists():
        return None
    t = p.read_text()
    get = lambda pat: (m.group(1) if (m := re.search(pat, t)) else None)  # noqa: E731
    return {"wall": get(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): (\S+)"),
            "peak_rss_kib": int(get(r"Maximum resident set size \(kbytes\): (\d+)") or 0),
            "exit": int((out / f"{name}.exit").read_text()) if (out / f"{name}.exit").exists() else None}


def capture(name):
    d = out / name
    if not (d / "capture.json").exists():
        return None
    c = json.loads((d / "capture.json").read_text())
    h = json.loads((out / f"{name}.hashes.json").read_text())
    return {"canonical": h, "vk_sha256": c["vk_sha256"], "vk_bytes": (d / "vk.bin").stat().st_size,
            "pp_digest": c["pp_digest"],
            **{s: {"constraints": c[s]["capture"]["constraints"], "auxiliary": c[s]["capture"]["auxiliary"],
                   "native_nonzeros": c[s]["native_nonzeros"]} for s in ("primary", "secondary")},
            "time": timing(name)}


def run(name):
    d = out / name
    r = d / "unified_batch_receipt.json"
    rec = json.loads(r.read_text()) if r.exists() else None
    err = [ln for ln in (out / "pilot.log").read_text().splitlines() if ln.startswith("ERROR")] \
        if (out / "pilot.log").exists() else []
    return {"time": timing(name), "receipt": rec, "zkl30_hook_lines": None, "errors_in_log": err[-3:]}


res = {"schema": "zkl30-colab-results-v1", "env": (out / "env.txt").read_text() if (out / "env.txt").exists() else None,
       "captures": {n: capture(n) for n in ("capture-original", "capture-inert", "capture-pruned")},
       "runs": {n: run(n) for n in ("run-original", "run-pruned", "adv-original-dead", "adv-pruned-dead",
                                    "adv-pruned-control", "adv-pruned-dead-secondary",
                                    "adv-original-dead-secondary")}}
checks = {}
co, ci, cp = (res["captures"][n] for n in ("capture-original", "capture-inert", "capture-pruned"))
if co:
    checks["original_reproduces_zkl22_pins"] = all(co["canonical"][s] == pins[s] for s in ("primary", "secondary"))
    checks["original_vk_matches_zkl22"] = co["vk_sha256"] == pins["vk_sha256"]
if ci:
    checks["inert_hook_reproduces_pins"] = all(ci["canonical"][s] == pins[s] for s in ("primary", "secondary"))
if cp:
    checks["pruned_matches_plan_hash"] = all(cp["canonical"][s] == plans[s]["expected"]["pruned_sha256"]
                                             for s in ("primary", "secondary"))
    checks["pruned_constraint_counts"] = all(cp[s]["constraints"] == plans[s]["expected"]["constraints"]
                                             for s in ("primary", "secondary"))
    checks["pruned_vk_differs"] = co is not None and cp["vk_sha256"] != co["vk_sha256"]
runs = res["runs"]
ok = lambda n: runs[n]["time"] is not None and runs[n]["time"]["exit"] == 0  # noqa: E731


def rejected(n):
    """Non-zero exit with a Nova unified-proof error, and the tamper hook applied."""
    r = runs[n]
    return (r["time"] is not None and r["time"]["exit"] != 0
            and any("Unified" in e for e in r["errors"])
            and any("tamper_applied=true" in h for h in r["zkl30_hook_lines"]))


def accepted_tampered(n):
    r = runs[n]
    return ok(n) and any("tamper_applied=true" in h for h in r["zkl30_hook_lines"])
checks["original_run_ok"] = ok("run-original")
checks["pruned_run_ok"] = ok("run-pruned")
checks["original_rejects_dead_tamper_primary"] = rejected("adv-original-dead")
checks["pruned_accepts_dead_tamper_primary"] = accepted_tampered("adv-pruned-dead")
checks["pruned_rejects_control_tamper"] = rejected("adv-pruned-control")
checks["original_rejects_dead_tamper_secondary"] = rejected("adv-original-dead-secondary")
checks["pruned_accepts_dead_tamper_secondary"] = accepted_tampered("adv-pruned-dead-secondary")
if ok("run-original") and ok("adv-pruned-dead"):
    a, b = runs["run-original"]["receipt"], runs["adv-pruned-dead"]["receipt"]
    keys = ("final_nullifier_root_hex", "settlement_txid_hex", "bitvm3_statement_304b_sha256_hex",
            "bitvm3_public_limbs_be_dec")
    checks["tampered_pruned_public_claims_equal_original"] = all(a[k] == b[k] for k in keys)
res["checks"] = checks
res["plans"] = {s: {"deletion_set": plans[s]["deletion_set"], "expected": plans[s]["expected"]} for s in plans}
(out / "zkl30_colab_results.json").write_text(json.dumps(res, indent=1, sort_keys=True)+"\n", encoding="utf-8")
print(json.dumps(checks, indent=1, sort_keys=True))
