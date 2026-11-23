#!/usr/bin/env bash
set -euo pipefail
umask 077

shz=$(realpath "${1:?pass the prebuilt shz CLI with mnr04-nova}")
bitcoind=$(realpath "${2:?pass pinned Bitcoin Core 31.1}")
mkdir -- "${3:?pass a new directory for benchmark results}"
results=$(realpath "$3")
export CUDA_VISIBLE_DEVICES=""
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-1}"

run() {
    local phase=$1
    shift
    /usr/bin/time -f '%e %U %S %M' -o "$results/$phase.time" \
        "$@" >"$results/$phase.stdout" 2>"$results/$phase.stderr"
}

run core "$shz" mnr04-regtest "$bitcoind" "$results/core-archive.json"
run key "$shz" mnr04-key-hash "$results/core-archive.json"
run prove "$shz" mnr04-prove "$results/core-archive.json" "$results/proof"
vk=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vk_sha256"])' "$results/key.stdout")
run verify "$shz" mnr04-verify "$results/core-archive.json" "$results/proof" "$vk"
python3 - "$results" <<'PY' >"$results/benchmark.json"
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
core_stdout = (root / "core.stdout").read_text()
core = json.loads(core_stdout[core_stdout.rfind("\n{") + 1:])
verified = json.loads((root / "verify.stdout").read_text())
prover = json.loads((root / "prove.stdout").read_text())
if core["native"]["txid"] != verified["native"]["txid"] or core["native"]["wtxid"] != verified["native"]["wtxid"]:
    raise SystemExit("Core and Nova verifier transaction identities differ")
if verified["proof_sha256"] != prover["proof_sha256"] or verified["vk_sha256"] != prover["vk_sha256"]:
    raise SystemExit("Nova prover and independent verifier artifacts differ")
phases = {}
for phase in ("core", "key", "prove", "verify"):
    elapsed, user, system, rss = (root / f"{phase}.time").read_text().split()
    phases[phase] = {
        "elapsed_seconds": float(elapsed),
        "user_cpu_seconds": float(user),
        "system_cpu_seconds": float(system),
        "peak_rss_kib": int(rss),
    }
print(json.dumps({
    "core": core,
    "independent_verification": verified,
    "prover_measurements": {
        key: prover[key] for key in (
            "primary_constraints", "secondary_constraints", "setup_seconds",
            "folding_seconds", "compression_seconds"
        )
    },
    "prior_mnr03_compressed_proof_bytes": 12376,
    "phases": phases,
    "cuda_used_for_nova": False,
    "rayon_threads": int(os.environ["RAYON_NUM_THREADS"]),
}, indent=2))
PY
