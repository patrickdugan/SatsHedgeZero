"""CBM-CACHE-03 clearing-gym sweep driver. CPU only, synthetic workloads.

python research/utxoref_verification_cache/cbm03_sweep.py --bin <cbm03_gym.exe> --split heldout --out <dir>

Seeds: dev = 1, 2 (smoke and policy settings only); held-out = 101, 102, 103 (chosen before
any held-out run; reported). One process per (size, connectivity, regime, seed); every arm and
budget replays the same reference trace inside it. Exit status 3 from the binary (a false
acceptance) aborts the sweep.
"""
import argparse, json, subprocess, sys, time, pathlib

SIZES = [8, 32, 128, 512, 2048]
CONNS = ["sparse", "dense"]
REGIMES = ["stable", "rotating", "churn"]
SPLITS = {"dev": [1, 2], "heldout": [101, 102, 103]}
BUDGETS = "65536,1048576,8388608,67108864"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--split", choices=SPLITS, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sizes", default=",".join(map(str, SIZES)))
    ap.add_argument("--windows", type=int, default=8)
    ap.add_argument("--cands", type=int, default=24)
    ap.add_argument("--tag", default="")
    ap.add_argument("--extra", default="", help="extra binary arguments, space separated")
    a = ap.parse_args()
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    rows = out / f"sweep_{a.split}{a.tag}.jsonl"
    log = out / f"commands_{a.split}{a.tag}.txt"
    with rows.open("w") as f, log.open("w") as lg:
        for n in map(int, a.sizes.split(",")):
            for conn in CONNS:
                for regime in REGIMES:
                    for seed in SPLITS[a.split]:
                        cmd = [a.bin, "--accounts", str(n), "--conn", conn, "--regime", regime, "--windows", str(a.windows),
                               "--cands", str(a.cands), "--seed", str(seed), "--budgets", BUDGETS,
                               "--check-every", "1" if n <= 512 else "4"] + a.extra.split()
                        lg.write(" ".join(cmd) + "\n"); lg.flush()
                        t = time.time()
                        p = subprocess.run(cmd, capture_output=True, text=True)
                        if p.returncode != 0:
                            sys.stderr.write(p.stderr)
                            raise SystemExit(f"run failed ({p.returncode}): {' '.join(cmd)}")
                        f.write(p.stdout); f.flush()
                        print(f"{n} {conn} {regime} seed {seed}: {time.time() - t:.1f} s", flush=True)

if __name__ == "__main__":
    main()
