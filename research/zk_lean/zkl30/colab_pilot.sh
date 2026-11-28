#!/usr/bin/env bash
# ZKL-30 Colab pilot: original vs pruned Mnr05UnifiedBatchStep augmented circuits.
# Run from the root of a clean SatsHedgeZero checkout of research/zkl-01-09-20261127.
# Synthetic funds, Bitcoin Core 31.1 regtest only. Writes zkl30-colab/ and
# zkl30-colab/zkl30_colab_results.json. Never run on the maintainer laptop.
set -uo pipefail
REPO="$(pwd)"
OUT="$REPO/zkl30-colab"
PLAN="$REPO/research/zk_lean/zkl30"
MAN="$REPO/research/mnr05_bitvm3_ln_dlc/Cargo.toml"
mkdir "$OUT" || exit 1
exec > >(tee -a "$OUT/pilot.log") 2>&1

field() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {'d': d}))" "$@"; }
SKIP_P="$(field "$PLAN/primary-plan.json" "','.join(map(str, sorted(d['deletion_set'])))")"
SKIP_S="$(field "$PLAN/secondary-plan.json" "','.join(map(str, sorted(d['deletion_set'])))")"
DEAD_P="$(field "$PLAN/primary-plan.json" "sorted(d['native_aux_index_of_dead_wires'].values())[0]")"
DEAD_S="$(field "$PLAN/secondary-plan.json" "sorted(d['native_aux_index_of_dead_wires'].values())[0]")"
echo "skip primary=$SKIP_P secondary=$SKIP_S dead aux primary=$DEAD_P secondary=$DEAD_S"

{ git rev-parse HEAD; nproc; free -g; rustc -V; cargo -V; python3 -V; } > "$OUT/env.txt" 2>&1

# Bitcoin Core 31.1 (same pin as .github/workflows/shz-mnr05-bitvm3-ci.yml).
curl -fsSL -o /tmp/bitcoin-31.1.tar.gz https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz
echo "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e  /tmp/bitcoin-31.1.tar.gz" | sha256sum -c - || exit 1
tar -xzf /tmp/bitcoin-31.1.tar.gz -C /tmp
BITCOIND=/tmp/bitcoin-31.1/bin/bitcoind

timed() { local name="$1"; shift; /usr/bin/time -v -o "$OUT/$name.time.txt" "$@" 2> "$OUT/$name.stderr.txt"; echo "$?" > "$OUT/$name.exit"; tail -5 "$OUT/$name.stderr.txt"; }
audit() {  # canonical hashes of a capture directory
  python3 "$REPO/research/zk_lean/audit_capture.py" "$1" > /dev/null && \
  python3 -c "import json,sys; a=json.load(open(sys.argv[1]+'/stream-audit.json')); print(json.dumps({s: a[s]['canonical_shape_sha256'] for s in ('primary','secondary')}))" "$1"
}

# 1. Original circuit, crates.io nova-snark 0.76.0, locked.
cargo build --release --locked --manifest-path "$MAN" --bin shz-mnr05-bitvm3-ln-dlc --example zkl_capture || exit 1
mkdir -p "$OUT/bin-original"
cp "$REPO/research/mnr05_bitvm3_ln_dlc/target/release/shz-mnr05-bitvm3-ln-dlc" \
   "$REPO/research/mnr05_bitvm3_ln_dlc/target/release/examples/zkl_capture" "$OUT/bin-original/"
ulimit -v 6291456
timed capture-original "$OUT/bin-original/zkl_capture" "$OUT/capture-original"
audit "$OUT/capture-original" > "$OUT/capture-original.hashes.json"
timed run-original "$OUT/bin-original/shz-mnr05-bitvm3-ln-dlc" run-all "$BITCOIND" "$OUT/run-original"
ulimit -v unlimited

# 2. Patched nova-snark (hook inert unless ZKL30_CIRCUIT is set).
bash "$PLAN/prepare_pruned_build.sh" "$REPO" /tmp/nova-zkl30 || exit 1
cargo build --release --manifest-path "$MAN" --bin shz-mnr05-bitvm3-ln-dlc --example zkl_capture || exit 1
mkdir -p "$OUT/bin-patched"
cp "$REPO/research/mnr05_bitvm3_ln_dlc/target/release/shz-mnr05-bitvm3-ln-dlc" \
   "$REPO/research/mnr05_bitvm3_ln_dlc/target/release/examples/zkl_capture" "$OUT/bin-patched/"
B="$OUT/bin-patched"
ulimit -v 6291456
timed capture-inert "$B/zkl_capture" "$OUT/capture-inert"
audit "$OUT/capture-inert" > "$OUT/capture-inert.hashes.json"

export ZKL30_CIRCUIT=Mnr05UnifiedBatchStep
# 3. Pruned experimental circuit: fresh public parameters and verification key.
ZKL30_SKIP_PRIMARY="$SKIP_P" ZKL30_SKIP_SECONDARY="$SKIP_S" timed capture-pruned "$B/zkl_capture" "$OUT/capture-pruned"
audit "$OUT/capture-pruned" > "$OUT/capture-pruned.hashes.json"
ZKL30_SKIP_PRIMARY="$SKIP_P" ZKL30_SKIP_SECONDARY="$SKIP_S" timed run-pruned "$B/shz-mnr05-bitvm3-ln-dlc" run-all "$BITCOIND" "$OUT/run-pruned"

# 4. Adversarial: perturb the primary dead-output wire (and a control wire).
ZKL30_TAMPER_PRIMARY_AUX="$DEAD_P" timed adv-original-dead "$B/shz-mnr05-bitvm3-ln-dlc" run-all "$BITCOIND" "$OUT/adv-original-dead"
ZKL30_SKIP_PRIMARY="$SKIP_P" ZKL30_SKIP_SECONDARY="$SKIP_S" ZKL30_TAMPER_PRIMARY_AUX="$DEAD_P" \
  timed adv-pruned-dead "$B/shz-mnr05-bitvm3-ln-dlc" run-all "$BITCOIND" "$OUT/adv-pruned-dead"
ZKL30_SKIP_PRIMARY="$SKIP_P" ZKL30_SKIP_SECONDARY="$SKIP_S" ZKL30_TAMPER_PRIMARY_AUX=0 \
  timed adv-pruned-control "$B/shz-mnr05-bitvm3-ln-dlc" run-all "$BITCOIND" "$OUT/adv-pruned-control"
ZKL30_SKIP_PRIMARY="$SKIP_P" ZKL30_SKIP_SECONDARY="$SKIP_S" ZKL30_TAMPER_SECONDARY_AUX="$DEAD_S" \
  timed adv-pruned-dead-secondary "$B/shz-mnr05-bitvm3-ln-dlc" run-all "$BITCOIND" "$OUT/adv-pruned-dead-secondary"
ZKL30_TAMPER_SECONDARY_AUX="$DEAD_S" timed adv-original-dead-secondary "$B/shz-mnr05-bitvm3-ln-dlc" run-all "$BITCOIND" "$OUT/adv-original-dead-secondary"
unset ZKL30_CIRCUIT

python3 "$PLAN/collect_results.py" "$OUT" "$PLAN"
