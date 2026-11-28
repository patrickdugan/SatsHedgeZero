#!/usr/bin/env bash
# ZKL-30: point a checkout's research/mnr05_bitvm3_ln_dlc build at a patched
# copy of nova-snark 0.76.0 (experimental skip/tamper hook, inactive unless
# ZKL30_CIRCUIT is set). Usage: prepare_pruned_build.sh <repo checkout> <dest dir>
# Modifies only the given checkout's mnr05 Cargo.toml (adds [patch.crates-io]).
set -euo pipefail
repo="$(cd "$1" && pwd)"
dest="$2"
crate="$repo/research/mnr05_bitvm3_ln_dlc"
cargo fetch --locked --manifest-path "$crate/Cargo.toml"
src="$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/nova-snark-0.76.0 | head -1)"
test -n "$src"
test ! -e "$dest"
cp -r "$src" "$dest"
chmod -R u+w "$dest"
python3 "$repo/research/zk_lean/zkl30/apply_nova_patch.py" "$dest"
grep -q 'zkl30-nova-patch' "$crate/Cargo.toml" || printf '\n# zkl30-nova-patch (experimental, not for production)\n[patch.crates-io]\nnova-snark = { path = "%s" }\n' "$dest" >> "$crate/Cargo.toml"
echo "patched nova-snark at $dest"
