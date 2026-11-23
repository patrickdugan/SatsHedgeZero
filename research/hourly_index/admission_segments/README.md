# INDEX-ADMIT-06: verified segment composition

This crate reuses the exact depth-18 packed Nova circuit and verification key from ADMIT-05. It prepares bounded, independently provable intervals at idle frontier boundaries. Workers start with the provided frontier and stream only their interval. The independent verifier reconstructs one key and checks every compressed proof, including its complete initial and terminal packed states, exact length, and shared source/network context. The first state must be the sentinel genesis and the final state must equal the receiver-owned expected snapshot claim.

This is a native multi-proof composition, not a recursive proof of all the verifications. The verified statement is structural log admission and sealing. Source authenticity, availability, watermark authority, on-NEAR verification and Bitcoin finality are separate requirements.

```sh
B=research/hourly_index/admission_segments
C=research/hourly_index/admission_scale/fixtures/128-expected.json
node --test "$B/tests/plan.test.mjs"
cargo test --release --manifest-path "$B/Cargo.toml"
cargo build --release --manifest-path "$B/Cargo.toml"
exe="$B/target/release/shz-hourly-index-admission-segments"
plan="$B/fixtures/128-plan.json"
"$exe" trace "$plan" "$C"
mkdir -p /tmp/shz-segments
for i in 0 1 2 3; do
  RAYON_NUM_THREADS=2 "$exe" prove "$plan" "$C" "$i" "/tmp/shz-segments/segment-$i"
done
"$exe" verify "$plan" "$C" /tmp/shz-segments
```

The default per-process proof budget is 256 folds. Larger segments require explicit `SHZ_SEGMENT_MAX_FOLDS` and remain capped at 8192. Plans contain at most 64 segments. A full 144000-report synthetic plan uses 64 segments with 2250 reports each. Its generation/replay is native-only, and the large-scale proof workload is not run by CI. Two-worker CI uses one Rayon thread per worker. Worker memory, proof bytes, setup and compression overhead matter in addition to folding throughput.
