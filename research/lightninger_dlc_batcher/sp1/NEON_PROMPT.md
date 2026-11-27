# Neon (Colab GPU) prompt: prove the DLC batch wrap guest and shrink-wrap it to Groth16

Paste the block below to Neon. Everything it needs is public: SatsHedgeZero `main` (this directory)
and garbled-snark-verifier (`nova-bitvm3/prover-gpu`, rev `f80c364`).

```
Goal: an SP1 6.9.0 Groth16 (BN254) proof of the Lightninger DLC batch wrap guest on its regtest
inputs, whose public values are exactly the 304-byte statement in
research/lightninger_dlc_batcher/artifacts/regtest/guest/expected_statement.bin.

Repos:
  git clone https://github.com/patrickdugan/SatsHedgeZero shz          # main
  git clone https://github.com/patrickdugan/garbled-snark-verifier gsv && git -C gsv checkout f80c364
Work under shz/research/lightninger_dlc_batcher.

1. Toolchain: Rust 1.90+, SP1 6.9.0 (`curl -L https://sp1up.succinct.xyz | bash && sp1up -v v6.9.0`),
   CUDA 12.8+, cmake, clang. Report `nvidia-smi` (GPU model, memory) first.

2. Inputs. guest/ holds clearing_proof.bin, guest_in.bin and expected_statement.bin (committed).
   The clearing verifier key is not committed (size); rebuild it, setup is deterministic:
     cargo build --release --bin dlc-batcher
     ./target/release/dlc-batcher clearing-vk 8 2 artifacts/regtest/guest/clearing_vk.bin
   Its SHA-256 must equal guest_input.json "clearing_vk_sha256". Stop if it differs.

3. Guest ELF and program key:
     cd sp1/script && cargo build --release
     ./target/release/dlc-batch-guest elf ../../dlc-batch-guest.elf     # prints the ELF SHA-256
     ./target/release/dlc-batch-guest vkey                              # SP1 program vkey hash (bytes32)
   Then execute once on CPU as a gate (also checks four refusal cases; on the laptop the honest run is
   163,595,198,099 instructions / 3,557 s and each refusal case re-runs the guest):
     ./target/release/dlc-batch-guest execute ../../artifacts/regtest/guest exec.json
   exec.json must show exit_code 0 and public_values_equal_expected_statement true.

4. GPU proof with nb3-prove-gpu (resumable; gsv/nova-bitvm3/prover-gpu/README.md):
     SP1_DIR=<sp1 checkout at b8387fa6> CUDA_ARCHS=<80 for A100, 89 for L4, 90 for H100> \
       gsv/nova-bitvm3/prover-gpu/scripts/build-with-local-sp1.sh
     G=../../artifacts/regtest/guest
     nb3-prove-gpu prove --elf ../../dlc-batch-guest.elf \
       --input $G/clearing_vk.bin --input $G/clearing_proof.bin --input $G/guest_in.bin \
       --run-dir runs/dlc-batch --out dlc-batch.compressed.bin \
       --element-threshold 134217728 --sp1-worker-defaults \
       --expect-public-sha256 $(sha256sum $G/expected_statement.bin | cut -d' ' -f1)
   Inputs go in that order (each is one SP1Stdin::write_vec). Wrap the run in
   gsv/nova-bitvm3/prover-gpu/scripts/supervise.sh so a stalled CUDA context restarts from the memo.
   If the GPU has 24 GB or more, SP1's own CUDA prover also works: ProverClient::builder().cuda(),
   client.prove(&pk, stdin).compressed().

5. Groth16: shrink, wrap and Groth16-prove the compressed proof with SP1 6.9.0's own path
   (sp1-sdk `.groth16()` on the same ELF and stdin with the CUDA prover, or sp1-prover's
   shrink -> wrap_bn254 -> wrap_groth16_bn254 on dlc-batch.compressed.bin with the Groth16 circuit
   artifacts SP1 6.9.0 downloads). Verify it with sp1-verifier's Groth16 verifier against the vkey
   hash from step 3 and the public values.

Return (as files, plus the numbers in your report):
  dlc-batch.groth16.bin (SP1ProofWithPublicValues, bincode) and its SHA-256,
  the Groth16 proof's raw bytes and public inputs (vkey_hash, committed_values_digest) as hex,
  SP1's Groth16 verifying key as hex (arkworks-compatible: G1/G2 points),
  ELF SHA-256, program vkey hash, instruction count, shard count, wall time per stage
  (execute, core+compress on GPU, shrink, wrap, Groth16), peak GPU and host memory, GPU model,
  and the public values (must be byte-identical to expected_statement.bin).
Budget: 163.6e9 instructions is about 4.8x M16 (34.1e9: 13,290 shards, 1 h 54 min on a 16 GB laptop
GPU from a warm memo), so expect roughly 60,000 shards at 2^27 elements.
Do not change the guest, the inputs or the SP1 version. If a stage fails, report the exact error and
the last 50 log lines; do not retry more than once.
```

When the proof comes back, `research/lightninger_dlc_batch_gc` garbles the verifier for SP1's
Groth16 key with public inputs `[vkey_hash, committed_values_digest]` in place of the
statement-pinned stand-in key used on regtest.
