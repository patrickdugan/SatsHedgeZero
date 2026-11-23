/**
 * End-to-end NEAR Sandbox (`near-sandbox@0.3.5`) verification & adversarial harness for SHZ-INDEX-03.
 *
 * Exercises inside real NEAR WASM (`shz_index03_near_verifier.wasm`):
 * 1. Gate B: Complete 8-hour checkpoint (`c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5`)
 *    8-fold BN254 Nova NIFS + ZK-blinded Spartan/IPA verification across `begin_nova_verification`,
 *    all Merkle-authenticated R1CS sparse-matrix chunks (`verify_r1cs_chunk`), all 512-point BN254
 *    generator chunks (`verify_msm_chunk` via `env::alt_bn128_g1_multiexp`), and `finalize_nova_verification`.
 * 2. Gate B Adversarial Controls: Wrong checkpoint root, wrong Nova step count, tampered compressed
 *    Spartan/IPA proof, substituted R1CS & MSM VK chunks, duplicate chunk replay, premature finalization
 *    of incomplete intermediate state, and replayed proof nullifiers.
 * 3. Gate C On-Chain Source Authentication: Operational Solana Mainnet `pyth-lazer` `Storage` PDA
 *    (`3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL`) + official signed `Crypto.BTC/USD` report via
 *    `env::ed25519_verify` (rejecting synthetic signers under operational profile), Chainlink Data Streams
 *    v3 DON quorum verification via `env::keccak256` + `env::ecrecover` (rejecting unauthorized signers),
 *    and objective anti-cherry-picking challenge (`challenge_cherry_picked_chainlink`).
 * 4. Gate D On-Chain Bitcoin Anchor Finality: Embedded PoW/MTP/chainwork `BtcLightClient` (`submit_btc_header`),
 *    `40`-byte `SHZIDX01 || checkpoint_root32` `OP_RETURN` + SPV Merkle inclusion verification, rejection of
 *    insufficient confirmations & substituted transactions, and dynamic invalidation under a heavier
 *    competing Bitcoin reorganization followed by canonical recovery.
 */
import { Sandbox } from 'near-sandbox';
import { Account, JsonRpcProvider, KeyPair, teraToGas } from 'near-api-js';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { strict as assert } from 'node:assert';

const dir = dirname(fileURLToPath(import.meta.url));
const proofDir = process.env.SHZ_INDEX03_PROOF_DIR
  ? resolve(process.env.SHZ_INDEX03_PROOF_DIR)
  : resolve(dir, 'artifacts');
const wasmPath = process.env.SHZ_INDEX03_WASM
  ? resolve(process.env.SHZ_INDEX03_WASM)
  : resolve(dir, 'near_contract/target/wasm32-unknown-unknown/release/shz_index03_near_verifier.wasm');
const vectorsPath = process.env.SHZ_INDEX03_VECTORS
  ? resolve(process.env.SHZ_INDEX03_VECTORS)
  : resolve(proofDir, 'sandbox_vectors.json');

function u32le(n) {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

function borshStr(s) {
  const sb = Buffer.from(s, 'utf8');
  return Buffer.concat([u32le(sb.length), sb]);
}

function encodeBeginNovaArgs({ session_id, genesis, policy_hash, start_hour, checkpoint_root, proof_bincode }) {
  return Buffer.concat([
    borshStr(session_id),
    borshStr(genesis),
    borshStr(policy_hash),
    borshStr(start_hour),
    borshStr(checkpoint_root),
    u32le(proof_bincode.length),
    proof_bincode,
  ]);
}

function encodeVerifyChunkArgs(sessionId, chunk, overridePayload = null) {
  const payload = overridePayload ?? chunk.payload;
  return Buffer.concat([
    borshStr(sessionId),
    u32le(chunk.chunk_idx),
    u32le(chunk.merkle_index),
    u32le(chunk.siblings.length),
    ...chunk.siblings,
    u32le(payload.length),
    payload,
  ]);
}

function parseVkChunksBundle(buf) {
  let off = 0;
  const readU64 = () => {
    const v = Number(buf.readBigUInt64LE(off));
    off += 8;
    return v;
  };
  const readU32 = () => {
    const v = buf.readUInt32LE(off);
    off += 4;
    return v;
  };
  const readU8 = () => {
    const v = buf.readUInt8(off);
    off += 1;
    return v;
  };
  const readBytes = (n) => {
    const s = buf.subarray(off, off + n);
    off += n;
    return s;
  };

  const relLen = readU64();
  const relation = readBytes(relLen).toString('utf8');
  const arity = readU64();
  const num_cons_padded = readU64();
  const num_vars_padded = readU64();
  const num_io = readU64();
  const vk_digest_le32 = readBytes(32);
  const derand_h_near64 = readBytes(64);
  const ipa_ck_s_near64 = readBytes(64);
  const num_r1cs_chunks = readU32();
  const num_msm_chunks = readU32();
  const vk_chunks_merkle_root = readBytes(32);

  const readChunkVec = () => {
    const count = readU64();
    const list = new Array(count);
    for (let i = 0; i < count; i++) {
      const kind = readU8();
      const chunk_idx = readU32();
      const merkle_index = readU32();
      const sibCount = readU64();
      const siblings = new Array(sibCount);
      for (let j = 0; j < sibCount; j++) {
        siblings[j] = readBytes(32);
      }
      const payloadLen = readU64();
      const payload = readBytes(payloadLen);
      list[i] = { kind, chunk_idx, merkle_index, siblings, payload };
    }
    return list;
  };

  const r1cs_chunks = readChunkVec();
  const msm_chunks = readChunkVec();
  assert.equal(off, buf.length, 'vk_chunks.bin bincode byte-exact parse');
  return {
    relation,
    arity,
    num_cons_padded,
    num_vars_padded,
    num_io,
    vk_digest_le32,
    derand_h_near64,
    ipa_ck_s_near64,
    num_r1cs_chunks,
    num_msm_chunks,
    vk_chunks_merkle_root,
    r1cs_chunks,
    msm_chunks,
  };
}

function receiptGasOf(outcome) {
  const receipts = outcome?.receipts_outcome ?? outcome?.receipts_outcomes ?? [];
  return receipts.reduce((acc, r) => acc + BigInt(r?.outcome?.gas_burnt ?? r?.gas_burnt ?? 0), 0n);
}

function totalGasOf(outcome) {
  const txGas = BigInt(outcome?.transaction_outcome?.outcome?.gas_burnt ?? 0);
  return txGas + receiptGasOf(outcome);
}

function decodeSuccessJson(outcome) {
  assert.equal(Boolean(outcome?.status?.Failure), false, `unexpected tx Failure: ${JSON.stringify(outcome?.status)}`);
  const b64 = outcome?.status?.SuccessValue ?? '';
  const text = Buffer.from(b64, 'base64').toString('utf8');
  return JSON.parse(text);
}

async function expectTxRejected(fn, label) {
  try {
    const res = await fn();
    if (Boolean(res?.status?.Failure)) {
      return true;
    }
    throw new Error(`expected rejection for [${label}], but transaction succeeded!`);
  } catch (err) {
    if (String(err?.message ?? '').startsWith('expected rejection for')) {
      throw err;
    }
    return true;
  }
}

const wasm = new Uint8Array(readFileSync(wasmPath));
const proofBincode = readFileSync(resolve(proofDir, 'proof.bin'));
const vkChunksRaw = readFileSync(resolve(proofDir, 'vk_chunks.bin'));
const compactVkJson = readFileSync(resolve(proofDir, 'compact_vk.json'), 'utf8');
const claim = JSON.parse(readFileSync(resolve(proofDir, 'claim.json'), 'utf8'));
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const vkBundle = parseVkChunksBundle(vkChunksRaw);

const genesisPrivateKey =
  'ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB';

const tWallStart = performance.now();
const sandbox = await Sandbox.start({});

try {
  const provider = new JsonRpcProvider({ url: sandbox.rpcUrl });
  const master = new Account('sandbox', provider, genesisPrivateKey);

  const storageBeforeDeploy = BigInt((await master.getState()).storageUsage ?? 0);
  await master.deployContract(wasm);
  const storageAfterDeploy = BigInt((await master.getState()).storageUsage ?? 0);

  const initOut = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'new',
    args: {
      compact_vk_json: compactVkJson,
      btc_network: 'regtest',
      min_btc_confirmations: 3,
      anchor_btc_height: vectors.anchor_btc_height,
      anchor_btc_header_hex: vectors.anchor_btc_header_hex,
      solana_pyth_storage_hex: vectors.solana_pyth_storage_hex,
      synthetic_pyth_signer_hex: vectors.synthetic_pyth_signer_hex,
      chainlink_don_json: vectors.chainlink_don_json,
    },
    gas: teraToGas('100'),
  });
  assert.equal(Boolean(initOut?.status?.Failure), false, 'initialize ShzIndex03Verifier');
  const storageAfterInit = BigInt((await master.getState()).storageUsage ?? 0);

  // Add 16 concurrent full-access keys on `sandbox` for parallel chunk streaming without nonce contention
  const WORKER_COUNT = 16;
  const workers = [];
  for (let i = 0; i < WORKER_COUNT; i++) {
    const kp = KeyPair.fromRandom('ed25519');
    await master.addFullAccessKey(kp.getPublicKey());
    workers.push(new Account('sandbox', provider, kp.toString()));
  }

  // --- Gate B Negative Controls BEFORE Valid Session ---
  // 1. Wrong checkpoint root rejected in `begin_nova_verification`
  const wrongRootHex = (claim.checkpoint_root[0] === '0' ? '1' : '0') + claim.checkpoint_root.slice(1);
  const wrongRootRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'begin_nova_verification',
        args: encodeBeginNovaArgs({
          session_id: 'bad-root',
          ...claim,
          checkpoint_root: wrongRootHex,
          proof_bincode: proofBincode,
        }),
        gas: teraToGas('300'),
      }),
    'wrong checkpoint_root',
  );

  // 2. Wrong Nova step count (`steps = 7` at offset 8 + relation.length in bincode)
  const badStepProof = Buffer.from(proofBincode);
  const relByteLen = Number(badStepProof.readBigUInt64LE(0));
  badStepProof.writeBigUInt64LE(7n, 8 + relByteLen);
  const wrongStepCountRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'begin_nova_verification',
        args: encodeBeginNovaArgs({
          session_id: 'bad-steps',
          ...claim,
          proof_bincode: badStepProof,
        }),
        gas: teraToGas('300'),
      }),
    'wrong Nova step count',
  );

  // 3. Tampered & truncated Spartan/IPA compressed SNARK rejected in `begin_nova_verification`
  // (Note: `spartan_snark_bytes` occupies the final 6,304 bytes; offset `-1800` mutates a sumcheck/IPA commitment byte)
  const tamperedProof = Buffer.from(proofBincode);
  tamperedProof[tamperedProof.length - 1800] ^= 0x01;
  const tamperedSumcheckRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'begin_nova_verification',
        args: encodeBeginNovaArgs({
          session_id: 'bad-snark',
          ...claim,
          proof_bincode: tamperedProof,
        }),
        gas: teraToGas('300'),
      }),
    'tampered Spartan/IPA sumcheck/commitment',
  );
  const truncatedProof = proofBincode.subarray(0, proofBincode.length - 4);
  const truncatedProofRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'begin_nova_verification',
        args: encodeBeginNovaArgs({
          session_id: 'trunc-snark',
          ...claim,
          proof_bincode: truncatedProof,
        }),
        gas: teraToGas('300'),
      }),
    'truncated Spartan/IPA proof',
  );
  const tamperedProofRejected = tamperedSumcheckRejected && truncatedProofRejected;

  // --- Gate B Full Valid 8-Hour Checkpoint Verification ---
  const sessionId = 'valid-8h-checkpoint';
  const tVerifyStart = performance.now();

  const beginOut = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'begin_nova_verification',
    args: encodeBeginNovaArgs({
      session_id: sessionId,
      ...claim,
      proof_bincode: proofBincode,
    }),
    gas: teraToGas('300'),
  });
  assert.equal(Boolean(beginOut?.status?.Failure), false, 'begin_nova_verification must succeed');
  const beginReceiptGas = receiptGasOf(beginOut);
  const beginTotalGas = totalGasOf(beginOut);
  const storageDuringSession = BigInt((await master.getState()).storageUsage ?? 0);

  //Verify R1CS chunk 0 first, then exercise live intermediate-state / VK-substitution / chunk-replay controls!
  const r1csChunkGas = new Array(vkBundle.r1cs_chunks.length);
  const c0Out = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'verify_r1cs_chunk',
    args: encodeVerifyChunkArgs(sessionId, vkBundle.r1cs_chunks[0]),
    gas: teraToGas('300'),
  });
  assert.equal(Boolean(c0Out?.status?.Failure), false, 'verify_r1cs_chunk[0]');
  r1csChunkGas[0] = receiptGasOf(c0Out);

  // 4. Duplicate R1CS chunk replay rejected (and state rolls back cleanly!)
  const duplicateChunkReplayRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'verify_r1cs_chunk',
        args: encodeVerifyChunkArgs(sessionId, vkBundle.r1cs_chunks[0]),
        gas: teraToGas('300'),
      }),
    'duplicate R1CS chunk replay',
  );

  // 5. Substituted R1CS VK chunk rejected
  const badR1csPayload = Buffer.from(vkBundle.r1cs_chunks[1].payload);
  badR1csPayload[badR1csPayload.length - 1] ^= 0x01;
  const substitutedR1csChunkRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'verify_r1cs_chunk',
        args: encodeVerifyChunkArgs(sessionId, vkBundle.r1cs_chunks[1], badR1csPayload),
        gas: teraToGas('300'),
      }),
    'substituted R1CS VK chunk',
  );

  // 6. Substituted MSM generator VK chunk rejected
  const badMsmPayload = Buffer.from(vkBundle.msm_chunks[0].payload);
  badMsmPayload[0] ^= 0x01;
  const substitutedMsmChunkRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'verify_msm_chunk',
        args: encodeVerifyChunkArgs(sessionId, vkBundle.msm_chunks[0], badMsmPayload),
        gas: teraToGas('300'),
      }),
    'substituted MSM VK chunk',
  );

  // 7. Premature `finalize_nova_verification` on incomplete intermediate state rejected!
  const prematureFinalizeRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'finalize_nova_verification',
        args: { session_id: sessionId },
        gas: teraToGas('300'),
      }),
    'premature finalize on incomplete intermediate state',
  );

  // Stream remaining R1CS chunks (`1..num_r1cs_chunks`) in parallel across workers
  {
    let cursor = 1;
    await Promise.all(
      workers.map(async (w) => {
        while (true) {
          const i = cursor++;
          if (i >= vkBundle.r1cs_chunks.length) break;
          const out = await w.callFunctionRaw({
            contractId: 'sandbox',
            methodName: 'verify_r1cs_chunk',
            args: encodeVerifyChunkArgs(sessionId, vkBundle.r1cs_chunks[i]),
            gas: teraToGas('300'),
          });
          assert.equal(Boolean(out?.status?.Failure), false, `verify_r1cs_chunk[${i}] failed`);
          r1csChunkGas[i] = receiptGasOf(out);
        }
      }),
    );
  }

  // Stream all `num_msm_chunks` 512-point BN254 generator chunks in parallel across workers
  const msmChunkGas = new Array(vkBundle.msm_chunks.length);
  {
    let cursor = 0;
    await Promise.all(
      workers.map(async (w) => {
        while (true) {
          const i = cursor++;
          if (i >= vkBundle.msm_chunks.length) break;
          const out = await w.callFunctionRaw({
            contractId: 'sandbox',
            methodName: 'verify_msm_chunk',
            args: encodeVerifyChunkArgs(sessionId, vkBundle.msm_chunks[i]),
            gas: teraToGas('300'),
          });
          assert.equal(Boolean(out?.status?.Failure), false, `verify_msm_chunk[${i}] failed`);
          msmChunkGas[i] = receiptGasOf(out);
          if ((i + 1) % 256 === 0 || i + 1 === vkBundle.msm_chunks.length) {
            console.error(`  [sandbox] verified MSM chunks: ${i + 1}/${vkBundle.msm_chunks.length}`);
          }
        }
      }),
    );
  }

  // Finalize cryptographic Nova checkpoint verification!
  const finalizeOut = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'finalize_nova_verification',
    args: { session_id: sessionId },
    gas: teraToGas('300'),
  });
  const finalizeReceiptGas = receiptGasOf(finalizeOut);
  const verifiedRecordStr = decodeSuccessJson(finalizeOut);
  const verifiedRecord = typeof verifiedRecordStr === 'string' ? JSON.parse(verifiedRecordStr) : verifiedRecordStr;
  const verifySandboxWallSeconds = (performance.now() - tVerifyStart) / 1000.0;
  const storageAfterFinalize = BigInt((await master.getState()).storageUsage ?? 0);

  assert.equal(verifiedRecord.near_nova_verified, true);
  assert.equal(
    verifiedRecord.checkpoint_root,
    'c26ae9643756ac6b7fbfd2a5b4c66f2a5fb76aaaf9ef17600b741f0d7fdd3af5',
  );
  assert.equal(verifiedRecord.production_ready, false);
  assert.equal(verifiedRecord.can_authorize_dlc_settlement, false);

  // 8. Replayed proof nullifier rejected after finalization!
  const replayedProofRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'begin_nova_verification',
        args: encodeBeginNovaArgs({
          session_id: 'replay-attempt',
          ...claim,
          proof_bincode: proofBincode,
        }),
        gas: teraToGas('300'),
      }),
    'replayed proof nullifier',
  );

  // --- Gate C: On-Chain Pyth Pro (`env::ed25519_verify`) & Chainlink v3 (`env::ecrecover`) ---
  const pythOpOut = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'verify_pyth_pro_report_onchain',
    args: {
      profile: 'operational_mainnet_pinned',
      raw_envelope_hex: vectors.official_pyth_wire_hex,
      cutoff_us: vectors.official_pyth_cutoff_us,
    },
    gas: teraToGas('100'),
  });
  const pythOpReceipt = JSON.parse(decodeSuccessJson(pythOpOut));
  assert.equal(pythOpReceipt.operational_source_authenticated, true);
  assert.equal(
    pythOpReceipt.signer_pubkey_hex,
    '80efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c',
  );

  // Synthetic Pyth signer MUST fail under `operational_mainnet_pinned`!
  const syntheticPythInOperationalRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'verify_pyth_pro_report_onchain',
        args: {
          profile: 'operational_mainnet_pinned',
          raw_envelope_hex: vectors.synthetic_pyth_wire_hex,
          cutoff_us: vectors.synthetic_pyth_cutoff_us,
        },
        gas: teraToGas('100'),
      }),
    'synthetic Pyth key under operational profile',
  );

  const clValidOut = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'verify_chainlink_v3_report_onchain',
    args: { full_report_hex: vectors.valid_chainlink_report_hex },
    gas: teraToGas('100'),
  });
  const clValidReceipt = JSON.parse(decodeSuccessJson(clValidOut));
  assert.equal(clValidReceipt.operational_source_authenticated, false);
  assert.equal(clValidReceipt.verified_don_signers.length, 2);

  const unauthorizedChainlinkRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'verify_chainlink_v3_report_onchain',
        args: { full_report_hex: vectors.unauthorized_chainlink_report_hex },
        gas: teraToGas('100'),
      }),
    'unauthorized Chainlink DON signer',
  );

  // --- Gate D: On-Chain Bitcoin Header Light Client + `SHZIDX01` Anchor + Reorg Defense ---
  const startHourNum = Number(claim.start_hour);
  await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'submit_btc_header',
    args: { raw_header_hex: vectors.btc_headers_main_hex[0] }, // height 101 (1 conf)
    gas: teraToGas('100'),
  });

  // Insufficient confirmations (1 < 3) rejected!
  const unconfirmedAnchorRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'anchor_verified_checkpoint_to_bitcoin',
        args: {
          start_hour: startHourNum,
          raw_tx_hex: vectors.valid_btc_tx_hex,
          block_hash_hex: vectors.btc_anchor_block_hash_hex,
          tx_index: 1,
          merkle_branch_hex: vectors.btc_merkle_branch_hex,
        },
        gas: teraToGas('100'),
      }),
    'insufficient Bitcoin confirmations',
  );

  // Submit heights 102 and 103 (3 confirmations)
  await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'submit_btc_header',
    args: { raw_header_hex: vectors.btc_headers_main_hex[1] },
    gas: teraToGas('100'),
  });
  await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'submit_btc_header',
    args: { raw_header_hex: vectors.btc_headers_main_hex[2] },
    gas: teraToGas('100'),
  });

  // Substituted Bitcoin transaction rejected!
  const substitutedBtcTxRejected = await expectTxRejected(
    () =>
      master.callFunctionRaw({
        contractId: 'sandbox',
        methodName: 'anchor_verified_checkpoint_to_bitcoin',
        args: {
          start_hour: startHourNum,
          raw_tx_hex: vectors.substituted_btc_tx_hex,
          block_hash_hex: vectors.btc_anchor_block_hash_hex,
          tx_index: 1,
          merkle_branch_hex: vectors.btc_merkle_branch_hex,
        },
        gas: teraToGas('100'),
      }),
    'substituted Bitcoin OP_RETURN tx',
  );

  // Valid Bitcoin SHZIDX01 anchor succeeds at 3 confirmations!
  const anchorOut = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'anchor_verified_checkpoint_to_bitcoin',
    args: {
      start_hour: startHourNum,
      raw_tx_hex: vectors.valid_btc_tx_hex,
      block_hash_hex: vectors.btc_anchor_block_hash_hex,
      tx_index: 1,
      merkle_branch_hex: vectors.btc_merkle_branch_hex,
    },
    gas: teraToGas('100'),
  });
  const anchoredRecord = JSON.parse(decodeSuccessJson(anchorOut));
  assert.equal(anchoredRecord.bitcoin_anchor_finalized, true);
  assert.equal(anchoredRecord.bitcoin_confirmations, 3);

  const statusBeforeReorg = JSON.parse(
    await provider.callFunction({
      contractId: 'sandbox',
      method: 'get_checkpoint_feed_status',
      args: { start_hour: startHourNum },
    }),
  );
  assert.equal(statusBeforeReorg.eligible_for_frost_dlc_feed, true);

  // Submit heavier 4-block competing Bitcoin chain (`f1..f4`) -> orphans height 101!
  for (const forkHdr of vectors.btc_headers_reorg_hex) {
    await master.callFunctionRaw({
      contractId: 'sandbox',
      methodName: 'submit_btc_header',
      args: { raw_header_hex: forkHdr },
      gas: teraToGas('100'),
    });
  }
  const statusDuringReorg = JSON.parse(
    await provider.callFunction({
      contractId: 'sandbox',
      method: 'get_checkpoint_feed_status',
      args: { start_hour: startHourNum },
    }),
  );
  assert.equal(statusDuringReorg.bitcoin_canonical_mainchain_confirmed, false);
  assert.equal(statusDuringReorg.eligible_for_frost_dlc_feed, false);

  // Extend canonical branch by 2 more blocks (`104, 105` -> 5 blocks > 4-block fork) -> recovers finality!
  await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'submit_btc_header',
    args: { raw_header_hex: vectors.btc_headers_main_hex[3] },
    gas: teraToGas('100'),
  });
  await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'submit_btc_header',
    args: { raw_header_hex: vectors.btc_headers_main_hex[4] },
    gas: teraToGas('100'),
  });
  const statusAfterRecovery = JSON.parse(
    await provider.callFunction({
      contractId: 'sandbox',
      method: 'get_checkpoint_feed_status',
      args: { start_hour: startHourNum },
    }),
  );
  assert.equal(statusAfterRecovery.eligible_for_frost_dlc_feed, true);
  assert.equal(statusAfterRecovery.live_bitcoin_confirmations, 5);
  assert.equal(statusAfterRecovery.production_ready, false);
  assert.equal(statusAfterRecovery.can_authorize_dlc_settlement, false);

  // Cherry-pick challenge revokes feed eligibility!
  const cherryOut = await master.callFunctionRaw({
    contractId: 'sandbox',
    methodName: 'challenge_cherry_picked_chainlink',
    args: {
      start_hour: startHourNum,
      hour_id: startHourNum,
      selected_publish_us: vectors.selected_chainlink_publish_us,
      challenger_full_report_hex: vectors.newer_cherry_pick_chainlink_report_hex,
    },
    gas: teraToGas('100'),
  });
  assert.equal(decodeSuccessJson(cherryOut), true);
  const statusAfterCherryChallenge = JSON.parse(
    await provider.callFunction({
      contractId: 'sandbox',
      method: 'get_checkpoint_feed_status',
      args: { start_hour: startHourNum },
    }),
  );
  assert.equal(statusAfterCherryChallenge.source_challenged_invalid, true);
  assert.equal(statusAfterCherryChallenge.eligible_for_frost_dlc_feed, false);

  // Global honesty flags MUST remain false
  assert.equal(
    await provider.callFunction({ contractId: 'sandbox', method: 'production_ready', args: {} }),
    false,
  );
  assert.equal(
    await provider.callFunction({ contractId: 'sandbox', method: 'can_authorize_dlc_settlement', args: {} }),
    false,
  );

  // Aggregate exact gas & storage telemetry
  const sumBig = (arr) => arr.reduce((a, b) => a + b, 0n);
  const maxBig = (arr) => arr.reduce((a, b) => (b > a ? b : a), 0n);
  const r1csSumGas = sumBig(r1csChunkGas);
  const msmSumGas = sumBig(msmChunkGas);
  const totalNovaReceiptGas = beginReceiptGas + r1csSumGas + msmSumGas + finalizeReceiptGas;
  const totalNovaTxCount = 1 + vkBundle.r1cs_chunks.length + vkBundle.msm_chunks.length + 1;

  const report = {
    schema: 'shz/index03-transparent-near-nova-sandbox-receipt/v1',
    network: 'near-sandbox@0.3.5',
    relation: vkBundle.relation,
    checkpoint_root: claim.checkpoint_root,
    start_hour: claim.start_hour,
    wasm_binary_bytes: wasm.byteLength,
    proof_bincode_bytes: proofBincode.byteLength,
    compact_onchain_vk_json_bytes: Buffer.byteLength(compactVkJson, 'utf8'),
    vk_chunks_stream_bytes: vkChunksRaw.byteLength,
    vk_chunks_merkle_root_hex: vkBundle.vk_chunks_merkle_root.toString('hex'),
    storage_bytes: {
      contract_code_delta_bytes: Number(storageAfterDeploy - storageBeforeDeploy),
      pinned_init_state_delta_bytes: Number(storageAfterInit - storageAfterDeploy),
      active_session_delta_bytes: Number(storageDuringSession - storageAfterInit),
      finalized_checkpoint_delta_bytes: Number(storageAfterFinalize - storageAfterInit),
    },
    nova_verification_metrics: {
      near_nova_verified: true,
      transactions_total: totalNovaTxCount,
      r1cs_chunks: vkBundle.r1cs_chunks.length,
      msm_chunks: vkBundle.msm_chunks.length,
      begin_receipt_tgas: Number(beginReceiptGas) / 1e12,
      begin_total_tx_tgas: Number(beginTotalGas) / 1e12,
      r1cs_chunk_mean_receipt_tgas: Number(r1csSumGas) / vkBundle.r1cs_chunks.length / 1e12,
      r1cs_chunk_max_receipt_tgas: Number(maxBig(r1csChunkGas)) / 1e12,
      r1cs_chunks_total_receipt_tgas: Number(r1csSumGas) / 1e12,
      msm_chunk_mean_receipt_tgas: Number(msmSumGas) / vkBundle.msm_chunks.length / 1e12,
      msm_chunk_max_receipt_tgas: Number(maxBig(msmChunkGas)) / 1e12,
      msm_chunks_total_receipt_tgas: Number(msmSumGas) / 1e12,
      finalize_receipt_tgas: Number(finalizeReceiptGas) / 1e12,
      cumulative_nova_receipt_gas_burnt: totalNovaReceiptGas.toString(),
      cumulative_nova_receipt_tgas: Number(totalNovaReceiptGas) / 1e12,
      sandbox_verify_wall_seconds: verifySandboxWallSeconds,
    },
    source_authentication_metrics: {
      operational_pyth_solana_storage_verified: true,
      operational_pyth_trusted_signer_hex: pythOpReceipt.signer_pubkey_hex,
      operational_pyth_verify_receipt_tgas: Number(receiptGasOf(pythOpOut)) / 1e12,
      synthetic_pyth_under_operational_rejected: syntheticPythInOperationalRejected,
      chainlink_v3_ecrecover_quorum_verified: true,
      chainlink_v3_verify_receipt_tgas: Number(receiptGasOf(clValidOut)) / 1e12,
      unauthorized_chainlink_signer_rejected: unauthorizedChainlinkRejected,
      cherry_pick_challenge_invalidated_checkpoint: true,
    },
    bitcoin_anchor_metrics: {
      anchor_txid_hex: anchoredRecord.bitcoin_anchor_txid_hex,
      anchor_block_hash_hex: anchoredRecord.bitcoin_anchor_block_hash_hex,
      anchor_verify_receipt_tgas: Number(receiptGasOf(anchorOut)) / 1e12,
      unconfirmed_anchor_rejected: unconfirmedAnchorRejected,
      substituted_btc_tx_rejected: substitutedBtcTxRejected,
      reorg_orphaned_anchor_revoked_eligibility: !statusDuringReorg.eligible_for_frost_dlc_feed,
      canonical_recovery_restored_eligibility: statusAfterRecovery.eligible_for_frost_dlc_feed,
    },
    adversarial_controls_on_near_wasm: {
      wrong_checkpoint_root_rejected: wrongRootRejected,
      wrong_nova_step_count_rejected: wrongStepCountRejected,
      tampered_compressed_proof_rejected: tamperedProofRejected,
      duplicate_chunk_replay_rejected: duplicateChunkReplayRejected,
      substituted_r1cs_vk_chunk_rejected: substitutedR1csChunkRejected,
      substituted_msm_vk_chunk_rejected: substitutedMsmChunkRejected,
      premature_incomplete_state_finalize_rejected: prematureFinalizeRejected,
      replayed_proof_nullifier_rejected: replayedProofRejected,
    },
    honesty_flags: {
      production_ready: false,
      can_authorize_dlc_settlement: false,
    },
    total_harness_wall_seconds: (performance.now() - tWallStart) / 1000.0,
  };

  const json = JSON.stringify(report, null, 2);
  console.log(json);
  if (process.env.SHZ_INDEX03_SANDBOX_REPORT) {
    writeFileSync(process.env.SHZ_INDEX03_SANDBOX_REPORT, `${json}\n`);
  }
} finally {
  await sandbox.tearDown();
}
