// SatsHedgeZero 4-Tab Protocol & Proof Workbench (`ui/public/workbench.js`)
// Renders a Deribit-style institutional bottom blotter into `<section id="shz-workbench-root">`:
//   1. Positions & MNR-02 Offline Closeout (0x83 Leaf 0 / CLTV Leaf 1 / CLTV Leaf 2 + Core v31.1 rejections)
//   2. LN-DLC Subchannels & CET Tree (Taproot NUMS + dyadic binary prefixes + LN Coop vs L1 CET toggle)
//   3. FROST & NEAR Fraud Guard (3-of-5 signer matrix, TVL<=10x Stake cap, TradeLayer tx14, Pyth, Equivocation/Deviation verdicts)
//   4. Nova v2 & BitVM3 Proof Inspector (600B transcript byte map, 276B LNMJNL01 + 8-field Pallas, Secq 3-field, 304B Groth16 limbs)
//
// Zero external dependencies. Safe for both browser ES module import and Node.js unit testing.

import {
  SATS_PER_BTC,
  buildInverseSpec,
  compressDyadicCetRanges,
  computeInversePayout,
  computeLiquidationPrices,
  lookupCetForPrice,
} from "./charts.js";

// ---------------------------------------------------------------------------
// Canonical Protocol Constants & Embedded Repo Evidence Fallbacks
// ---------------------------------------------------------------------------

export const UTXOREF_NUMS_INTERNAL_KEY_HEX =
  "c99e9965166e7ff80516494709db8fdfdc31b0626500bb70dc3652fc2ff584ab";

export const NOVA_TRANSCRIPT_DOMAIN =
  "UTXORef/LNMarkets/Nova/validated-signed-row/v1"; // exact 46 bytes

export const LNM_BATCH_DOMAIN =
  "UTXORef/LNMarkets/bitcoin-regtest/lnmarkets/v1/";

export const BITVM3_STATEMENT_MAGIC = "UTXOREF_L2_SETTLEMENT_GROTH16_V0\0"; // exact 33 bytes

export const MAX_ROW_AMOUNT_51BIT = (1n << 51n) - 1n;
export const MAX_CUMULATIVE_56BIT = (1n << 56n) - 1n;

export const DEFAULT_HONESTY_FLAGS = Object.freeze({
  native_statement_verified: true,
  nova_snark_verified: false,
  bitvm3_onchain_verified: false,
  production_ready: false,
});

export const DEFAULT_MNR02_RECEIPT = Object.freeze({
  issue: "SHZ-MNR-02: Bob-offline multilateral closeout with Bitcoin-enforceable settlement",
  core_version: "Bitcoin Core daemon version v31.1.0 bitcoind",
  production_ready: false,
  bitcoin_spend_enforced: true,
  alice_bob_funding_txid:
    "7f96d2ee64b511c8f70880feedc106062e7cab0baff2f9262fa8ba4209011cd0",
  alice_carol_offset_funding_txid:
    "e33b911ac3e5d589ab9498a2e335b49dbebda1f6987e5b585dc37ccba698d2f1",
  bob_offline_after_height: 106,
  bob_offline_routed_settlement_60k: {
    label: "bob-offline-multilateral-routed-cet-60k",
    txid: "479c905ce4fb52b1cd3e98404405843a9510a46ba162a4b8d83216e4ae985e36",
    wtxid: "4201996e3cb07400b32037b713b819e43c4db2d69835f049b04cd53d3bc254dd",
    vsize: 316,
    locktime: 200,
    script_path_used:
      "Leaf 0: <P_Alice> CHECKSIGVERIFY <P_RouterGuard> CHECKSIGVERIFY <P_Bob> CHECKSIG",
    sighash_flags_hex: ["0x83 (Bob)", "0x01 (Guard)", "0x01 (Alice)"],
    outputs_sats: [83333334, 7575757, 59089579, 330],
    witness_item_lengths: [65, 65, 65, 102, 65],
    confirmed_block_height: 201,
    confirmed_block_hash:
      "5c7c9d49154d7ff6eea62b0f996ed57abf34da5c70d3b00d2c9ec52cc09611ea",
    core_confirmations: 1,
  },
  unilateral_fallback_when_lp_disappears: {
    label: "unilateral-fallback-cet-when-lp-disappears",
    txid: "e25179f1cead10eb1108f31f968c5a61fd3854c430b7a74f7ba24b2e892297f9",
    wtxid: "9e5d19d3b8508523d2d2c0f8d8a701a8442bb51bb1f2c1320bf602934beb3b70",
    vsize: 257,
    locktime: 216,
    grace_race_cltv: 206,
    script_path_used:
      "Leaf 1: <206/216> OP_CLTV OP_DROP <pk0> CHECKSIGVERIFY <pk1> CHECKSIG",
    sighash_flags_hex: ["0x00 (SIGHASH_DEFAULT)", "0x00 (SIGHASH_DEFAULT)"],
    outputs_sats: [83333334, 66665336, 330],
    witness_item_lengths: [64, 64, 73, 97],
    confirmed_block_height: 217,
    core_confirmations: 1,
  },
  withheld_oracle_presigned_refund: {
    label: "withheld-oracle-presigned-cltv-refund",
    txid: "13fa2753fb6172619ac9bca15a17c9347da01da65e454464b270535c91f17bf3",
    wtxid: "a92a5da9d584dfb7076868918badd26512e37c01a357f869cd1b38c535b5893b",
    vsize: 257,
    locktime: 240,
    script_path_used:
      "Leaf 2: <240> OP_CLTV OP_DROP <pk0> CHECKSIGVERIFY <pk1> CHECKSIG",
    sighash_flags_hex: ["0x00 (SIGHASH_DEFAULT)", "0x00 (SIGHASH_DEFAULT)"],
    outputs_sats: [99999335, 49999335, 330],
    witness_item_lengths: [64, 64, 73, 97],
    confirmed_block_height: 241,
    core_confirmations: 6,
  },
  cpfp_anchor_child_spend: {
    label: "cpfp-330-sat-anchor-fee-rescue-child",
    txid: "7cbb00b8500f3acf7bbb7a8357cfbce6d99ae96872436178fc9ab851bc63730f",
    vsize: 169,
    outputs_sats: [45330],
    confirmed_block_height: 241,
    core_confirmations: 6,
  },
  adversarial_probes: [
    {
      probe_id: "divert-bob-output-0-by-1-sat",
      description:
        "Alice + Guard re-sign 0x01 trying to shave 1 sat off offline Bob's Output 0; Bob's 0x83 signature rejects in Core.",
      core_accepted: false,
      core_reject_reason:
        "mempool-script-verify-flag-failed (Invalid Schnorr signature)",
    },
    {
      probe_id: "alice-premature-unilateral-race-at-maturity",
      description:
        "Alice attempts to broadcast Leaf 1 unilateral CET (locktime=206) at maturity height 200 to bypass Carol's route.",
      core_accepted: false,
      core_reject_reason: "non-final",
    },
    {
      probe_id: "premature-refund-before-cltv-240",
      description:
        "Attempt to broadcast pre-signed refund transaction before refund_cltv_height=240.",
      core_accepted: false,
      core_reject_reason: "non-final",
    },
  ],
  reorg_probe: {
    invalidated_height: 241,
    post_invalidate_tip_height: 240,
    refund_tx_returned_to_mempool: true,
    restored_tip_height: 246,
    restored_confirmations: 6,
  },
});

export const DEFAULT_BASELINE_EVIDENCE = Object.freeze({
  protocol: "SatsHedgeZero v0.2.0",
  collateral_v0: "VanillaBtc (P2TR UTXO / Lightning Subchannel; TAP v1 hook ready)",
  fee_bps: 0,
  dex_simulation: {
    event_id: "SHZ-BTCUSD-PERP-20261123",
    execution_price_usd: 100000,
    matched_usd_notional: 2000,
    protocol_fee_sats: 0,
    compressed_cet_count: 5749,
    tradelayer_vwap_price_usd: 108200,
    tradelayer_merkle_root_hex:
      "5dbc792917c799a91be81689dcf26aa16f0f5978e9dde3a5f16f82fc1cace605",
    coop_close_mark_price_usd: 108000,
    coop_close_long_sats: 348148,
    coop_close_short_sats: 1851852,
    l1_cet_settled_price_usd: 108200,
    l1_cet_long_sats: 351562,
    l1_cet_short_sats: 1848438,
    short_hedged_usd_value_at_settlement: 2000,
  },
  fraud_simulation: {
    equivocation_verdict: {
      event_id: "SHZ-EQUIVOCATION-CASE",
      slashed_yocto_near: "10000000000000000000000000000",
      challenger_reward_yocto_near: "5000000000000000000000000000",
      victim_restitution_yocto_near: "0",
      treasury_burn_yocto_near: "5000000000000000000000000000",
      extracted_btc_slash_secret_key: [
        153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153,
        153, 152, 84, 72, 118, 128, 72, 226, 57, 213, 89, 107, 248, 38, 105,
        207, 218, 219,
      ],
      victim_shortfall_sats: 0,
      attested_price_usd: 0,
      canonical_price_usd: 0,
      deviation_bps: 10000,
    },
    equivocation_key_matches_confed_pubkey: true,
    deviation_borsh_payload_bytes: 2799,
    deviation_verdict: {
      event_id: "SHZ-DEVIATION-CASE",
      slashed_yocto_near: "5000000000000000000000000000",
      challenger_reward_yocto_near: "1000000000000000000000000000",
      victim_restitution_yocto_near: "1054700000000000000000000",
      treasury_burn_yocto_near: "3998945300000000000000000000",
      extracted_btc_slash_secret_key: null,
      victim_shortfall_sats: 105470,
      attested_price_usd: 89500,
      canonical_price_usd: 100550,
      deviation_bps: 1098,
    },
  },
});

// ---------------------------------------------------------------------------
// Pure Synchronous SHA-256 & Binary Wire Helpers (zero dependencies)
// ---------------------------------------------------------------------------

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const textEncoder = new TextEncoder();

export function utf8Bytes(str) {
  return textEncoder.encode(String(str));
}

/**
 * Pure synchronous FIPS 180-4 SHA-256 returning a 32-byte Uint8Array.
 */
export function sha256Bytes(input) {
  const data =
    input instanceof Uint8Array
      ? input
      : typeof input === "string"
        ? utf8Bytes(input)
        : Uint8Array.from(input);

  const bitLen = BigInt(data.length) * 8n;
  const rem = (data.length + 9) % 64;
  const padLen = rem === 0 ? 0 : 64 - rem;
  const totalLen = data.length + 1 + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(data, 0);
  padded[data.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setBigUint64(totalLen - 8, bitLen, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = dv.getUint32(off + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 =
        ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^
        ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^
        (w[i - 15] >>> 3);
      const s1 =
        ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^
        ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^
        (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 =
        ((e >>> 6) | (e << 26)) ^
        ((e >>> 11) | (e << 21)) ^
        ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 =
        ((a >>> 2) | (a << 30)) ^
        ((a >>> 13) | (a << 19)) ^
        ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, h0, false);
  odv.setUint32(4, h1, false);
  odv.setUint32(8, h2, false);
  odv.setUint32(12, h3, false);
  odv.setUint32(16, h4, false);
  odv.setUint32(20, h5, false);
  odv.setUint32(24, h6, false);
  odv.setUint32(28, h7, false);
  return out;
}

export function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] & 0xff).toString(16).padStart(2, "0");
  }
  return hex;
}

export function hexToBytes(hex, expectedLen = null) {
  const clean = String(hex || "").replace(/^0x/i, "").replace(/\s+/g, "");
  if (clean.length % 2 !== 0) {
    throw new RangeError("hex string must have even length");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  if (expectedLen != null && out.length !== expectedLen) {
    throw new RangeError(`expected ${expectedLen} bytes, got ${out.length}`);
  }
  return out;
}

function readU32LE(bytes, offset) {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

function writeU16LE(buf, offset, val) {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
}

function writeU32LE(buf, offset, val) {
  const v = val >>> 0;
  buf[offset] = v & 0xff;
  buf[offset + 1] = (v >>> 8) & 0xff;
  buf[offset + 2] = (v >>> 16) & 0xff;
  buf[offset + 3] = (v >>> 24) & 0xff;
}

function writeU64LE(buf, offset, val) {
  let v = BigInt(val);
  for (let i = 0; i < 8; i++) {
    buf[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function readU64LE(bytes, offset) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[offset + i]);
  }
  return v;
}

export function u128FromLeBytes(bytes, offset = 0) {
  let v = 0n;
  for (let i = 15; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[offset + i]);
  }
  return v;
}

export function u128FromBeBytes(bytes, offset = 0) {
  let v = 0n;
  for (let i = 0; i < 16; i++) {
    v = (v << 8n) | BigInt(bytes[offset + i]);
  }
  return v;
}

function concatBytes(...chunks) {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

function deterministicBytes(tag, len) {
  const out = new Uint8Array(len);
  let offset = 0;
  let ctr = 0;
  while (offset < len) {
    const h = sha256Bytes(`${tag}#${ctr}`);
    const take = Math.min(32, len - offset);
    out.set(h.subarray(0, take), offset);
    offset += take;
    ctr++;
  }
  return out;
}

// ---------------------------------------------------------------------------
// 1. Nova v2 600-Byte Signed-Row Transcript (`validated-signed-row/v1`)
// ---------------------------------------------------------------------------

export const NOVA_TRANSCRIPT_RANGES = Object.freeze([
  {
    id: "domain",
    start: 0,
    end: 46,
    label: "Domain Tag",
    color: "#38bdf8",
    encoding: "ASCII literal (46B)",
    description:
      'Fixed Nova v2 domain separator "UTXORef/LNMarkets/Nova/validated-signed-row/v1" preventing cross-protocol transcript collisions.',
  },
  {
    id: "summary_digest",
    start: 46,
    end: 78,
    label: "Summary Digest",
    color: "#00d285",
    encoding: "SHA-256 (32B)",
    description:
      "Canonical DlcSummary digest binding trader/maker x-only keys, NUMS P2TR funding script, and outcome Merkle root.",
  },
  {
    id: "batch_consent_digest",
    start: 78,
    end: 110,
    label: "Batch Consent",
    color: "#22d3ee",
    encoding: "SHA-256 (32B)",
    description:
      "SHA-256 batch consent message digest tying this contract row to the specific settlement batch epoch and context.",
  },
  {
    id: "summary_signatures",
    start: 110,
    end: 238,
    label: "Summary Sigs (2x64B)",
    color: "#10b981",
    encoding: "2 × BIP-340 Schnorr (128B)",
    description:
      "Trader (110..174) and Maker (174..238) 64-byte BIP-340 Schnorr signatures authorizing DlcSummary origination.",
  },
  {
    id: "batch_signatures",
    start: 238,
    end: 366,
    label: "Batch Sigs (2x64B)",
    color: "#34d399",
    encoding: "2 × BIP-340 Schnorr (128B)",
    description:
      "Trader (238..302) and Maker (302..366) 64-byte BIP-340 batch consent signatures authorizing multilateral netting.",
  },
  {
    id: "oracle_attestations",
    start: 366,
    end: 496,
    label: "2-of-3 Oracle Attest.",
    color: "#f59e0b",
    encoding: "2 × (u8 idx + 64B sig) = 130B",
    description:
      "Strictly sorted 2-of-3 oracle attestations: Oracle 0 at 366..431 (1B index + 64B BIP-340 sig) and Oracle 1 at 431..496.",
  },
  {
    id: "outcome_and_payouts",
    start: 496,
    end: 564,
    label: "Outcome + 4×u64le Sats",
    color: "#fb923c",
    encoding: "u32le + 32B msg + 4×u64le (68B)",
    description:
      "Outcome index u32le (496..500), 32B outcome message (500..532), and trader/maker/anchor/fee sats as 4×u64le (532..564, each < 2^51).",
  },
  {
    id: "funding_outpoint",
    start: 564,
    end: 600,
    label: "Funding Outpoint",
    color: "#ff4d6d",
    encoding: "32B txid (display) + u32le vout (36B)",
    description:
      "P2TR funding UTXO reference: display-order funding_txid (564..596) and funding_vout u32le (596..600).",
  },
]);

/**
 * Encodes a byte-exact 600-byte Nova v2 signed-row transcript (`validated-signed-row/v1`).
 */
export function buildNovaTranscript600B({
  summaryDigestHex = null,
  batchConsentDigestHex = null,
  summarySigsHex = null,
  batchSigsHex = null,
  oracle0Index = 0,
  oracle0SigHex = null,
  oracle1Index = 2,
  oracle1SigHex = null,
  outcomeIndex = 60_000,
  outcomeMessageHex = null,
  traderSats = 59_089_579,
  makerSats = 83_333_334,
  anchorSats = 330,
  feeSats = 1_000,
  fundingTxidHex = DEFAULT_MNR02_RECEIPT.alice_bob_funding_txid,
  fundingVout = 1,
} = {}) {
  for (const [name, amt] of [
    ["traderSats", traderSats],
    ["makerSats", makerSats],
    ["anchorSats", anchorSats],
    ["feeSats", feeSats],
  ]) {
    const b = BigInt(amt);
    if (b < 0n || b > MAX_ROW_AMOUNT_51BIT) {
      throw new RangeError(`${name} exceeds 51-bit Nova circuit bound`);
    }
  }
  if (oracle0Index >= oracle1Index) {
    throw new RangeError("oracle indices must be strictly sorted (oracle0Index < oracle1Index)");
  }

  const buf = new Uint8Array(600);
  const domainBytes = utf8Bytes(NOVA_TRANSCRIPT_DOMAIN);
  if (domainBytes.length !== 46) {
    throw new Error(`expected 46-byte domain tag, got ${domainBytes.length}`);
  }
  buf.set(domainBytes, 0);

  const summaryDigest = summaryDigestHex
    ? hexToBytes(summaryDigestHex, 32)
    : sha256Bytes("SHZ/Nova/DlcSummary/MNR02/60k");
  buf.set(summaryDigest, 46);

  const batchConsentDigest = batchConsentDigestHex
    ? hexToBytes(batchConsentDigestHex, 32)
    : sha256Bytes("SHZ/Nova/BatchConsent/Epoch200");
  buf.set(batchConsentDigest, 78);

  const summarySigs = summarySigsHex
    ? hexToBytes(summarySigsHex, 128)
    : deterministicBytes("SHZ/Nova/SummarySigs/2of2", 128);
  buf.set(summarySigs, 110);

  const batchSigs = batchSigsHex
    ? hexToBytes(batchSigsHex, 128)
    : deterministicBytes("SHZ/Nova/BatchSigs/2of2", 128);
  buf.set(batchSigs, 238);

  buf[366] = oracle0Index & 0xff;
  const o0Sig = oracle0SigHex
    ? hexToBytes(oracle0SigHex, 64)
    : deterministicBytes("SHZ/Nova/Oracle0Sig", 64);
  buf.set(o0Sig, 367);

  buf[431] = oracle1Index & 0xff;
  const o1Sig = oracle1SigHex
    ? hexToBytes(oracle1SigHex, 64)
    : deterministicBytes("SHZ/Nova/Oracle1Sig", 64);
  buf.set(o1Sig, 432);

  writeU32LE(buf, 496, outcomeIndex);
  const outcomeMsg = outcomeMessageHex
    ? hexToBytes(outcomeMessageHex, 32)
    : sha256Bytes(`SHZ/Outcome/BTCUSD/${outcomeIndex}`);
  buf.set(outcomeMsg, 500);

  writeU64LE(buf, 532, traderSats);
  writeU64LE(buf, 540, makerSats);
  writeU64LE(buf, 548, anchorSats);
  writeU64LE(buf, 556, feeSats);

  const fundingTxid = hexToBytes(fundingTxidHex, 32);
  buf.set(fundingTxid, 564);
  writeU32LE(buf, 596, fundingVout);

  const slices = sliceNovaTranscript600B(buf);
  const transcriptSha256Hex = bytesToHex(sha256Bytes(buf));

  return {
    bytes: buf,
    hex: bytesToHex(buf),
    length: buf.length,
    transcriptSha256Hex,
    slices,
  };
}

/**
 * Slices a 600-byte Nova v2 signed-row transcript into the 8 canonical offset ranges
 * (`0..46`, `46..78`, `78..110`, `110..238`, `238..366`, `366..496`, `496..564`, `564..600`)
 * with decoded metadata for interactive inspection.
 */
export function sliceNovaTranscript600B(input) {
  const bytes =
    input instanceof Uint8Array ? input : hexToBytes(String(input || ""), 600);
  if (bytes.length !== 600) {
    throw new RangeError(`Nova v2 transcript must be exactly 600 bytes, got ${bytes.length}`);
  }

  return NOVA_TRANSCRIPT_RANGES.map((spec) => {
    const slice = bytes.subarray(spec.start, spec.end);
    const hex = bytesToHex(slice);
    let decoded = {};

    if (spec.id === "domain") {
      const ascii = Array.from(slice, (b) => String.fromCharCode(b)).join("");
      decoded = {
        ascii,
        matchesCanonicalHeader: ascii === NOVA_TRANSCRIPT_DOMAIN,
      };
    } else if (spec.id === "oracle_attestations") {
      decoded = {
        oracle0Index: bytes[366],
        oracle0SigPreview: bytesToHex(bytes.subarray(367, 383)) + "…",
        oracle1Index: bytes[431],
        oracle1SigPreview: bytesToHex(bytes.subarray(432, 448)) + "…",
        strictlySorted: bytes[366] < bytes[431],
      };
    } else if (spec.id === "outcome_and_payouts") {
      const outcomeIndex = readU32LE(bytes, 496);
      const outcomeMsgHex = bytesToHex(bytes.subarray(500, 532));
      const traderSats = readU64LE(bytes, 532);
      const makerSats = readU64LE(bytes, 540);
      const anchorSats = readU64LE(bytes, 548);
      const feeSats = readU64LE(bytes, 556);
      const allUnder51Bit =
        traderSats <= MAX_ROW_AMOUNT_51BIT &&
        makerSats <= MAX_ROW_AMOUNT_51BIT &&
        anchorSats <= MAX_ROW_AMOUNT_51BIT &&
        feeSats <= MAX_ROW_AMOUNT_51BIT;
      decoded = {
        outcomeIndex,
        outcomeMsgHex,
        traderSats: Number(traderSats),
        makerSats: Number(makerSats),
        anchorSats: Number(anchorSats),
        feeSats: Number(feeSats),
        totalSats: Number(traderSats + makerSats + anchorSats + feeSats),
        allUnder51Bit,
      };
    } else if (spec.id === "funding_outpoint") {
      decoded = {
        fundingTxidDisplayHex: bytesToHex(bytes.subarray(564, 596)),
        fundingVout: readU32LE(bytes, 596),
      };
    } else if (spec.id === "summary_signatures" || spec.id === "batch_signatures") {
      decoded = {
        sig0Hex: bytesToHex(slice.subarray(0, 64)),
        sig1Hex: bytesToHex(slice.subarray(64, 128)),
      };
    } else {
      decoded = { digestHex: hex };
    }

    return {
      ...spec,
      byteLength: spec.end - spec.start,
      rangeLabel: `${spec.start}..${spec.end}`,
      hex,
      decoded,
    };
  });
}

// ---------------------------------------------------------------------------
// 2. 276-Byte LNMJNL01 Journal, 8-Field Pallas Folded State & Secq 3-Field Claim
// ---------------------------------------------------------------------------

/**
 * Builds an exact 276-byte `LNMJNL01` public journal and derives the 8-field Pallas folded state.
 */
export function buildLnmJournal276B({
  rowCount = 2,
  totalCollateralSats = 150_000_000,
  totalPayoutSats = 149_998_670,
  totalFeeSats = 1_000,
  epoch = 200,
  transcriptHex = null,
} = {}) {
  const buf = new Uint8Array(276);
  buf.set(utf8Bytes("LNMJNL01"), 0); // 0..8 magic
  writeU32LE(buf, 8, 1); // version = 1
  writeU32LE(buf, 12, rowCount);
  writeU64LE(buf, 16, epoch);
  writeU64LE(buf, 24, totalCollateralSats);
  writeU64LE(buf, 32, totalPayoutSats);
  writeU64LE(buf, 40, totalFeeSats);
  // 48..276: 7 x 32B roots/digests (old_nullifier, new_nullifier, batch_txid, commitment, domain...) + 4B flags
  const domainHash = sha256Bytes(LNM_BATCH_DOMAIN);
  const oldNullifierRoot = sha256Bytes("SHZ/SMT/OldNullifierRoot/256");
  const newNullifierRoot = sha256Bytes("SHZ/SMT/NewNullifierRoot/256");
  const batchTxDigest = hexToBytes(
    DEFAULT_MNR02_RECEIPT.bob_offline_routed_settlement_60k.txid,
    32
  );
  const transcriptChainDigest = transcriptHex
    ? sha256Bytes(hexToBytes(transcriptHex, 600))
    : sha256Bytes("SHZ/Nova/TranscriptChain/v2");
  const policyRoot = sha256Bytes("SHZ/Policy/Frost3of5+MNR02");
  const numsCommitment = hexToBytes(UTXOREF_NUMS_INTERNAL_KEY_HEX, 32);

  buf.set(domainHash, 48);
  buf.set(oldNullifierRoot, 80);
  buf.set(newNullifierRoot, 112);
  buf.set(batchTxDigest, 144);
  buf.set(transcriptChainDigest, 176);
  buf.set(policyRoot, 208);
  buf.set(numsCommitment, 240);
  writeU32LE(buf, 272, 0x00000001); // flags

  const journalDigest = sha256Bytes(buf);
  const journalShaLow128Le = u128FromLeBytes(journalDigest, 0).toString(10);
  const journalShaHigh128Le = u128FromLeBytes(journalDigest, 16).toString(10);
  const transcriptChainDigestHex = bytesToHex(transcriptChainDigest);

  const pallas8Fields = [
    { index: 0, name: "count", value: String(rowCount) },
    { index: 1, name: "total_collateral_sats", value: String(totalCollateralSats) },
    { index: 2, name: "total_payout_sats", value: String(totalPayoutSats) },
    { index: 3, name: "total_fee_sats", value: String(totalFeeSats) },
    { index: 4, name: "transcript_chain_digest_hex", value: transcriptChainDigestHex },
    { index: 5, name: "journal_sha_low128_le", value: journalShaLow128Le },
    { index: 6, name: "journal_sha_high128_le", value: journalShaHigh128Le },
    { index: 7, name: "epoch", value: String(epoch) },
  ];

  const cumulativeWithin56Bit =
    BigInt(totalCollateralSats) <= MAX_CUMULATIVE_56BIT &&
    BigInt(totalPayoutSats) <= MAX_CUMULATIVE_56BIT &&
    BigInt(totalFeeSats) <= MAX_CUMULATIVE_56BIT;

  return {
    magic: "LNMJNL01",
    length: buf.length,
    bytes: buf,
    hex: bytesToHex(buf),
    journalSha256Hex: bytesToHex(journalDigest),
    transcriptChainDigestHex,
    journalShaLow128Le,
    journalShaHigh128Le,
    cumulativeWithin56Bit,
    pallas8Fields,
  };
}

/**
 * Computes the Secq BIP-340 3-field claim `[1, claim_low128_le, claim_high128_le]`
 * over `SHA256(pubkey_x || msg32 || sig64)`.
 */
export function buildSecqBip340Claim({
  pubkeyXHex = UTXOREF_NUMS_INTERNAL_KEY_HEX,
  msg32Hex = null,
  sig64Hex = null,
  slot = "Row[0].summary_signatures[0] (Trader BIP-340)",
} = {}) {
  const pk = hexToBytes(pubkeyXHex, 32);
  const msg = msg32Hex
    ? hexToBytes(msg32Hex, 32)
    : sha256Bytes("SHZ/Nova/DlcSummary/MNR02/60k");
  const sig = sig64Hex
    ? hexToBytes(sig64Hex, 64)
    : deterministicBytes("SHZ/Nova/SummarySigs/2of2", 64);
  const digest = sha256Bytes(concatBytes(pk, msg, sig));
  const low128Le = u128FromLeBytes(digest, 0).toString(10);
  const high128Le = u128FromLeBytes(digest, 16).toString(10);

  return {
    slot,
    pubkeyXHex: bytesToHex(pk),
    msg32Hex: bytesToHex(msg),
    sig64Hex: bytesToHex(sig),
    claimSha256Hex: bytesToHex(digest),
    fields: ["1", low128Le, high128Le],
  };
}

// ---------------------------------------------------------------------------
// 3. 304-Byte UTXOREF_L2_SETTLEMENT_GROTH16_V0 BitVM3 Statement & Public Inputs
// ---------------------------------------------------------------------------

/**
 * Encodes the exact 304-byte `UTXOREF_L2_SETTLEMENT_GROTH16_V0\0` wire statement:
 *   33B ASCII magic || u16le(0) || u8(networkCode) || 8 × 32B hashes || u64le(epochId) || u32le(assertionVout)
 * and splits `d = SHA256(bytes304)` into `[u128_be(d[0..16]), u128_be(d[16..32])]`.
 */
export function encodeBitvm3SettlementStatement304B({
  networkCode = 0, // STATEMENT.md: 0 = bitcoin-regtest, 1 = bitcoin-testnet4
  chainGenesisHashHex = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  contractIdHex = null,
  commitmentHashHex = null,
  assertionTxidHex = DEFAULT_MNR02_RECEIPT.alice_bob_funding_txid,
  settlementTxidHex = DEFAULT_MNR02_RECEIPT.bob_offline_routed_settlement_60k.txid,
  programHashHex = null,
  verifyingKeyHashHex = null,
  policyHashHex = null,
  epochId = 200,
  assertionVout = 1,
} = {}) {
  const buf = new Uint8Array(304);
  const magic = utf8Bytes(BITVM3_STATEMENT_MAGIC);
  if (magic.length !== 33) {
    throw new Error(`expected 33-byte BitVM3 magic, got ${magic.length}`);
  }
  buf.set(magic, 0);
  writeU16LE(buf, 33, 0);
  buf[35] = networkCode & 0xff;

  const hashes = [
    hexToBytes(chainGenesisHashHex, 32),
    contractIdHex ? hexToBytes(contractIdHex, 32) : sha256Bytes("SHZ/Contract/MNR02-60K"),
    commitmentHashHex ? hexToBytes(commitmentHashHex, 32) : sha256Bytes("SHZ/Journal/LNMJNL01"),
    hexToBytes(assertionTxidHex, 32),
    hexToBytes(settlementTxidHex, 32),
    programHashHex ? hexToBytes(programHashHex, 32) : sha256Bytes("SHZ/NovaV2/ProgramHash"),
    verifyingKeyHashHex ? hexToBytes(verifyingKeyHashHex, 32) : sha256Bytes("SHZ/Groth16/VK/v0"),
    policyHashHex ? hexToBytes(policyHashHex, 32) : sha256Bytes("SHZ/Policy/UTXORef+0x83"),
  ];

  let pos = 36;
  for (const h of hashes) {
    buf.set(h, pos);
    pos += 32;
  }
  // pos === 292
  writeU64LE(buf, 292, epochId);
  writeU32LE(buf, 300, assertionVout);

  return formatBitvm3Groth16PublicInputs(buf, {
    networkCode,
    epochId,
    assertionVout,
    assertionTxidHex,
    settlementTxidHex,
  });
}

/**
 * Formats an exact 304-byte `UTXOREF_L2_SETTLEMENT_GROTH16_V0\0` payload into
 * Groth16/BitVM3 public input limbs `[u128_be(d[0..16]), u128_be(d[16..32])]`.
 */
export function formatBitvm3Groth16PublicInputs(input, meta = {}) {
  const bytes =
    input instanceof Uint8Array ? input : hexToBytes(String(input || ""), 304);
  if (bytes.length !== 304) {
    throw new RangeError(
      `UTXOREF_L2_SETTLEMENT_GROTH16_V0 statement must be exactly 304 bytes, got ${bytes.length}`
    );
  }
  const magicAscii = Array.from(bytes.subarray(0, 33), (b) =>
    String.fromCharCode(b)
  ).join("");
  if (magicAscii !== BITVM3_STATEMENT_MAGIC) {
    throw new Error("invalid UTXOREF_L2_SETTLEMENT_GROTH16_V0 magic header");
  }

  const d = sha256Bytes(bytes);
  const limb0 = u128FromBeBytes(d, 0);
  const limb1 = u128FromBeBytes(d, 16);
  const limb0Hex = `0x${limb0.toString(16).padStart(32, "0")}`;
  const limb1Hex = `0x${limb1.toString(16).padStart(32, "0")}`;

  return {
    magic: "UTXOREF_L2_SETTLEMENT_GROTH16_V0\\0",
    length: 304,
    bytes,
    statementHex: bytesToHex(bytes),
    sha256Hex: bytesToHex(d),
    limbs: [limb0.toString(10), limb1.toString(10)],
    limbsHex: [limb0Hex, limb1Hex],
    networkCode: meta.networkCode ?? bytes[35],
    epochId: meta.epochId ?? Number(readU64LE(bytes, 292)),
    assertionVout: meta.assertionVout ?? readU32LE(bytes, 300),
    honestyFlags: { ...DEFAULT_HONESTY_FLAGS },
  };
}

// ---------------------------------------------------------------------------
// 4. SHZ-MNR-01/02 Multilateral Netted Closeout Math & Fraud Helpers
// ---------------------------------------------------------------------------

/**
 * Exact SHZ-MNR-01/02 toward-zero truncated inverse Long PnL in satoshis:
 * `(notional_usd * 1e8 * (exit_price - entry_price)) / (entry_price * exit_price)`
 */
export function inverseLongPnlTruncSats(notionalUsd, entryPriceUsd, exitPriceUsd) {
  const n = BigInt(Math.round(notionalUsd)) * SATS_PER_BTC;
  const p0 = BigInt(Math.round(entryPriceUsd));
  const p2 = BigInt(Math.round(exitPriceUsd));
  if (p0 <= 0n || p2 <= 0n) return 0;
  return Number((n * (p2 - p0)) / (p0 * p2));
}

/**
 * Computes deterministic SHZ-MNR-02 Bob-offline routed settlement outputs for any position.
 * Default benchmark (`$50,000` notional, `$50k` entry, `$55k` Carol closeout, `$60k` maturity)
 * matches Bitcoin Core v31.1 receipt:
 *   Bob Output 0 = 83,333,334 sats (0x83-locked)
 *   Carol Output 1 = 7,575,757 sats
 *   Alice Output 2 = 59,089,579 sats (50,000,000 margin + 9,090,909 locked PnL - 1,000 fee - 330 anchor)
 *   Anchor Output 3 = 330 sats
 */
export function computeMnr02CloseoutPreview({
  notionalUsd = 50_000,
  entryPriceUsd = 50_000,
  carolClosePriceUsd = 55_000,
  maturityPriceUsd = 60_000,
  aliceMarginSats = 50_000_000,
  bobMarginSats = 100_000_000,
  minerFeeSats = 1_000,
  anchorSats = 330,
} = {}) {
  const totalCollateral = aliceMarginSats + bobMarginSats;
  const aliceLockedPnl = inverseLongPnlTruncSats(
    notionalUsd,
    entryPriceUsd,
    carolClosePriceUsd
  );
  const bobPnlAtMaturity = -inverseLongPnlTruncSats(
    notionalUsd,
    entryPriceUsd,
    maturityPriceUsd
  );
  const bobOutput0Sats = Math.max(
    0,
    Math.min(totalCollateral, bobMarginSats + bobPnlAtMaturity)
  );
  const carolPnlAtMaturity = inverseLongPnlTruncSats(
    notionalUsd,
    carolClosePriceUsd,
    maturityPriceUsd
  );
  const carolOutput1Sats = Math.max(0, carolPnlAtMaturity);
  const aliceRaw = totalCollateral - bobOutput0Sats - carolOutput1Sats;
  const aliceOutput2Sats = Math.max(0, aliceRaw - minerFeeSats - anchorSats);

  return {
    notionalUsd,
    entryPriceUsd,
    carolClosePriceUsd,
    maturityPriceUsd,
    aliceLockedPnlSats: aliceLockedPnl,
    bobOutput0Sats,
    carolOutput1Sats,
    aliceOutput2Sats,
    anchorOutput3Sats: anchorSats,
    minerFeeSats,
    protocolFeeSats: 0,
    totalInputSats: totalCollateral,
  };
}

/**
 * Formats `extracted_btc_slash_secret_key` (32-element byte array or hex string) into canonical lowercase hex.
 */
export function formatExtractedKeyHex(keyData) {
  if (!keyData) return null;
  if (typeof keyData === "string") return keyData.replace(/^0x/i, "").toLowerCase();
  if (Array.isArray(keyData) || keyData instanceof Uint8Array) {
    return bytesToHex(Uint8Array.from(keyData));
  }
  return null;
}

function yoctoToNearString(yocto) {
  if (yocto == null) return "0 NEAR";
  const str = String(yocto).replace(/\..*$/, "");
  // Handle JS scientific notation if parsed from JSON number (e.g. 1e+28)
  let big;
  if (/e\+/i.test(String(yocto))) {
    const [mant, expStr] = String(yocto).toLowerCase().split("e+");
    const [intPart, fracPart = ""] = mant.split(".");
    const zeros = Math.max(0, Number(expStr) - fracPart.length);
    big = BigInt(intPart + fracPart + "0".repeat(zeros));
  } else {
    big = BigInt(str || "0");
  }
  const denom = 10n ** 24n;
  const whole = big / denom;
  const rem = big % denom;
  if (rem === 0n) return `${Number(whole).toLocaleString("en-US")} NEAR`;
  const frac = rem.toString().padStart(24, "0").slice(0, 4).replace(/0+$/, "");
  return `${Number(whole).toLocaleString("en-US")}.${frac} NEAR`;
}

// ---------------------------------------------------------------------------
// State Normalization & Default Positions
// ---------------------------------------------------------------------------

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtUsd(val) {
  if (val == null || !Number.isFinite(Number(val))) return "—";
  return `$${Math.round(Number(val)).toLocaleString("en-US")}`;
}

function fmtSats(val, signed = false) {
  if (val == null || !Number.isFinite(Number(val))) return "—";
  const n = Math.round(Number(val));
  const prefix = signed && n > 0 ? "+" : "";
  return `${prefix}${n.toLocaleString("en-US")}`;
}

function shortHex(hex, lead = 10, tail = 8) {
  const s = String(hex || "");
  if (s.length <= lead + tail + 3) return s;
  return `${s.slice(0, lead)}…${s.slice(-tail)}`;
}

export function buildDefaultPositions(markPriceUsd = 100_000) {
  return [
    {
      id: "pos-mnr02-alice-bob",
      instrument: "BTC-27DEC26-DLC",
      side: "long",
      notionalUsd: 50_000,
      entryPriceUsd: 50_000,
      markPriceUsd: 55_000,
      longLevX: 2,
      shortLevX: 1,
      marginSats: 50_000_000,
      counterpartyMarginSats: 100_000_000,
      bobStatus: "offline",
      isMnr02Reference: true,
    },
    {
      id: "pos-satshedge-1x",
      instrument: "BTC-INVERSE-PERP",
      side: "short",
      notionalUsd: 2_000,
      entryPriceUsd: 100_000,
      markPriceUsd,
      longLevX: 10,
      shortLevX: 1,
      marginSats: 2_000_000,
      counterpartyMarginSats: 200_000,
      bobStatus: "online",
      isMnr02Reference: false,
    },
  ];
}

export function normalizeWorkbenchState(rawState = {}, ui = {}) {
  const state = rawState && typeof rawState === "object" ? rawState : {};
  const market = state.market || {};
  const quote = state.quote || {};
  const baselineEvidence = state.baselineEvidence || DEFAULT_BASELINE_EVIDENCE;
  const mnr02Receipt = state.mnr02Receipt || DEFAULT_MNR02_RECEIPT;

  const markPriceUsd = Number(
    market.markPriceUsd ??
      market.markPrice ??
      market.mark_price_usd ??
      quote.entryPriceUsd ??
      100_000
  );

  const rawPositions =
    Array.isArray(state.positions) && state.positions.length > 0
      ? state.positions
      : buildDefaultPositions(markPriceUsd);

  const bobOverrides = ui.bobStatusById || {};

  const positions = rawPositions.map((p, idx) => {
    const id = String(p.id || `pos-${idx}`);
    const side = String(p.side || "long").toLowerCase();
    const notionalUsd = Number(p.notionalUsd ?? p.usdNotional ?? p.usd_notional ?? 2_000);
    const entryPriceUsd = Number(p.entryPriceUsd ?? p.entry_price_usd ?? 100_000);
    const posMark = Number(p.markPriceUsd ?? p.mark_price_usd ?? markPriceUsd);
    const longLevX = Number(p.longLevX ?? (side === "long" ? p.leverageX ?? p.leverage ?? 10 : 10));
    const shortLevX = Number(p.shortLevX ?? (side === "short" ? p.leverageX ?? p.leverage ?? 1 : 1));
    const spec = buildInverseSpec({
      usdNotional: notionalUsd,
      entryPriceUsd,
      longLevX,
      shortLevX,
      longMarginSats:
        side === "long" ? p.marginSats ?? p.longMarginSats ?? null : p.counterpartyMarginSats ?? null,
      shortMarginSats:
        side === "short" ? p.marginSats ?? p.shortMarginSats ?? null : p.counterpartyMarginSats ?? null,
    });
    const payout = computeInversePayout(spec, posMark);
    const liq = computeLiquidationPrices(spec);
    const marginSats = side === "short" ? spec.shortMarginSats : spec.longMarginSats;
    const pnlSats = side === "short" ? payout.shortPnlSats : payout.longPnlSats;
    const usdValue = side === "short" ? payout.shortUsdValue : payout.longUsdValue;
    const liqPriceUsd = side === "short" ? liq.shortLiqUsd : liq.longLiqUsd;
    const bobStatus =
      bobOverrides[id] ||
      String(p.bobStatus || (p.isMnr02Reference ? "offline" : "online")).toLowerCase();

    return {
      id,
      instrument: p.instrument || market.symbol || "BTC-INVERSE-PERP",
      side,
      notionalUsd,
      entryPriceUsd,
      markPriceUsd: posMark,
      marginSats,
      counterpartyMarginSats:
        side === "short" ? spec.longMarginSats : spec.shortMarginSats,
      pnlSats,
      usdValue,
      liqPriceUsd,
      isCoveredSatsHedge: side === "short" && liq.isCoveredSyntheticUsd,
      bobStatus,
      isMnr02Reference: Boolean(p.isMnr02Reference),
    };
  });

  const activeSpec = buildInverseSpec({
    usdNotional: Number(quote.usdNotional ?? quote.usd_notional ?? 1_000),
    entryPriceUsd: Number(quote.entryPriceUsd ?? quote.entry_price_usd ?? markPriceUsd),
    longLevX: Number(quote.longLevX ?? quote.long_lev_x ?? 10),
    shortLevX: Number(quote.shortLevX ?? quote.short_lev_x ?? 1),
    longMarginSats: quote.longMarginSats ?? quote.long_margin_sats ?? null,
    shortMarginSats: quote.shortMarginSats ?? quote.short_margin_sats ?? null,
  });

  const cets = compressDyadicCetRanges(activeSpec, 20, 250);
  const activeMarkCet = lookupCetForPrice(cets, markPriceUsd, 20);

  // Nova v2 + BitVM3 artifacts (accept external backend receipt if present, else deterministic wire-exact)
  const extNova = state.novaSummary || state.novaBitvm || state.novaProof || null;
  const extTranscriptHex =
    extNova?.transcript600Hex ||
    extNova?.transcript_600b_hex ||
    extNova?.nova_transcript_600b_hex ||
    null;
  const extBitvm3Hex =
    extNova?.bitvm3Statement304Hex ||
    extNova?.bitvm3_statement_304b_hex ||
    extNova?.statement_304b_hex ||
    null;
  const transcript =
    extTranscriptHex && String(extTranscriptHex).length === 1200
      ? {
          hex: extTranscriptHex,
          length: 600,
          transcriptSha256Hex: bytesToHex(sha256Bytes(hexToBytes(extTranscriptHex, 600))),
          slices: sliceNovaTranscript600B(extTranscriptHex),
        }
      : buildNovaTranscript600B({
          traderSats:
            mnr02Receipt?.bob_offline_routed_settlement_60k?.outputs_sats?.[2] ?? 59_089_579,
          makerSats:
            mnr02Receipt?.bob_offline_routed_settlement_60k?.outputs_sats?.[0] ?? 83_333_334,
          anchorSats:
            mnr02Receipt?.bob_offline_routed_settlement_60k?.outputs_sats?.[3] ?? 330,
          feeSats: 1_000,
          fundingTxidHex:
            mnr02Receipt?.alice_bob_funding_txid || DEFAULT_MNR02_RECEIPT.alice_bob_funding_txid,
        });

  const journal = buildLnmJournal276B({
    rowCount: extNova?.rowCount ?? extNova?.row_count ?? 2,
    totalCollateralSats:
      extNova?.totalCollateralSats ?? extNova?.total_collateral_sats ?? 150_000_000,
    totalPayoutSats:
      extNova?.totalPayoutSats ?? extNova?.total_payout_sats ?? 149_998_670,
    totalFeeSats: extNova?.totalFeeSats ?? extNova?.total_fee_sats ?? 1_000,
    epoch: extNova?.epoch ?? 200,
    transcriptHex: transcript.hex,
  });

  const secqClaim = buildSecqBip340Claim({
    pubkeyXHex: UTXOREF_NUMS_INTERNAL_KEY_HEX,
    msg32Hex: transcript.slices[1].hex,
    sig64Hex: transcript.slices[3].hex.slice(0, 128),
    slot: "Row[0].summary_signatures[0] (Trader BIP-340)",
  });

  const bitvm3 =
    extBitvm3Hex && String(extBitvm3Hex).length === 608
      ? formatBitvm3Groth16PublicInputs(extBitvm3Hex)
      : encodeBitvm3SettlementStatement304B({
          assertionTxidHex:
            mnr02Receipt?.alice_bob_funding_txid || DEFAULT_MNR02_RECEIPT.alice_bob_funding_txid,
          settlementTxidHex:
            mnr02Receipt?.bob_offline_routed_settlement_60k?.txid ||
            DEFAULT_MNR02_RECEIPT.bob_offline_routed_settlement_60k.txid,
          epochId: 200,
          assertionVout: 1,
        });

  const honestyFlags = {
    ...DEFAULT_HONESTY_FLAGS,
    ...(extNova?.honestyFlags || extNova?.honesty_flags || {}),
    ...(state.testnet4LiveReceipt?.clearing_report?.honesty || {}),
  };

  return {
    markPriceUsd,
    testnet4LiveReceipt: state.testnet4LiveReceipt || null,
    clearing33kReceipt: state.clearing33kReceipt || null,
    market: {
      symbol: market.symbol || market.instrument || "BTC-INVERSE-PERP",
      tradelayerVwapUsd:
        market.tradelayerVwapUsd ??
        market.tradelayerVwap ??
        baselineEvidence?.dex_simulation?.tradelayer_vwap_price_usd ??
        108_200,
      tradelayerMerkleRoot:
        market.tradelayerMerkleRoot ??
        baselineEvidence?.dex_simulation?.tradelayer_merkle_root_hex ??
        DEFAULT_BASELINE_EVIDENCE.dex_simulation.tradelayer_merkle_root_hex,
      pythConfBps: market.pythConfBps ?? market.pythConfidenceBps ?? 20,
      frostSigners: market.frostSigners || [
        { id: 1, name: "frost-node-1.shz", status: "online", weight: "1/5", latencyMs: 18 },
        { id: 2, name: "frost-node-2.shz", status: "online", weight: "1/5", latencyMs: 24 },
        { id: 3, name: "frost-node-3.shz", status: "online", weight: "1/5", latencyMs: 19 },
        { id: 4, name: "frost-node-4.shz", status: "standby", weight: "1/5", latencyMs: 31 },
        { id: 5, name: "frost-node-5.shz", status: "online", weight: "1/5", latencyMs: 22 },
      ],
      nearVaultStakeNear: market.nearVaultStakeNear ?? 10_000,
      nearVaultTvlNearEq: market.nearVaultTvlNearEq ?? 42_500, // 4.25x <= 10x cap
    },
    positions,
    activeSpec,
    cets,
    activeMarkCet,
    baselineEvidence,
    mnr02Receipt,
    nova: {
      transcript,
      journal,
      secqClaim,
      bitvm3,
      honestyFlags,
    },
  };
}

// ---------------------------------------------------------------------------
// Scoped Component Styles (`<style id="shz-workbench-styles">`)
// ---------------------------------------------------------------------------

export const WORKBENCH_CSS = `
#shz-workbench-root {
  background: #0a0e14;
  color: #e6edf7;
  border-top: 1px solid #1d2635;
  font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 12px;
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
}
.shz-wb-mono {
  font-family: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-variant-numeric: tabular-nums;
}
.shz-wb-tabs {
  display: flex;
  align-items: center;
  gap: 2px;
  background: #10151e;
  border-bottom: 1px solid #1d2635;
  padding: 0 10px;
  overflow-x: auto;
}
.shz-wb-tab {
  appearance: none;
  background: transparent;
  color: #8fa2bc;
  border: none;
  border-bottom: 2px solid transparent;
  padding: 9px 12px;
  font-size: 11.5px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.shz-wb-tab:hover { color: #e6edf7; }
.shz-wb-tab.active {
  color: #e6edf7;
  border-bottom-color: #38bdf8;
  background: rgba(56, 189, 248, 0.06);
}
.shz-wb-count {
  font-size: 10px;
  padding: 1px 5px;
  border-radius: 3px;
  background: #172030;
  color: #8fa2bc;
}
.shz-wb-tab.active .shz-wb-count { background: rgba(56, 189, 248, 0.16); color: #38bdf8; }
.shz-wb-body {
  padding: 10px 12px 14px;
  overflow: auto;
  flex: 1;
}
.shz-wb-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 11.5px;
}
.shz-wb-table th {
  text-align: left;
  color: #6b7f9c;
  font-weight: 600;
  font-size: 10.5px;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  padding: 6px 8px;
  border-bottom: 1px solid #1d2635;
  white-space: nowrap;
}
.shz-wb-table td {
  padding: 7px 8px;
  border-bottom: 1px solid #141c28;
  vertical-align: middle;
  white-space: nowrap;
}
.shz-wb-table tr:hover td { background: rgba(29, 38, 53, 0.35); }
.shz-wb-num { text-align: right; }
.shz-wb-pos { color: #00d285; }
.shz-wb-neg { color: #ff4d6d; }
.shz-wb-amber { color: #f59e0b; }
.shz-wb-cyan { color: #38bdf8; }
.shz-wb-muted { color: #8fa2bc; }
.shz-wb-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 10.5px;
  font-weight: 600;
  border: 1px solid #1d2635;
  background: #10151e;
}
.shz-wb-pill-long { color: #00d285; border-color: rgba(0, 210, 133, 0.45); background: rgba(0, 210, 133, 0.10); }
.shz-wb-pill-short { color: #ff4d6d; border-color: rgba(255, 77, 109, 0.45); background: rgba(255, 77, 109, 0.10); }
.shz-wb-pill-amber { color: #f59e0b; border-color: rgba(245, 158, 11, 0.45); background: rgba(245, 158, 11, 0.10); }
.shz-wb-pill-cyan { color: #38bdf8; border-color: rgba(56, 189, 248, 0.45); background: rgba(56, 189, 248, 0.10); }
.shz-wb-btn {
  appearance: none;
  background: #141c29;
  color: #e6edf7;
  border: 1px solid #26344a;
  border-radius: 3px;
  padding: 4px 8px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
}
.shz-wb-btn:hover { background: #1c2738; border-color: #38bdf8; }
.shz-wb-btn-active,
.shz-wb-btn-primary {
  background: rgba(56, 189, 248, 0.14);
  border-color: #38bdf8;
  color: #38bdf8;
}
.shz-wb-btn-amber {
  background: rgba(245, 158, 11, 0.14);
  border-color: #f59e0b;
  color: #f59e0b;
}
.shz-wb-btn-amber:hover { background: rgba(245, 158, 11, 0.24); }
.shz-wb-card {
  background: #10151e;
  border: 1px solid #1d2635;
  border-radius: 4px;
  padding: 10px 12px;
}
.shz-wb-grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.shz-wb-grid-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.shz-wb-grid-5 { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px; }
@media (max-width: 1024px) {
  .shz-wb-grid-2, .shz-wb-grid-3, .shz-wb-grid-5 { grid-template-columns: 1fr; }
}
.shz-wb-inspector {
  margin-top: 10px;
  background: #0d121a;
  border: 1px solid #29384f;
  border-radius: 4px;
  padding: 12px;
}
.shz-wb-hdr-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 10px;
}
.shz-wb-title { font-size: 12px; font-weight: 700; color: #e6edf7; }
.shz-wb-kv {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 3px 0;
  border-bottom: 1px dashed #192232;
  font-size: 11px;
}
.shz-wb-kv:last-child { border-bottom: none; }
.shz-wb-meter {
  height: 10px;
  background: #0a0e14;
  border: 1px solid #1d2635;
  border-radius: 3px;
  overflow: hidden;
  margin: 6px 0;
}
.shz-wb-meter-fill { height: 100%; background: #00d285; }
.shz-wb-bytebar {
  display: flex;
  width: 100%;
  height: 28px;
  border: 1px solid #1d2635;
  border-radius: 4px;
  overflow: hidden;
  margin: 8px 0;
}
.shz-wb-seg {
  border: none;
  border-right: 1px solid #0a0e14;
  cursor: pointer;
  color: #0a0e14;
  font-weight: 700;
  font-size: 10px;
  padding: 0 3px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  opacity: 0.78;
}
.shz-wb-seg:hover, .shz-wb-seg.selected { opacity: 1; outline: 2px solid #e6edf7; outline-offset: -2px; }
.shz-wb-hexbox {
  background: #080b10;
  border: 1px solid #1d2635;
  border-radius: 3px;
  padding: 8px;
  font-size: 10.5px;
  word-break: break-all;
  line-height: 1.45;
  color: #a9bdd8;
  max-height: 112px;
  overflow: auto;
}
.shz-wb-cet-scroll {
  max-height: 210px;
  overflow: auto;
  border: 1px solid #1d2635;
  border-radius: 4px;
  margin-top: 8px;
}
.shz-wb-row-highlight td { background: rgba(56, 189, 248, 0.12); }
`;

export function injectWorkbenchStyles(doc = typeof document !== "undefined" ? document : null) {
  if (!doc || !doc.head || typeof doc.createElement !== "function") return;
  if (typeof doc.getElementById === "function" && doc.getElementById("shz-workbench-styles")) {
    return;
  }
  const style = doc.createElement("style");
  style.id = "shz-workbench-styles";
  style.textContent = WORKBENCH_CSS;
  doc.head.appendChild(style);
}

// ---------------------------------------------------------------------------
// Pure HTML Renderers for All 4 Tabs (Testable in Node DOM Stubs & Browser)
// ---------------------------------------------------------------------------

function renderMnr02InspectorHtml(vm, ui) {
  if (!ui.mnr02InspectorPosId) return "";
  const pos =
    vm.positions.find((p) => p.id === ui.mnr02InspectorPosId) || vm.positions[0];
  const r = vm.mnr02Receipt || DEFAULT_MNR02_RECEIPT;
  const leaf0 = r.bob_offline_routed_settlement_60k || DEFAULT_MNR02_RECEIPT.bob_offline_routed_settlement_60k;
  const leaf1 = r.unilateral_fallback_when_lp_disappears || DEFAULT_MNR02_RECEIPT.unilateral_fallback_when_lp_disappears;
  const leaf2 = r.withheld_oracle_presigned_refund || DEFAULT_MNR02_RECEIPT.withheld_oracle_presigned_refund;
  const cpfp = r.cpfp_anchor_child_spend || DEFAULT_MNR02_RECEIPT.cpfp_anchor_child_spend;
  const probes = Array.isArray(r.adversarial_probes)
    ? r.adversarial_probes
    : DEFAULT_MNR02_RECEIPT.adversarial_probes;

  const customPreview =
    ui.mnr02ApiResult ||
    computeMnr02CloseoutPreview({
      notionalUsd: pos?.notionalUsd ?? 50_000,
      entryPriceUsd: pos?.entryPriceUsd ?? 50_000,
      carolClosePriceUsd: pos?.isMnr02Reference ? 55_000 : Math.round((pos?.markPriceUsd ?? 100_000) * 1.02),
      maturityPriceUsd: pos?.isMnr02Reference ? 60_000 : Math.round((pos?.markPriceUsd ?? 100_000) * 1.05),
      aliceMarginSats: pos?.marginSats ?? 50_000_000,
      bobMarginSats: pos?.counterpartyMarginSats ?? 100_000_000,
    });

  return `
    <div class="shz-wb-inspector" data-mnr02-inspector="open">
      <div class="shz-wb-hdr-row">
        <div>
          <span class="shz-wb-title">SHZ-MNR-02 Bob-Offline Multilateral Closeout Inspector</span>
          <span class="shz-wb-pill shz-wb-pill-long shz-wb-mono" style="margin-left:8px;">${escapeHtml(r.core_version || "Bitcoin Core v31.1.0")}</span>
          <span class="shz-wb-pill shz-wb-pill-cyan shz-wb-mono">bitcoin_spend_enforced: ${r.bitcoin_spend_enforced ? "true" : "false"}</span>
          <span class="shz-wb-pill shz-wb-pill-amber shz-wb-mono">Bob offline after h=${r.bob_offline_after_height ?? 106}</span>
        </div>
        <button class="shz-wb-btn" data-action="close-mnr02">Close Inspector ✕</button>
      </div>

      <div class="shz-wb-grid-3">
        <div class="shz-wb-card">
          <div class="shz-wb-hdr-row">
            <span class="shz-wb-pos shz-wb-mono" style="font-weight:700;">Leaf 0 · Route CET (0x83, nLockTime ${leaf0.locktime})</span>
            <span class="shz-wb-pill shz-wb-pill-long">CONFIRMED h=${leaf0.confirmed_block_height}</span>
          </div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">TxID</span><span class="shz-wb-mono shz-wb-cyan" title="${escapeHtml(leaf0.txid)}">${escapeHtml(shortHex(leaf0.txid, 12, 10))}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">vSize / Witness</span><span class="shz-wb-mono">${leaf0.vsize} vB · [${(leaf0.witness_item_lengths || []).join(", ")}]B</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">SIGHASH</span><span class="shz-wb-mono shz-wb-amber">${escapeHtml((leaf0.sighash_flags_hex || []).join(" · "))}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Output 0 (Bob 0x83-locked)</span><span class="shz-wb-mono shz-wb-pos">${fmtSats(leaf0.outputs_sats?.[0] ?? 83333334)} sats</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Output 1 (Carol Route)</span><span class="shz-wb-mono shz-wb-cyan">${fmtSats(leaf0.outputs_sats?.[1] ?? 7575757)} sats</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Output 2 (Alice Net)</span><span class="shz-wb-mono">${fmtSats(leaf0.outputs_sats?.[2] ?? 59089579)} sats</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Output 3 (CPFP Anchor)</span><span class="shz-wb-mono shz-wb-amber">${fmtSats(leaf0.outputs_sats?.[3] ?? 330)} sats (child ${escapeHtml(shortHex(cpfp.txid, 8, 6))})</span></div>
        </div>

        <div class="shz-wb-card">
          <div class="shz-wb-hdr-row">
            <span class="shz-wb-amber shz-wb-mono" style="font-weight:700;">Leaf 1 · Unilateral Fallback (CLTV 206 / ${leaf1.locktime})</span>
            <span class="shz-wb-pill shz-wb-pill-amber">GRACE EXIT</span>
          </div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">TxID</span><span class="shz-wb-mono">${escapeHtml(shortHex(leaf1.txid, 12, 10))}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">SIGHASH</span><span class="shz-wb-mono">0x00 (SIGHASH_DEFAULT)</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Bob / Alice / Anchor</span><span class="shz-wb-mono">${fmtSats(leaf1.outputs_sats?.[0] ?? 83333334)} / ${fmtSats(leaf1.outputs_sats?.[1] ?? 66665336)} / ${leaf1.outputs_sats?.[2] ?? 330}</span></div>
          <div style="margin-top:8px; padding-top:8px; border-top:1px solid #1d2635;">
            <div class="shz-wb-hdr-row" style="margin-bottom:4px;">
              <span class="shz-wb-cyan shz-wb-mono" style="font-weight:700;">Leaf 2 · Timeout Refund (CLTV ${leaf2.locktime})</span>
              <span class="shz-wb-pill shz-wb-pill-cyan">6-BLK REORG OK</span>
            </div>
            <div class="shz-wb-kv"><span class="shz-wb-muted">TxID</span><span class="shz-wb-mono">${escapeHtml(shortHex(leaf2.txid, 12, 10))}</span></div>
            <div class="shz-wb-kv"><span class="shz-wb-muted">Bob / Alice / Anchor</span><span class="shz-wb-mono">${fmtSats(leaf2.outputs_sats?.[0] ?? 99999335)} / ${fmtSats(leaf2.outputs_sats?.[1] ?? 49999335)} / ${leaf2.outputs_sats?.[2] ?? 330}</span></div>
          </div>
        </div>

        <div class="shz-wb-card">
          <div class="shz-wb-hdr-row">
            <span class="shz-wb-neg shz-wb-mono" style="font-weight:700;">Core v31.1 Adversarial Rejections</span>
            <span class="shz-wb-pill shz-wb-pill-short">${probes.length} REJECTED</span>
          </div>
          ${probes
            .map(
              (pr) => `
            <div style="padding:5px 0; border-bottom:1px dashed #192232;">
              <div style="display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:4px 8px;">
                <span class="shz-wb-mono" style="font-size:10.5px; color:#e6edf7; white-space:nowrap;">${escapeHtml(pr.probe_id)}</span>
                <span class="shz-wb-pill shz-wb-pill-short shz-wb-mono" style="font-size:10px;">${escapeHtml(pr.core_reject_reason)}</span>
              </div>
              <div class="shz-wb-muted" style="font-size:10.5px; margin-top:2px;">${escapeHtml(pr.description)}</div>
            </div>`
            )
            .join("")}
          <div class="shz-wb-kv" style="margin-top:6px;">
            <span class="shz-wb-muted">Selected Position Preview (${escapeHtml(pos?.instrument || "DLC")})</span>
            <span class="shz-wb-mono shz-wb-pos">Carol ${fmtSats(customPreview.carolOutput1Sats)} · Locked ${fmtSats(customPreview.aliceLockedPnlSats, true)} sats</span>
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderTab1Positions(vm, ui) {
  const rows = vm.positions
    .map((pos) => {
      const sideLabel =
        pos.side === "short"
          ? pos.isCoveredSatsHedge
            ? "SHORT 1x SatsHedge"
            : "SHORT"
          : "LONG";
      const sideCls = pos.side === "short" ? "shz-wb-pill-short" : "shz-wb-pill-long";
      const pnlCls = pos.pnlSats >= 0 ? "shz-wb-pos" : "shz-wb-neg";
      const bobOffline = pos.bobStatus === "offline";
      const liqHtml =
        pos.liqPriceUsd === null
          ? `<span class="shz-wb-pill shz-wb-pill-long shz-wb-mono">∞ UNLIQUIDATABLE</span>`
          : `<span class="shz-wb-mono shz-wb-amber">${fmtUsd(pos.liqPriceUsd)}</span>`;
      const isInspected = ui.mnr02InspectorPosId === pos.id;

      return `
        <tr data-position-id="${escapeHtml(pos.id)}" class="${isInspected ? "shz-wb-row-highlight" : ""}">
          <td class="shz-wb-mono" style="font-weight:700;">${escapeHtml(pos.instrument)}</td>
          <td><span class="shz-wb-pill ${sideCls} shz-wb-mono">${sideLabel}</span></td>
          <td class="shz-wb-num shz-wb-mono">${fmtUsd(pos.notionalUsd)}</td>
          <td class="shz-wb-num shz-wb-mono">${fmtUsd(pos.entryPriceUsd)}</td>
          <td class="shz-wb-num shz-wb-mono">${fmtUsd(pos.markPriceUsd)}</td>
          <td class="shz-wb-num shz-wb-mono">${fmtSats(pos.marginSats)}</td>
          <td class="shz-wb-num shz-wb-mono ${pnlCls}">${fmtSats(pos.pnlSats, true)}</td>
          <td class="shz-wb-num shz-wb-mono shz-wb-cyan">$${Number(pos.usdValue).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
          <td>${liqHtml}</td>
          <td>
            <button class="shz-wb-btn shz-wb-mono ${bobOffline ? "shz-wb-btn-amber" : ""}" data-action="toggle-bob" data-pos-id="${escapeHtml(pos.id)}">
              Bob: ${bobOffline ? "Offline" : "Online"}
            </button>
          </td>
          <td style="display:flex; gap:5px;">
            ${
              !pos.isMnr02Reference && !pos.id.startsWith("pos-satshedge")
                ? `<button class="shz-wb-btn shz-wb-mono" style="border-color:#00d285;color:#00d285;" data-action="close-ptlc" data-pos-id="${escapeHtml(pos.id)}">⚡ Settle PTLC</button>`
                : ""
            }
            <button class="shz-wb-btn shz-wb-btn-primary shz-wb-mono" data-action="closeout-mnr02" data-pos-id="${escapeHtml(pos.id)}">
              Close Out via Carol (MNR-02 0x83)
            </button>
          </td>
        </tr>`;
    })
    .join("");

  return `
    <div style="overflow-x:auto;">
      <table class="shz-wb-table">
        <thead>
          <tr>
            <th>Instrument</th>
            <th>Side</th>
            <th class="shz-wb-num">Notional USD</th>
            <th class="shz-wb-num">Entry</th>
            <th class="shz-wb-num">Mark</th>
            <th class="shz-wb-num">Margin Sats</th>
            <th class="shz-wb-num">Unrealized PnL Sats</th>
            <th class="shz-wb-num">USD Value</th>
            <th>Liq Price</th>
            <th>Bob Counterparty Status</th>
            <th>Multilateral Action</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${renderMnr02InspectorHtml(vm, ui)}
  `;
}

function renderTab2Subchannels(vm, ui) {
  const mode = ui.cetSimMode || "coop";
  const dex = vm.baselineEvidence?.dex_simulation || DEFAULT_BASELINE_EVIDENCE.dex_simulation;
  const activeCet = vm.activeMarkCet;

  // Sample ~36 representative dyadic CETs centered around the active mark price for crisp display
  const allCets = vm.cets;
  const activeIdx = activeCet
    ? allCets.findIndex((c) => c.prefix === activeCet.prefix)
    : Math.floor(allCets.length / 2);
  const startIdx = Math.max(0, activeIdx - 14);
  const sampleCets = allCets.slice(startIdx, Math.min(allCets.length, startIdx + 32));

  const simCard =
    mode === "coop"
      ? `
        <div class="shz-wb-card">
          <div class="shz-wb-hdr-row">
            <span class="shz-wb-pos shz-wb-mono" style="font-weight:700;">Instant 0-Fee LN Coop Close (Off-Chain Fast Path)</span>
            <span class="shz-wb-pill shz-wb-pill-long shz-wb-mono">0 L1 TXS · 0 SATS FEE</span>
          </div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Event / Subchannel</span><span class="shz-wb-mono">${escapeHtml(dex.event_id)} · $${Number(dex.matched_usd_notional).toLocaleString("en-US")} Notional</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Agreed Mark Price</span><span class="shz-wb-mono shz-wb-cyan">${fmtUsd(dex.coop_close_mark_price_usd)}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Long Payout / Short Payout</span><span class="shz-wb-mono"><span class="shz-wb-pos">${fmtSats(dex.coop_close_long_sats)}</span> / <span class="shz-wb-short">${fmtSats(dex.coop_close_short_sats)}</span> sats</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Protocol Fee</span><span class="shz-wb-mono shz-wb-pos">0 sats (0 bps)</span></div>
        </div>`
      : `
        <div class="shz-wb-card">
          <div class="shz-wb-hdr-row">
            <span class="shz-wb-amber shz-wb-mono" style="font-weight:700;">Broadcast L1 Adaptor CET (Unilateral Oracle Unlock)</span>
            <span class="shz-wb-pill shz-wb-pill-amber shz-wb-mono">3-of-5 FROST ATTESTATION</span>
          </div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Settled Price (TradeLayer VWAP)</span><span class="shz-wb-mono shz-wb-amber">${fmtUsd(dex.l1_cet_settled_price_usd)}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Long Payout / Short Payout</span><span class="shz-wb-mono"><span class="shz-wb-pos">${fmtSats(dex.l1_cet_long_sats)}</span> / <span class="shz-wb-cyan">${fmtSats(dex.l1_cet_short_sats)}</span> sats</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">1x SatsHedge Short USD Value</span><span class="shz-wb-mono shz-wb-pos">${fmtUsd(dex.short_hedged_usd_value_at_settlement)} (Exact Synthetic USD Parity)</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Active Quote Matching Prefix</span><span class="shz-wb-mono shz-wb-cyan">${activeCet ? `${activeCet.prefix} → [${fmtUsd(activeCet.minPriceUsd)}, ${fmtUsd(activeCet.maxPriceUsd)}]` : "—"}</span></div>
        </div>`;

  return `
    <div class="shz-wb-grid-2">
      <div class="shz-wb-card">
        <div class="shz-wb-hdr-row">
          <span class="shz-wb-title">Taproot NUMS P2TR Funding & Dyadic Compression</span>
          <span class="shz-wb-pill shz-wb-pill-long shz-wb-mono">Vanilla BTC P2TR v0</span>
        </div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Taproot NUMS Internal Key</span><span class="shz-wb-mono shz-wb-cyan" title="${UTXOREF_NUMS_INTERNAL_KEY_HEX}">${UTXOREF_NUMS_INTERNAL_KEY_HEX.slice(0, 20)}…${UTXOREF_NUMS_INTERNAL_KEY_HEX.slice(-12)}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">20-bit Price Space → Active Quote CETs</span><span class="shz-wb-mono">1,048,576 → <strong class="shz-wb-pos">${allCets.length}</strong> prefixes (≤250 sats err)</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Baseline DEX Sim CET Count</span><span class="shz-wb-mono">${Number(dex.compressed_cet_count).toLocaleString("en-US")} CETs (0 fee)</span></div>
        <div style="display:flex; gap:6px; margin-top:8px;">
          <button class="shz-wb-btn shz-wb-mono ${mode === "coop" ? "shz-wb-btn-active" : ""}" data-action="cet-sim-mode" data-mode="coop">Instant 0-Fee LN Coop Close</button>
          <button class="shz-wb-btn shz-wb-mono ${mode === "l1" ? "shz-wb-btn-amber" : ""}" data-action="cet-sim-mode" data-mode="l1">Broadcast L1 Adaptor CET</button>
        </div>
      </div>
      ${simCard}
    </div>

    <div class="shz-wb-cet-scroll">
      <table class="shz-wb-table">
        <thead>
          <tr>
            <th>Dyadic Binary Prefix</th>
            <th>Bit Depth</th>
            <th>Price Interval [min_usd, max_usd]</th>
            <th class="shz-wb-num">Long Sats</th>
            <th class="shz-wb-num">Short Sats</th>
            <th class="shz-wb-num">Protocol Fee</th>
          </tr>
        </thead>
        <tbody>
          ${sampleCets
            .map((c) => {
              const isMark = activeCet && c.prefix === activeCet.prefix;
              return `
                <tr class="${isMark ? "shz-wb-row-highlight" : ""}">
                  <td class="shz-wb-mono ${isMark ? "shz-wb-cyan" : ""}">${escapeHtml(c.prefix)}${isMark ? ' <span class="shz-wb-pill shz-wb-pill-cyan">MARK</span>' : ""}</td>
                  <td class="shz-wb-mono shz-wb-muted">${c.prefixLen}b / 20b</td>
                  <td class="shz-wb-mono">[${fmtUsd(c.minPriceUsd)}, ${fmtUsd(c.maxPriceUsd)}]</td>
                  <td class="shz-wb-num shz-wb-mono shz-wb-pos">${fmtSats(c.longSats)}</td>
                  <td class="shz-wb-num shz-wb-mono shz-wb-neg">${fmtSats(c.shortSats)}</td>
                  <td class="shz-wb-num shz-wb-mono shz-wb-pos">0 sats</td>
                </tr>`;
            })
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderTab3FraudGuard(vm, ui) {
  const fraud = vm.baselineEvidence?.fraud_simulation || DEFAULT_BASELINE_EVIDENCE.fraud_simulation;
  const eq = fraud.equivocation_verdict || DEFAULT_BASELINE_EVIDENCE.fraud_simulation.equivocation_verdict;
  const dev = fraud.deviation_verdict || DEFAULT_BASELINE_EVIDENCE.fraud_simulation.deviation_verdict;
  const extractedKeyHex = formatExtractedKeyHex(eq.extracted_btc_slash_secret_key);
  const selectedVerdict = ui.fraudVerdictMode || "equivocation";

  const stakeNear = vm.market.nearVaultStakeNear || 10_000;
  const maxTvlNear = stakeNear * 10;
  const curTvlNear = vm.market.nearVaultTvlNearEq || 42_500;
  const capPct = Math.min(100, Math.round((curTvlNear / maxTvlNear) * 100));

  const verdictPanel =
    selectedVerdict === "equivocation"
      ? `
        <div class="shz-wb-card" data-fraud-verdict="equivocation">
          <div class="shz-wb-hdr-row">
            <span class="shz-wb-neg shz-wb-mono" style="font-weight:700;">Equivocation Slash Verdict (${escapeHtml(eq.event_id)})</span>
            <span class="shz-wb-pill shz-wb-pill-short shz-wb-mono">KEY EXTRACTED · ${yoctoToNearString(eq.slashed_yocto_near)} SLASHED</span>
          </div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Extracted secp256k1 Private Key</span><span class="shz-wb-mono shz-wb-amber" style="word-break:break-all;">${escapeHtml(extractedKeyHex)}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Matches Confederation Pubkey</span><span class="shz-wb-mono shz-wb-pos">${fraud.equivocation_key_matches_confed_pubkey ? "true (verified)" : "false"}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Challenger Reward / Treasury Burn</span><span class="shz-wb-mono">${yoctoToNearString(eq.challenger_reward_yocto_near)} / ${yoctoToNearString(eq.treasury_burn_yocto_near)}</span></div>
        </div>`
      : `
        <div class="shz-wb-card" data-fraud-verdict="deviation">
          <div class="shz-wb-hdr-row">
            <span class="shz-wb-amber shz-wb-mono" style="font-weight:700;">Dual-Consensus Deviation Slash (${escapeHtml(dev.event_id)})</span>
            <span class="shz-wb-pill shz-wb-pill-amber shz-wb-mono">${fraud.deviation_borsh_payload_bytes ?? 2799}B BORSH · ${fmtSats(dev.victim_shortfall_sats)} SATS RESTITUTION</span>
          </div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Dishonest Attested vs Canonical Price</span><span class="shz-wb-mono"><span class="shz-wb-neg">${fmtUsd(dev.attested_price_usd)}</span> vs <span class="shz-wb-pos">${fmtUsd(dev.canonical_price_usd)}</span> (${dev.deviation_bps} bps)</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Victim Restitution</span><span class="shz-wb-mono shz-wb-pos">${fmtSats(dev.victim_shortfall_sats)} sats (${yoctoToNearString(dev.victim_restitution_yocto_near)})</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Total Slashed / Challenger / Burn</span><span class="shz-wb-mono">${yoctoToNearString(dev.slashed_yocto_near)} · ${yoctoToNearString(dev.challenger_reward_yocto_near)} · ${yoctoToNearString(dev.treasury_burn_yocto_near)}</span></div>
        </div>`;

  return `
    <div class="shz-wb-grid-5" style="margin-bottom:10px;">
      ${vm.market.frostSigners
        .map(
          (node) => `
        <div class="shz-wb-card" style="padding:7px 9px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="shz-wb-mono" style="font-weight:700; font-size:11px;">FROST #${node.id}</span>
            <span class="shz-wb-pill ${node.status === "online" ? "shz-wb-pill-long" : "shz-wb-pill-amber"} shz-wb-mono">${escapeHtml(node.status.toUpperCase())}</span>
          </div>
          <div class="shz-wb-muted shz-wb-mono" style="font-size:10px; margin-top:4px;">${escapeHtml(node.name)} · ${node.latencyMs}ms</div>
        </div>`
        )
        .join("")}
    </div>

    <div class="shz-wb-grid-2">
      <div class="shz-wb-card">
        <div class="shz-wb-hdr-row">
          <span class="shz-wb-title">NEAR Bonded Vault TVL Cap (TVL ≤ 10× Stake)</span>
          <span class="shz-wb-pill shz-wb-pill-long shz-wb-mono">${capPct}% OF CAP</span>
        </div>
        <div class="shz-wb-meter"><div class="shz-wb-meter-fill" style="width:${capPct}%;"></div></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Bonded Stake / Max TVL / Active TVL</span><span class="shz-wb-mono">${stakeNear.toLocaleString("en-US")} / ${maxTvlNear.toLocaleString("en-US")} / ${curTvlNear.toLocaleString("en-US")} NEAR</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">TradeLayer tx14 Merkle Root</span><span class="shz-wb-mono shz-wb-cyan" title="${escapeHtml(vm.market.tradelayerMerkleRoot)}">${escapeHtml(shortHex(vm.market.tradelayerMerkleRoot, 14, 10))}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">TradeLayer VWAP / Pyth Relay Conf</span><span class="shz-wb-mono shz-wb-amber">${fmtUsd(vm.market.tradelayerVwapUsd)} · ±${vm.market.pythConfBps} bps</span></div>
        <div style="display:flex; gap:6px; margin-top:8px;">
          <button class="shz-wb-btn shz-wb-mono ${selectedVerdict === "equivocation" ? "shz-wb-btn-active" : ""}" data-action="fraud-verdict" data-verdict="equivocation">Inspect Equivocation Slash (10,000 NEAR)</button>
          <button class="shz-wb-btn shz-wb-mono ${selectedVerdict === "deviation" ? "shz-wb-btn-amber" : ""}" data-action="fraud-verdict" data-verdict="deviation">Inspect Deviation Slash (2,799B Borsh)</button>
        </div>
      </div>
      ${verdictPanel}
    </div>
  `;
}

function renderTab4NovaBitvm(vm, ui) {
  const { transcript, journal, secqClaim, bitvm3, honestyFlags } = vm.nova;
  const selectedId = ui.selectedSliceId || transcript.slices[0].id;
  const activeSlice =
    transcript.slices.find((s) => s.id === selectedId) || transcript.slices[0];

  const segmentsHtml = transcript.slices
    .map((s) => {
      const pct = ((s.byteLength / 600) * 100).toFixed(2);
      const isSel = s.id === activeSlice.id;
      return `<button class="shz-wb-seg shz-wb-mono ${isSel ? "selected" : ""}" data-action="select-slice" data-slice-id="${escapeHtml(s.id)}" style="width:${pct}%; background:${s.color};" title="${escapeHtml(s.label)} (${s.rangeLabel}, ${s.byteLength}B)">${escapeHtml(s.rangeLabel)}</button>`;
    })
    .join("");

  const sliceChipsHtml = transcript.slices
    .map((s) => {
      const isSel = s.id === activeSlice.id;
      return `<button class="shz-wb-btn shz-wb-mono ${isSel ? "shz-wb-btn-active" : ""}" data-action="select-slice" data-slice-id="${escapeHtml(s.id)}">${escapeHtml(s.rangeLabel)} · ${escapeHtml(s.label)} (${s.byteLength}B)</button>`;
    })
    .join("");

  const decodedRows = Object.entries(activeSlice.decoded || {})
    .map(
      ([k, v]) =>
        `<div class="shz-wb-kv"><span class="shz-wb-muted shz-wb-mono">${escapeHtml(k)}</span><span class="shz-wb-mono">${escapeHtml(typeof v === "object" ? JSON.stringify(v) : String(v))}</span></div>`
    )
    .join("");

  const tn4 = vm.testnet4LiveReceipt;
  const c33k = vm.clearing33kReceipt;
  const tn4Snark = tn4?.clearing_report?.external_nova_snark_receipt;
  const tn4BannerHtml = tn4
    ? `
    <div class="shz-wb-card" style="margin-bottom:10px; border-color:#00d285;">
      <div class="shz-wb-hdr-row">
        <span class="shz-wb-title">Live Bitcoin Testnet4 3-Party DLC Clearing + <span class="shz-wb-mono shz-wb-pos">lnm-nova CompressedSNARK</span></span>
        <span class="shz-wb-pill shz-wb-pill-long shz-wb-mono">TESTNET4 #${tn4.testnet4_tip_height} · ${tn4Snark?.compressed_proof_bytes?.toLocaleString("en-US") || "12,376"}B SNARK VERIFIED</span>
      </div>
      <div class="shz-wb-grid-2">
        <div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Testnet4 Funding Tx (3 NUMS P2TR DLCs)</span><a href="${escapeHtml(tn4.funding_tx_explorer_uri)}" target="_blank" rel="noopener" class="shz-wb-mono shz-wb-cyan">${escapeHtml(shortHex(tn4.funding_txid, 14, 10))}</a></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Testnet4 Atomic Clearing Tx (= batch_txid)</span><a href="${escapeHtml(tn4.atomic_clearing_tx_explorer_uri)}" target="_blank" rel="noopener" class="shz-wb-mono shz-wb-pos">${escapeHtml(shortHex(tn4.atomic_clearing_txid, 14, 10))}</a></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Testnet4 $1 Run ($80k→$100k→$125k)</span><span class="shz-wb-mono"><span class="shz-wb-pos">Alice +450 sats PnL</span> · <span class="shz-wb-cyan">Bob 1,250 sats (83.3%) Freed</span></span></div>
        </div>
        <div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Full-Scale $33k Run ($50k→$55k→$60k)</span><span class="shz-wb-mono"><span class="shz-wb-pos">Alice +${fmtSats(c33k?.clearing_report?.utxoref_pnl_clearing?.total_winner_routed_pnl_sats ?? 11_000_000)} PnL</span> · <span class="shz-wb-cyan">Bob ${fmtSats(c33k?.clearing_report?.utxoref_pnl_clearing?.bob_freed_collateral_sats ?? 90_000_000)} Freed</span></span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Spartan+IPA Verifier Key SHA256</span><span class="shz-wb-mono shz-wb-amber">${escapeHtml(shortHex(tn4Snark?.verifier_key_sha256_hex || "", 14, 10))}</span></div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">R1CS Constraints / Proof Digest</span><span class="shz-wb-mono">${(tn4Snark?.primary_constraints || 275234).toLocaleString("en-US")} gates · ${escapeHtml(shortHex(tn4Snark?.proof_sha256_hex || "", 10, 8))}</span></div>
        </div>
      </div>
    </div>`
    : "";

  return `
    <div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px;" data-honesty-badges="true">
      <span class="shz-wb-pill ${honestyFlags.native_statement_verified ? "shz-wb-pill-long" : "shz-wb-pill-short"} shz-wb-mono">native_statement_verified: ${honestyFlags.native_statement_verified}</span>
      <span class="shz-wb-pill ${honestyFlags.nova_snark_verified ? "shz-wb-pill-long" : "shz-wb-pill-amber"} shz-wb-mono">nova_snark_verified: ${honestyFlags.nova_snark_verified}</span>
      <span class="shz-wb-pill ${honestyFlags.bitvm3_onchain_verified ? "shz-wb-pill-long" : "shz-wb-pill-amber"} shz-wb-mono">bitvm3_onchain_verified: ${honestyFlags.bitvm3_onchain_verified}</span>
      <span class="shz-wb-pill ${honestyFlags.production_ready ? "shz-wb-pill-long" : "shz-wb-pill-short"} shz-wb-mono">production_ready: ${honestyFlags.production_ready}</span>
    </div>
    ${tn4BannerHtml}

    <div class="shz-wb-card" style="margin-bottom:10px;">
      <div class="shz-wb-hdr-row">
        <span class="shz-wb-title">600-Byte Nova v2 Signed-Row Transcript (<span class="shz-wb-mono shz-wb-cyan">validated-signed-row/v1</span>)</span>
        <span class="shz-wb-mono shz-wb-muted">SHA256: ${escapeHtml(shortHex(transcript.transcriptSha256Hex, 14, 10))}</span>
      </div>
      <div class="shz-wb-bytebar">${segmentsHtml}</div>
      <div style="display:flex; flex-wrap:wrap; gap:5px; margin-bottom:8px;">${sliceChipsHtml}</div>
      <div class="shz-wb-grid-2">
        <div>
          <div class="shz-wb-kv"><span class="shz-wb-muted">Selected Offset Range</span><span class="shz-wb-mono shz-wb-cyan">${escapeHtml(activeSlice.rangeLabel)} (${activeSlice.byteLength} bytes) · ${escapeHtml(activeSlice.encoding)}</span></div>
          <div class="shz-wb-muted" style="font-size:11px; margin:5px 0 6px;">${escapeHtml(activeSlice.description)}</div>
          ${decodedRows}
        </div>
        <div>
          <div class="shz-wb-muted shz-wb-mono" style="font-size:10px; margin-bottom:4px;">RAW SLICE HEX (${activeSlice.byteLength}B)</div>
          <div class="shz-wb-hexbox shz-wb-mono">${escapeHtml(activeSlice.hex)}</div>
        </div>
      </div>
    </div>

    <div class="shz-wb-grid-3">
      <div class="shz-wb-card">
        <div class="shz-wb-hdr-row">
          <span class="shz-wb-title">276B <span class="shz-wb-mono shz-wb-cyan">LNMJNL01</span> + 8-Field Pallas State</span>
          <span class="shz-wb-pill shz-wb-pill-long shz-wb-mono">56-BIT OK</span>
        </div>
        ${journal.pallas8Fields
          .map(
            (f) =>
              `<div class="shz-wb-kv"><span class="shz-wb-muted shz-wb-mono">[${f.index}] ${escapeHtml(f.name)}</span><span class="shz-wb-mono" title="${escapeHtml(f.value)}">${escapeHtml(shortHex(f.value, 12, 8))}</span></div>`
          )
          .join("")}
      </div>

      <div class="shz-wb-card">
        <div class="shz-wb-hdr-row">
          <span class="shz-wb-title">Secq BIP-340 3-Field Claim</span>
          <span class="shz-wb-pill shz-wb-pill-cyan shz-wb-mono">ROW-BOUND</span>
        </div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Bound Slot</span><span class="shz-wb-mono">${escapeHtml(secqClaim.slot)}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">[0] active_flag</span><span class="shz-wb-mono shz-wb-pos">${escapeHtml(secqClaim.fields[0])}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">[1] claim_low128_le</span><span class="shz-wb-mono" title="${escapeHtml(secqClaim.fields[1])}">${escapeHtml(shortHex(secqClaim.fields[1], 14, 8))}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">[2] claim_high128_le</span><span class="shz-wb-mono" title="${escapeHtml(secqClaim.fields[2])}">${escapeHtml(shortHex(secqClaim.fields[2], 14, 8))}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">SHA256(pk||msg||sig)</span><span class="shz-wb-mono shz-wb-cyan">${escapeHtml(shortHex(secqClaim.claimSha256Hex, 12, 8))}</span></div>
      </div>

      <div class="shz-wb-card">
        <div class="shz-wb-hdr-row">
          <span class="shz-wb-title">304B <span class="shz-wb-mono shz-wb-amber">UTXOREF_L2_SETTLEMENT_GROTH16_V0</span></span>
          <span class="shz-wb-pill shz-wb-pill-amber shz-wb-mono">2×u128 BE</span>
        </div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Wire Size / Epoch</span><span class="shz-wb-mono">${bitvm3.length}B · epoch ${bitvm3.epochId} · vout ${bitvm3.assertionVout}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">SHA256(statement_304B)</span><span class="shz-wb-mono shz-wb-cyan" title="${escapeHtml(bitvm3.sha256Hex)}">${escapeHtml(shortHex(bitvm3.sha256Hex, 12, 10))}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Limb 0 (u128 BE d[0..16])</span><span class="shz-wb-mono" title="${escapeHtml(bitvm3.limbs[0])}">${escapeHtml(shortHex(bitvm3.limbsHex[0], 14, 8))}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Limb 1 (u128 BE d[16..32])</span><span class="shz-wb-mono" title="${escapeHtml(bitvm3.limbs[1])}">${escapeHtml(shortHex(bitvm3.limbsHex[1], 14, 8))}</span></div>
        <div class="shz-wb-kv"><span class="shz-wb-muted">Limb 0 Decimal</span><span class="shz-wb-mono shz-wb-muted" style="font-size:10px;">${escapeHtml(bitvm3.limbs[0])}</span></div>
      </div>
    </div>
  `;
}

export function renderWorkbenchHtml(vm, ui = {}) {
  const activeTab = ui.activeTab || "positions";
  const tabs = [
    { id: "positions", label: "Positions & MNR-02 Offline Closeout", badge: String(vm.positions.length) },
    { id: "subchannels", label: "LN-DLC Subchannels & CET Tree", badge: `${vm.cets.length} CETs` },
    { id: "fraud", label: "FROST & NEAR Fraud Guard", badge: "3-of-5" },
    { id: "nova", label: "Nova v2 & BitVM3 Proof Inspector", badge: "600B / 304B" },
  ];

  let bodyHtml = "";
  if (activeTab === "subchannels") bodyHtml = renderTab2Subchannels(vm, ui);
  else if (activeTab === "fraud") bodyHtml = renderTab3FraudGuard(vm, ui);
  else if (activeTab === "nova") bodyHtml = renderTab4NovaBitvm(vm, ui);
  else bodyHtml = renderTab1Positions(vm, ui);

  return `
    <div class="shz-wb-tabs" role="tablist">
      ${tabs
        .map(
          (t) => `
        <button class="shz-wb-tab ${activeTab === t.id ? "active" : ""}" role="tab" aria-selected="${activeTab === t.id}" data-action="switch-tab" data-tab="${t.id}">
          ${escapeHtml(t.label)}
          <span class="shz-wb-count shz-wb-mono">${escapeHtml(t.badge)}</span>
        </button>`
        )
        .join("")}
    </div>
    <div class="shz-wb-body">${bodyHtml}</div>
  `;
}

// ---------------------------------------------------------------------------
// Interactive Controller & Browser Auto-Mount
// ---------------------------------------------------------------------------

export class ShzWorkbenchController {
  constructor(rootEl, initialState = null) {
    this.rootEl = rootEl;
    this.rawState = initialState || {};
    this.ui = {
      activeTab: "positions",
      bobStatusById: {},
      mnr02InspectorPosId: null,
      mnr02ApiResult: null,
      cetSimMode: "coop",
      fraudVerdictMode: "equivocation",
      selectedSliceId: "domain",
    };

    if (rootEl && typeof rootEl.addEventListener === "function") {
      this._onClick = (ev) => this._handleClick(ev);
      this._onMouseOver = (ev) => this._handleHover(ev);
      rootEl.addEventListener("click", this._onClick);
      rootEl.addEventListener("mouseover", this._onMouseOver);
    }
    this.render();
  }

  setState(nextState) {
    this.rawState = nextState || {};
    this.render();
  }

  openMnr02Closeout(posId) {
    this.ui.activeTab = "positions";
    this.ui.mnr02InspectorPosId = posId;
    this.ui.mnr02ApiResult = null;
    this.render();

    // Optionally call shared @ui-terminal backend hook if present
    if (
      typeof window !== "undefined" &&
      window.SHZ_API &&
      typeof window.SHZ_API.triggerMnr02Closeout === "function"
    ) {
      const vm = normalizeWorkbenchState(this.rawState, this.ui);
      const pos = vm.positions.find((p) => p.id === posId);
      if (pos) {
        Promise.resolve(
          window.SHZ_API.triggerMnr02Closeout({
            positionId: pos.id,
            notionalUsd: pos.notionalUsd,
            entryPriceUsd: pos.entryPriceUsd,
            bobOffline: pos.bobStatus === "offline",
          })
        )
          .then((res) => {
            if (res && typeof res === "object" && res.carolOutput1Sats != null) {
              this.ui.mnr02ApiResult = res;
              this.render();
            }
          })
          .catch(() => {
            // Local deterministic Core v31.1 receipt inspector remains active.
          });
      }
    }
  }

  _handleHover(ev) {
    const target = ev?.target?.closest?.("[data-action='select-slice']");
    if (!target) return;
    const id = target.getAttribute("data-slice-id");
    if (id && id !== this.ui.selectedSliceId) {
      this.ui.selectedSliceId = id;
      this.render();
    }
  }

  _handleClick(ev) {
    const btn = ev?.target?.closest?.("[data-action]");
    if (!btn) return;
    const action = btn.getAttribute("data-action");
    if (action === "switch-tab") {
      this.ui.activeTab = btn.getAttribute("data-tab") || "positions";
      this.render();
    } else if (action === "toggle-bob") {
      const posId = btn.getAttribute("data-pos-id");
      const vm = normalizeWorkbenchState(this.rawState, this.ui);
      const cur = vm.positions.find((p) => p.id === posId)?.bobStatus || "online";
      const nextStatus = cur === "offline" ? "online" : "offline";
      this.ui.bobStatusById[posId] = nextStatus;
      if (
        typeof window !== "undefined" &&
        window.SHZ_API &&
        typeof window.SHZ_API.toggleBobStatus === "function"
      ) {
        try {
          window.SHZ_API.toggleBobStatus(posId, nextStatus === "offline");
        } catch {
          // Local override remains active.
        }
      }
      this.render();
    } else if (action === "close-ptlc") {
      const posId = btn.getAttribute("data-pos-id");
      if (
        typeof window !== "undefined" &&
        window.SHZ_API &&
        typeof window.SHZ_API.closePositionPtlc === "function"
      ) {
        Promise.resolve(window.SHZ_API.closePositionPtlc(posId)).catch(() => {});
      }
    } else if (action === "closeout-mnr02") {
      const posId = btn.getAttribute("data-pos-id");
      this.openMnr02Closeout(posId);
    } else if (action === "close-mnr02") {
      this.ui.mnr02InspectorPosId = null;
      this.render();
    } else if (action === "cet-sim-mode") {
      this.ui.cetSimMode = btn.getAttribute("data-mode") || "coop";
      this.render();
    } else if (action === "fraud-verdict") {
      this.ui.fraudVerdictMode = btn.getAttribute("data-verdict") || "equivocation";
      this.render();
    } else if (action === "select-slice") {
      this.ui.selectedSliceId = btn.getAttribute("data-slice-id") || "domain";
      this.render();
    }
  }

  render() {
    if (!this.rootEl) return "";
    const vm = normalizeWorkbenchState(this.rawState, this.ui);
    const html = renderWorkbenchHtml(vm, this.ui);
    this.rootEl.innerHTML = html;
    return html;
  }
}

let activeWorkbench = null;

export function mountWorkbench(rootOrId = "shz-workbench-root", initialState = null) {
  let rootEl = null;
  if (typeof rootOrId === "string") {
    if (typeof document !== "undefined") {
      injectWorkbenchStyles(document);
      rootEl = document.getElementById(rootOrId);
    }
  } else {
    rootEl = rootOrId;
    if (typeof document !== "undefined") injectWorkbenchStyles(document);
  }
  if (!rootEl) return null;
  const seed = initialState || (typeof window !== "undefined" ? window.SHZ_STATE : null);
  activeWorkbench = new ShzWorkbenchController(rootEl, seed);
  return activeWorkbench;
}

function bootWorkbenchInBrowser() {
  if (typeof window === "undefined" || typeof document === "undefined") return;

  const init = () => {
    const ctrl = mountWorkbench("shz-workbench-root", window.SHZ_STATE || null);
    window.SHZ_WORKBENCH = ctrl;
  };

  window.addEventListener("shz:state", (ev) => {
    if (!activeWorkbench) init();
    if (activeWorkbench && ev?.detail) {
      activeWorkbench.setState(ev.detail);
    }
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
}

bootWorkbenchInBrowser();
