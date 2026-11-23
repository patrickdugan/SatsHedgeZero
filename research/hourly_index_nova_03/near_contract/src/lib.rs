//! `SHZ-INDEX-03`: Transparent Nova Checkpoint Verifier, Pyth Pro + Chainlink Data Streams
//! Source Authenticator, and Bitcoin `SHZIDX01` SPV Light-Client Contract on NEAR WASM.
//!
//! Architecture (`Route B + Route C`):
//! - Verifies a genuine, setup-free 8-fold `Bn256EngineIPA` Nova Non-Interactive Folding (`NIFS`)
//!   + ZK-blinded `RelaxedR1CSSNARK` (`Spartan` outer/inner/batch sumchecks + `IPA` polynomial
//!   commitment) against the canonical 8-hour SHZ checkpoint (`shz/hourly-index-checkpoint-nova/v1`).
//! - Uses 100% native NEAR host precompiles (`env::alt_bn128_g1_multiexp`, `env::keccak256`,
//!   `env::sha256`, `env::ed25519_verify`, `env::ecrecover`) with ZERO Groth16, ZERO KZG,
//!   ZERO trusted setup ceremonies, and ZERO Starknet dependencies.
//! - Stores a compact ~420-byte Merkle-pinned verifier key on-chain (`vk_chunks_merkle_root`)
//!   and authenticates every streamed R1CS sparse-matrix chunk and BN254 generator chunk via
//!   SHA-256 Merkle proofs into an immutable `AuthenticatedVerificationSession`.
//! - Authenticates operational Solana Mainnet `pyth-lazer` `Storage` (`3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL`)
//!   Ed25519 envelopes AND Chainlink Data Streams v3 DON secp256k1 `ecrecover` quorums, with
//!   strict isolation between `operational_mainnet_pinned` and `synthetic_test_only` profiles
//!   plus objective anti-cherry-picking fraud proofs.
//! - Binds accepted checkpoints to canonical-chain confirmed `40`-byte `SHZIDX01 || checkpoint_root32`
//!   Bitcoin `OP_RETURN` transactions under an embedded PoW/MTP/chainwork `BtcLightClient` modeled on
//!   `Near-One/btc-light-client-contract`.
//! - Retains `production_ready == false` and `can_authorize_dlc_settlement == false`.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use bincode::Options;
use ff::{Field, PrimeField};
use halo2curves::{
    bn256::{Fr as BnScalar, G1 as BnPoint, G1Affine as BnAffine},
    grumpkin::{Fr as GrScalar, G1 as GrPoint, G1Affine as GrAffine},
    group::{Curve, Group},
    pasta::{Fp as PallasBase, Fq as PallasScalar, Pallas as PallasPoint, PallasAffine},
    CurveAffine,
};
use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize},
    env, near_bindgen, AccountId, PanicOnDefault,
};
use serde::{Deserialize, Serialize};

#[path = "../../prover/src/btc_anchor.rs"]
pub mod btc_anchor;
#[path = "../../prover/src/decider_equations.rs"]
pub mod decider_equations;
#[path = "../../../near_pyth_channel/near_contract/src/pyth_payload.rs"]
mod pyth_payload;

use btc_anchor::{BtcLightClient, BtcNetwork, StoredBtcHeader, VerifiedBitcoinAnchorReceipt};
use decider_equations::{
    begin_decider_session, evaluate_msm_chunk, evaluate_packed_r1cs_chunk,
    finalize_decider_session, scalar_from_le32, sha256_bytes, AuthenticatedVerificationSession,
    Bn254NifsSpartanProof, CompactPinnedVerifierKey,
};

const PYTH_SOLANA_FORMAT_MAGIC: u32 = 2_182_742_457;
const PYTH_STORAGE_DISCRIMINATOR: [u8; 8] = [0xd1, 0x75, 0xff, 0xb9, 0xc4, 0xaf, 0x44, 0x09];

fn near_sha256(data: &[u8]) -> [u8; 32] {
    env::sha256(data)
        .try_into()
        .expect("NEAR env::sha256 returns 32 bytes")
}

fn near_keccak256(data: &[u8]) -> [u8; 32] {
    env::keccak256(data)
        .try_into()
        .expect("NEAR env::keccak256 returns 32 bytes")
}

fn near_bn254_multiexp(terms: &[([u8; 64], [u8; 32])]) -> Result<[u8; 64], String> {
    if terms.is_empty() {
        return Ok([0u8; 64]);
    }
    let mut buf = Vec::with_capacity(terms.len() * 96);
    for (pt, sc) in terms {
        let s = scalar_from_le32(sc)?;
        if bool::from(s.is_zero()) || pt.iter().all(|&b| b == 0) {
            continue;
        }
        buf.extend_from_slice(pt);
        buf.extend_from_slice(sc);
    }
    if buf.is_empty() {
        return Ok([0u8; 64]);
    }
    env::alt_bn128_g1_multiexp(&buf)
        .try_into()
        .map_err(|_| "alt_bn128_g1_multiexp output length != 64".to_owned())
}

fn f_from_le16(bytes: &[u8]) -> BnScalar {
    bytes.iter().rev().fold(BnScalar::ZERO, |acc, b| {
        acc * BnScalar::from(256u64) + BnScalar::from(u64::from(*b))
    })
}

fn parse_hex32_strict(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err("noncanonical 32-byte lowercase hex".into());
    }
    hex::decode(s)
        .map_err(|_| "hex decode failed".to_owned())?
        .try_into()
        .map_err(|_| "hex32 len".to_owned())
}

fn build_v1_claim_state(
    genesis: &str,
    policy_hash: &str,
    start_hour_str: &str,
    checkpoint_root: &str,
    count: u64,
) -> Result<(u64, Vec<BnScalar>), String> {
    let start = start_hour_str
        .parse::<u64>()
        .map_err(|_| "invalid start_hour u64".to_owned())?;
    if start.to_string() != start_hour_str || start % 8 != 0 || start > 999_999_992 {
        return Err("noncanonical or misaligned 8-hour start_hour".into());
    }
    let mut out = vec![BnScalar::from(count), BnScalar::from(start)];
    for h in [genesis, policy_hash, checkpoint_root] {
        let b = parse_hex32_strict(h)?;
        out.push(f_from_le16(&b[..16]));
        out.push(f_from_le16(&b[16..]));
    }
    Ok((start, out))
}

#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct BeginNovaArgs {
    pub session_id: String,
    pub genesis: String,
    pub policy_hash: String,
    pub start_hour: String,
    pub checkpoint_root: String,
    pub proof_bincode: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct VerifyChunkArgs {
    pub session_id: String,
    pub chunk_idx: u32,
    pub merkle_index: u32,
    pub merkle_siblings: Vec<[u8; 32]>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainChainlinkDonConfig {
    pub profile: String,
    pub config_digest_hex: String,
    pub feed_id_hex: String,
    pub f: u8,
    /// Lowercase 40-hex-char Ethereum addresses (without `0x` or with `0x`).
    pub signers_hex: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedCheckpointRecord {
    pub relation: String,
    pub genesis: String,
    pub policy_hash: String,
    pub start_hour: u64,
    pub checkpoint_root: String,
    pub proof_sha256_hex: String,
    pub vk_chunks_merkle_root_hex: String,
    pub verified_r1cs_chunks: u32,
    pub verified_msm_chunks: u32,
    pub near_nova_verified: bool,
    pub bitcoin_anchor_finalized: bool,
    pub bitcoin_anchor_txid_hex: Option<String>,
    pub bitcoin_anchor_block_hash_hex: Option<String>,
    pub bitcoin_confirmations: u64,
    pub source_challenged_invalid: bool,
    pub production_ready: bool,
    pub can_authorize_dlc_settlement: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainPythVerifyReceipt {
    pub profile: String,
    pub operational_source_authenticated: bool,
    pub signer_pubkey_hex: String,
    pub price_e8: u64,
    pub publish_time_us: u64,
    pub envelope_sha256_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainChainlinkVerifyReceipt {
    pub profile: String,
    pub operational_source_authenticated: bool,
    pub feed_id_hex: String,
    pub price_e8: u64,
    pub observations_timestamp_us: u64,
    pub verified_don_signers: Vec<String>,
    pub full_report_sha256_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointFeedStatus {
    pub start_hour: u64,
    pub checkpoint_root: String,
    pub near_nova_verified: bool,
    pub bitcoin_canonical_mainchain_confirmed: bool,
    pub live_bitcoin_confirmations: u64,
    pub source_challenged_invalid: bool,
    pub eligible_for_frost_dlc_feed: bool,
    pub production_ready: bool,
    pub can_authorize_dlc_settlement: bool,
}

fn parse_solana_storage_ed25519_signers(raw_hex: &str) -> Result<Vec<([u8; 32], u64)>, String> {
    let raw = hex::decode(raw_hex).map_err(|_| "invalid Solana Storage hex".to_owned())?;
    if raw.len() != 381 || raw[0..8] != PYTH_STORAGE_DISCRIMINATOR {
        return Err("invalid 381-byte Solana pyth-lazer Storage account".into());
    }
    let n = raw[80] as usize;
    if n == 0 || n > 5 {
        return Err("invalid Solana Storage trusted signer count".into());
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = 81 + i * 40;
        let pk: [u8; 32] = raw[off..off + 32].try_into().unwrap();
        let exp = i64::from_le_bytes(raw[off + 32..off + 40].try_into().unwrap());
        if exp <= 0 {
            return Err("non-positive signer expiry".into());
        }
        out.push((pk, (exp as u64).saturating_mul(1_000_000)));
    }
    Ok(out)
}

fn verify_chainlink_v3_with_near_ecrecover(
    full_report: &[u8],
    cfg: &OnChainChainlinkDonConfig,
) -> Result<OnChainChainlinkVerifyReceipt, String> {
    let min_signers = usize::from(cfg.f) + 1;
    if cfg.signers_hex.len() < min_signers || cfg.signers_hex.len() > 31 {
        return Err("invalid DON signer set size".into());
    }
    if full_report.len() < 224 || full_report.len() > 16_384 || full_report.len() % 32 != 0 {
        return Err("invalid Chainlink fullReport ABI length".into());
    }
    let expected_cfg_digest = parse_hex32_strict(&cfg.config_digest_hex)?;
    let expected_feed_id = parse_hex32_strict(&cfg.feed_id_hex)?;

    let config_digest: [u8; 32] = full_report[0..32].try_into().unwrap();
    let epoch_and_round: [u8; 32] = full_report[32..64].try_into().unwrap();
    let extra_hash: [u8; 32] = full_report[64..96].try_into().unwrap();
    if config_digest != expected_cfg_digest {
        return Err("Chainlink configDigest mismatch".into());
    }

    let read_u64_word = |off: usize| -> Result<u64, String> {
        let w = full_report
            .get(off..off + 32)
            .ok_or("truncated ABI word")?;
        if w[..24].iter().any(|&b| b != 0) {
            return Err("ABI uint64 high bytes non-zero".into());
        }
        Ok(u64::from_be_bytes(w[24..32].try_into().unwrap()))
    };

    let blob_off = read_u64_word(96)? as usize;
    let rs_off = read_u64_word(128)? as usize;
    let ss_off = read_u64_word(160)? as usize;
    let raw_vs: [u8; 32] = full_report[192..224].try_into().unwrap();

    if blob_off != 224 {
        return Err("non-canonical reportBlob ABI offset".into());
    }
    let blob_len = read_u64_word(blob_off)? as usize;
    if blob_len != 288 || rs_off != blob_off + 32 + 288 {
        return Err("invalid v3 reportBlob length or rawRs offset".into());
    }
    let report_blob = &full_report[blob_off + 32..blob_off + 32 + 288];
    let rs_len = read_u64_word(rs_off)? as usize;
    if rs_len < min_signers || rs_len > 31 {
        return Err("insufficient Chainlink DON quorum signatures".into());
    }
    if ss_off != rs_off + 32 + rs_len * 32 {
        return Err("non-canonical rawSs offset".into());
    }
    let ss_len = read_u64_word(ss_off)? as usize;
    if ss_len != rs_len || full_report.len() != ss_off + 32 + ss_len * 32 {
        return Err("rawSs length or total report length mismatch".into());
    }
    if raw_vs[rs_len..].iter().any(|&b| b != 0) {
        return Err("non-zero trailing rawVs bytes".into());
    }

    // Exact Verifier.sol signing hash via native NEAR env::keccak256!
    let report_keccak = near_keccak256(report_blob);
    let mut pre = [0u8; 128];
    pre[0..32].copy_from_slice(&report_keccak);
    pre[32..64].copy_from_slice(&config_digest);
    pre[64..96].copy_from_slice(&epoch_and_round);
    pre[96..128].copy_from_slice(&extra_hash);
    let signing_hash = near_keccak256(&pre);

    let mut allowed = BTreeSet::new();
    for s in &cfg.signers_hex {
        let clean = s.strip_prefix("0x").unwrap_or(s);
        let addr: [u8; 20] = hex::decode(clean)
            .map_err(|_| "bad DON signer address hex".to_owned())?
            .try_into()
            .map_err(|_| "DON signer must be 20 bytes".to_owned())?;
        allowed.insert(addr);
    }

    let mut seen = BTreeSet::new();
    let mut verified_don_signers = Vec::with_capacity(rs_len);
    for i in 0..rs_len {
        let r_slice = &full_report[rs_off + 32 + i * 32..rs_off + 64 + i * 32];
        let s_slice = &full_report[ss_off + 32 + i * 32..ss_off + 64 + i * 32];
        let v_id = match raw_vs[i] {
            0 | 1 => raw_vs[i],
            27 | 28 => raw_vs[i] - 27,
            _ => return Err("invalid recovery id v".into()),
        };
        let mut sig64 = [0u8; 64];
        sig64[0..32].copy_from_slice(r_slice);
        sig64[32..64].copy_from_slice(s_slice);

        // Native NEAR host precompile `env::ecrecover` with EIP-2 malleability protection (`true`)!
        let pk64 = env::ecrecover(&signing_hash, &sig64, v_id, true)
            .ok_or_else(|| "NEAR env::ecrecover rejected DON signature".to_owned())?;
        let pk_keccak = near_keccak256(&pk64);
        let addr: [u8; 20] = pk_keccak[12..32].try_into().unwrap();
        if !allowed.contains(&addr) {
            return Err("unauthorized Chainlink DON signer".into());
        }
        if !seen.insert(addr) {
            return Err("duplicate Chainlink DON signer".into());
        }
        verified_don_signers.push(format!("0x{}", hex::encode(addr)));
    }

    let feed_id: [u8; 32] = report_blob[0..32].try_into().unwrap();
    if feed_id != expected_feed_id {
        return Err("Chainlink feedId mismatch".into());
    }
    let valid_from = u64::from_be_bytes(report_blob[56..64].try_into().unwrap());
    let obs_sec = u64::from_be_bytes(report_blob[88..96].try_into().unwrap());
    let exp_sec = u64::from_be_bytes(report_blob[184..192].try_into().unwrap());
    if obs_sec < valid_from || exp_sec <= obs_sec {
        return Err("invalid Chainlink timestamp ordering".into());
    }
    if (report_blob[192] & 0x80) != 0 || report_blob[192..208].iter().any(|&b| b != 0) {
        return Err("invalid benchmarkPrice sign/high bits".into());
    }
    let benchmark_e18 = u128::from_be_bytes(report_blob[208..224].try_into().unwrap());
    let price_e8 = u64::try_from(benchmark_e18 / 10_000_000_000u128)
        .map_err(|_| "price_e8 overflow".to_owned())?;
    if price_e8 == 0 || price_e8 > 10_000_000_000_000_000 {
        return Err("price_e8 out of SHZ bounds".into());
    }

    let operational = cfg.profile == "operational_mainnet_pinned";
    Ok(OnChainChainlinkVerifyReceipt {
        profile: cfg.profile.clone(),
        operational_source_authenticated: operational,
        feed_id_hex: hex::encode(feed_id),
        price_e8,
        observations_timestamp_us: obs_sec.checked_mul(1_000_000).ok_or("ts overflow")?,
        verified_don_signers,
        full_report_sha256_hex: hex::encode(env::sha256(full_report)),
    })
}

/// Adaptive pure-WASM Pippenger MSM retained ONLY for Route A / Grumpkin empirical gas comparison.
pub fn pippenger_msm<C: CurveAffine>(scalars: &[C::ScalarExt], bases: &[C]) -> C::CurveExt {
    assert_eq!(scalars.len(), bases.len());
    let n = scalars.len();
    if n == 0 {
        return C::CurveExt::identity();
    }
    let w: usize = if n < 32 {
        3
    } else if n < 128 {
        4
    } else if n < 512 {
        5
    } else {
        6
    };
    let num_buckets = (1usize << w) - 1;
    let mask = num_buckets as u64;
    let num_windows = 256usize.div_ceil(w);
    let reprs: Vec<[u8; 32]> = scalars
        .iter()
        .map(|s| {
            let mut out = [0u8; 32];
            out.copy_from_slice(s.to_repr().as_ref());
            out
        })
        .collect();
    let get_window = |repr: &[u8; 32], bit_offset: usize| -> usize {
        let byte_idx = bit_offset >> 3;
        let bit_shift = bit_offset & 7;
        let mut word = u64::from(repr[byte_idx]);
        if byte_idx + 1 < 32 {
            word |= u64::from(repr[byte_idx + 1]) << 8;
        }
        ((word >> bit_shift) & mask) as usize
    };
    let mut total: Option<C::CurveExt> = None;
    for win in (0..num_windows).rev() {
        if let Some(mut t) = total {
            for _ in 0..w {
                t = t.double();
            }
            total = Some(t);
        }
        let bit_offset = win * w;
        let mut buckets: Vec<Option<C::CurveExt>> = vec![None; num_buckets];
        for (repr, base) in reprs.iter().zip(bases.iter()) {
            let idx = get_window(repr, bit_offset);
            if idx != 0 {
                let slot = &mut buckets[idx - 1];
                *slot = Some(match *slot {
                    None => base.to_curve(),
                    Some(acc) => acc + *base,
                });
            }
        }
        let mut running: Option<C::CurveExt> = None;
        let mut win_sum: Option<C::CurveExt> = None;
        for b in buckets.into_iter().rev() {
            if let Some(bv) = b {
                running = Some(match running {
                    None => bv,
                    Some(r) => r + bv,
                });
            }
            if let Some(r) = running {
                win_sum = Some(match win_sum {
                    None => r,
                    Some(ws) => ws + r,
                });
            }
        }
        if let Some(ws) = win_sum {
            total = Some(match total {
                None => ws,
                Some(t) => t + ws,
            });
        }
    }
    total.unwrap_or_else(C::CurveExt::identity)
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
struct PendingSessionMeta {
    genesis: String,
    policy_hash: String,
    start_hour: u64,
    checkpoint_root: String,
    session_bincode: Vec<u8>,
}

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ShzIndex03Verifier {
    pub owner: AccountId,
    pub pinned_vk_bincode: Vec<u8>,
    pub btc_light_client_json: String,
    pub operational_pyth_signers: Vec<([u8; 32], u64)>,
    pub synthetic_pyth_signers: Vec<([u8; 32], u64)>,
    pub chainlink_don_json: String,
    pending_sessions: BTreeMap<String, PendingSessionMeta>,
    consumed_proof_nullifiers: BTreeSet<[u8; 32]>,
    verified_checkpoints_json: BTreeMap<u64, String>,
}

impl ShzIndex03Verifier {
    fn load_vk(&self) -> CompactPinnedVerifierKey {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&self.pinned_vk_bincode)
            .expect("pinned VK bincode")
    }

    fn load_btc_lc(&self) -> BtcLightClient {
        serde_json::from_str(&self.btc_light_client_json).expect("BtcLightClient JSON")
    }

    fn save_btc_lc(&mut self, lc: &BtcLightClient) {
        self.btc_light_client_json = serde_json::to_string(lc).expect("serialize BtcLightClient");
    }

    fn load_don_cfg(&self) -> OnChainChainlinkDonConfig {
        serde_json::from_str(&self.chainlink_don_json).expect("Chainlink DON JSON")
    }
}

#[near_bindgen]
impl ShzIndex03Verifier {
    #[init]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        compact_vk_json: String,
        btc_network: String,
        min_btc_confirmations: u64,
        anchor_btc_height: u64,
        anchor_btc_header_hex: String,
        solana_pyth_storage_hex: String,
        synthetic_pyth_signer_hex: String,
        chainlink_don_json: String,
    ) -> Self {
        assert!(!env::state_exists(), "already initialized");
        let compact_vk: CompactPinnedVerifierKey =
            serde_json::from_str(&compact_vk_json).unwrap_or_else(|e| env::panic_str(&format!("bad compact_vk: {e}")));
        let pinned_vk_bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&compact_vk)
            .expect("encode VK");

        let net = match btc_network.as_str() {
            "mainnet" => BtcNetwork::Mainnet,
            "testnet4" => BtcNetwork::Testnet4,
            "regtest" => BtcNetwork::Regtest,
            _ => env::panic_str("unsupported btc_network"),
        };
        let hdr = hex::decode(&anchor_btc_header_hex)
            .unwrap_or_else(|_| env::panic_str("invalid anchor_btc_header_hex"));
        let lc = BtcLightClient::from_trusted_anchor_header(net, min_btc_confirmations, anchor_btc_height, &hdr)
            .unwrap_or_else(|e| env::panic_str(&e));

        let op_signers = parse_solana_storage_ed25519_signers(&solana_pyth_storage_hex)
            .unwrap_or_else(|e| env::panic_str(&e));
        let syn_pk = parse_hex32_strict(&synthetic_pyth_signer_hex)
            .unwrap_or_else(|e| env::panic_str(&e));
        let don_cfg: OnChainChainlinkDonConfig = serde_json::from_str(&chainlink_don_json)
            .unwrap_or_else(|e| env::panic_str(&format!("bad chainlink_don_json: {e}")));
        assert!(
            don_cfg.profile == "operational_mainnet_pinned"
                || don_cfg.profile == "synthetic_test_only",
            "invalid DON profile"
        );

        Self {
            owner: env::predecessor_account_id(),
            pinned_vk_bincode,
            btc_light_client_json: serde_json::to_string(&lc).unwrap(),
            operational_pyth_signers: op_signers,
            synthetic_pyth_signers: vec![(syn_pk, u64::MAX)],
            chainlink_don_json,
            pending_sessions: BTreeMap::new(),
            consumed_proof_nullifiers: BTreeSet::new(),
            verified_checkpoints_json: BTreeMap::new(),
        }
    }

    // --- Gate B: Stateful Transparent BN254 8-Fold Nova NIFS + Spartan/IPA Verification ---

    pub fn begin_nova_verification(&mut self, #[serializer(borsh)] args: BeginNovaArgs) -> String {
        if args.session_id.is_empty() || args.session_id.len() > 64 {
            env::panic_str("invalid session_id");
        }
        if self.pending_sessions.contains_key(&args.session_id) {
            env::panic_str("duplicate active session_id");
        }
        let proof_sha = sha256_bytes(&args.proof_bincode);
        if self.consumed_proof_nullifiers.contains(&proof_sha) {
            env::panic_str("replayed proof nullifier rejected");
        }

        let (start_hour, z0) = build_v1_claim_state(
            &args.genesis,
            &args.policy_hash,
            &args.start_hour,
            &args.checkpoint_root,
            0,
        )
        .unwrap_or_else(|e| env::panic_str(&e));
        let (_, z8) = build_v1_claim_state(
            &args.genesis,
            &args.policy_hash,
            &args.start_hour,
            &args.checkpoint_root,
            8,
        )
        .unwrap_or_else(|e| env::panic_str(&e));

        if self.verified_checkpoints_json.contains_key(&start_hour) {
            env::panic_str("checkpoint start_hour already verified");
        }

        let proof: Bn254NifsSpartanProof = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(2 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize(&args.proof_bincode)
            .unwrap_or_else(|e| env::panic_str(&format!("proof decode failed: {e}")));

        let vk = self.load_vk();
        let session = begin_decider_session(
            &vk,
            &proof,
            proof_sha,
            &z0,
            &z8,
            true,
            near_keccak256,
            near_bn254_multiexp,
        )
        .unwrap_or_else(|e| env::panic_str(&e));

        let session_bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&session)
            .expect("encode session");

        self.pending_sessions.insert(
            args.session_id,
            PendingSessionMeta {
                genesis: args.genesis,
                policy_hash: args.policy_hash,
                start_hour,
                checkpoint_root: args.checkpoint_root,
                session_bincode,
            },
        );
        hex::encode(proof_sha)
    }

    pub fn verify_r1cs_chunk(&mut self, #[serializer(borsh)] args: VerifyChunkArgs) -> u32 {
        let meta = self
            .pending_sessions
            .get_mut(&args.session_id)
            .unwrap_or_else(|| env::panic_str("unknown session_id"));
        let mut session: AuthenticatedVerificationSession = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&meta.session_bincode)
            .expect("decode session");

        evaluate_packed_r1cs_chunk(
            &mut session,
            args.chunk_idx,
            args.merkle_index,
            &args.merkle_siblings,
            &args.payload,
            near_sha256,
        )
        .unwrap_or_else(|e| env::panic_str(&e));

        meta.session_bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&session)
            .expect("encode session");
        session.verified_r1cs_chunks
    }

    pub fn verify_msm_chunk(&mut self, #[serializer(borsh)] args: VerifyChunkArgs) -> u32 {
        let meta = self
            .pending_sessions
            .get_mut(&args.session_id)
            .unwrap_or_else(|| env::panic_str("unknown session_id"));
        let mut session: AuthenticatedVerificationSession = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&meta.session_bincode)
            .expect("decode session");

        evaluate_msm_chunk(
            &mut session,
            args.chunk_idx,
            args.merkle_index,
            &args.merkle_siblings,
            &args.payload,
            near_sha256,
            near_bn254_multiexp,
        )
        .unwrap_or_else(|e| env::panic_str(&e));

        meta.session_bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&session)
            .expect("encode session");
        session.verified_msm_chunks
    }

    pub fn finalize_nova_verification(&mut self, session_id: String) -> String {
        let vk = self.load_vk();
        let meta = self
            .pending_sessions
            .remove(&session_id)
            .unwrap_or_else(|| env::panic_str("unknown session_id"));
        let mut session: AuthenticatedVerificationSession = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&meta.session_bincode)
            .expect("decode session");

        if self.consumed_proof_nullifiers.contains(&session.proof_sha256)
            || self.verified_checkpoints_json.contains_key(&meta.start_hour)
        {
            env::panic_str("replayed proof or duplicate start_hour");
        }

        finalize_decider_session(&mut session, &vk.ipa_ck_s_near64, near_bn254_multiexp)
            .unwrap_or_else(|e| env::panic_str(&e));

        self.consumed_proof_nullifiers.insert(session.proof_sha256);
        let record = VerifiedCheckpointRecord {
            relation: session.relation,
            genesis: meta.genesis,
            policy_hash: meta.policy_hash,
            start_hour: meta.start_hour,
            checkpoint_root: meta.checkpoint_root,
            proof_sha256_hex: hex::encode(session.proof_sha256),
            vk_chunks_merkle_root_hex: hex::encode(session.vk_chunks_merkle_root),
            verified_r1cs_chunks: session.verified_r1cs_chunks,
            verified_msm_chunks: session.verified_msm_chunks,
            near_nova_verified: true,
            bitcoin_anchor_finalized: false,
            bitcoin_anchor_txid_hex: None,
            bitcoin_anchor_block_hash_hex: None,
            bitcoin_confirmations: 0,
            source_challenged_invalid: false,
            production_ready: false,
            can_authorize_dlc_settlement: false,
        };
        let json = serde_json::to_string(&record).unwrap();
        self.verified_checkpoints_json
            .insert(meta.start_hour, json.clone());
        json
    }

    // --- Gate C: On-Chain Pyth Pro (Ed25519) & Chainlink v3 (secp256k1 ecrecover) + Anti-Cherry-Picking ---

    pub fn verify_pyth_pro_report_onchain(
        &self,
        profile: String,
        raw_envelope_hex: String,
        cutoff_us: u64,
    ) -> String {
        let raw = hex::decode(&raw_envelope_hex)
            .unwrap_or_else(|_| env::panic_str("invalid Pyth envelope hex"));
        if raw.len() < 102 {
            env::panic_str("truncated Pyth Solana envelope");
        }
        let magic = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        if magic != PYTH_SOLANA_FORMAT_MAGIC {
            env::panic_str("wrong Pyth Solana envelope magic");
        }
        let sig: [u8; 64] = raw[4..68].try_into().unwrap();
        let pubkey: [u8; 32] = raw[68..100].try_into().unwrap();
        let payload_len = u16::from_le_bytes(raw[100..102].try_into().unwrap()) as usize;
        if raw.len() != 102 + payload_len {
            env::panic_str("Pyth Solana envelope length mismatch");
        }
        let payload = &raw[102..];

        let (signers, is_operational) = match profile.as_str() {
            "operational_mainnet_pinned" => (&self.operational_pyth_signers, true),
            "synthetic_test_only" => (&self.synthetic_pyth_signers, false),
            _ => env::panic_str("unknown source profile"),
        };

        let parsed = pyth_payload::parse_btc_usd_signed_price(payload)
            .unwrap_or_else(|| env::panic_str("invalid Pyth BTC/USD PayloadData"));
        let publish_us: u64 = parsed.publish_time_us.parse().unwrap();
        if publish_us > cutoff_us {
            env::panic_str("Pyth observation in future relative to cutoff_us");
        }
        let authorized = signers
            .iter()
            .any(|(pk, exp_us)| pk == &pubkey && publish_us <= *exp_us);
        if !authorized {
            env::panic_str("unauthorized or expired Pyth Ed25519 signer");
        }
        if !env::ed25519_verify(&sig, payload, &pubkey) {
            env::panic_str("NEAR env::ed25519_verify rejected Pyth signature");
        }

        let receipt = OnChainPythVerifyReceipt {
            profile,
            operational_source_authenticated: is_operational,
            signer_pubkey_hex: hex::encode(pubkey),
            price_e8: parsed.price_e8.parse().unwrap(),
            publish_time_us: publish_us,
            envelope_sha256_hex: hex::encode(env::sha256(&raw)),
        };
        serde_json::to_string(&receipt).unwrap()
    }

    pub fn verify_chainlink_v3_report_onchain(&self, full_report_hex: String) -> String {
        let raw = hex::decode(&full_report_hex)
            .unwrap_or_else(|_| env::panic_str("invalid Chainlink hex"));
        let cfg = self.load_don_cfg();
        let receipt = verify_chainlink_v3_with_near_ecrecover(&raw, &cfg)
            .unwrap_or_else(|e| env::panic_str(&e));
        serde_json::to_string(&receipt).unwrap()
    }

    pub fn challenge_cherry_picked_chainlink(
        &mut self,
        start_hour: u64,
        hour_id: u64,
        selected_publish_us: u64,
        challenger_full_report_hex: String,
    ) -> bool {
        if hour_id < start_hour || hour_id >= start_hour + 8 {
            env::panic_str("hour_id outside checkpoint epoch");
        }
        let raw = hex::decode(&challenger_full_report_hex)
            .unwrap_or_else(|_| env::panic_str("invalid challenger hex"));
        let cfg = self.load_don_cfg();
        let receipt = verify_chainlink_v3_with_near_ecrecover(&raw, &cfg)
            .unwrap_or_else(|e| env::panic_str(&e));

        let cutoff_us = (hour_id + 1) * 3_600_000_000;
        let window_start_us = cutoff_us - 300_000_000;
        let is_newer_eligible = receipt.observations_timestamp_us >= window_start_us
            && receipt.observations_timestamp_us <= cutoff_us
            && receipt.observations_timestamp_us > selected_publish_us;

        if is_newer_eligible {
            if let Some(rec_json) = self.verified_checkpoints_json.get(&start_hour).cloned() {
                let mut rec: VerifiedCheckpointRecord = serde_json::from_str(&rec_json).unwrap();
                rec.source_challenged_invalid = true;
                self.verified_checkpoints_json
                    .insert(start_hour, serde_json::to_string(&rec).unwrap());
            }
        }
        is_newer_eligible
    }

    // --- Gate D: Bitcoin Header Light Client (`Near-One` model) + `SHZIDX01` Anchor Binding ---

    pub fn submit_btc_header(&mut self, raw_header_hex: String) -> String {
        let hdr = hex::decode(&raw_header_hex)
            .unwrap_or_else(|_| env::panic_str("invalid 80-byte header hex"));
        let mut lc = self.load_btc_lc();
        let stored: StoredBtcHeader = lc
            .submit_header(&hdr)
            .unwrap_or_else(|e| env::panic_str(&e));
        self.save_btc_lc(&lc);
        serde_json::to_string(&stored).unwrap()
    }

    pub fn anchor_verified_checkpoint_to_bitcoin(
        &mut self,
        start_hour: u64,
        raw_tx_hex: String,
        block_hash_hex: String,
        tx_index: u32,
        merkle_branch_hex: Vec<String>,
    ) -> String {
        let rec_json = self
            .verified_checkpoints_json
            .get(&start_hour)
            .cloned()
            .unwrap_or_else(|| env::panic_str("checkpoint not Nova-verified"));
        let mut rec: VerifiedCheckpointRecord = serde_json::from_str(&rec_json).unwrap();
        if !rec.near_nova_verified || rec.source_challenged_invalid {
            env::panic_str("checkpoint ineligible for Bitcoin anchor");
        }

        let expected_root = parse_hex32_strict(&rec.checkpoint_root).unwrap();
        let raw_tx =
            hex::decode(&raw_tx_hex).unwrap_or_else(|_| env::panic_str("invalid raw_tx_hex"));
        let lc = self.load_btc_lc();
        let anchor: VerifiedBitcoinAnchorReceipt = lc
            .verify_checkpoint_anchor_finality(
                &expected_root,
                &raw_tx,
                &block_hash_hex,
                tx_index,
                &merkle_branch_hex,
            )
            .unwrap_or_else(|e| env::panic_str(&e));

        rec.bitcoin_anchor_finalized = true;
        rec.bitcoin_anchor_txid_hex = Some(anchor.txid_hex);
        rec.bitcoin_anchor_block_hash_hex = Some(anchor.block_hash_hex);
        rec.bitcoin_confirmations = anchor.confirmations;
        let updated = serde_json::to_string(&rec).unwrap();
        self.verified_checkpoints_json
            .insert(start_hour, updated.clone());
        updated
    }

    /// Re-evaluates canonical mainchain inclusion dynamically against the CURRENT `BtcLightClient` tip
    /// so any subsequent Bitcoin reorganization that orphans the anchor block immediately revokes eligibility!
    pub fn get_checkpoint_feed_status(&self, start_hour: u64) -> String {
        let rec_json = self
            .verified_checkpoints_json
            .get(&start_hour)
            .unwrap_or_else(|| env::panic_str("checkpoint not found"));
        let rec: VerifiedCheckpointRecord = serde_json::from_str(rec_json).unwrap();
        let lc = self.load_btc_lc();

        let (canonical_confirmed, live_confs) = match &rec.bitcoin_anchor_block_hash_hex {
            Some(bh) if rec.bitcoin_anchor_finalized => {
                if let Some(&anchor_h) = lc.mainchain_hash_to_height.get(bh) {
                    let tip_h = lc.headers_pool.get(&lc.tip_hash_hex).unwrap().height;
                    let confs = tip_h.saturating_sub(anchor_h) + 1;
                    (confs >= lc.min_confirmations, confs)
                } else {
                    (false, 0)
                }
            }
            _ => (false, 0),
        };

        let status = CheckpointFeedStatus {
            start_hour,
            checkpoint_root: rec.checkpoint_root,
            near_nova_verified: rec.near_nova_verified,
            bitcoin_canonical_mainchain_confirmed: canonical_confirmed,
            live_bitcoin_confirmations: live_confs,
            source_challenged_invalid: rec.source_challenged_invalid,
            eligible_for_frost_dlc_feed: rec.near_nova_verified
                && canonical_confirmed
                && !rec.source_challenged_invalid,
            production_ready: false,
            can_authorize_dlc_settlement: false,
        };
        serde_json::to_string(&status).unwrap()
    }

    pub fn get_verified_checkpoint(&self, start_hour: u64) -> Option<String> {
        self.verified_checkpoints_json.get(&start_hour).cloned()
    }

    pub fn production_ready(&self) -> bool {
        false
    }

    pub fn can_authorize_dlc_settlement(&self) -> bool {
        false
    }

    // --- Microbenchmark endpoints retained for reproducible Route A vs B vs C profiling ---

    pub fn bench_host_bn254_multiexp(&self, n: usize) -> String {
        let g = BnAffine::generator();
        let coords = g.coordinates().unwrap();
        let mut pt64 = [0u8; 64];
        pt64[0..32].copy_from_slice(coords.x().to_repr().as_ref());
        pt64[32..64].copy_from_slice(coords.y().to_repr().as_ref());

        let mut s =
            BnScalar::from(0x1234_5678_9abc_def0u64).square().square() + BnScalar::from(7u64);
        let mult = BnScalar::from(0x9e37_79b9_7f4a_7c15u64);
        let mut buf = Vec::with_capacity(n * 96);
        for _ in 0..n {
            buf.extend_from_slice(&pt64);
            buf.extend_from_slice(s.to_repr().as_ref());
            s *= mult;
        }
        hex::encode(env::alt_bn128_g1_multiexp(&buf))
    }

    pub fn bench_wasm_msm(&self, curve: String, n: usize) -> String {
        match curve.as_str() {
            "pallas" => {
                let g = PallasAffine::generator();
                let bases = vec![g; n];
                let mut s = PallasScalar::from(0x1234_5678_9abc_def0u64).square().square();
                let m = PallasScalar::from(0x9e37_79b9_7f4a_7c15u64);
                let scalars: Vec<_> = (0..n)
                    .map(|_| {
                        s *= m;
                        s
                    })
                    .collect();
                let out: PallasPoint = pippenger_msm(&scalars, &bases);
                let aff = out.to_affine();
                let x: PallasBase = *aff.coordinates().unwrap().x();
                hex::encode(x.to_repr().as_ref())
            }
            "grumpkin" => {
                let g = GrAffine::generator();
                let bases = vec![g; n];
                let mut s = GrScalar::from(0x1234_5678_9abc_def0u64).square().square();
                let m = GrScalar::from(0x9e37_79b9_7f4a_7c15u64);
                let scalars: Vec<_> = (0..n)
                    .map(|_| {
                        s *= m;
                        s
                    })
                    .collect();
                let out: GrPoint = pippenger_msm(&scalars, &bases);
                let aff = out.to_affine();
                hex::encode(aff.coordinates().unwrap().x().to_repr().as_ref())
            }
            "bn254" => {
                let g = BnAffine::generator();
                let bases = vec![g; n];
                let mut s = BnScalar::from(0x1234_5678_9abc_def0u64).square().square();
                let m = BnScalar::from(0x9e37_79b9_7f4a_7c15u64);
                let scalars: Vec<_> = (0..n)
                    .map(|_| {
                        s *= m;
                        s
                    })
                    .collect();
                let out: BnPoint = pippenger_msm(&scalars, &bases);
                let aff = out.to_affine();
                hex::encode(aff.coordinates().unwrap().x().to_repr().as_ref())
            }
            _ => env::panic_str("unknown curve"),
        }
    }
}
